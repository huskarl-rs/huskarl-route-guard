//! The rule-id router that owns the path-confusion guard.
//!
//! An authorization layer that maps request paths to per-path rules needs the same two
//! things regardless of which proxy or framework hosts it:
//!
//! - **Rule identity** — every pattern produced by one `route`/`subtree` call shares a
//!   rule id, so the structural guard reasons at rule granularity (movement *within* a
//!   subtree is not a relocation).
//! - **The structural verdict** — deny a request whose path could be routed differently
//!   by a normalizing backend than the rule the raw path matched.
//!
//! [`RuleRouter`] owns the `id → rule` table, the default rule, and a
//! [`StructuralGuard`] over the
//! [owned segment-tree router](crate::route_tree). Public matchit-style pattern strings
//! are lowered into the owned grammar at build time; whatever the grammar cannot express
//! (in-segment prefix/suffix params) is a build-time error.
//!
//! [`RuleRouter::builder`] is the intended way to construct one: its
//! [`route`](RuleRouterBuilder::route) / [`subtree`](RuleRouterBuilder::subtree) /
//! [`blob_subtree`](RuleRouterBuilder::blob_subtree) methods expand subtree patterns
//! internally. The registration-level [`RuleRouter::build`] remains for callers that
//! assemble [`Registration`]s inside a builder of their own (as huskarl-pingora's
//! `Guard`/`LoginProxy` do); rule ids are assigned from registration order, so the
//! rule-granularity contract holds by construction on both paths.

use bon::bon;

use crate::{
    path_confusion::{CaseSensitivity, DecodeLayers, DenyReason, PathConfusion, StructuralClasses},
    route_tree::{
        BuildError, LowerError, MethodMatch, Router, Segment, StructuralGuard, lower_matchit,
    },
    structural::{classes_present, enabled_classes, enabled_encodings},
};

/// The outcome of matching a path: which rule applies, and whether it came from a
/// registration or is the default rule (no registration covered the path).
///
/// The distinction is the route table's coverage made visible — an authorization
/// layer typically logs *which* registration authorized a request, and treats a
/// [`Default`](Self::Default) fall-through as its own case. Use
/// [`rule`](Self::rule) when only the rule matters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleMatch<'a, R> {
    /// A registration matched: its rule id (the registration's position in build
    /// order) and rule.
    Matched {
        /// The matched registration's rule id.
        id: u32,
        /// The matched registration's rule.
        rule: &'a R,
    },
    /// No registration covers the path; the default rule applies.
    Default {
        /// The default rule.
        rule: &'a R,
    },
}

impl<'a, R> RuleMatch<'a, R> {
    /// The rule to apply — the matched registration's, or the default.
    #[must_use]
    pub fn rule(&self) -> &'a R {
        match self {
            Self::Matched { rule, .. } | Self::Default { rule } => rule,
        }
    }

    /// The matched registration's rule id, or `None` for the default rule.
    #[must_use]
    pub fn id(&self) -> Option<u32> {
        match self {
            Self::Matched { id, .. } => Some(*id),
            Self::Default { .. } => None,
        }
    }

    /// Whether the default rule applied (no registration covers the path).
    #[must_use]
    pub fn is_default(&self) -> bool {
        matches!(self, Self::Default { .. })
    }
}

/// Error building a [`RuleRouter`]. Callers typically map this into their own
/// configuration-error type.
#[derive(Debug)]
pub enum RuleRouterError {
    /// A pattern could not be lowered into the route grammar (e.g. an in-segment
    /// prefix/suffix param, a non-final catch-all, or a conflict with another route).
    Route {
        /// The offending pattern.
        pattern: String,
        /// A human-readable reason.
        reason: &'static str,
    },
    /// A registered pattern is itself non-canonical — it carries a recognized structural form
    /// (`%2F`, `..`, `//`, `;`, or an enabled opt-in form) that the guard treats as
    /// route structure, so a normalizing backend would never present it canonically.
    NonCanonical {
        /// The offending pattern.
        pattern: String,
    },
    /// A registered pattern contains ASCII uppercase under
    /// [`CaseSensitivity::Insensitive`]. A case-folding backend resolves it to lowercase,
    /// so a differently-cased request could reach it without the matched rule's checks.
    NonCanonicalCase {
        /// The offending pattern.
        pattern: String,
    },
    /// A registration's [`MethodMatch::OneOf`] is empty. It would match no method at
    /// all, silently leaving every request on the registration's paths to the default
    /// rule — almost certainly a construction bug, so it is rejected rather than
    /// registered as unreachable.
    EmptyMethodSet {
        /// The registration's first pattern, for attribution.
        pattern: String,
    },
    /// A registration has no patterns, so its rule would be unreachable while still
    /// consuming a rule id.
    EmptyPatternSet,
    /// More registrations than there are rule ids: `u32::MAX` is reserved as the
    /// default rule's sentinel id. Unreachable in any realistic configuration;
    /// rejected rather than assumed impossible.
    TooManyRegistrations,
}

impl std::fmt::Display for RuleRouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Route { pattern, reason } => {
                write!(f, "invalid route pattern {pattern:?}: {reason}")
            }
            Self::NonCanonical { pattern } => write!(
                f,
                "route pattern {pattern:?} is non-canonical — it carries a recognized structural form \
                 (%2F, .., //, ;, …) the path-confusion guard treats as route structure, so \
                 requests to it would always be denied; register the canonical pattern, or \
                 disable path_confusion"
            ),
            Self::NonCanonicalCase { pattern } => write!(
                f,
                "route pattern {pattern:?} contains uppercase but the backend is declared \
                 case-insensitive; register it in lowercase (the form the backend resolves to)"
            ),
            Self::EmptyMethodSet { pattern } => write!(
                f,
                "registration for {pattern:?} has an empty method set — it would match no \
                 request; list at least one method, or use MethodMatch::Any"
            ),
            Self::EmptyPatternSet => f.write_str(
                "registration has no route patterns — its rule would be unreachable; add at least one pattern or remove the registration",
            ),
            Self::TooManyRegistrations => {
                f.write_str("too many registrations: u32::MAX is reserved as the default rule's id")
            }
        }
    }
}

impl std::error::Error for RuleRouterError {}

/// One registration: a group of patterns sharing one rule — the crate's unit of **rule
/// identity**. [`RuleRouter::build`] assigns each registration the rule id equal to its
/// position, so identity is a fact of the input's shape rather than a contract the
/// caller must uphold: patterns in one registration can never end up under different
/// rules, and a rule can never be silently detached from its patterns.
///
/// Construct via [`route`](Self::route) / [`subtree`](Self::subtree) /
/// [`blob_subtree`](Self::blob_subtree) (mirroring the builder methods), qualified with
/// [`for_methods`](Self::for_methods) where the rule is method-specific — or fill the
/// fields directly for full control.
#[derive(Clone, Debug)]
pub struct Registration<R> {
    /// The `matchit`-style patterns this registration covers, all under one rule id.
    /// Must contain at least one pattern; an empty list is rejected at build time.
    pub patterns: Vec<String>,
    /// The rule every pattern resolves to.
    pub rule: R,
    /// Declares the catch-all tail an **opaque** blob key space (see
    /// [`RuleRouterBuilder::blob_subtree`]). Ignored for patterns without a catch-all.
    pub opaque: bool,
    /// Which method(s) the rule applies to. Path precedence is resolved before this
    /// value; see [`MethodMatch`].
    pub method: MethodMatch,
}

impl<R> Registration<R> {
    /// A single exact-match pattern (the row-level [`RuleRouterBuilder::route`]).
    pub fn route(pattern: impl Into<String>, rule: R) -> Self {
        Self {
            patterns: vec![pattern.into()],
            rule,
            opaque: false,
            method: MethodMatch::Any,
        }
    }

    /// A path and everything beneath it, expanded via
    /// [`subtree_patterns`](crate::subtree_patterns) (the row-level
    /// [`RuleRouterBuilder::subtree`]).
    pub fn subtree(path: &str, rule: R) -> Self {
        Self {
            patterns: crate::subtree_patterns(path),
            rule,
            opaque: false,
            method: MethodMatch::Any,
        }
    }

    /// Like [`subtree`](Self::subtree), with the catch-all tail declared an opaque
    /// blob key space (the row-level [`RuleRouterBuilder::blob_subtree`]).
    pub fn blob_subtree(path: &str, rule: R) -> Self {
        Self {
            opaque: true,
            ..Self::subtree(path, rule)
        }
    }

    /// Restrict the registration to the given method(s) — a bare [`http::Method`],
    /// an array, or a `Vec` of them — all under the registration's single rule id.
    /// Path precedence is resolved before method matching; see [`MethodMatch`].
    #[must_use]
    pub fn for_methods(mut self, method: impl Into<MethodMatch>) -> Self {
        self.method = method.into();
        self
    }
}

/// A `path → rule` router with rule-granularity identity and the path-confusion guard.
pub struct RuleRouter<R> {
    rules: Vec<R>,
    default: R,
    guard: StructuralGuard,
}

impl<R> std::fmt::Debug for RuleRouter<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleRouter")
            .field("rules", &self.rules.len())
            .finish_non_exhaustive()
    }
}

impl<R> RuleRouter<R> {
    /// Builds the router from [`Registration`]s. Each registration's patterns share
    /// one rule id — its position in `registrations` — so rule identity holds by
    /// construction; there is no id contract for the caller to get wrong.
    ///
    /// This is the **registration-level** entry point, for callers that assemble
    /// [`Registration`]s inside a builder of their own (as huskarl-pingora's
    /// `Guard`/`LoginProxy` do). Everyone else should prefer [`RuleRouter::builder`],
    /// whose methods construct the registrations internally.
    ///
    /// Runs the build-time canonical-pattern checks unless the guard is `Off`: a pattern
    /// that itself carries an enabled structural form is rejected
    /// ([`RuleRouterError::NonCanonical`]), and under [`CaseSensitivity::Insensitive`] an
    /// uppercase pattern is rejected ([`RuleRouterError::NonCanonicalCase`]). Each pattern
    /// is then lowered into the route grammar; an unrepresentable pattern is a
    /// [`RuleRouterError::Route`].
    ///
    /// # Errors
    ///
    /// Returns a [`RuleRouterError`] for an invalid, conflicting, or non-canonical
    /// pattern, a registration with no patterns ([`RuleRouterError::EmptyPatternSet`]),
    /// or one with an empty [`MethodMatch::OneOf`]
    /// ([`RuleRouterError::EmptyMethodSet`]) — either of which would silently match
    /// nothing.
    pub fn build(
        registrations: Vec<Registration<R>>,
        default: R,
        path_confusion: PathConfusion,
        structural_classes: StructuralClasses,
        decode_layers: DecodeLayers,
        case_sensitivity: CaseSensitivity,
    ) -> Result<Self, RuleRouterError> {
        let byte_enabled = enabled_classes(&structural_classes);
        let enc = enabled_encodings(&structural_classes, decode_layers);

        let mut tree_entries = Vec::new();
        // Patterns parallel to `tree_entries`, kept so a tree build failure can be
        // attributed to the pattern that caused it.
        let mut patterns: Vec<String> = Vec::new();
        let mut rules: Vec<R> = Vec::new();
        for reg in registrations {
            if reg.patterns.is_empty() {
                return Err(RuleRouterError::EmptyPatternSet);
            }
            // An empty method set would claim the registration's terminals for *no*
            // method, leaving its paths silently on the default rule — reject it.
            if matches!(&reg.method, MethodMatch::OneOf(ms) if ms.is_empty()) {
                return Err(RuleRouterError::EmptyMethodSet {
                    pattern: reg.patterns.first().cloned().unwrap_or_default(),
                });
            }
            // The rule id is the registration's position. `u32::MAX` is the internal
            // default-rule sentinel (`route_tree::DEFAULT_RULE`), so it must never be
            // assigned to a real registration.
            let id = u32::try_from(rules.len())
                .ok()
                .filter(|&id| id != crate::route_tree::DEFAULT_RULE)
                .ok_or(RuleRouterError::TooManyRegistrations)?;
            for pattern in reg.patterns {
                let lowered = lower_matchit(&pattern).map_err(|e| RuleRouterError::Route {
                    pattern: pattern.clone(),
                    reason: lower_reason(&e),
                })?;
                // Build-time canonical-pattern check: a registered pattern that itself
                // carries a structural byte in a literal segment (or, under a
                // case-folding backend, uppercase) is non-canonical — the backend would
                // never present it as written. Parameter names are route metadata, not
                // request-path bytes, so inspect the lowered literals rather than the
                // source pattern.
                if path_confusion != PathConfusion::Off {
                    let literals = lowered.segments.iter().filter_map(|segment| match segment {
                        Segment::Literal(literal) => Some(literal.as_str()),
                        Segment::Wildcard | Segment::CatchAll => None,
                    });
                    if literals.clone().any(|literal| {
                        !classes_present(literal, byte_enabled, enc)
                            .intersect(byte_enabled)
                            .is_empty()
                    }) {
                        return Err(RuleRouterError::NonCanonical { pattern });
                    }
                    if case_sensitivity.is_insensitive()
                        && literals
                            .clone()
                            .any(|literal| literal.bytes().any(|b| b.is_ascii_uppercase()))
                    {
                        return Err(RuleRouterError::NonCanonicalCase { pattern });
                    }
                }

                tree_entries.push((lowered, id, reg.opaque, reg.method.clone()));
                patterns.push(pattern);
            }
            rules.push(reg.rule);
        }

        let router = Router::build(&tree_entries).map_err(|e| map_build_err(e, &patterns))?;
        let guard = StructuralGuard::new(
            router,
            path_confusion,
            structural_classes,
            decode_layers,
            case_sensitivity,
        );

        Ok(Self {
            rules,
            default,
            guard,
        })
    }

    /// Resolves `path` in one call: the path-confusion verdict first, then the rule
    /// match. `Err(reason)` means the request must be **denied** (`400`) as ambiguous —
    /// no rule is offered, because the guard cannot know which rule the backend would
    /// actually serve. `Ok` carries the [`RuleMatch`]: the matched registration's rule,
    /// or the default rule for a path no registration covers.
    ///
    /// This is the intended entry point for request handling: it cannot be called
    /// without the guard running. [`match_rule_unchecked`](Self::match_rule_unchecked) and
    /// [`ambiguous`](Self::ambiguous) expose the two halves separately for callers
    /// that need them apart (e.g. logging the raw-path rule even on a denial) — if you
    /// use those, *you* are responsible for consulting both on every request.
    ///
    /// # The path argument
    ///
    /// `path` must be the **request path alone** — `uri.path()`, never a full
    /// request-target. Input is validated before the guard runs: it must start with `/`
    /// (or be the special `*` request target) and must not contain `?` or `#`. Passing a
    /// full request-target such as `/admin?x=1`, or an absolute URI, returns
    /// [`DenyReason::InvalidPathInput`] rather than falling through to the default rule.
    ///
    /// # Errors
    ///
    /// The guard's [`DenyReason`], naming the check and byte class that fired:
    /// [`message`](DenyReason::message) is the short static string for the denial
    /// response body; its `Display` is the attributed line for the *log*, so an
    /// operator can trace a `400` to the configuration knob or registration that
    /// governs it. Which forms deny on sight and which deny only when they would
    /// relocate the path to a different rule is tabulated in
    /// [How the guard decides](crate::_docs::explanation::decision).
    pub fn resolve(
        &self,
        path: &str,
        method: &http::Method,
    ) -> Result<RuleMatch<'_, R>, DenyReason> {
        if !is_request_path(path) {
            return Err(DenyReason::InvalidPathInput);
        }
        match self.guard.verdict(path, method) {
            Some(reason) => Err(reason),
            None => Ok(self.match_rule_unchecked(path, method)),
        }
    }

    /// Matches `path`, returning the [`RuleMatch`]: the matched registration's rule,
    /// or the default rule for a path no registration covers.
    ///
    /// This is the raw match half only — it performs neither input validation nor a
    /// path-confusion check. Prefer [`resolve`](Self::resolve), which does both. The
    /// `_unchecked` suffix is intentional: this method can authorize a path the backend
    /// interprets differently, and exists for diagnostics, tests, and callers that have
    /// already performed both checks themselves.
    pub fn match_rule_unchecked(&self, path: &str, method: &http::Method) -> RuleMatch<'_, R> {
        match self.guard.resolve(path, method) {
            // Fail closed if an id ever falls outside `rules`, rather than panicking.
            Some(id) => match self.rules.get(id as usize) {
                Some(rule) => RuleMatch::Matched { id, rule },
                None => RuleMatch::Default {
                    rule: &self.default,
                },
            },
            None => RuleMatch::Default {
                rule: &self.default,
            },
        }
    }

    /// Path-confusion verdict. Returns `Some(reason)` if `path` should be denied for
    /// `method`. The verdict re-routes the path internally, so the caller's matched rule
    /// id is not needed.
    ///
    /// The verdict half only — pair it with
    /// [`match_rule_unchecked`](Self::match_rule_unchecked), or use
    /// [`resolve`](Self::resolve), which runs both. This method performs the same input
    /// validation as `resolve`.
    pub fn ambiguous(&self, path: &str, method: &http::Method) -> Option<DenyReason> {
        if is_request_path(path) {
            self.guard.verdict(path, method)
        } else {
            Some(DenyReason::InvalidPathInput)
        }
    }

    /// The anchor the structural verdict reasons over for `path` — the prefix no
    /// modeled transform may rewrite. Test-only window onto the guard, so the
    /// reference backend can be asserted to respect it.
    #[cfg(test)]
    pub(crate) fn structural_anchor<'p>(&self, path: &'p str) -> Option<&'p str> {
        self.guard.structural_anchor(path)
    }
}

/// Whether a value is a request path rather than a complete request-target or URI.
/// `*` is the HTTP asterisk-form target (normally `OPTIONS *`).
fn is_request_path(path: &str) -> bool {
    (path.starts_with('/') || path == "*") && !path.bytes().any(|b| matches!(b, b'?' | b'#'))
}

#[bon]
impl<R> RuleRouter<R> {
    /// Builds the router configured on this builder — the terminal step of
    /// [`RuleRouter::builder`].
    ///
    /// Register rules with the builder's [`route`](RuleRouterBuilder::route),
    /// [`subtree`](RuleRouterBuilder::subtree), and
    /// [`blob_subtree`](RuleRouterBuilder::blob_subtree) methods (plus their
    /// method-qualified `*_for` variants, which take one method or several — all under
    /// that registration's single rule id). Each call is one [`Registration`]: subtree
    /// patterns expand internally, and rule ids are registration positions, so rule
    /// identity holds by construction.
    ///
    /// ```
    /// use huskarl_route_guard::{
    ///     RuleRouter,
    ///     path_confusion::{CaseSensitivity, DecodeLayers},
    /// };
    ///
    /// let router = RuleRouter::builder()
    ///     .default("default-rule")
    ///     .case_sensitivity(CaseSensitivity::Sensitive)
    ///     .decode_layers(DecodeLayers::Single)
    ///     .subtree("/admin", "admin-rule")
    ///     .route("/health", "health-rule")
    ///     .build()
    ///     .expect("valid route table");
    ///
    /// let matched = router
    ///     .resolve("/admin/users", &http::Method::GET)
    ///     .expect("clean path");
    /// assert_eq!(*matched.rule(), "admin-rule");
    /// ```
    ///
    /// A table whose size is only known at runtime — a config file, a tenant list —
    /// registers in bulk via [`routes`](RuleRouterBuilder::routes) /
    /// [`subtrees`](RuleRouterBuilder::subtrees). And because every registration method
    /// is **state-preserving** (generic over the builder's typestate), mixed-kind
    /// dynamic tables can also just reassign the builder in a loop:
    ///
    /// ```
    /// # use huskarl_route_guard::{
    /// #     RuleRouter,
    /// #     path_confusion::{CaseSensitivity, DecodeLayers},
    /// # };
    /// let configured = vec![("/admin", "admin-rule"), ("/api", "api-rule")];
    ///
    /// let router = RuleRouter::builder()
    ///     .default("default-rule")
    ///     .case_sensitivity(CaseSensitivity::Sensitive)
    ///     .decode_layers(DecodeLayers::Single)
    ///     .subtrees(configured)
    ///     .build()
    ///     .expect("valid route table");
    /// # assert!(router.resolve("/api/v1", &http::Method::GET).is_ok());
    /// ```
    ///
    /// # Errors
    ///
    /// Returns a [`RuleRouterError`] for an invalid, conflicting, or non-canonical
    /// pattern — the same build-time checks as [`RuleRouter::build`].
    #[builder(state_mod(vis = "pub"))]
    pub fn new(
        #[builder(field)] registrations: Vec<Registration<R>>,
        /// The rule for paths that match no registered route.
        default: R,
        /// Which path-confusion guard to apply. Defaults to
        /// [`PathConfusion::RejectStructural`].
        #[builder(default)]
        path_confusion: PathConfusion,
        /// The structural classes and encodings the guard recognises beyond the
        /// always-on quartet. Defaults to [`StructuralClasses::new`].
        #[builder(default)]
        structural_classes: StructuralClasses,
        /// Whether more than one percent-decode pass can happen behind this layer
        /// (a CDN/WAF/proxy decoding in front of the origin) — a **required**
        /// declaration with no default (see [`DecodeLayers`]). When unsure, declare
        /// [`UpToTwo`](DecodeLayers::UpToTwo): within the supported model it can only
        /// add denials.
        decode_layers: DecodeLayers,
        /// Whether the upstream resolves paths case-sensitively — a **required**
        /// declaration with no default (see [`CaseSensitivity`]).
        case_sensitivity: CaseSensitivity,
    ) -> Result<Self, RuleRouterError> {
        Self::build(
            registrations,
            default,
            path_confusion,
            structural_classes,
            decode_layers,
            case_sensitivity,
        )
    }
}

impl<R, S: rule_router_builder::State> RuleRouterBuilder<R, S> {
    /// Registers a single exact-match route pattern with an associated rule.
    ///
    /// Patterns use `matchit` syntax (`/users/{id}`, `/files/{*rest}`). This matches the
    /// given path *exactly* — `route("/admin", …)` does not cover `/admin/` or
    /// `/admin/users`. To apply a rule to a path and everything beneath it (the usual
    /// intent for an authorization layer), prefer [`subtree`](Self::subtree).
    pub fn route(self, pattern: impl Into<String>, rule: R) -> Self {
        self.push(Registration::route(pattern, rule))
    }

    /// Like [`route`](Self::route), but the rule applies only to the given `method`(s)
    /// — a bare [`http::Method`], an array, or a `Vec` of them, all under this one
    /// registration's rule id (so `[GET, HEAD]` is one rule, not two). Other methods
    /// on the same path fall through to any method-wildcard rule registered for it,
    /// else the default rule. Path precedence is resolved first: a method mismatch on
    /// this route does **not** fall back to a less-specific wildcard or catch-all route.
    /// See [`MethodMatch`] for the complete rule.
    pub fn route_for(
        self,
        method: impl Into<MethodMatch>,
        pattern: impl Into<String>,
        rule: R,
    ) -> Self {
        self.push(Registration::route(pattern, rule).for_methods(method))
    }

    /// Registers a batch of [`route`](Self::route)s — one `(pattern, rule)` registration
    /// per item, each under its own rule id. For route tables whose size is only known
    /// at runtime (a config file, a tenant list).
    pub fn routes<P>(mut self, routes: impl IntoIterator<Item = (P, R)>) -> Self
    where
        P: Into<String>,
    {
        for (pattern, rule) in routes {
            self = self.push(Registration::route(pattern, rule));
        }
        self
    }

    /// Applies a rule to a path **and everything beneath it**.
    ///
    /// This is the recommended way to protect an area of the URL space: matching only an
    /// exact path (via [`route`](Self::route)) is a common source of authorization gaps,
    /// because a request to `/admin/` or `/admin/users` would otherwise fall through to
    /// the default rule. The path expands via [`subtree_patterns`](crate::subtree_patterns),
    /// every pattern sharing one rule id — so movement *within* the subtree is never a
    /// relocation to the path-confusion guard:
    ///
    /// - `subtree("/admin", …)`  covers `/admin`, `/admin/`, and `/admin/...`
    /// - `subtree("/admin/", …)` covers `/admin/` and `/admin/...` (not bare `/admin`)
    /// - `subtree("/", …)` covers the entire path space
    ///
    /// A more-specific [`route`](Self::route) still takes precedence over the subtree's
    /// catch-all, so exact carve-outs can be layered on top.
    pub fn subtree(self, path: &str, rule: R) -> Self {
        self.push(Registration::subtree(path, rule))
    }

    /// Like [`subtree`](Self::subtree), but the rule applies only to the given
    /// `method`(s) — a bare [`http::Method`], an array, or a `Vec` of them, all under
    /// this one registration's rule id. Path precedence is resolved before method
    /// matching; see [`MethodMatch`].
    pub fn subtree_for(self, method: impl Into<MethodMatch>, path: &str, rule: R) -> Self {
        self.push(Registration::subtree(path, rule).for_methods(method))
    }

    /// Registers a batch of [`subtree`](Self::subtree)s — one `(path, rule)`
    /// registration per item, each subtree under its own rule id. For route tables whose
    /// size is only known at runtime (a config file, a tenant list).
    pub fn subtrees<P>(mut self, subtrees: impl IntoIterator<Item = (P, R)>) -> Self
    where
        P: AsRef<str>,
    {
        for (path, rule) in subtrees {
            self = self.push(Registration::subtree(path.as_ref(), rule));
        }
        self
    }

    /// Like [`subtree`](Self::subtree), but declares the subtree an **opaque** key
    /// space whose uniformity is *guaranteed at build time*. Runtime tolerance is the
    /// same for both — any fully-registered single-rule subtree tolerates
    /// separator-like forms (`%2F`, `;`, `\`) in its keys, and dot-segments that stay
    /// inside it, while climbs out and NUL truncation always deny.
    /// The declaration is about *change over time*: registering a more-specific
    /// [`route`](Self::route) or subtree **under a blob is a build error**
    /// ([`RuleRouterError::Route`]), so a later registration cannot silently break
    /// the uniformity and flip live opaque-key traffic to `400`s. Under a plain
    /// [`subtree`](Self::subtree), a nested registration is allowed and (safely,
    /// fail-closed) starts denying the affected structural keys.
    ///
    /// Prefer this over `subtree` for any prefix whose keys are known to carry
    /// structural forms (object-store keys, …); use `subtree` where you may need
    /// nested routes.
    pub fn blob_subtree(self, path: &str, rule: R) -> Self {
        self.push(Registration::blob_subtree(path, rule))
    }

    /// Like [`blob_subtree`](Self::blob_subtree), but the rule applies only to the
    /// given `method`(s) — a bare [`http::Method`], an array, or a `Vec` of them, all
    /// under this one registration's rule id. Path precedence is resolved before
    /// method matching; see [`MethodMatch`].
    pub fn blob_subtree_for(self, method: impl Into<MethodMatch>, path: &str, rule: R) -> Self {
        self.push(Registration::blob_subtree(path, rule).for_methods(method))
    }

    /// Push one registration; its rule id is its position, assigned at build.
    fn push(mut self, registration: Registration<R>) -> Self {
        self.registrations.push(registration);
        self
    }
}

/// Map a lowering failure to a stable, human-readable reason.
fn lower_reason(e: &LowerError) -> &'static str {
    match e {
        LowerError::MissingLeadingSlash => "route pattern must begin with '/'",
        LowerError::EmptyInteriorSegment => "route pattern has an empty path segment",
        LowerError::PrefixSuffixParam => {
            "in-segment prefix/suffix parameters (e.g. /v{ver}) are not supported"
        }
        LowerError::CatchAllNotLast => "a catch-all {*…} must be the final path segment",
        LowerError::MalformedParam => "malformed route parameter",
        LowerError::InvalidParam => "route parameter must have a non-empty name without '*'",
    }
}

/// Map a route-tree build failure to a [`RuleRouterError`], naming the offending
/// pattern: for a conflict, the entry (from `patterns`, parallel to the tree entries)
/// that hit it; for an opaque-sibling violation, the path prefix where the blob is
/// rooted. With no opaque routes declared, only a terminal conflict is reachable.
fn map_build_err(e: BuildError, patterns: &[String]) -> RuleRouterError {
    match e {
        BuildError::Conflict { index } => RuleRouterError::Route {
            pattern: patterns.get(index).cloned().unwrap_or_default(),
            reason: "two routes resolve to the same path",
        },
        BuildError::OpaqueTailHasSibling { at } => RuleRouterError::Route {
            pattern: at,
            reason: "a blob_subtree has a nested route under it; remove the nested route or use subtree",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_confusion::{DenyReason, StructuralClass, StructuralClasses};

    /// Build a router from `(pattern, rule)` rows, grouping consecutive rows with the
    /// same rule value into one [`Registration`] (rule ids are then positional, so a
    /// row's rule value equals its registration's id in these tests).
    fn router(rows: &[(&str, u32)], pc: PathConfusion) -> Result<RuleRouter<u32>, RuleRouterError> {
        let mut regs: Vec<Registration<u32>> = Vec::new();
        for (pattern, rule) in rows {
            match regs.last_mut() {
                Some(reg) if reg.rule == *rule => reg.patterns.push((*pattern).to_owned()),
                _ => regs.push(Registration::route(*pattern, *rule)),
            }
        }
        RuleRouter::build(
            regs,
            u32::MAX,
            pc,
            StructuralClasses::new(),
            DecodeLayers::Single,
            CaseSensitivity::Sensitive,
        )
    }

    fn denied(r: &RuleRouter<u32>, path: &str) -> bool {
        r.ambiguous(path, &http::Method::GET).is_some()
    }

    #[test]
    fn resolve_runs_verdict_then_match() {
        let r = router(
            &[("/admin", 0), ("/admin/", 0), ("/admin/{*rest}", 0)],
            PathConfusion::RejectStructural,
        )
        .expect("build");
        // Clean paths resolve to their rule (or the default).
        assert_eq!(
            r.resolve("/admin/x", &http::Method::GET),
            Ok(RuleMatch::Matched { id: 0, rule: &0 })
        );
        assert_eq!(
            r.resolve("/nope", &http::Method::GET),
            Ok(RuleMatch::Default { rule: &u32::MAX })
        );
        // An ambiguous path is denied before any rule is offered — the same verdict
        // `ambiguous` reports, attributed to the byte class that fired.
        let denied = r.resolve("/admin%2fx", &http::Method::GET);
        assert_eq!(
            denied,
            Err(DenyReason::Structural(StructuralClass::Separator))
        );
        assert_eq!(denied.err(), r.ambiguous("/admin%2fx", &http::Method::GET));
        // The response-body string stays coarse; the attribution is for the log.
        assert_eq!(
            denied.expect_err("denied").message(),
            "Ambiguous request path"
        );
    }

    #[test]
    fn resolve_rejects_non_path_input_even_when_guard_is_off() {
        let r = router(&[("/admin", 0)], PathConfusion::Off).expect("build");
        for input in [
            "/admin?x=1",
            "/admin#fragment",
            "https://example.test/admin",
            "admin",
            "",
        ] {
            assert_eq!(
                r.resolve(input, &http::Method::GET),
                Err(DenyReason::InvalidPathInput),
                "{input:?}"
            );
            assert_eq!(
                r.ambiguous(input, &http::Method::GET),
                Some(DenyReason::InvalidPathInput),
                "{input:?}"
            );
        }

        assert!(r.resolve("*", &http::Method::OPTIONS).is_ok());
        assert!(
            r.match_rule_unchecked("/admin?x=1", &http::Method::GET)
                .is_default(),
            "the explicitly unchecked API retains raw matcher semantics"
        );
    }

    #[test]
    fn matches_and_defaults() {
        let r = router(
            &[("/admin", 0), ("/admin/", 0), ("/admin/{*rest}", 0)],
            PathConfusion::RejectStructural,
        )
        .expect("build");
        assert_eq!(
            r.match_rule_unchecked("/admin", &http::Method::GET).id(),
            Some(0)
        );
        assert_eq!(
            r.match_rule_unchecked("/admin/x", &http::Method::GET).id(),
            Some(0)
        );
        assert!(
            r.match_rule_unchecked("/nope", &http::Method::GET)
                .is_default()
        );
    }

    #[test]
    fn uniform_subtree_scopes_encoded_slash() {
        // Scoped denial: a fully-registered single-rule subtree tolerates an encoded
        // slash beneath it (every reachable rule past the anchor is the matched one) —
        // no blob_subtree declaration needed. Dot-segments anchor at the root, where
        // this table is not uniform, so traversal still denies.
        let r = router(
            &[("/files", 0), ("/files/", 0), ("/files/{*rest}", 0)],
            PathConfusion::RejectStructural,
        )
        .expect("build");
        assert!(!denied(&r, "/files/a%2fb"));
        assert!(!denied(&r, "/files/a/../b"), "climb resolves within /files");
        assert!(denied(&r, "/files/../b"), "climb escapes the subtree");
        assert!(!denied(&r, "/files/clean"));

        // Route-table monotonicity, at unit scale: registering anything under the
        // subtree breaks its uniformity, flipping the tolerated byte back to a deny.
        let r = router(
            &[
                ("/files", 0),
                ("/files/", 0),
                ("/files/{*rest}", 0),
                ("/files/secret", 1),
            ],
            PathConfusion::RejectStructural,
        )
        .expect("build");
        assert!(denied(&r, "/files/a%2fb"));
    }

    #[test]
    fn rejects_prefix_suffix_param() {
        let err = router(&[("/v{ver}", 0)], PathConfusion::RejectStructural)
            .expect_err("prefix param rejected");
        assert!(matches!(err, RuleRouterError::Route { .. }));
    }

    #[test]
    fn rejects_invalid_matchit_params() {
        for pattern in ["/{}", "/{*}", "/{foo*bar}", "/files/{*rest}/"] {
            let err = RuleRouter::builder()
                .default(0)
                .case_sensitivity(CaseSensitivity::Sensitive)
                .decode_layers(DecodeLayers::Single)
                .route(pattern, 1)
                .build()
                .expect_err("invalid matchit pattern must fail the build");
            assert!(matches!(err, RuleRouterError::Route { .. }), "{pattern}");
        }
    }

    #[test]
    fn canonicality_ignores_parameter_names() {
        let router = RuleRouter::builder()
            .default(0)
            .case_sensitivity(CaseSensitivity::Insensitive)
            .decode_layers(DecodeLayers::Single)
            .route("/{UserId}", 1)
            .route("/items/{x;y}", 2)
            .build()
            .expect("parameter names are metadata, not path bytes");

        assert_eq!(
            *router
                .match_rule_unchecked("/value", &http::Method::GET)
                .rule(),
            1
        );
        assert_eq!(
            *router
                .match_rule_unchecked("/items/value", &http::Method::GET)
                .rule(),
            2
        );

        let err = RuleRouter::builder()
            .default(0)
            .case_sensitivity(CaseSensitivity::Insensitive)
            .decode_layers(DecodeLayers::Single)
            .route("/Admin/{UserId}", 1)
            .build()
            .expect_err("uppercase literal path bytes remain non-canonical");
        assert!(matches!(err, RuleRouterError::NonCanonicalCase { .. }));
    }

    #[test]
    fn rejects_non_canonical_pattern() {
        let err = router(&[("/a/../b", 0)], PathConfusion::RejectStructural)
            .expect_err("non-canonical pattern rejected");
        assert!(matches!(err, RuleRouterError::NonCanonical { .. }));
    }

    #[test]
    fn opaque_blob_tolerates_separator_via_registration_flag() {
        // The `opaque` registration flag (set by the builder's blob_subtree) reaches
        // the tree as a build-time guarantee; runtime tolerance comes from the
        // subtree's uniformity — structural bytes in the tail flow, a climb out of it
        // denies.
        let r = RuleRouter::build(
            vec![Registration::blob_subtree("/files", 0)],
            u32::MAX,
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            DecodeLayers::Single,
            CaseSensitivity::Sensitive,
        )
        .expect("build");
        assert!(!denied(&r, "/files/a%2fb"));
        assert!(denied(&r, "/files/../b"), "climb out of the blob");
        assert!(!denied(&r, "/files/a/../b"), "climb within the blob");
    }

    #[test]
    fn opaque_blob_with_sibling_is_build_error() {
        let err = RuleRouter::build(
            vec![
                Registration::blob_subtree("/files", 0),
                Registration::route("/files/secret", 1),
            ],
            u32::MAX,
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            DecodeLayers::Single,
            CaseSensitivity::Sensitive,
        )
        .expect_err("opaque blob with sibling");
        assert!(matches!(&err, RuleRouterError::Route { .. }));
        // The error names where the blob is rooted.
        assert!(err.to_string().contains("/files"));
    }

    #[test]
    fn error_display_names_the_pattern() {
        let err = router(&[("/a/../b", 0)], PathConfusion::RejectStructural)
            .expect_err("non-canonical pattern rejected");
        assert!(err.to_string().contains("/a/../b"));
    }

    #[test]
    fn conflict_error_names_the_pattern() {
        let err = router(&[("/dup", 0), ("/dup", 1)], PathConfusion::RejectStructural)
            .expect_err("conflicting routes rejected");
        assert!(matches!(&err, RuleRouterError::Route { .. }));
        assert!(err.to_string().contains("/dup"));
    }

    #[test]
    fn rule_ids_are_registration_positions() {
        // Rule identity is positional: patterns in one registration share its index,
        // and there is no id for a caller to get wrong.
        let r = RuleRouter::build(
            vec![
                Registration::subtree("/admin", 10),
                Registration::route("/health", 20),
            ],
            u32::MAX,
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            DecodeLayers::Single,
            CaseSensitivity::Sensitive,
        )
        .expect("build");
        assert_eq!(
            r.match_rule_unchecked("/admin/x", &http::Method::GET),
            RuleMatch::Matched { id: 0, rule: &10 }
        );
        assert_eq!(
            r.match_rule_unchecked("/health", &http::Method::GET),
            RuleMatch::Matched { id: 1, rule: &20 }
        );
    }

    #[test]
    fn rejects_empty_method_set() {
        // An empty OneOf would match no request at all — its paths would silently
        // fall to the default rule.
        let err = RuleRouter::build(
            vec![Registration::route("/x", 0).for_methods(Vec::new())],
            u32::MAX,
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            DecodeLayers::Single,
            CaseSensitivity::Sensitive,
        )
        .expect_err("empty method set rejected");
        assert!(matches!(&err, RuleRouterError::EmptyMethodSet { pattern } if pattern == "/x"));
        assert!(err.to_string().contains("/x"));
    }

    #[test]
    fn rejects_empty_pattern_set() {
        let err = RuleRouter::build(
            vec![Registration {
                patterns: Vec::new(),
                rule: 0,
                opaque: false,
                method: MethodMatch::Any,
            }],
            u32::MAX,
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            DecodeLayers::Single,
            CaseSensitivity::Sensitive,
        )
        .expect_err("empty pattern set rejected");
        assert!(matches!(err, RuleRouterError::EmptyPatternSet));
    }

    #[test]
    fn duplicate_method_in_set_is_conflict() {
        let err = RuleRouter::build(
            vec![Registration::route("/x", 0).for_methods([http::Method::GET, http::Method::GET])],
            u32::MAX,
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            DecodeLayers::Single,
            CaseSensitivity::Sensitive,
        )
        .expect_err("duplicate method in one set rejected");
        assert!(matches!(&err, RuleRouterError::Route { .. }));
    }

    // ── builder ──────────────────────────────────────────────────────────────

    #[test]
    fn builder_assigns_grouped_ids() {
        let r = RuleRouter::builder()
            .default(u32::MAX)
            .case_sensitivity(CaseSensitivity::Sensitive)
            .decode_layers(DecodeLayers::Single)
            .subtree("/admin", 10)
            .route("/health", 20)
            .build()
            .expect("build");
        // The whole subtree shares one rule id; the route gets the next.
        assert_eq!(
            r.match_rule_unchecked("/admin", &http::Method::GET),
            RuleMatch::Matched { id: 0, rule: &10 }
        );
        assert_eq!(
            r.match_rule_unchecked("/admin/x/y", &http::Method::GET),
            RuleMatch::Matched { id: 0, rule: &10 }
        );
        assert_eq!(
            r.match_rule_unchecked("/health", &http::Method::GET),
            RuleMatch::Matched { id: 1, rule: &20 }
        );
        assert_eq!(
            r.match_rule_unchecked("/nope", &http::Method::GET),
            RuleMatch::Default { rule: &u32::MAX }
        );
    }

    #[test]
    fn builder_defaults_to_reject_structural() {
        // path_confusion / structural_classes are optional with safe defaults; the
        // guard runs without either being set.
        let r = RuleRouter::builder()
            .default(u32::MAX)
            .case_sensitivity(CaseSensitivity::Sensitive)
            .decode_layers(DecodeLayers::Single)
            .subtree("/admin", 0)
            .build()
            .expect("build");
        assert!(r.ambiguous("/admin%2fx", &http::Method::GET).is_some());
        assert!(r.ambiguous("/admin/x", &http::Method::GET).is_none());
    }

    #[test]
    fn builder_blob_subtree_declares_opaque_tail() {
        let r = RuleRouter::builder()
            .default(u32::MAX)
            .case_sensitivity(CaseSensitivity::Sensitive)
            .decode_layers(DecodeLayers::Single)
            .blob_subtree("/files", 0)
            .build()
            .expect("build");
        assert!(
            r.ambiguous("/files/a%2fb", &http::Method::GET).is_none(),
            "encoded slash tolerated inside the blob key"
        );
        assert!(
            r.ambiguous("/files/../b", &http::Method::GET).is_some(),
            "dot-segment climbing out of the blob still denied"
        );
        assert!(
            r.ambiguous("/files/a/../b", &http::Method::GET).is_none(),
            "dot-segment resolving within the blob tolerated"
        );
    }

    #[test]
    fn builder_blob_subtree_with_nested_route_is_error() {
        let err = RuleRouter::builder()
            .default(u32::MAX)
            .case_sensitivity(CaseSensitivity::Sensitive)
            .decode_layers(DecodeLayers::Single)
            .blob_subtree("/files", 0)
            .route("/files/secret", 1)
            .build()
            .expect_err("nested route under a blob");
        assert!(matches!(err, RuleRouterError::Route { .. }));
    }

    #[test]
    fn builder_method_qualified_registrations() {
        let r = RuleRouter::builder()
            .default(u32::MAX)
            .case_sensitivity(CaseSensitivity::Sensitive)
            .decode_layers(DecodeLayers::Single)
            .route_for(http::Method::GET, "/x", 0)
            .route("/x", 1)
            .subtree_for(http::Method::POST, "/api", 2)
            .build()
            .expect("build");
        // Specific method wins; other methods fall to the wildcard rule on that path.
        assert_eq!(
            r.match_rule_unchecked("/x", &http::Method::GET).id(),
            Some(0)
        );
        assert_eq!(
            r.match_rule_unchecked("/x", &http::Method::POST).id(),
            Some(1)
        );
        // A method-only subtree leaves other methods on the default rule.
        assert_eq!(
            r.match_rule_unchecked("/api/v1", &http::Method::POST).id(),
            Some(2)
        );
        assert!(
            r.match_rule_unchecked("/api/v1", &http::Method::GET)
                .is_default()
        );
    }

    #[test]
    fn precise_verdicts_use_the_request_method() {
        let registrations = || {
            vec![
                // GET deliberately has the same rule id at the wildcard and literal
                // terminals. It is the method-blind representative at both positions.
                Registration {
                    patterns: vec!["/x/{id}".to_owned(), "/x/a".to_owned()],
                    rule: 0,
                    opaque: false,
                    method: http::Method::GET.into(),
                },
                Registration::route("/x/{id}", 1).for_methods(http::Method::POST),
                Registration::route("/x/a", 2).for_methods(http::Method::POST),
            ]
        };

        let decoded = RuleRouter::build(
            registrations(),
            u32::MAX,
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            DecodeLayers::Single,
            CaseSensitivity::Sensitive,
        )
        .expect("build");
        // `%61` moves POST from the wildcard registration to the literal one, while
        // GET stays on registration 0. The verdict must judge the requested method,
        // not GET's identical representative ids.
        assert_eq!(decoded.ambiguous("/x/%61", &http::Method::GET), None);
        assert_eq!(
            decoded.ambiguous("/x/%61", &http::Method::POST),
            Some(DenyReason::DecodeRelocation)
        );
        assert_eq!(
            decoded.resolve("/x/%61", &http::Method::POST),
            Err(DenyReason::DecodeRelocation)
        );

        let folded = RuleRouter::build(
            registrations(),
            u32::MAX,
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            DecodeLayers::Single,
            CaseSensitivity::Insensitive,
        )
        .expect("build");
        assert_eq!(folded.ambiguous("/x/A", &http::Method::GET), None);
        assert_eq!(
            folded.ambiguous("/x/A", &http::Method::POST),
            Some(DenyReason::CaseFoldRelocation)
        );
        assert_eq!(
            folded.resolve("/x/A", &http::Method::POST),
            Err(DenyReason::CaseFoldRelocation)
        );
    }

    #[test]
    fn up_to_two_decode_preserves_single_pass_denials() {
        let registrations = || {
            vec![
                // The raw and twice-decoded forms are both rule 0, while the
                // once-decoded form is rule 1: A -> B -> A.
                Registration {
                    patterns: vec!["/x/{id}".to_owned(), "/x/a".to_owned()],
                    rule: 0,
                    opaque: false,
                    method: MethodMatch::Any,
                },
                Registration::route("/x/%61", 1),
            ]
        };
        let build = |layers| {
            RuleRouter::build(
                registrations(),
                u32::MAX,
                PathConfusion::RejectStructural,
                StructuralClasses::new(),
                layers,
                CaseSensitivity::Sensitive,
            )
            .expect("build")
        };

        let path = "/x/%2561";
        let single = build(DecodeLayers::Single);
        assert_eq!(
            single.ambiguous(path, &http::Method::GET),
            Some(DenyReason::DecodeRelocation)
        );

        let up_to_two = build(DecodeLayers::UpToTwo);
        assert_eq!(
            up_to_two.ambiguous(path, &http::Method::GET),
            Some(DenyReason::DecodeRelocation),
            "checking a second pass must not erase the first-pass relocation"
        );
    }

    #[test]
    fn builder_supports_dynamic_registration() {
        // Runtime-sized tables register in bulk (`subtrees`/`routes`), and — because
        // registration methods are state-preserving (generic over the builder's
        // typestate) — by reassigning in a loop for mixed kinds. This test pins both.
        let subtrees = vec![("/admin", 0_u32), ("/api", 1)];
        let routes = vec![("/health", 2_u32), ("/version", 3)];
        let r = RuleRouter::builder()
            .default(u32::MAX)
            .case_sensitivity(CaseSensitivity::Sensitive)
            .decode_layers(DecodeLayers::Single)
            .subtrees(subtrees)
            .routes(routes)
            .build()
            .expect("build");
        // Each item is its own registration: ids stay per-subtree/per-route.
        assert_eq!(
            r.match_rule_unchecked("/admin/x", &http::Method::GET).id(),
            Some(0)
        );
        assert_eq!(
            r.match_rule_unchecked("/api/v1", &http::Method::GET).id(),
            Some(1)
        );
        assert_eq!(
            r.match_rule_unchecked("/health", &http::Method::GET).id(),
            Some(2)
        );
        assert_eq!(
            r.match_rule_unchecked("/version", &http::Method::GET).id(),
            Some(3)
        );

        // The loop form for mixed-kind dynamic tables.
        let mut b = RuleRouter::builder()
            .default(u32::MAX)
            .case_sensitivity(CaseSensitivity::Sensitive)
            .decode_layers(DecodeLayers::Single);
        for (path, rule) in [("/admin", 0_u32), ("/public", 1)] {
            b = b.subtree(path, rule);
        }
        let r = b.build().expect("build");
        assert_eq!(
            r.match_rule_unchecked("/public/x", &http::Method::GET).id(),
            Some(1)
        );
    }

    #[test]
    fn multi_method_registration_shares_one_rule_id() {
        // "This rule for GET and HEAD" is one registration → one rule id, so the two
        // methods can never drift apart and movement between them is not a relocation.
        let r = RuleRouter::builder()
            .default(u32::MAX)
            .case_sensitivity(CaseSensitivity::Sensitive)
            .decode_layers(DecodeLayers::Single)
            .route_for([http::Method::GET, http::Method::HEAD], "/x", 0)
            .subtree_for(vec![http::Method::PUT, http::Method::POST], "/api", 1)
            .build()
            .expect("build");
        assert_eq!(
            r.match_rule_unchecked("/x", &http::Method::GET).id(),
            Some(0)
        );
        assert_eq!(
            r.match_rule_unchecked("/x", &http::Method::HEAD).id(),
            Some(0)
        );
        assert!(
            r.match_rule_unchecked("/x", &http::Method::POST)
                .is_default()
        );
        assert_eq!(
            r.match_rule_unchecked("/api/v1", &http::Method::PUT).id(),
            Some(1)
        );
        assert_eq!(
            r.match_rule_unchecked("/api/v1", &http::Method::POST).id(),
            Some(1)
        );
        assert!(
            r.match_rule_unchecked("/api/v1", &http::Method::DELETE)
                .is_default()
        );
    }
}
