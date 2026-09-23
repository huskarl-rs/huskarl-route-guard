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
//! [`PathConfusionGuard`] over the
//! [owned segment-tree router](crate::route_tree). Public matchit-style pattern strings
//! are lowered into the owned grammar at build time; whatever the grammar cannot express
//! (in-segment prefix/suffix params) is a build-time error.
//!
//! [`RuleRouter::builder`] is the intended way to construct one: its
//! [`route`](RuleRouterBuilder::route) / [`subtree`](RuleRouterBuilder::subtree) /
//! [`exclusive_subtree`](RuleRouterBuilder::exclusive_subtree) methods expand subtree patterns
//! internally. The registration-level [`RuleRouter::from_registrations`] remains for callers that
//! assemble [`Registration`]s inside a builder of their own (as huskarl-pingora's
//! `Guard`/`LoginProxy` do); rule ids are assigned from registration order, so the
//! rule-granularity contract holds by construction on both paths.

use crate::{
    config::{GuardConfig, GuardMode, ResolveError},
    guard::PathConfusionGuard,
    route_tree::{BuildError, LowerError, MethodMatch, Router, Segment, lower_matchit},
    structural::{classes_present, enabled_classes, enabled_encodings},
};

/// The outcome of matching a path: which rule applies, and whether it came from a
/// registration or is the default rule (no registration covered the path and method).
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
    /// No path matches, or the selected path has no rule for this method and no
    /// all-method rule; the default applies.
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
    /// [`CaseSensitivity::Insensitive`](crate::CaseSensitivity::Insensitive). A case-folding backend resolves it to lowercase,
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
                 set GuardMode::Disabled only if checks are enforced elsewhere"
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
/// identity**. [`RuleRouter::from_registrations`] assigns each registration the rule id equal to its
/// position, so identity is a fact of the input's shape rather than a contract the
/// caller must uphold: patterns in one registration can never end up under different
/// rules, and a rule can never be silently detached from its patterns.
///
/// Construct via [`route`](Self::route) / [`subtree`](Self::subtree) /
/// [`exclusive_subtree`](Self::exclusive_subtree) (mirroring the builder methods), qualified with
/// [`for_methods`](Self::for_methods) where the rule is method-specific — or
/// use [`patterns`](Self::patterns) to group several patterns under one identity.
#[derive(Clone, Debug)]
pub struct Registration<R> {
    /// The `matchit`-style patterns this registration covers, all under one rule id.
    /// Must contain at least one pattern; an empty list is rejected at build time.
    pub(crate) patterns: Vec<String>,
    /// The rule every pattern resolves to.
    pub(crate) rule: R,
    /// Forbids nested paths beneath a catch-all. Set only by `exclusive_subtree`.
    pub(crate) opaque: bool,
    /// Which method(s) the rule applies to. Path precedence is resolved before this
    /// value; see [`MethodMatch`].
    pub(crate) method: MethodMatch,
}

impl<R> Registration<R> {
    /// Groups patterns under one rule identity.
    ///
    /// Unlike separate registrations, changes between these patterns do not
    /// cross a rule boundary. An empty iterator is rejected when building.
    pub fn patterns(patterns: impl IntoIterator<Item = impl Into<String>>, rule: R) -> Self {
        Self {
            patterns: patterns.into_iter().map(Into::into).collect(),
            rule,
            opaque: false,
            method: MethodMatch::Any,
        }
    }

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

    /// Like [`subtree`](Self::subtree), but rejects paths that take precedence beneath
    /// it, including through overlapping literal and wildcard branches, in either
    /// registration order. Lower-priority fallbacks and method rules at the same
    /// path patterns remain valid.
    /// Request-time checks are unchanged. Method restrictions can still introduce
    /// default-rule gaps at more-specific paths; see [`for_methods`](Self::for_methods).
    pub fn exclusive_subtree(path: &str, rule: R) -> Self {
        Self {
            opaque: true,
            ..Self::subtree(path, rule)
        }
    }

    /// Restrict the registration to the given method(s) — a bare [`http::Method`],
    /// an array, or a `Vec` of them — all under the registration's single rule id.
    /// Path precedence is resolved before method matching; see [`MethodMatch`].
    /// Structural coverage uses the request method. A complete subtree can accept
    /// encoded keys for a listed method. More-specific paths without a rule for that
    /// method still create default-rule gaps. See
    /// [Registering routes](crate::_docs::guide::registering).
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
    guard: PathConfusionGuard,
}

impl<R> std::fmt::Debug for RuleRouter<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleRouter")
            .field("rules", &self.rules.len())
            .finish_non_exhaustive()
    }
}

impl<R> RuleRouter<R> {
    /// Starts a route table with an explicit default rule and guard configuration.
    ///
    /// Both required parsing assumptions are supplied through [`GuardConfig::new`].
    /// Add paths with the builder's helpers or [`register`](RuleRouterBuilder::register).
    ///
    /// ```
    /// use huskarl_route_guard::{CaseSensitivity, DecodeDepth, GuardConfig, RuleRouter};
    ///
    /// let config = GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne);
    /// let router = RuleRouter::builder("public", config)
    ///     .subtree("/admin", "admin")
    ///     .build()
    ///     .expect("valid routes");
    /// assert_eq!(
    ///     *router
    ///         .resolve("/admin/users", &http::Method::GET)
    ///         .unwrap()
    ///         .rule(),
    ///     "admin"
    /// );
    /// ```
    pub fn builder(default: R, config: GuardConfig) -> RuleRouterBuilder<R> {
        RuleRouterBuilder {
            registrations: Vec::new(),
            default,
            config,
        }
    }

    /// Builds a route table from an iterator of registrations.
    ///
    /// Each registration receives one identity, shared by all its patterns.
    /// This is equivalent to `builder(default, config).register_all(registrations).build()`.
    ///
    /// # Errors
    ///
    /// Rejects invalid or conflicting patterns, empty pattern or method sets,
    /// and nested paths beneath an exclusive subtree. When checks are enabled,
    /// also rejects structural forms in literals and uppercase literals under
    /// case-insensitive parsing.
    pub fn from_registrations(
        default: R,
        config: GuardConfig,
        registrations: impl IntoIterator<Item = Registration<R>>,
    ) -> Result<Self, RuleRouterError> {
        let GuardConfig {
            mode,
            ref structural_classes,
            decode_depth,
            case_sensitivity,
        } = config;
        let byte_enabled = enabled_classes(structural_classes);
        let enc = enabled_encodings(structural_classes, decode_depth);

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
                if mode != GuardMode::Disabled {
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
        let guard = PathConfusionGuard::new(router, config);

        Ok(Self {
            rules,
            default,
            guard,
        })
    }

    /// Resolves `path` in one call: the path-confusion verdict first, then the rule
    /// match. `Err(reason)` means the request must be **denied** — no rule is offered.
    /// Path denials normally map to `400`; an internal invariant failure maps to `500`.
    /// `Ok` carries the [`RuleMatch`]: the matched registration's rule,
    /// or the default rule for a path no registration covers.
    ///
    /// This is the request-handling entry point and always runs the configured checks.
    /// Use [`inspect_raw`](Self::inspect_raw) only to log the original path's match,
    /// including when this method denies the request.
    ///
    /// # The path argument
    ///
    /// `path` must be the **request path alone** — `uri.path()`, never a full
    /// request-target. Input is validated before the guard runs: it must start with `/`
    /// (or be the special `*` request target) and must not contain `?` or `#`. Passing a
    /// full request-target such as `/admin?x=1`, or an absolute URI, returns
    /// [`ResolveError::InvalidPathInput`] rather than falling through to the default rule.
    ///
    /// # Errors
    ///
    /// The guard's [`ResolveError`] names the check and byte class that fired.
    /// [`message`](ResolveError::message) is the short static string for the denial
    /// response body; its `Display` is the attributed line for the *log*, so an
    /// operator can trace a `400` to the configuration knob or registration that
    /// governs it. See [Handling a denial](crate::_docs::guide::handling_denials)
    /// for the response to each reason.
    ///
    /// [`ResolveError::InvalidRuleId`] indicates an internal invariant violation
    /// and should be reported as a server error, not a client `400`.
    pub fn resolve(
        &self,
        path: &str,
        method: &http::Method,
    ) -> Result<RuleMatch<'_, R>, ResolveError> {
        if !is_request_path(path) {
            return Err(ResolveError::InvalidPathInput);
        }
        match self.guard.verdict(path, method) {
            Some(reason) => Err(reason),
            None => self.matched_rule(path, method),
        }
    }

    /// Inspects raw path matching for diagnostics, without checking ambiguity.
    ///
    /// Use this to log which rule the original spelling selects, including on a
    /// denied request. A successful inspection is **not** permission to authorize
    /// or forward: request handling must use [`resolve`](Self::resolve).
    ///
    /// # Errors
    ///
    /// Returns [`ResolveError::InvalidPathInput`] for a non-path input or
    /// [`ResolveError::InvalidRuleId`] for an internal invariant failure.
    pub fn inspect_raw(
        &self,
        path: &str,
        method: &http::Method,
    ) -> Result<RuleMatch<'_, R>, ResolveError> {
        if !is_request_path(path) {
            return Err(ResolveError::InvalidPathInput);
        }
        self.matched_rule(path, method)
    }

    // The reference backend needs to route transformed inputs even when they are
    // outside the public request-path boundary.
    #[cfg(test)]
    pub(crate) fn raw_match_for_test(&self, path: &str, method: &http::Method) -> RuleMatch<'_, R> {
        self.matched_rule(path, method)
            .expect("valid test rule table")
    }

    fn matched_rule(
        &self,
        path: &str,
        method: &http::Method,
    ) -> Result<RuleMatch<'_, R>, ResolveError> {
        match self.guard.resolve(path, method) {
            Some(id) => self
                .rules
                .get(id as usize)
                .map(|rule| RuleMatch::Matched { id, rule })
                .ok_or(ResolveError::InvalidRuleId),
            None => Ok(RuleMatch::Default {
                rule: &self.default,
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn denial_for_test(
        &self,
        path: &str,
        method: &http::Method,
    ) -> Option<ResolveError> {
        self.resolve(path, method).err()
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

/// A route table under construction.
///
/// Create with [`RuleRouter::builder`]. Configuration and the default are required
/// up front, so every builder can be finished or extended in a loop.
pub struct RuleRouterBuilder<R> {
    registrations: Vec<Registration<R>>,
    default: R,
    config: GuardConfig,
}

impl<R> RuleRouterBuilder<R> {
    /// Adds one registration. Its patterns and methods share one rule identity.
    ///
    /// ```
    /// use huskarl_route_guard::{
    ///     CaseSensitivity, DecodeDepth, GuardConfig, Registration, RuleRouter,
    /// };
    ///
    /// let router = RuleRouter::builder(
    ///     "default",
    ///     GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne),
    /// )
    /// .register(
    ///     Registration::route("/health", "health")
    ///         .for_methods([http::Method::GET, http::Method::HEAD]),
    /// )
    /// .register(Registration::patterns(["/ready", "/live"], "probes"))
    /// .build()
    /// .expect("valid routes");
    /// assert_eq!(
    ///     router.resolve("/ready", &http::Method::GET).unwrap().id(),
    ///     router.resolve("/live", &http::Method::GET).unwrap().id()
    /// );
    /// ```
    #[must_use]
    pub fn register(mut self, registration: Registration<R>) -> Self {
        self.registrations.push(registration);
        self
    }

    /// Adds registrations in iteration order, preserving each one's identity.
    #[must_use]
    pub fn register_all(
        mut self,
        registrations: impl IntoIterator<Item = Registration<R>>,
    ) -> Self {
        self.registrations.extend(registrations);
        self
    }

    /// Registers an exact path or whole-segment pattern, such as `/users/{id}`.
    /// Use [`subtree`](Self::subtree) to include descendants.
    #[must_use]
    pub fn route(self, pattern: impl Into<String>, rule: R) -> Self {
        self.register(Registration::route(pattern, rule))
    }

    /// Registers a prefix and its descendants under one rule identity.
    ///
    /// `/files` includes `/files`, `/files/`, and descendants.
    /// A trailing slash in the input excludes the bare path. More-specific
    /// registrations take precedence. See [Routing behavior](crate::_docs::reference::routing).
    #[must_use]
    pub fn subtree(self, path: &str, rule: R) -> Self {
        self.register(Registration::subtree(path, rule))
    }

    /// Registers a subtree and forbids more-specific paths beneath it.
    ///
    /// Exclusivity is checked at build time; request-time checks are the same as
    /// [`subtree`](Self::subtree). It does not disable checks or guarantee tolerance
    /// when method restrictions introduce other rule identities.
    #[must_use]
    pub fn exclusive_subtree(self, path: &str, rule: R) -> Self {
        self.register(Registration::exclusive_subtree(path, rule))
    }

    /// Validates the registrations and constructs the router.
    ///
    /// # Errors
    ///
    /// Returns the errors documented on [`RuleRouter::from_registrations`].
    pub fn build(self) -> Result<RuleRouter<R>, RuleRouterError> {
        RuleRouter::from_registrations(self.default, self.config, self.registrations)
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
            reason: "an exclusive_subtree has a nested route under it; remove the nested route or use subtree",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        CaseSensitivity, DecodeDepth, ResolveError, StructuralClass, StructuralClasses,
    };

    /// Build a router from `(pattern, rule)` rows, grouping consecutive rows with the
    /// same rule value into one [`Registration`] (rule ids are then positional, so a
    /// row's rule value equals its registration's id in these tests).
    fn router(rows: &[(&str, u32)], pc: GuardMode) -> Result<RuleRouter<u32>, RuleRouterError> {
        let mut regs: Vec<Registration<u32>> = Vec::new();
        for (pattern, rule) in rows {
            match regs.last_mut() {
                Some(reg) if reg.rule == *rule => reg.patterns.push((*pattern).to_owned()),
                _ => regs.push(Registration::route(*pattern, *rule)),
            }
        }
        RuleRouter::from_registrations(
            u32::MAX,
            GuardConfig {
                mode: pc,
                structural_classes: StructuralClasses::new(),
                decode_depth: DecodeDepth::UpToOne,
                case_sensitivity: CaseSensitivity::Sensitive,
            },
            regs,
        )
    }

    fn denied(r: &RuleRouter<u32>, path: &str) -> bool {
        r.denial_for_test(path, &http::Method::GET).is_some()
    }

    #[test]
    fn invalid_rule_id_denies_instead_of_authorizing_with_default() {
        let mut r = RuleRouter::from_registrations(
            "public",
            GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne),
            vec![Registration::route("/admin", "protected")],
        )
        .expect("build");
        // Inject an invariant violation that public construction cannot create.
        r.rules.clear();
        assert_eq!(
            r.resolve("/admin", &http::Method::GET),
            Err(ResolveError::InvalidRuleId)
        );
        assert!(
            r.resolve("/unmatched", &http::Method::GET)
                .expect("default")
                .is_default()
        );
    }

    #[test]
    fn raw_inspection_reports_an_invalid_rule_id() {
        let mut r = router(&[("/admin", 0)], GuardMode::Disabled).expect("build");
        r.rules.clear();
        assert_eq!(
            r.inspect_raw("/admin", &http::Method::GET),
            Err(ResolveError::InvalidRuleId)
        );
    }

    #[test]
    fn method_qualified_subtrees_allow_structural_keys_for_listed_methods() {
        for registration in [
            Registration::subtree("/files", "files"),
            Registration::exclusive_subtree("/files", "files"),
        ] {
            let config = GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne);
            let unrestricted = RuleRouter::from_registrations(
                "default",
                config.clone(),
                vec![registration.clone()],
            )
            .expect("build");
            let restricted = RuleRouter::from_registrations(
                "default",
                config,
                vec![registration.for_methods(http::Method::GET)],
            )
            .expect("build");
            assert!(
                unrestricted
                    .resolve("/files/a%2fb", &http::Method::GET)
                    .is_ok()
            );
            assert_eq!(
                *restricted
                    .resolve("/files/a%2fb", &http::Method::GET)
                    .expect("same GET rule")
                    .rule(),
                "files"
            );
            assert!(
                restricted
                    .resolve("/files/a%2fb", &http::Method::POST)
                    .expect("uniform default")
                    .is_default()
            );
            assert_eq!(
                *restricted
                    .resolve("/files/clean", &http::Method::GET)
                    .expect("clean")
                    .rule(),
                "files"
            );
        }
    }

    #[test]
    fn resolve_runs_verdict_then_match() {
        let r = router(
            &[("/admin", 0), ("/admin/", 0), ("/admin/{*rest}", 0)],
            GuardMode::RejectAmbiguous,
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
            Err(ResolveError::Structural(StructuralClass::Separator))
        );
        assert_eq!(
            denied.err(),
            r.denial_for_test("/admin%2fx", &http::Method::GET)
        );
        // The response-body string stays coarse; the attribution is for the log.
        assert_eq!(
            denied.expect_err("denied").message(),
            "Ambiguous request path"
        );
    }

    #[test]
    fn resolve_rejects_non_path_input_even_when_guard_is_off() {
        let r = router(&[("/admin", 0)], GuardMode::Disabled).expect("build");
        for input in [
            "/admin?x=1",
            "/admin#fragment",
            "https://example.test/admin",
            "admin",
            "",
        ] {
            assert_eq!(
                r.resolve(input, &http::Method::GET),
                Err(ResolveError::InvalidPathInput),
                "{input:?}"
            );
            assert_eq!(
                r.denial_for_test(input, &http::Method::GET),
                Some(ResolveError::InvalidPathInput),
                "{input:?}"
            );
        }

        assert!(r.resolve("*", &http::Method::OPTIONS).is_ok());
        assert!(
            r.raw_match_for_test("/admin?x=1", &http::Method::GET)
                .is_default(),
            "the explicitly unchecked API retains raw matcher semantics"
        );
    }

    #[test]
    fn matches_and_defaults() {
        let r = router(
            &[("/admin", 0), ("/admin/", 0), ("/admin/{*rest}", 0)],
            GuardMode::RejectAmbiguous,
        )
        .expect("build");
        assert_eq!(
            r.raw_match_for_test("/admin", &http::Method::GET).id(),
            Some(0)
        );
        assert_eq!(
            r.raw_match_for_test("/admin/x", &http::Method::GET).id(),
            Some(0)
        );
        assert!(
            r.raw_match_for_test("/nope", &http::Method::GET)
                .is_default()
        );
    }

    #[test]
    fn uniform_subtree_scopes_encoded_slash() {
        // Scoped denial: a fully-registered single-rule subtree tolerates an encoded
        // slash beneath it (every reachable rule past the anchor is the matched one) —
        // no exclusive_subtree declaration needed. Dot-segments anchor at the root, where
        // this table is not uniform, so traversal still denies.
        let r = router(
            &[("/files", 0), ("/files/", 0), ("/files/{*rest}", 0)],
            GuardMode::RejectAmbiguous,
        )
        .expect("build");
        assert!(!denied(&r, "/files/a%2fb"));
        assert!(!denied(&r, "/files/a/../b"), "climb resolves within /files");
        assert!(denied(&r, "/files/../b"), "climb escapes the subtree");
        assert!(!denied(&r, "/files/clean"));

        // Adding a nested rule breaks this subtree's uniformity, flipping the
        // tolerated byte back to a deny. Other additions can restore uniformity.
        let r = router(
            &[
                ("/files", 0),
                ("/files/", 0),
                ("/files/{*rest}", 0),
                ("/files/secret", 1),
            ],
            GuardMode::RejectAmbiguous,
        )
        .expect("build");
        assert!(denied(&r, "/files/a%2fb"));
    }

    #[test]
    fn rejects_prefix_suffix_param() {
        let err = router(&[("/v{ver}", 0)], GuardMode::RejectAmbiguous)
            .expect_err("prefix param rejected");
        assert!(matches!(err, RuleRouterError::Route { .. }));
    }

    #[test]
    fn rejects_invalid_matchit_params() {
        for pattern in ["/{}", "/{*}", "/{foo*bar}", "/files/{*rest}/"] {
            let err = RuleRouter::builder(
                0,
                GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne),
            )
            .route(pattern, 1)
            .build()
            .expect_err("invalid matchit pattern must fail the build");
            assert!(matches!(err, RuleRouterError::Route { .. }), "{pattern}");
        }
    }

    #[test]
    fn canonicality_ignores_parameter_names() {
        let router = RuleRouter::builder(
            0,
            GuardConfig::new(CaseSensitivity::Insensitive, DecodeDepth::UpToOne),
        )
        .route("/{UserId}", 1)
        .route("/items/{x;y}", 2)
        .build()
        .expect("parameter names are metadata, not path bytes");

        assert_eq!(
            *router
                .raw_match_for_test("/value", &http::Method::GET)
                .rule(),
            1
        );
        assert_eq!(
            *router
                .raw_match_for_test("/items/value", &http::Method::GET)
                .rule(),
            2
        );

        let err = RuleRouter::builder(
            0,
            GuardConfig::new(CaseSensitivity::Insensitive, DecodeDepth::UpToOne),
        )
        .route("/Admin/{UserId}", 1)
        .build()
        .expect_err("uppercase literal path bytes remain non-canonical");
        assert!(matches!(err, RuleRouterError::NonCanonicalCase { .. }));
    }

    #[test]
    fn rejects_non_canonical_pattern() {
        let err = router(&[("/a/../b", 0)], GuardMode::RejectAmbiguous)
            .expect_err("non-canonical pattern rejected");
        assert!(matches!(err, RuleRouterError::NonCanonical { .. }));
    }

    #[test]
    fn opaque_blob_tolerates_separator_via_registration_flag() {
        // The `opaque` registration flag (set by the builder's exclusive_subtree) reaches
        // the tree as a build-time guarantee; runtime tolerance comes from the
        // subtree's uniformity — structural bytes in the tail flow, a climb out of it
        // denies.
        let r = RuleRouter::from_registrations(
            u32::MAX,
            GuardConfig {
                mode: GuardMode::RejectAmbiguous,
                structural_classes: StructuralClasses::new(),
                decode_depth: DecodeDepth::UpToOne,
                case_sensitivity: CaseSensitivity::Sensitive,
            },
            vec![Registration::exclusive_subtree("/files", 0)],
        )
        .expect("build");
        assert!(!denied(&r, "/files/a%2fb"));
        assert!(denied(&r, "/files/../b"), "climb out of the blob");
        assert!(!denied(&r, "/files/a/../b"), "climb within the blob");
    }

    #[test]
    fn opaque_blob_with_sibling_is_build_error() {
        let err = RuleRouter::from_registrations(
            u32::MAX,
            GuardConfig {
                mode: GuardMode::RejectAmbiguous,
                structural_classes: StructuralClasses::new(),
                decode_depth: DecodeDepth::UpToOne,
                case_sensitivity: CaseSensitivity::Sensitive,
            },
            vec![
                Registration::exclusive_subtree("/files", 0),
                Registration::route("/files/secret", 1),
            ],
        )
        .expect_err("opaque blob with sibling");
        assert!(matches!(&err, RuleRouterError::Route { .. }));
        // The error names where the blob is rooted.
        assert!(err.to_string().contains("/files"));
    }

    #[test]
    fn error_display_names_the_pattern() {
        let err = router(&[("/a/../b", 0)], GuardMode::RejectAmbiguous)
            .expect_err("non-canonical pattern rejected");
        assert!(err.to_string().contains("/a/../b"));
    }

    #[test]
    fn conflict_error_names_the_pattern() {
        let err = router(&[("/dup", 0), ("/dup", 1)], GuardMode::RejectAmbiguous)
            .expect_err("conflicting routes rejected");
        assert!(matches!(&err, RuleRouterError::Route { .. }));
        assert!(err.to_string().contains("/dup"));
    }

    #[test]
    fn rule_ids_are_registration_positions() {
        // Rule identity is positional: patterns in one registration share its index,
        // and there is no id for a caller to get wrong.
        let r = RuleRouter::from_registrations(
            u32::MAX,
            GuardConfig {
                mode: GuardMode::RejectAmbiguous,
                structural_classes: StructuralClasses::new(),
                decode_depth: DecodeDepth::UpToOne,
                case_sensitivity: CaseSensitivity::Sensitive,
            },
            vec![
                Registration::subtree("/admin", 10),
                Registration::route("/health", 20),
            ],
        )
        .expect("build");
        assert_eq!(
            r.raw_match_for_test("/admin/x", &http::Method::GET),
            RuleMatch::Matched { id: 0, rule: &10 }
        );
        assert_eq!(
            r.raw_match_for_test("/health", &http::Method::GET),
            RuleMatch::Matched { id: 1, rule: &20 }
        );
    }

    #[test]
    fn rejects_empty_method_set() {
        // An empty OneOf would match no request at all — its paths would silently
        // fall to the default rule.
        let err = RuleRouter::from_registrations(
            u32::MAX,
            GuardConfig {
                mode: GuardMode::RejectAmbiguous,
                structural_classes: StructuralClasses::new(),
                decode_depth: DecodeDepth::UpToOne,
                case_sensitivity: CaseSensitivity::Sensitive,
            },
            vec![Registration::route("/x", 0).for_methods(Vec::new())],
        )
        .expect_err("empty method set rejected");
        assert!(matches!(&err, RuleRouterError::EmptyMethodSet { pattern } if pattern == "/x"));
        assert!(err.to_string().contains("/x"));
    }

    #[test]
    fn rejects_empty_pattern_set() {
        let err = RuleRouter::from_registrations(
            u32::MAX,
            GuardConfig {
                mode: GuardMode::RejectAmbiguous,
                structural_classes: StructuralClasses::new(),
                decode_depth: DecodeDepth::UpToOne,
                case_sensitivity: CaseSensitivity::Sensitive,
            },
            vec![Registration {
                patterns: Vec::new(),
                rule: 0,
                opaque: false,
                method: MethodMatch::Any,
            }],
        )
        .expect_err("empty pattern set rejected");
        assert!(matches!(err, RuleRouterError::EmptyPatternSet));
    }

    #[test]
    fn duplicate_method_in_set_is_conflict() {
        let err = RuleRouter::from_registrations(
            u32::MAX,
            GuardConfig {
                mode: GuardMode::RejectAmbiguous,
                structural_classes: StructuralClasses::new(),
                decode_depth: DecodeDepth::UpToOne,
                case_sensitivity: CaseSensitivity::Sensitive,
            },
            vec![Registration::route("/x", 0).for_methods([http::Method::GET, http::Method::GET])],
        )
        .expect_err("duplicate method in one set rejected");
        assert!(matches!(&err, RuleRouterError::Route { .. }));
    }

    // ── builder ──────────────────────────────────────────────────────────────

    #[test]
    fn builder_assigns_grouped_ids() {
        let r = RuleRouter::builder(
            u32::MAX,
            GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne),
        )
        .subtree("/admin", 10)
        .route("/health", 20)
        .build()
        .expect("build");
        // The whole subtree shares one rule id; the route gets the next.
        assert_eq!(
            r.raw_match_for_test("/admin", &http::Method::GET),
            RuleMatch::Matched { id: 0, rule: &10 }
        );
        assert_eq!(
            r.raw_match_for_test("/admin/x/y", &http::Method::GET),
            RuleMatch::Matched { id: 0, rule: &10 }
        );
        assert_eq!(
            r.raw_match_for_test("/health", &http::Method::GET),
            RuleMatch::Matched { id: 1, rule: &20 }
        );
        assert_eq!(
            r.raw_match_for_test("/nope", &http::Method::GET),
            RuleMatch::Default { rule: &u32::MAX }
        );
    }

    #[test]
    fn builder_defaults_to_reject_structural() {
        // path_confusion / structural_classes are optional with safe defaults; the
        // guard runs without either being set.
        let r = RuleRouter::builder(
            u32::MAX,
            GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne),
        )
        .subtree("/admin", 0)
        .build()
        .expect("build");
        assert!(
            r.denial_for_test("/admin%2fx", &http::Method::GET)
                .is_some()
        );
        assert!(r.denial_for_test("/admin/x", &http::Method::GET).is_none());
    }

    #[test]
    fn builder_blob_subtree_declares_opaque_tail() {
        let r = RuleRouter::builder(
            u32::MAX,
            GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne),
        )
        .exclusive_subtree("/files", 0)
        .build()
        .expect("build");
        assert!(
            r.denial_for_test("/files/a%2fb", &http::Method::GET)
                .is_none(),
            "encoded slash tolerated inside the blob key"
        );
        assert!(
            r.denial_for_test("/files/../b", &http::Method::GET)
                .is_some(),
            "dot-segment climbing out of the blob still denied"
        );
        assert!(
            r.denial_for_test("/files/a/../b", &http::Method::GET)
                .is_none(),
            "dot-segment resolving within the blob tolerated"
        );
    }

    #[test]
    fn builder_blob_subtree_with_nested_route_is_error() {
        let err = RuleRouter::builder(
            u32::MAX,
            GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne),
        )
        .exclusive_subtree("/files", 0)
        .route("/files/secret", 1)
        .build()
        .expect_err("nested route under a blob");
        assert!(matches!(err, RuleRouterError::Route { .. }));
    }

    #[test]
    fn builder_method_qualified_registrations() {
        let r = RuleRouter::builder(
            u32::MAX,
            GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne),
        )
        .register(Registration::route("/x", 0).for_methods(http::Method::GET))
        .route("/x", 1)
        .register(Registration::subtree("/api", 2).for_methods(http::Method::POST))
        .build()
        .expect("build");
        // Specific method wins; other methods fall to the wildcard rule on that path.
        assert_eq!(r.raw_match_for_test("/x", &http::Method::GET).id(), Some(0));
        assert_eq!(
            r.raw_match_for_test("/x", &http::Method::POST).id(),
            Some(1)
        );
        // A method-only subtree leaves other methods on the default rule.
        assert_eq!(
            r.raw_match_for_test("/api/v1", &http::Method::POST).id(),
            Some(2)
        );
        assert!(
            r.raw_match_for_test("/api/v1", &http::Method::GET)
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

        let decoded = RuleRouter::from_registrations(
            u32::MAX,
            GuardConfig {
                mode: GuardMode::RejectAmbiguous,
                structural_classes: StructuralClasses::new(),
                decode_depth: DecodeDepth::UpToOne,
                case_sensitivity: CaseSensitivity::Sensitive,
            },
            registrations(),
        )
        .expect("build");
        // `%61` moves POST from the wildcard registration to the literal one, while
        // GET stays on registration 0. The verdict must judge the requested method,
        // not GET's identical representative ids.
        assert_eq!(decoded.denial_for_test("/x/%61", &http::Method::GET), None);
        assert_eq!(
            decoded.denial_for_test("/x/%61", &http::Method::POST),
            Some(ResolveError::DecodeRuleChange)
        );
        assert_eq!(
            decoded.resolve("/x/%61", &http::Method::POST),
            Err(ResolveError::DecodeRuleChange)
        );

        let folded = RuleRouter::from_registrations(
            u32::MAX,
            GuardConfig {
                mode: GuardMode::RejectAmbiguous,
                structural_classes: StructuralClasses::new(),
                decode_depth: DecodeDepth::UpToOne,
                case_sensitivity: CaseSensitivity::Insensitive,
            },
            registrations(),
        )
        .expect("build");
        assert_eq!(folded.denial_for_test("/x/A", &http::Method::GET), None);
        assert_eq!(
            folded.denial_for_test("/x/A", &http::Method::POST),
            Some(ResolveError::CaseFoldRuleChange)
        );
        assert_eq!(
            folded.resolve("/x/A", &http::Method::POST),
            Err(ResolveError::CaseFoldRuleChange)
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
            RuleRouter::from_registrations(
                u32::MAX,
                GuardConfig {
                    mode: GuardMode::RejectAmbiguous,
                    structural_classes: StructuralClasses::new(),
                    decode_depth: layers,
                    case_sensitivity: CaseSensitivity::Sensitive,
                },
                registrations(),
            )
            .expect("build")
        };

        let path = "/x/%2561";
        let single = build(DecodeDepth::UpToOne);
        assert_eq!(
            single.denial_for_test(path, &http::Method::GET),
            Some(ResolveError::DecodeRuleChange)
        );

        let up_to_two = build(DecodeDepth::UpToTwo);
        assert_eq!(
            up_to_two.denial_for_test(path, &http::Method::GET),
            Some(ResolveError::DecodeRuleChange),
            "checking a second pass must not erase the first-pass relocation"
        );
    }

    #[test]
    fn builder_supports_dynamic_registration() {
        // Runtime-sized tables register in bulk (`subtrees`/`routes`), and — because
        // the builder has a single type and supports reassignment in a loop.
        let subtrees = vec![("/admin", 0_u32), ("/api", 1)];
        let routes = vec![("/health", 2_u32), ("/version", 3)];
        let r = RuleRouter::builder(
            u32::MAX,
            GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne),
        )
        .register_all(
            subtrees
                .into_iter()
                .map(|(path, rule)| Registration::subtree(path, rule)),
        )
        .register_all(
            routes
                .into_iter()
                .map(|(path, rule)| Registration::route(path, rule)),
        )
        .build()
        .expect("build");
        // Each item is its own registration: ids stay per-subtree/per-route.
        assert_eq!(
            r.raw_match_for_test("/admin/x", &http::Method::GET).id(),
            Some(0)
        );
        assert_eq!(
            r.raw_match_for_test("/api/v1", &http::Method::GET).id(),
            Some(1)
        );
        assert_eq!(
            r.raw_match_for_test("/health", &http::Method::GET).id(),
            Some(2)
        );
        assert_eq!(
            r.raw_match_for_test("/version", &http::Method::GET).id(),
            Some(3)
        );

        // The loop form for mixed-kind dynamic tables.
        let mut b = RuleRouter::builder(
            u32::MAX,
            GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne),
        );
        for (path, rule) in [("/admin", 0_u32), ("/public", 1)] {
            b = b.subtree(path, rule);
        }
        let r = b.build().expect("build");
        assert_eq!(
            r.raw_match_for_test("/public/x", &http::Method::GET).id(),
            Some(1)
        );
    }

    #[test]
    fn multi_method_registration_shares_one_rule_id() {
        // "This rule for GET and HEAD" is one registration → one rule id, so the two
        // methods can never drift apart and movement between them is not a relocation.
        let r = RuleRouter::builder(
            u32::MAX,
            GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne),
        )
        .register(Registration::route("/x", 0).for_methods([http::Method::GET, http::Method::HEAD]))
        .register(
            Registration::subtree("/api", 1)
                .for_methods(vec![http::Method::PUT, http::Method::POST]),
        )
        .build()
        .expect("build");
        assert_eq!(r.raw_match_for_test("/x", &http::Method::GET).id(), Some(0));
        assert_eq!(
            r.raw_match_for_test("/x", &http::Method::HEAD).id(),
            Some(0)
        );
        assert!(r.raw_match_for_test("/x", &http::Method::POST).is_default());
        assert_eq!(
            r.raw_match_for_test("/api/v1", &http::Method::PUT).id(),
            Some(1)
        );
        assert_eq!(
            r.raw_match_for_test("/api/v1", &http::Method::POST).id(),
            Some(1)
        );
        assert!(
            r.raw_match_for_test("/api/v1", &http::Method::DELETE)
                .is_default()
        );
    }
}
