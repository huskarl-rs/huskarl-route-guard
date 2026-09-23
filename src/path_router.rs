//! The rule-id router that owns the path-confusion guard.
//!
//! An authorization layer that maps request paths to per-path rules needs the same two
//! things regardless of which proxy or framework hosts it:
//!
//! - **Rule identity** — each concrete method or ALL definition has one rule ID shared
//!   across its registration's patterns. Inheritance returns that original identity,
//!   so movement within the same rule is not a relocation.
//! - **The structural verdict** — deny a request whose path could be routed differently
//!   by a normalizing backend than the rule the raw path matched.
//!
//! [`RuleRouter`] owns the `id → rule` table, the default rule, and a
//! [`PathConfusionGuard`] over the
//! [owned segment-tree router](crate::route_tree). Public matchit-style pattern strings
//! are lowered into the owned grammar at build time; whatever the grammar cannot express
//! (in-segment prefix/suffix params) is a build-time error.
//!
//! [`RuleRouter::builder`] constructs path tables with
//! [`register_path`](RuleRouterBuilder::register_path),
//! [`register_subtree`](RuleRouterBuilder::register_subtree), and
//! [`register_exclusive_subtree`](RuleRouterBuilder::register_exclusive_subtree).
//! Each table groups method overrides, an optional ALL rule, and explicit inheritance.
//! [`RuleRouter::from_registrations`] accepts assembled [`PathRegistration`] values;
//! rule IDs are assigned to concrete definitions in insertion order.

use crate::{
    config::{GuardConfig, GuardMode, ResolveError},
    guard::PathConfusionGuard,
    route_tree::{BuildError, LowerError, MethodMatch, Router, Segment, lower_matchit},
    structural::{classes_present, enabled_classes, enabled_encodings},
};

/// The outcome of matching a path: which rule applies, and whether it came from a
/// concrete definition or is the default rule after path lookup was exhausted.
///
/// The distinction is the route table's coverage made visible — an authorization
/// layer typically logs *which* registration authorized a request, and treats a
/// [`Default`](Self::Default) fall-through as its own case. Use
/// [`rule`](Self::rule) when only the rule matters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleMatch<'a, R> {
    /// A concrete definition matched, directly or through inheritance. IDs follow
    /// definition insertion order, with each definition shared across its patterns.
    Matched {
        /// The matched registration's rule id.
        id: u32,
        /// The matched registration's rule.
        rule: &'a R,
    },
    /// Path lookup exhausted all matching paths, possibly through inheritance.
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

    /// Whether path lookup exhausted all matching paths and selected the default.
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
    /// route structure. Active guard modes forbid these forms in registered literals.
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
    /// A concrete override's method set is empty, so its rule could
    /// never be selected. A path table with no concrete definitions is valid.
    EmptyMethodSet {
        /// The registration's first pattern, for attribution.
        pattern: String,
    },
    /// A registration has no patterns, so its rule would be unreachable while still
    /// consuming a rule id.
    EmptyPatternSet,
    /// More concrete definitions than rule IDs: the two highest `u32` values are
    /// reserved for default and method denial. Unreachable in realistic configurations;
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
                f.write_str("too many rule definitions: the two highest u32 IDs are reserved for default and method denial")
            }
        }
    }
}

impl std::error::Error for RuleRouterError {}

/// A path's concrete method overrides, optional ALL rule, and fallback behavior.
///
/// Missing methods deny unless [`fallback_inherit`](Self::fallback_inherit) is enabled.
/// Inheritance continues matching the original path and preserves the defining rule's
/// identity. It cannot be assigned to an individual method.
#[derive(Clone, Debug)]
pub struct PathRegistration<R> {
    patterns: Vec<String>,
    rules: Vec<(MethodMatch, R)>,
    exclusive: bool,
    inherit: bool,
}

impl<R> PathRegistration<R> {
    /// Register one exact path or whole-segment pattern. Initially all methods deny.
    pub fn path(pattern: impl Into<String>) -> Self {
        Self::patterns([pattern.into()])
    }

    /// Group patterns under the same method table. Each concrete rule has one identity
    /// shared across all these patterns.
    pub fn patterns(patterns: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            patterns: patterns.into_iter().map(Into::into).collect(),
            rules: Vec::new(),
            exclusive: false,
            inherit: false,
        }
    }

    /// Register a prefix, its trailing slash, and descendants with one method table.
    #[must_use]
    pub fn subtree(path: &str) -> Self {
        Self::patterns(crate::subtree_patterns(path))
    }

    /// Register a subtree and forbid overriding paths in its catch-all tail.
    #[must_use]
    pub fn exclusive_subtree(path: &str) -> Self {
        Self {
            exclusive: true,
            ..Self::subtree(path)
        }
    }

    /// Supply the concrete rule for methods without an explicit override.
    /// Repeated ALL entries are rejected at build time.
    #[must_use]
    pub fn all(mut self, rule: R) -> Self {
        self.rules.push((MethodMatch::Any, rule));
        self
    }

    /// Supply a concrete override for one method. Duplicate methods are build errors.
    #[must_use]
    pub fn method(self, method: http::Method, rule: R) -> Self {
        self.methods([method], rule)
    }

    /// Share one override identity across several methods. Empty or repeated methods
    /// are rejected when building the router.
    #[must_use]
    pub fn methods(mut self, methods: impl IntoIterator<Item = http::Method>, rule: R) -> Self {
        self.rules
            .push((MethodMatch::OneOf(methods.into_iter().collect()), rule));
        self
    }

    /// Continue to the next matching path when neither a method override nor ALL
    /// supplies a rule. Defaults to false. Every intermediate path controls its own
    /// continuation; an unresolved non-inheriting path denies. Exhaustion uses default.
    /// A concrete ALL rule takes precedence and makes inheritance unnecessary here.
    #[must_use]
    pub fn fallback_inherit(mut self, inherit: bool) -> Self {
        self.inherit = inherit;
        self
    }
}

/// A `path → rule` router with rule-granularity identity and the path-confusion guard.
pub struct RuleRouter<R> {
    rules: Vec<R>,
    default: R,
    guard: PathConfusionGuard,
    diagnostic_patterns: Vec<crate::diagnostics::DiagnosticPattern>,
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
    ///     .register_subtree("/admin", |path| path.all("admin"))
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
    /// Each concrete rule definition receives one identity shared by its patterns.
    /// Inheritance creates no new identity.
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
        registrations: impl IntoIterator<Item = PathRegistration<R>>,
    ) -> Result<Self, RuleRouterError> {
        let mut tree_entries = Vec::new();
        let mut patterns = Vec::new();
        let mut rules = Vec::new();
        let mut path_fallbacks = std::collections::HashMap::new();
        for registration in registrations {
            if registration.patterns.is_empty() {
                return Err(RuleRouterError::EmptyPatternSet);
            }
            let mut parsed = Vec::new();
            for pattern in &registration.patterns {
                let lowered = validate_pattern(pattern, &config)?;
                if path_fallbacks
                    .insert(lowered.clone(), registration.inherit)
                    .is_some_and(|previous| previous != registration.inherit)
                {
                    return Err(RuleRouterError::Route {
                        pattern: pattern.clone(),
                        reason: "conflicting fallback settings at the same path",
                    });
                }
                parsed.push(lowered);
            }
            if registration.rules.is_empty() {
                // A path with no rules still claims a terminal, but has no public ID.
                for (pattern, lowered) in registration.patterns.iter().zip(&parsed) {
                    tree_entries.push((
                        lowered.clone(),
                        crate::route_tree::DENIED_RULE,
                        registration.exclusive,
                        MethodMatch::OneOf(Vec::new()),
                    ));
                    patterns.push(pattern.clone());
                }
            }
            for (method, rule) in registration.rules {
                if matches!(&method, MethodMatch::OneOf(methods) if methods.is_empty()) {
                    return Err(RuleRouterError::EmptyMethodSet {
                        pattern: registration.patterns.first().cloned().unwrap_or_default(),
                    });
                }
                // The two highest IDs are reserved for default and method denial.
                let id = u32::try_from(rules.len())
                    .ok()
                    .filter(|&id| id < crate::route_tree::DENIED_RULE)
                    .ok_or(RuleRouterError::TooManyRegistrations)?;
                for (pattern, lowered) in registration.patterns.iter().zip(&parsed) {
                    tree_entries.push((
                        lowered.clone(),
                        id,
                        registration.exclusive,
                        method.clone(),
                    ));
                    patterns.push(pattern.clone());
                }
                rules.push(rule);
            }
        }
        let router = Router::build_with_fallbacks(
            &tree_entries,
            &path_fallbacks.into_iter().collect::<Vec<_>>(),
        )
        .map_err(|error| map_build_err(error, &patterns))?;
        let diagnostic_patterns = tree_entries
            .into_iter()
            .zip(patterns)
            .map(
                |((parsed, _, _, methods), source)| crate::diagnostics::DiagnosticPattern {
                    parsed,
                    source,
                    methods,
                },
            )
            .collect();
        let guard = PathConfusionGuard::new(router, config);

        Ok(Self {
            rules,
            default,
            guard,
            diagnostic_patterns,
        })
    }

    /// Reports method gaps that hide a less-specific path's rule.
    ///
    /// This opt-in lint does not affect construction or request handling. It checks
    /// standard HTTP methods and explicitly registered extension methods against
    /// representative paths at pairwise pattern overlaps. Every report includes a
    /// concrete witness; an empty result is not proof that no gaps exist.
    ///
    /// Patterns are retained for this analysis. Calling this method allocates and
    /// examines pattern pairs; use it during startup, not for each request.
    /// Results follow registration order and do not depend on guard mode.
    #[must_use]
    pub fn diagnostics(&self) -> Vec<crate::MethodGapDiagnostic> {
        crate::diagnostics::method_gaps(&self.diagnostic_patterns, &self.guard)
    }

    /// Resolves `path` in one call: the path-confusion verdict first, then the rule
    /// match. `Err(reason)` means the request must be **denied** — no rule is offered.
    /// Ambiguity/input denials normally map to `400`, method-policy denials to `403`,
    /// and internal invariant failures to `500`.
    /// `Ok` carries the [`RuleMatch`]: the matched registration's rule,
    /// or the default rule after matching is exhausted. A method gap at a
    /// non-inheriting path returns [`ResolveError::MethodNotConfigured`].
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
        let id = self.guard.checked(path, method)?;
        self.rule_for_id(id)
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
    ) -> Result<crate::RawMatch, ResolveError> {
        if !is_request_path(path) {
            return Err(ResolveError::InvalidPathInput);
        }
        let id = self.guard.resolve(path, method);
        if id == Some(crate::route_tree::DENIED_RULE) {
            return Ok(crate::RawMatch::MethodDenied);
        }
        let matched = self.rule_for_id(id)?;
        Ok(matched
            .id()
            .map_or(crate::RawMatch::Default, |id| crate::RawMatch::Matched {
                id,
            }))
    }

    /// Explains guard checks without returning an authorization rule.
    ///
    /// Scoped structural denials include their anchor and the rule identities
    /// contributing to its conservative coverage. Other denials carry their usual
    /// reason. This runs checks (including custom probes) once and allocates extra
    /// diagnostic data; use [`resolve`](Self::resolve) for request handling.
    ///
    /// # Errors
    ///
    /// Returns input-validation or internal rule-ID errors. Ordinary guard denials
    /// appear in [`ResolutionExplanation::denial`](crate::ResolutionExplanation::denial).
    pub fn explain(
        &self,
        path: &str,
        method: &http::Method,
    ) -> Result<crate::ResolutionExplanation, ResolveError> {
        let raw_match = self.inspect_raw(path, method)?;
        let denial = self.guard.checked(path, method).err();
        let structural = if matches!(denial, Some(ResolveError::Structural(_))) {
            self.guard.structural_explanation(path, method)
        } else {
            None
        };
        Ok(crate::ResolutionExplanation {
            raw_match,
            denial,
            structural,
        })
    }

    // The reference backend needs to route transformed inputs even when they are
    // outside the public request-path boundary.
    #[cfg(test)]
    pub(crate) fn raw_match_for_test(&self, path: &str, method: &http::Method) -> RuleMatch<'_, R> {
        self.rule_for_id(self.guard.resolve(path, method))
            .expect("test path must have a rule")
    }

    #[cfg(test)]
    pub(crate) fn raw_identity_for_test(&self, path: &str, method: &http::Method) -> Option<u32> {
        self.guard.resolve(path, method)
    }

    fn rule_for_id(&self, id: Option<u32>) -> Result<RuleMatch<'_, R>, ResolveError> {
        match id {
            Some(crate::route_tree::DENIED_RULE) => Err(ResolveError::MethodNotConfigured),
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
    registrations: Vec<PathRegistration<R>>,
    default: R,
    config: GuardConfig,
}

impl<R> RuleRouterBuilder<R> {
    /// Adds a registration. Each concrete definition has one identity shared across
    /// its patterns; inherited results retain the original defining identity.
    ///
    /// ```
    /// use huskarl_route_guard::{
    ///     CaseSensitivity, DecodeDepth, GuardConfig, PathRegistration, RuleRouter,
    /// };
    ///
    /// let router = RuleRouter::builder(
    ///     "default",
    ///     GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne),
    /// )
    /// .register(
    ///     PathRegistration::path("/health")
    ///         .methods([http::Method::GET, http::Method::HEAD], "health"),
    /// )
    /// .register(PathRegistration::patterns(["/ready", "/live"]).all("probes"))
    /// .build()
    /// .expect("valid routes");
    /// assert_eq!(
    ///     router.resolve("/ready", &http::Method::GET).unwrap().id(),
    ///     router.resolve("/live", &http::Method::GET).unwrap().id()
    /// );
    /// ```
    #[must_use]
    pub fn register(mut self, registration: PathRegistration<R>) -> Self {
        self.registrations.push(registration);
        self
    }

    /// Define a path's method table and fallback together.
    ///
    /// ```
    /// use http::Method;
    /// use huskarl_route_guard::{CaseSensitivity, DecodeDepth, GuardConfig, RuleRouter};
    /// let router = RuleRouter::builder(
    ///     "public",
    ///     GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne),
    /// )
    /// .register_subtree("/files", |path| path.method(Method::GET, "read"))
    /// .register_path("/files/special", |path| {
    ///     path.fallback_inherit(true).method(Method::POST, "write")
    /// })
    /// .build()
    /// .unwrap();
    /// assert_eq!(
    ///     *router
    ///         .resolve("/files/special", &Method::GET)
    ///         .unwrap()
    ///         .rule(),
    ///     "read"
    /// );
    /// assert!(router.resolve("/files/hello%20world", &Method::GET).is_ok());
    /// assert!(router.resolve("/files/hello", &Method::DELETE).is_err());
    /// ```
    #[must_use]
    pub fn register_path(
        self,
        pattern: impl Into<String>,
        configure: impl FnOnce(PathRegistration<R>) -> PathRegistration<R>,
    ) -> Self {
        self.register(configure(PathRegistration::path(pattern)))
    }

    /// Define one method table shared by a prefix, trailing slash, and descendants.
    ///
    /// `/files` includes `/files`, `/files/`, and descendants. A trailing slash in
    /// the input excludes the bare path. More-specific registrations take precedence.
    #[must_use]
    pub fn register_subtree(
        self,
        path: &str,
        configure: impl FnOnce(PathRegistration<R>) -> PathRegistration<R>,
    ) -> Self {
        self.register(configure(PathRegistration::subtree(path)))
    }

    /// Define an exclusive subtree's method table and fallback together.
    ///
    /// Rejects overriding paths in the catch-all tail at build time, including
    /// overlapping literal and wildcard branches. Request-time checks are unchanged;
    /// exclusivity does not disable method restrictions or guarantee acceptance.
    #[must_use]
    pub fn register_exclusive_subtree(
        self,
        path: &str,
        configure: impl FnOnce(PathRegistration<R>) -> PathRegistration<R>,
    ) -> Self {
        self.register(configure(PathRegistration::exclusive_subtree(path)))
    }

    /// Adds registrations in iteration order, preserving each one's identity.
    #[must_use]
    pub fn register_all(
        mut self,
        registrations: impl IntoIterator<Item = PathRegistration<R>>,
    ) -> Self {
        self.registrations.extend(registrations);
        self
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

/// Validate literal request bytes once per declared pattern, including paths with
/// no concrete rules. Parameter names are metadata and are not scanned.
fn validate_pattern(
    pattern: &str,
    config: &GuardConfig,
) -> Result<crate::route_tree::Pattern, RuleRouterError> {
    let lowered = lower_matchit(pattern).map_err(|error| RuleRouterError::Route {
        pattern: pattern.to_owned(),
        reason: lower_reason(&error),
    })?;
    if config.mode != GuardMode::Disabled {
        let enabled = enabled_classes(&config.structural_classes);
        let enc = enabled_encodings(&config.structural_classes, config.decode_depth);
        for segment in &lowered.segments {
            if let Segment::Literal(literal) = segment {
                if !classes_present(literal, enabled, enc)
                    .intersect(enabled)
                    .is_empty()
                {
                    return Err(RuleRouterError::NonCanonical {
                        pattern: pattern.to_owned(),
                    });
                }
                if config.case_sensitivity.is_insensitive()
                    && literal.bytes().any(|b| b.is_ascii_uppercase())
                {
                    return Err(RuleRouterError::NonCanonicalCase {
                        pattern: pattern.to_owned(),
                    });
                }
            }
        }
    }
    Ok(lowered)
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
    /// same rule value into one [`PathRegistration`] (rule ids are then positional, so a
    /// row's rule value equals its registration's id in these tests).
    fn router(rows: &[(&str, u32)], pc: GuardMode) -> Result<RuleRouter<u32>, RuleRouterError> {
        let mut regs: Vec<PathRegistration<u32>> = Vec::new();
        for (pattern, rule) in rows {
            match regs.last_mut() {
                Some(reg) if reg.rules[0].1 == *rule => reg.patterns.push((*pattern).to_owned()),
                _ => regs.push(PathRegistration::path(*pattern).all(*rule)),
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
            vec![PathRegistration::path("/admin").all("protected")],
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
            PathRegistration::subtree("/files"),
            PathRegistration::exclusive_subtree("/files"),
        ] {
            let config = GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne);
            let unrestricted = RuleRouter::from_registrations(
                "default",
                config.clone(),
                vec![registration.clone().all("files")],
            )
            .expect("build");
            let restricted = RuleRouter::from_registrations(
                "default",
                config,
                vec![registration.method(http::Method::GET, "files")],
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
            assert_eq!(
                restricted
                    .resolve("/files/a%2fb", &http::Method::POST)
                    .unwrap_err(),
                ResolveError::MethodNotConfigured
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
            .register_path(pattern, |path| path.all(1))
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
        .register_path("/{UserId}", |path| path.all(1))
        .register_path("/items/{x;y}", |path| path.all(2))
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
        .register_path("/Admin/{UserId}", |path| path.all(1))
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
        // The exclusive registration flag (set by `register_exclusive_subtree`) reaches
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
            vec![PathRegistration::exclusive_subtree("/files").all(0)],
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
                PathRegistration::exclusive_subtree("/files").all(0),
                PathRegistration::path("/files/secret").all(1),
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
                PathRegistration::subtree("/admin").all(10),
                PathRegistration::path("/health").all(20),
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
            vec![PathRegistration::path("/x").methods(Vec::new(), 0)],
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
            vec![PathRegistration::patterns(Vec::<String>::new()).all(0)],
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
            vec![PathRegistration::path("/x").methods([http::Method::GET, http::Method::GET], 0)],
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
        .register_subtree("/admin", |path| path.all(10))
        .register_path("/health", |path| path.all(20))
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
        .register_subtree("/admin", |path| path.all(0))
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
        .register_exclusive_subtree("/files", |path| path.all(0))
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
        .register_exclusive_subtree("/files", |path| path.all(0))
        .register_path("/files/secret", |path| path.all(1))
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
        .register(PathRegistration::path("/x").method(http::Method::GET, 0))
        .register_path("/x", |path| path.all(1))
        .register(PathRegistration::subtree("/api").method(http::Method::POST, 2))
        .build()
        .expect("build");
        // Specific method wins; other methods fall to the wildcard rule on that path.
        assert_eq!(r.raw_match_for_test("/x", &http::Method::GET).id(), Some(0));
        assert_eq!(
            r.raw_match_for_test("/x", &http::Method::POST).id(),
            Some(1)
        );
        // A method-only subtree denies other methods unless it inherits.
        assert_eq!(
            r.raw_match_for_test("/api/v1", &http::Method::POST).id(),
            Some(2)
        );
        assert_eq!(
            r.resolve("/api/v1", &http::Method::GET).unwrap_err(),
            ResolveError::MethodNotConfigured
        );
    }

    #[test]
    fn precise_verdicts_use_the_request_method() {
        let registrations = || {
            vec![
                // GET deliberately has the same rule id at the wildcard and literal
                // terminals. It is the method-blind representative at both positions.
                PathRegistration::patterns(vec!["/x/{id}".to_owned(), "/x/a".to_owned()])
                    .method(http::Method::GET, 0),
                PathRegistration::path("/x/{id}").method(http::Method::POST, 1),
                PathRegistration::path("/x/a").method(http::Method::POST, 2),
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
                PathRegistration::patterns(vec!["/x/{id}".to_owned(), "/x/a".to_owned()]).all(0),
                PathRegistration::path("/x/%61").all(1),
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
                .map(|(path, rule)| PathRegistration::subtree(path).all(rule)),
        )
        .register_all(
            routes
                .into_iter()
                .map(|(path, rule)| PathRegistration::path(path).all(rule)),
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
            b = b.register_subtree(path, |path| path.all(rule));
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
        .register(PathRegistration::path("/x").methods([http::Method::GET, http::Method::HEAD], 0))
        .register(
            PathRegistration::subtree("/api")
                .methods(vec![http::Method::PUT, http::Method::POST], 1),
        )
        .build()
        .expect("build");
        assert_eq!(r.raw_match_for_test("/x", &http::Method::GET).id(), Some(0));
        assert_eq!(
            r.raw_match_for_test("/x", &http::Method::HEAD).id(),
            Some(0)
        );
        assert_eq!(
            r.resolve("/x", &http::Method::POST).unwrap_err(),
            ResolveError::MethodNotConfigured
        );
        assert_eq!(
            r.raw_match_for_test("/api/v1", &http::Method::PUT).id(),
            Some(1)
        );
        assert_eq!(
            r.raw_match_for_test("/api/v1", &http::Method::POST).id(),
            Some(1)
        );
        assert_eq!(
            r.resolve("/api/v1", &http::Method::DELETE).unwrap_err(),
            ResolveError::MethodNotConfigured
        );
    }
}
