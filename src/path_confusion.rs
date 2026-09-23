//! Path-confusion configuration: the types that declare the guard's mode and the
//! backend behaviours it models.
//!
//! Rules are matched on the request path, but the **raw** path is forwarded upstream
//! unchanged. If the proxy and the upstream disagree about what a path *means* — a
//! parser differential — a request can be authorized as one path while the upstream
//! acts on another (`/x/../admin/secret`, `/admin%2fsecret`, `/%61dmin`, …). The
//! guard denies a request when an interpretation in its declared model selects a
//! different rule; it never rewrites what is forwarded.
//!
//! Four types configure the guard, individually through
//! [`RuleRouter::build`](crate::RuleRouter::build) or grouped in [`GuardConfig`]
//! through [`RuleRouter::build_with_config`](crate::RuleRouter::build_with_config):
//!
//! - [`PathConfusion`] selects the mode (the default scoped structural check, the strict
//!   all-positions reject, or off);
//! - [`CaseSensitivity`] declares whether the upstream folds ASCII case — **required**,
//!   with no default, because the library cannot infer it;
//! - [`DecodeLayers`] declares whether up to two percent-decode passes may happen
//!   behind this layer (a CDN/WAF/proxy in front of the origin) — likewise
//!   **required**, with no default;
//! - [`StructuralClasses`] selects which structural classes and encodings beyond the
//!   always-on default the guard recognises, plus any custom [`StructuralProbe`]
//!   detectors.
//!
//! When the guard denies, it reports a [`DenyReason`] naming the
//! check and structural class that fired, so an operator can attribute a `400` to the
//! configuration knob (or [`blob_subtree`](crate::RuleRouterBuilder::blob_subtree)
//! registration) that governs it.
//!
//! The full story lives in the [extended documentation](crate::_docs):
//!
//! - [The security contract](crate::_docs::reference::contract) — the property the guard
//!   enforces, its conditions, and precisely where it over-denies;
//! - [How the guard decides](crate::_docs::explanation::decision) — the checks that
//!   run per request, and which forms deny on sight versus only on relocation;
//! - [Supported interpretations](crate::_docs::reference::coverage) — what is and is not caught;
//! - [The guard never rewrites the path](crate::_docs::explanation::no_rewrite) —
//!   detection, not sanitisation, as a design position;
//! - [Where the differential lives](crate::_docs::explanation::topology) — the split
//!   topology this crate exists for, and why the configuration is global;
//! - [Choosing a configuration](crate::_docs::guide::configuring) — the four
//!   per-deployment decisions and their conservative directions;
//! - [Glossary](crate::_docs::reference::glossary) — the small amount of
//!   library-specific vocabulary.

use std::sync::Arc;

/// Reusable deployment assumptions and enforcement settings for a route guard.
///
/// Case sensitivity and decode depth are required; there is deliberately no
/// `Default` implementation. The mode and structural classes start with their
/// conservative built-in defaults and can be customized before construction.
/// Use with [`RuleRouter::build_with_config`](crate::RuleRouter::build_with_config).
///
/// ```
/// use huskarl_route_guard::{
///     Registration, RuleRouter,
///     path_confusion::{CaseSensitivity, DecodeLayers, GuardConfig},
/// };
///
/// let config = GuardConfig::new(CaseSensitivity::Sensitive, DecodeLayers::Single);
/// let router = RuleRouter::build_with_config(
///     vec![Registration::subtree("/admin", "protected")],
///     "public",
///     config,
/// )
/// .expect("valid routes");
/// assert!(
///     router
///         .resolve("/admin%2fusers", &http::Method::GET)
///         .is_err()
/// );
/// ```
#[derive(Clone, Debug)]
pub struct GuardConfig {
    /// Enforcement mode; defaults to scoped structural rejection.
    pub path_confusion: PathConfusion,
    /// Additional structural classes and custom probes.
    pub structural_classes: StructuralClasses,
    /// Declared maximum whole-path percent-decode depth.
    pub decode_layers: DecodeLayers,
    /// Whether downstream path interpretation folds ASCII case.
    pub case_sensitivity: CaseSensitivity,
}

impl GuardConfig {
    /// Declare the required deployment assumptions with default enforcement settings.
    #[must_use]
    pub fn new(case_sensitivity: CaseSensitivity, decode_layers: DecodeLayers) -> Self {
        Self {
            path_confusion: PathConfusion::default(),
            structural_classes: StructuralClasses::default(),
            decode_layers,
            case_sensitivity,
        }
    }
}

/// Which path-confusion guard is active.
///
/// Defaults to [`RejectStructural`](PathConfusion::RejectStructural): a recognized
/// structural form denies unless the route table proves it harmless — every rule
/// reachable past the form's anchor must be the rule the raw path matched (**scoped
/// denial**) — while non-structural forms (ASCII case, ordinary escapes) deny only
/// when the declared transform would **relocate** the path to a different rule.
/// Which form gets which treatment is tabulated in
/// [How the guard decides](crate::_docs::explanation::decision).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PathConfusion {
    /// Deny (`400`) a request carrying a recognized structural form (`%2F`, `..`, `;`, …)
    /// when its modeled reach contains another rule. This check does not simulate one
    /// particular backend; it relies on the property the supported structural
    /// interpretations share: a form rewrites the path at or after its own position (a
    /// dot-segment additionally removes at most one preceding segment). The form
    /// denies iff the route table makes some *other* rule — the default rule via a
    /// coverage gap included — reachable within that bound. In practice: encoded
    /// separators and matrix params **flow** under a fully-registered single-rule
    /// subtree ([`subtree`](crate::RuleRouterBuilder::subtree) /
    /// [`blob_subtree`](crate::RuleRouterBuilder::blob_subtree)) and in unrouted
    /// space, and **deny** wherever registrations divide the space; a `..` flows
    /// only when its possible traversal stays inside its own rule; NUL always
    /// denies. **The default.**
    #[default]
    RejectStructural,
    /// Deny (`400`) any request carrying a recognized structural form (`%2F`, `..`, `//`, `;`)
    /// **anywhere** in the path — the strictest point on the same axis as
    /// [`RejectStructural`](Self::RejectStructural), with *every* position treated as
    /// live (the table is not consulted). Strict hygiene / defense in depth: refuses
    /// `..`, `//`, encoded separators, etc. outright, even where they would not change
    /// the matched rule. It also rejects every percent escape and, under a declared
    /// case-insensitive interpretation, uppercase. Opt in deliberately: this rejects
    /// legitimate encoded content such as blob keys. Honors the configured
    /// [`StructuralClasses`].
    RejectNonCanonical,
    /// Disable the guard entirely.
    Off,
}

impl PathConfusion {
    /// Deny recognized structural forms in route-relevant positions, without modeling a
    /// backend (scoped structural check; see
    /// [`RejectStructural`](Self::RejectStructural)). **The default.**
    #[must_use]
    pub fn reject_structural() -> Self {
        Self::RejectStructural
    }

    /// Deny any path this mode considers non-canonical — strict hygiene, including
    /// every recognized structural form and every percent escape (see
    /// [`RejectNonCanonical`](Self::RejectNonCanonical)).
    #[must_use]
    pub fn reject_non_canonical() -> Self {
        Self::RejectNonCanonical
    }

    /// Disable the path-confusion guard.
    #[must_use]
    pub fn off() -> Self {
        Self::Off
    }
}

/// Whether the upstream resolves paths case-sensitively — a declaration consuming
/// builders (e.g. huskarl-pingora's `Guard` / `LoginProxy`) **require**, with no
/// default.
///
/// Path matching here is case-sensitive (so is the route matcher). Whether that matches the
/// upstream is a security fact the library cannot infer and will not guess: a
/// case-folding backend (IIS, ASP.NET, servlet containers on Windows, files on a
/// Windows/macOS filesystem) routes `/ADMIN` and `/admin` identically, so a
/// differently-cased request can reach a rule *without its checks*. You must state
/// which world you are in; there is no default.
///
/// - [`Sensitive`](Self::Sensitive) — the upstream distinguishes case. Routes that
///   differ only by ASCII case are treated as genuinely distinct and allowed.
/// - [`Insensitive`](Self::Insensitive) — the upstream folds ASCII case. The guard runs
///   the **precise case-fold check**: it lowercases the request path, re-routes it, and
///   denies only if the folded path lands on a *different* rule — so mixed-case content
///   that folds within its own rule (`/files/ReadMe.TXT`) keeps flowing, while `/ADMIN`
///   folding onto a distinct `/admin` rule is denied. Route patterns must be registered
///   in lowercase (uppercase is a build error — it is the form the backend resolves
///   to), and two routes that differ only by case become a **hard config error** — the
///   table would otherwise be ambiguous on that backend. Models ASCII case only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaseSensitivity {
    /// The upstream distinguishes ASCII case (the typical Unix-style backend).
    Sensitive,
    /// The upstream folds ASCII case (IIS/ASP.NET, Windows/macOS filesystems).
    Insensitive,
}

impl CaseSensitivity {
    /// Whether this is [`Insensitive`](Self::Insensitive).
    pub(crate) fn is_insensitive(self) -> bool {
        matches!(self, Self::Insensitive)
    }
}

/// Which whole-path percent-decode depths may happen behind this layer before the
/// path is finally routed — a declaration consuming builders **require**, with no
/// default.
///
/// Decode depth is a *topology* fact, not a backend implementation detail, and the
/// library will not guess it (the same posture as [`CaseSensitivity`]). With a
/// decoding layer in front of the origin — a CDN, a WAF, a proxy chained before
/// another proxy — the path is percent-decoded more than once, and a double-encoded
/// structural form (`%252F` → `%2F` → `/`) reaches the final router as path
/// *structure*. That layering is exactly **CVE-2025-0108** (Palo Alto PAN-OS): nginx
/// decoded `%252e%252e` once to `%2e%2e` and let it past a no-auth prefix, then
/// Apache decoded *again* to `..` and traversed into a protected script.
///
/// - [`Single`](Self::Single) — no more than one decode pass happens behind this layer.
///   `%252F` reaches the application as the literal
///   content `%2F`, so double-encoded forms are not treated as structure.
/// - [`UpToTwo`](Self::UpToTwo) — the whole path may receive one or two decode
///   passes; the exact backend depth is not assumed. The guard recognises
///   double-percent-encoded structural forms (`%252F`, `%252E`, `%253B`, …) as
///   their class, and checks both possible complete-path results.
///
/// **When unsure, declare [`UpToTwo`](Self::UpToTwo)** — within the supported model it
/// can only deny more, and its over-denial surface is small: paths carrying a
/// literal `%25XX` sequence as genuine content (e.g. a percent-encoded URL embedded
/// in a path segment). Inside a uniform single-rule subtree
/// ([`subtree`](crate::RuleRouterBuilder::subtree) /
/// [`blob_subtree`](crate::RuleRouterBuilder::blob_subtree)), double-encoded
/// *separators* in opaque keys stay tolerated even under `UpToTwo`.
///
/// Scope: this models the **canonical** double-encoding, where the `%` itself is
/// encoded (`%25` + `2e` = `%252e`) — the form *any* double-decoder resolves. Apache
/// **CVE-2021-42013** used a narrower variant, `%%32%65` (a bare `%` plus encoded
/// *digits*), which resolves to `.` only on a decoder that also treats a malformed
/// `%` as a literal and keeps going — a quirk beyond "decodes twice". That
/// decoder-leniency form is a [`StructuralClasses::with_probe`] (custom detector)
/// case, not something `UpToTwo` implies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeLayers {
    /// At most one percent-decode pass happens behind this layer.
    Single,
    /// The whole path may receive one or two decode passes — for example because
    /// the exact behaviour of a CDN, WAF, proxy chain, or origin is uncertain.
    /// Both possible complete-path results are checked.
    UpToTwo,
}

impl DecodeLayers {
    /// Whether this is [`UpToTwo`](Self::UpToTwo).
    pub(crate) fn is_up_to_two(self) -> bool {
        matches!(self, Self::UpToTwo)
    }
}

/// The structural-form class that triggered a denial — the attribution carried by
/// [`DenyReason`], mapping a `400` back to the byte family (and so to the
/// configuration knob or registration that governs it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StructuralClass {
    /// A `.`/`..` dot-segment — literal, encoded (`%2E`), or revealed by an enabled
    /// delimiter (`..%2Fx`, `..;x`). Denied whenever its climb radius could leave
    /// the matched rule; a climb that provably resolves within its own uniform
    /// subtree flows.
    DotSegment,
    /// An encoded or alternate `/` separator (`%2F`, `//`, and enabled forms).
    /// Denied unless every rule reachable past its anchor is the matched rule —
    /// tolerated under a fully-registered single-rule subtree
    /// ([`subtree`](crate::RuleRouterBuilder::subtree) /
    /// [`blob_subtree`](crate::RuleRouterBuilder::blob_subtree)).
    Separator,
    /// A `;`/`%3B` matrix path-parameter. Scoped like
    /// [`Separator`](Self::Separator).
    MatrixParam,
    /// A raw or `%00` NUL — truncates a C-string backend. Denied everywhere,
    /// unconditionally.
    NulTruncation,
    /// A `\`/`%5C` treated as a separator (declared via
    /// [`StructuralClasses::with_backslash`]). Scoped like
    /// [`Separator`](Self::Separator).
    Backslash,
    /// ASCII uppercase under a declared case-folding backend
    /// ([`CaseSensitivity::Insensitive`]) — reported only by the strict
    /// [`RejectNonCanonical`](PathConfusion::RejectNonCanonical) mode's presence
    /// deny; the default mode judges case by relocation instead
    /// ([`DenyReason::CaseFoldRelocation`]).
    Uppercase,
}

impl std::fmt::Display for StructuralClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::DotSegment => "dot-segment (`.`/`..`)",
            Self::Separator => "encoded or alternate path separator",
            Self::MatrixParam => "matrix path-parameter (`;`)",
            Self::NulTruncation => "NUL byte (truncation)",
            Self::Backslash => "backslash separator",
            Self::Uppercase => "uppercase under a case-folding backend",
        })
    }
}

/// Why the guard denied a request path — which check fired, with the byte class
/// where one is attributable.
///
/// The attribution is what makes a `400` actionable instead of a dead end: each
/// variant names the check, and its documentation names the sanctioned remedy (a
/// [`blob_subtree`](crate::RuleRouterBuilder::blob_subtree) registration for opaque
/// keys, a configuration declaration to review, …). Use [`Display`](std::fmt::Display)
/// for an attributed log line; use [`message`](Self::message) for the short static
/// string suitable for the denial response body (it deliberately does not vary with
/// the attribution).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DenyReason {
    /// The route tree returned an ID absent from the rule table. This indicates an
    /// internal invariant violation, not invalid client input. Deny the request and
    /// report an internal server error; never authorize it using the default rule.
    InvalidRuleId,
    /// The supplied value was not a request path: paths must start with `/` (or be the
    /// special `*` request target) and must not contain a query (`?`) or fragment (`#`).
    /// Pass `uri.path()`, never a complete request target or URI.
    InvalidPathInput,
    /// The scoped structural check: a structural form of this class could
    /// relocate the request — some rule other than the matched one is reachable
    /// within the byte's anchored scope. Remedies: if the prefix legitimately
    /// carries opaque keys, register it as a whole single-rule subtree
    /// (`subtree`/`blob_subtree`) so its uniformity is visible; a NUL has no remedy
    /// by design. The full triage procedure is
    /// [Handling a denial](crate::_docs::guide::handling_denials).
    Structural(StructuralClass),
    /// The precise case-fold check: lowercasing the path relocates it to a
    /// *different* rule than the raw path matched (backend declared
    /// [`CaseSensitivity::Insensitive`]). Not an over-approximation — a fold that
    /// stays within its own rule is allowed.
    CaseFoldRelocation,
    /// The precise content-decode check: one of the possible completely decoded
    /// forms (one pass, plus two under [`DecodeLayers::UpToTwo`], lowercased under
    /// a case-folding backend) relocates the path to a *different* rule. Not an
    /// over-approximation — same-rule decodes (`/foo%20bar`) are allowed.
    DecodeRelocation,
    /// The strict [`RejectNonCanonical`](PathConfusion::RejectNonCanonical) mode's
    /// presence deny: a structural form of this class, anywhere in the path.
    NonCanonical(StructuralClass),
    /// The strict mode's escape rule: the path carries a percent-escape at all.
    NonCanonicalEscape,
    /// A registered [`StructuralProbe`] matched; carries the probe's
    /// [`name`](StructuralProbe::name).
    Probe(&'static str),
    /// A path already flagged as suspicious exceeds the length cap (defense in
    /// depth; clean paths are never length-checked).
    TooLong,
}

impl DenyReason {
    /// The short, static denial message for the HTTP response body. Deliberately
    /// coarse — it does not vary with the attribution, so a response leaks nothing
    /// about the route table; put [`Display`](std::fmt::Display) in the *log* instead.
    #[must_use]
    pub fn message(&self) -> &'static str {
        match self {
            Self::InvalidRuleId => "Internal routing error",
            Self::InvalidPathInput => "Invalid request path",
            Self::Structural(_)
            | Self::CaseFoldRelocation
            | Self::DecodeRelocation
            | Self::Probe(_) => "Ambiguous request path",
            Self::NonCanonical(_) | Self::NonCanonicalEscape => "Non-canonical request path",
            Self::TooLong => "Request path too long",
        }
    }
}

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRuleId => {
                f.write_str("internal routing error: matched rule ID is absent from the rule table")
            }
            Self::InvalidPathInput => f.write_str(
                "invalid request path input: pass uri.path(), not a complete request target or URI",
            ),
            Self::Structural(c) => {
                write!(
                    f,
                    "ambiguous request path: {c} in a route-relevant position"
                )
            }
            Self::CaseFoldRelocation => {
                f.write_str("ambiguous request path: case-folding relocates it to a different rule")
            }
            Self::DecodeRelocation => f.write_str(
                "ambiguous request path: percent-decoding relocates it to a different rule",
            ),
            Self::NonCanonical(c) => write!(f, "non-canonical request path: {c}"),
            Self::NonCanonicalEscape => {
                f.write_str("non-canonical request path: percent-escape present")
            }
            Self::Probe(name) => {
                write!(
                    f,
                    "ambiguous request path: structural probe {name:?} matched"
                )
            }
            Self::TooLong => f.write_str("suspicious request path exceeds the length cap"),
        }
    }
}

/// A structural character whose alternate (overlong-UTF-8) encodings a backend may
/// decode and then honor as path structure — the selector for
/// [`StructuralClasses::with_overlong`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuralChar {
    /// `/` — the path separator (`%C0%AF`, …).
    Slash,
    /// `.` — feeds dot-segment (`.`/`..`) resolution (`%C0%AE`, …).
    Dot,
}

/// A user-defined structural detector for teaching the
/// structural modes a path form the built-in alphabet doesn't ship.
///
/// The built-in alphabet knows `%2F`, `..`, `;`, and the opt-in classes/encodings.
/// A backend that treats some *other* byte or encoding as path structure — a fresh
/// path-confusion CVE, a vendor quirk — is invisible to the structural modes until a
/// release adds the form. Wrap a detector in [`StructuralClasses::with_probe`] and it
/// is consulted on every request: return `true` and the request is denied.
///
/// # Contract
///
/// `matches` must be **pure, deterministic, and ~O(n)** — it runs on every request.
/// The check is **whole-path**: presence *anywhere* denies, even inside an opaque
/// `blob_subtree` tail that tolerates the built-in separator-like forms. That is the
/// monotonic, blunt semantics of a custom detector — by construction it can only
/// ever deny *more*, never fewer, at the
/// cost of also rejecting legitimate content that carries the form. Scope the
/// predicate as tightly as you can (match the dangerous *sequence*, not a lone byte)
/// to limit that collateral, and fold the form into the alphabet proper once there is
/// time for a release.
pub trait StructuralProbe: Send + Sync {
    /// A short static identifier for this probe, used in `Debug` output.
    fn name(&self) -> &'static str;
    /// Whether `path` carries this probe's structural form. See the trait docs for
    /// the whole-path, all-positions-live contract.
    fn matches(&self, path: &str) -> bool;
}

/// The structural alphabet the guard recognises **beyond the always-on default
/// quartet** (encoded-slash, dot-segment, matrix-param, NUL-truncation).
///
/// [`new`](Self::new) (the default) enables just that quartet — the separator-like
/// and climb/truncate forms whose legitimate-traffic cost is near nil. Turn on the
/// opt-in classes and encodings to match a backend that considers *more* paths
/// equivalent:
///
/// ```
/// # use huskarl_route_guard::path_confusion::{StructuralClasses, StructuralChar};
/// // A Windows/IIS-style backend that also decodes overlong UTF-8.
/// let classes = StructuralClasses::new()
///     .with_backslash()
///     .with_overlong([StructuralChar::Slash, StructuralChar::Dot]);
/// ```
///
/// Each toggle is a per-deployment **security** decision: enabling a class makes the
/// guard treat that form as route structure (so it checks wherever a wildcard or
/// catch-all matched it); leaving it off assumes the backend does not. Two declarations are **not**
/// here, deliberately: case ([`CaseSensitivity`]) and decode depth ([`DecodeLayers`])
/// are required, separate declarations on the builder rather than opt-ins, because
/// every deployment must answer them.
// Each field is an independent, orthogonal class/encoding toggle — a flat set of
// booleans is the clearest representation, not a code smell here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Default)]
pub struct StructuralClasses {
    /// `\`/`%5C` as a path separator (Windows/IIS).
    pub(crate) backslash: bool,
    /// Recognise overlong UTF-8 `/` (`%C0%AF`, …).
    pub(crate) overlong_slash: bool,
    /// Recognise overlong UTF-8 `.` (`%C0%AE`, …).
    pub(crate) overlong_dot: bool,
    /// Recognise fullwidth-form structural confusables (`／`/`．`/`；`/`＼`).
    pub(crate) unicode: bool,
    /// Custom structural detectors ([`StructuralProbe`]).
    pub(crate) probes: Vec<Arc<dyn StructuralProbe>>,
}

impl StructuralClasses {
    /// The default set: just the always-on quartet (encoded-slash, dot-segment,
    /// matrix-param, NUL-truncation), no opt-in classes, encodings, or probes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Treat `\`/`%5C` as a path separator — for Windows/IIS backends. Opt-in, not
    /// default, because a raw `\` is legitimate *content* on a Unix backend — its
    /// canonical spelling — so denying it by default would reject canonical paths.
    #[must_use]
    pub fn with_backslash(mut self) -> Self {
        self.backslash = true;
        self
    }

    /// Recognise overlong (non-shortest-form) UTF-8 encodings of the given
    /// structural characters — `%C0%AF` → `/`, `%C0%AE` → `.`, plus their 3- and
    /// 4-byte forms — as their class. Standards-conforming decoders reject overlong
    /// forms, so this is off unless a backend that accepts them (the classic
    /// legacy-IIS Unicode traversal vector) is being modeled.
    #[must_use]
    pub fn with_overlong(mut self, chars: impl IntoIterator<Item = StructuralChar>) -> Self {
        for c in chars {
            match c {
                StructuralChar::Slash => self.overlong_slash = true,
                StructuralChar::Dot => self.overlong_dot = true,
            }
        }
        self
    }

    /// Recognise the **fullwidth-form** structural confusables — `／` (U+FF0F), `．`
    /// (U+FF0E), `；` (U+FF1B), and (when [`with_backslash`](Self::with_backslash) is also
    /// set) `＼` (U+FF3C) — that NFKC compatibility normalization folds to `/`, `.`, `;`,
    /// `\`, in both raw and percent-encoded (`%EF%BC%8F`) form. Enable this for a backend
    /// that Unicode-normalizes the path before routing: such a backend treats
    /// `/api／secret` as `/api/secret`, so the fullwidth solidus is a separator the guard
    /// must account for.
    ///
    /// Scope is **NFKC structural** confusables only — the handful of fullwidth forms
    /// that fold to a delimiter. Two related things are deliberately *not* covered:
    /// fullwidth *letters* that fold onto a different literal route (`/ＡＤＭＩＮ` →
    /// `/admin`, a content relocation), and visual look-alikes NFKC does not decompose
    /// (U+2044 fraction slash, U+2215 division slash). For either, use a
    /// [`with_probe`](Self::with_probe) — e.g. one that denies non-ASCII paths.
    #[must_use]
    pub fn with_unicode_normalization(mut self) -> Self {
        self.unicode = true;
        self
    }

    /// Add a custom [`StructuralProbe`] for a structural form the
    /// built-in alphabet doesn't ship (e.g. an incident mitigation). See
    /// [`StructuralProbe`] for the whole-path, all-positions-live semantics.
    #[must_use]
    pub fn with_probe(mut self, probe: impl StructuralProbe + 'static) -> Self {
        self.probes.push(Arc::new(probe));
        self
    }
}

impl std::fmt::Debug for StructuralClasses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let probes: Vec<&'static str> = self.probes.iter().map(|p| p.name()).collect();
        f.debug_struct("StructuralClasses")
            .field("backslash", &self.backslash)
            .field("overlong_slash", &self.overlong_slash)
            .field("overlong_dot", &self.overlong_dot)
            .field("unicode", &self.unicode)
            .field("probes", &probes)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_quartet_only() {
        // The always-on quartet lives in `enabled_classes`; the opt-in set is empty.
        let c = StructuralClasses::new();
        assert!(!c.backslash);
        assert!(!c.overlong_slash);
        assert!(!c.overlong_dot);
        assert!(!c.unicode);
        assert!(c.probes.is_empty());
    }

    #[test]
    fn builders_toggle_their_field() {
        assert!(StructuralClasses::new().with_backslash().backslash);
        assert!(
            StructuralClasses::new()
                .with_unicode_normalization()
                .unicode
        );

        let both =
            StructuralClasses::new().with_overlong([StructuralChar::Slash, StructuralChar::Dot]);
        assert!(both.overlong_slash && both.overlong_dot);
        let slash_only = StructuralClasses::new().with_overlong([StructuralChar::Slash]);
        assert!(slash_only.overlong_slash && !slash_only.overlong_dot);
    }

    #[test]
    fn deny_reason_messages_stay_static_and_coarse() {
        // The response-body string is deliberately coarse (no attribution leaks into
        // the response); the attributed detail lives in Display for logs.
        let d = DenyReason::Structural(StructuralClass::Separator);
        assert_eq!(d.message(), "Ambiguous request path");
        assert!(d.to_string().contains("separator"));
        assert_eq!(
            DenyReason::CaseFoldRelocation.message(),
            "Ambiguous request path"
        );
        assert_eq!(
            DenyReason::DecodeRelocation.message(),
            "Ambiguous request path"
        );
        assert_eq!(DenyReason::Probe("p").message(), "Ambiguous request path");
        assert_eq!(
            DenyReason::NonCanonical(StructuralClass::DotSegment).message(),
            "Non-canonical request path"
        );
        assert_eq!(
            DenyReason::NonCanonicalEscape.message(),
            "Non-canonical request path"
        );
        assert_eq!(DenyReason::TooLong.message(), "Request path too long");
        assert_eq!(
            DenyReason::InvalidPathInput.message(),
            "Invalid request path"
        );
        // The probe's name reaches the log line.
        assert!(
            DenyReason::Probe("reject-non-ascii")
                .to_string()
                .contains("reject-non-ascii")
        );
    }

    #[test]
    fn probe_registered_and_named() {
        struct P;
        impl StructuralProbe for P {
            fn name(&self) -> &'static str {
                "p"
            }
            fn matches(&self, path: &str) -> bool {
                path.contains('~')
            }
        }
        let c = StructuralClasses::new().with_probe(P);
        assert_eq!(c.probes.len(), 1);
        assert!(c.probes[0].matches("/a~b"));
        assert!(!c.probes[0].matches("/ab"));
        // probe does not flip any class field
        assert!(!c.backslash && !c.unicode);
    }
}
