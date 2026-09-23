//! Configure downstream parsing assumptions and enforcement.
//!
//! Use [`GuardConfig`] with [`RuleRouter::from_registrations`](crate::RuleRouter::from_registrations),
//! or pass it to [`RuleRouter::builder`](crate::RuleRouter::builder).
//!
//! | Setting | Purpose | Default |
//! |---|---|---|
//! | [`GuardMode`] | Choose checks based on possible rule changes, strict rejection, or off | [`RejectAmbiguous`](GuardMode::RejectAmbiguous) |
//! | [`CaseSensitivity`] | Declare whether downstream routing folds ASCII case | Required |
//! | [`DecodeDepth`] | Declare the maximum supported percent-decode depth | Required |
//! | [`StructuralClasses`] | Enable additional structural forms and custom detectors | Built-in classes only |
//!
//! These settings describe possible downstream behaviors; the crate does not detect
//! them from your deployment. The default mode permits some structural forms when
//! the checks establish that they cannot change the rule.
//!
//! For practical choices, follow [Choosing a configuration](crate::_docs::guide::configuring).
//! For exact guarantees and exclusions, consult the
//! [security contract](crate::_docs::reference::contract) and
//! [supported parsing behaviors](crate::_docs::reference::coverage).
//! [How the guard decides](crate::_docs::explanation::decision) explains the algorithm.
//!
//! A rejected request carries a [`ResolveError`]. Its [`Display`](std::fmt::Display)
//! gives the log detail; [`message()`](ResolveError::message) gives a short response
//! message. The calling application sends the response and must not forward a
//! rejected request.

use std::sync::Arc;

/// Reusable deployment assumptions and enforcement settings for a route guard.
///
/// Case sensitivity and decode depth are required; there is deliberately no
/// `Default` implementation. The mode and structural classes start with their
/// conservative built-in defaults and can be customized before construction.
/// Use with [`RuleRouter::from_registrations`](crate::RuleRouter::from_registrations).
///
/// ```
/// use huskarl_route_guard::{
///     Registration, RuleRouter,
///     config::{CaseSensitivity, DecodeDepth, GuardConfig},
/// };
///
/// let config = GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne);
/// let router = RuleRouter::from_registrations(
///     "public",
///     config,
///     [Registration::subtree("/admin", "protected")],
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
    /// Enforcement mode; defaults to checking for possible rule changes.
    pub mode: GuardMode,
    /// Additional structural classes and custom probes.
    pub structural_classes: StructuralClasses,
    /// Declared maximum whole-path percent-decode depth.
    pub decode_depth: DecodeDepth,
    /// Whether downstream path interpretation folds ASCII case.
    pub case_sensitivity: CaseSensitivity,
}

impl GuardConfig {
    /// Declare the required deployment assumptions with default enforcement settings.
    #[must_use]
    pub fn new(case_sensitivity: CaseSensitivity, decode_depth: DecodeDepth) -> Self {
        Self {
            mode: GuardMode::default(),
            structural_classes: StructuralClasses::default(),
            decode_depth,
            case_sensitivity,
        }
    }

    /// Selects enforcement without changing the declared parsing assumptions.
    #[must_use]
    pub fn with_mode(mut self, mode: GuardMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets additional structural forms and custom probes.
    #[must_use]
    pub fn with_structural_classes(mut self, classes: StructuralClasses) -> Self {
        self.structural_classes = classes;
        self
    }
}

/// Which ambiguity checks to run.
///
/// The default checks for possible rule changes. The strict mode rejects every
/// recognized non-canonical form, even when the rule would stay the same.
/// See the [security contract](crate::_docs::reference::contract) for exact behavior.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GuardMode {
    /// Check whether downstream parsing could select a different rule. The default.
    ///
    /// This mode accepts structural forms such as encoded slashes
    /// when every path in the analyzed region selects the same rule for the request method.
    /// Structural analysis is conservative and may reject more than actual parsing
    /// would require. Case folding and percent-decoding compare the resulting rules
    /// directly for the request method. NUL is always rejected.
    ///
    /// See [How the guard decides](crate::_docs::explanation::decision).
    #[default]
    RejectAmbiguous,
    /// Reject every enabled structural form, every complete percent escape, and
    /// uppercase ASCII when case-insensitive parsing is configured.
    ///
    /// Applies everywhere, including blob subtrees, without checking whether the
    /// rule would change. This can reject legitimate encoded keys. Recognition is
    /// still limited to the configured [`StructuralClasses`] and parsing model.
    RequireCanonical,
    /// Disable ambiguity checks and custom probes. [`resolve`](crate::RuleRouter::resolve)
    /// still validates the path input and checks internal rule IDs.
    Disabled,
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
/// Decode depth describes the actual decoding performed after this guard, including
/// intermediaries and the origin; it cannot be inferred from the number of processes.
/// The library will not guess it (the same posture as [`CaseSensitivity`]). When both
/// an intermediary and the origin decode the path, a double-encoded
/// structural form (`%252F` → `%2F` → `/`) reaches the final router as path
/// *structure*. That layering is exactly **CVE-2025-0108** (Palo Alto PAN-OS): nginx
/// decoded `%252e%252e` once to `%2e%2e` and let it past a no-auth prefix, then
/// Apache decoded *again* to `..` and traversed into a protected script.
///
/// - [`UpToOne`](Self::UpToOne) — no more than one decode pass happens behind this layer.
///   `%252F` remains `%252F` without decoding or becomes the literal content `%2F`
///   after one pass; it does not become a slash within this depth.
/// - [`UpToTwo`](Self::UpToTwo) — the whole path may receive zero, one, or two decode
///   passes; the exact backend depth is not assumed. The guard recognises
///   double-percent-encoded structural forms (`%252F`, `%252E`, `%253B`, …) as
///   their class, and checks both possible complete-path results.
///
/// **When unsure, declare [`UpToTwo`](Self::UpToTwo)** — within the supported model it
/// can only deny more. Additional denials can affect nested escapes, including
/// escapes assembled from encoded hex digits. More than two decode passes are outside
/// the model. Inside a subtree with uniform coverage for the request method
/// ([`subtree`](crate::RuleRouterBuilder::subtree) /
/// [`exclusive_subtree`](crate::RuleRouterBuilder::exclusive_subtree)), double-encoded
/// *separators* in keys can stay tolerated even under `UpToTwo` in
/// [`RejectAmbiguous`](GuardMode::RejectAmbiguous). Exclusivity alone does not
/// establish uniform coverage, and other checks can still deny the request.
///
/// Each permitted whole-path decode result receives structural analysis as well as
/// rule comparison. This includes combinations with enabled fullwidth and overlong
/// forms, and escapes whose hex digits are themselves encoded (`%25%32%65` →
/// `%2e` → `.`). Incomplete or malformed escapes remain literal during a pass;
/// a later permitted pass can decode an escape assembled by the earlier pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeDepth {
    /// At most one percent-decode pass happens behind this layer.
    UpToOne,
    /// The whole path may receive zero, one, or two decode passes — for example because
    /// the exact behaviour of a CDN, WAF, proxy chain, or origin is uncertain.
    /// Both possible complete-path results are checked.
    UpToTwo,
}

impl DecodeDepth {
    /// Whether this is [`UpToTwo`](Self::UpToTwo).
    pub(crate) fn is_up_to_two(self) -> bool {
        matches!(self, Self::UpToTwo)
    }
}

/// The structural-form class that triggered a denial — the attribution carried by
/// [`ResolveError`], mapping a `400` back to the byte family (and so to the
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
    /// [`exclusive_subtree`](crate::RuleRouterBuilder::exclusive_subtree)).
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
    /// [`RequireCanonical`](GuardMode::RequireCanonical) mode's presence
    /// deny; the default mode judges case by relocation instead
    /// ([`ResolveError::CaseFoldRuleChange`]).
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
/// [`exclusive_subtree`](crate::RuleRouterBuilder::exclusive_subtree) registration for opaque
/// keys, a configuration declaration to review, …). Use [`Display`](std::fmt::Display)
/// for an attributed log line; use [`message`](Self::message) for the short static
/// string suitable for the denial response body (it deliberately does not vary with
/// the attribution).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResolveError {
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
    /// (`subtree`/`exclusive_subtree`) so its uniformity is visible; a NUL has no remedy
    /// by design. The full triage procedure is
    /// [Handling a denial](crate::_docs::guide::handling_denials).
    Structural(StructuralClass),
    /// The precise case-fold check: lowercasing the path relocates it to a
    /// *different* rule than the raw path matched (backend declared
    /// [`CaseSensitivity::Insensitive`]). Not an over-approximation — a fold that
    /// stays within its own rule passes this check; other checks may still deny it.
    CaseFoldRuleChange,
    /// The precise content-decode check: one of the possible completely decoded
    /// forms (one pass, plus two under [`DecodeDepth::UpToTwo`], lowercased under
    /// a case-folding backend) relocates the path to a *different* rule. Not an
    /// over-approximation — same-rule decodes pass this comparison, but structural
    /// analysis, length limits, and custom probes may still deny them.
    DecodeRuleChange,
    /// The strict [`RequireCanonical`](GuardMode::RequireCanonical) mode's
    /// presence deny: a structural form of this class, anywhere in the path.
    NonCanonical(StructuralClass),
    /// The strict mode's escape rule: the path carries a complete `%XX` escape.
    NonCanonicalEscape,
    /// A registered [`StructuralProbe`] matched; carries the probe's
    /// [`name`](StructuralProbe::name).
    Probe(&'static str),
    /// A path requiring structural, decode, case-fold, or custom-probe checks
    /// exceeds 8,192 bytes. In [`RejectAmbiguous`](GuardMode::RejectAmbiguous), any
    /// `%` triggers the cap, even if malformed. In strict mode, complete escapes
    /// and recognized non-canonical forms trigger it. Paths requiring no checks
    /// bypass this cap; the caller must enforce an overall request-size limit.
    TooLong,
}

impl ResolveError {
    /// The short, static denial message for the HTTP response body. Deliberately
    /// coarse — it reports a broad error category without rule IDs or structural
    /// class details. Acceptance and denial can still reveal routing behavior; put
    /// [`Display`](std::fmt::Display) in the *log* for the detailed attribution.
    #[must_use]
    pub fn message(&self) -> &'static str {
        match self {
            Self::InvalidRuleId => "Internal routing error",
            Self::InvalidPathInput => "Invalid request path",
            Self::Structural(_)
            | Self::CaseFoldRuleChange
            | Self::DecodeRuleChange
            | Self::Probe(_) => "Ambiguous request path",
            Self::NonCanonical(_) | Self::NonCanonicalEscape => "Non-canonical request path",
            Self::TooLong => "Request path too long",
        }
    }
}

impl std::error::Error for ResolveError {}

impl std::fmt::Display for ResolveError {
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
            Self::CaseFoldRuleChange => {
                f.write_str("ambiguous request path: case-folding relocates it to a different rule")
            }
            Self::DecodeRuleChange => f.write_str(
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
/// is consulted in active guard modes if earlier checks have not already denied
/// the request: return `true` and the request is denied.
///
/// # Contract
///
/// Probes inspect the **original request path**, not decoded interpretations.
/// A detector for a decoded character must also account for its percent-encoded
/// spellings. For a conservative literal-ASCII restriction, see the example in
/// [Supported path interpretations](crate::_docs::reference::coverage).
///
/// `matches` must be **pure, deterministic, and ~O(n)**. Checks short-circuit on
/// denial, and `Disabled` skips probes; do not rely on a probe being called for
/// logging or other side effects.
/// The check is **whole-path**: presence *anywhere* denies, even inside an opaque
/// `exclusive_subtree` tail that tolerates the built-in separator-like forms. That is the
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
/// # use huskarl_route_guard::config::{StructuralClasses, StructuralChar};
/// // A Windows/IIS-style backend that also decodes overlong UTF-8.
/// let classes = StructuralClasses::new()
///     .with_backslash()
///     .with_overlong([StructuralChar::Slash, StructuralChar::Dot]);
/// ```
///
/// Each toggle is a per-deployment **security** decision: enabling a class makes the
/// guard treat that form as route structure (so it checks wherever a wildcard or
/// catch-all matched it); leaving it off assumes the backend does not. Two declarations are **not**
/// here, deliberately: case ([`CaseSensitivity`]) and decode depth ([`DecodeDepth`])
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
    /// [`with_probe`](Self::with_probe) — e.g. one that rejects both non-ASCII
    /// characters and percent escapes, as shown in the
    /// [coverage reference](crate::_docs::reference::coverage).
    #[must_use]
    pub fn with_fullwidth_structure(mut self) -> Self {
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
        assert!(StructuralClasses::new().with_fullwidth_structure().unicode);

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
        let d = ResolveError::Structural(StructuralClass::Separator);
        assert_eq!(d.message(), "Ambiguous request path");
        assert!(d.to_string().contains("separator"));
        assert_eq!(
            ResolveError::CaseFoldRuleChange.message(),
            "Ambiguous request path"
        );
        assert_eq!(
            ResolveError::DecodeRuleChange.message(),
            "Ambiguous request path"
        );
        assert_eq!(ResolveError::Probe("p").message(), "Ambiguous request path");
        assert_eq!(
            ResolveError::NonCanonical(StructuralClass::DotSegment).message(),
            "Non-canonical request path"
        );
        assert_eq!(
            ResolveError::NonCanonicalEscape.message(),
            "Non-canonical request path"
        );
        assert_eq!(ResolveError::TooLong.message(), "Request path too long");
        assert_eq!(
            ResolveError::InvalidPathInput.message(),
            "Invalid request path"
        );
        // The probe's name reaches the log line.
        assert!(
            ResolveError::Probe("reject-non-ascii")
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
