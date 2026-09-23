//! Path-confusion checks over the route tree's coverage summaries.

use std::{cell::LazyCell, sync::Arc};

use crate::{
    config::{GuardConfig, GuardMode, ResolveError, StructuralProbe},
    route_tree::{Cover, DEFAULT_RULE, Router, RuleId},
    structural::{
        ClassSet, Encodings, ScanResult, classes_present, enabled_classes, enabled_encodings,
        primary_class, scan,
    },
};

/// Length cap for a *suspicious* path: once a structural byte is flagged, a path over
/// this length is denied. Clean paths bypass it (they cannot be ambiguous). Defense in
/// depth — Pingora bounds the request line well below this.
const MAX_PATH_LEN: usize = 8192;

/// The runtime path-confusion verdict, driven by the owned [`Router`].
///
/// This is the liveness runtime built on the **scoped-denial** model. Every modeled
/// boundary-shift transform (`%2F` decode, `//` merge, `;` strip, `\`-as-separator,
/// and the enabled alternate encodings) rewrites the path only *at or after* the byte
/// that triggers it, so the paths a backend could reinterpret a request into all
/// extend the **stable prefix** — the path up to the last clean separator before the
/// earliest structural occurrence. A boundary-shift byte therefore denies only when
/// the route table makes some *other* rule reachable past that anchor
/// ([`Router::anchor_cover`] ≠ uniformly the matched rule, counting fall-through to
/// the default rule). Dot-segments climb — each `..`-capable segment pops at most one
/// level — so they raise the anchor toward the root before the same check; NUL
/// truncation denies unconditionally (its legitimate-use rate is ~nil). Because
/// registered patterns are canonical, any structural byte in a matched path
/// necessarily falls in a capture — the build-time canonicality check in
/// `path_router` is load-bearing for that.
///
/// Three checks compose under the default mode — the positional verdict above, then
/// the precise case-fold and content-decode verdicts (apply the declared transform,
/// re-route, deny only a rule change), then any break-glass probes. The full decision
/// story, including why positional over-approximates (it treats every path extending
/// the anchor as reachable, not just actual transform images) while the fold/decode
/// checks are exact, is [`crate::_docs::explanation::decision`].
pub(crate) struct PathConfusionGuard {
    router: Router,
    mode: GuardMode,
    /// Byte classes that deny, derived from the configured classes plus (when the backend
    /// folds case) [`ClassSet::CASE`].
    enabled: ClassSet,
    /// Which alternate encodings the scanner recognises.
    enc: Encodings,
    /// Whether the backend folds ASCII case (drives the content-decode lowercasing).
    case_insensitive: bool,
    /// Custom break-glass probes — a structural form the built-in alphabet doesn't ship,
    /// denied on whole-path presence.
    probes: Vec<Arc<dyn StructuralProbe>>,
}

impl PathConfusionGuard {
    pub(crate) fn structural_explanation(
        &self,
        path: &str,
        method: &http::Method,
    ) -> Option<crate::StructuralExplanation> {
        let anchor = self.structural_anchor(path)?;
        let mut registrations = self.router.anchor_identities(anchor, method);
        let includes_default = registrations.last() == Some(&DEFAULT_RULE);
        if includes_default {
            registrations.pop();
        }
        Some(crate::StructuralExplanation {
            anchor: anchor.to_owned(),
            registrations,
            includes_default,
        })
    }

    pub(crate) fn method_gap(&self, path: &str, method: &http::Method) -> Option<RuleId> {
        self.router.method_gap(path, method)
    }

    /// Build a guard over `router` for the given mode and structural configuration.
    pub(crate) fn new(router: Router, config: GuardConfig) -> Self {
        let GuardConfig {
            mode,
            structural_classes: classes,
            decode_depth: layers,
            case_sensitivity: case,
        } = config;
        let mut enabled = enabled_classes(&classes);
        if case.is_insensitive() {
            enabled.insert(ClassSet::CASE);
        }
        Self {
            router,
            mode,
            enabled,
            enc: enabled_encodings(&classes, layers),
            case_insensitive: case.is_insensitive(),
            probes: classes.probes,
        }
    }

    /// Check interpretations and return the raw identity they agree with. Matching
    /// is lazy so unconditional denials do not need to traverse the route tree.
    pub(crate) fn checked(
        &self,
        path: &str,
        method: &http::Method,
    ) -> Result<Option<RuleId>, ResolveError> {
        let raw = LazyCell::new(|| self.router.resolve(path, method));
        let raw_rule = || *raw;
        let denial = match self.mode {
            GuardMode::Disabled => None,
            GuardMode::RejectAmbiguous => self
                .positional_deny(path, method, &raw_rule)
                .or_else(|| self.case_fold_deny(path, method, &raw_rule))
                .or_else(|| self.content_decode_deny(path, method, &raw_rule))
                .or_else(|| self.custom_probe_deny(path)),
            // Strict: every position live (opaque ignored) and any percent-escape is
            // itself non-canonical.
            GuardMode::RequireCanonical => self
                .noncanonical_deny(path)
                .or_else(|| escape_present(path).then_some(ResolveError::NonCanonicalEscape))
                .or_else(|| self.custom_probe_deny(path)),
        };
        match denial {
            Some(reason) => Err(reason),
            None => Ok(*raw),
        }
    }

    /// Break-glass verdict: deny if any registered custom probe recognises its form
    /// anywhere in `path`, attributing the probe by name. A no-op (one `is_empty`)
    /// when no probe is registered.
    fn custom_probe_deny(&self, path: &str) -> Option<ResolveError> {
        let probe = self.probes.iter().find(|p| p.matches(path))?;
        if path.len() > MAX_PATH_LEN {
            Some(ResolveError::TooLong)
        } else {
            Some(ResolveError::Probe(probe.name()))
        }
    }

    /// Whether `path` must be denied for GET. Test-only convenience for method-agnostic
    /// route tables; production calls `checked` with the request's actual method.
    #[cfg(test)]
    pub(crate) fn ambiguous(&self, path: &str) -> bool {
        self.checked(path, &http::Method::GET).is_err()
    }

    /// The method-resolved rule id — for the router's unchecked match operation.
    pub(crate) fn resolve(&self, path: &str, method: &http::Method) -> Option<RuleId> {
        self.router.resolve(path, method)
    }

    /// Positional verdict for [`GuardMode::RejectAmbiguous`] — the **scoped
    /// denial**. A clean path (no enabled structural byte) is the fast path and never
    /// walks the tree; a flagged path is denied unless every rule reachable past its
    /// anchor is the very rule it matched (see [`Router::anchor_cover`]).
    ///
    /// The anchor: boundary-shift bytes cannot rewrite anything before the last clean
    /// separator preceding the earliest structural occurrence, so that stable prefix
    /// bounds their reach. Dot-segments raise the anchor one level per capable
    /// segment, stopping at the root. A table that routes uniformly even at the
    /// root cannot be traversed between rules. NUL truncation keeps its
    /// unconditional deny: it has essentially no legitimate use, so the scoping win
    /// is not worth modeling.
    ///
    /// [`ClassSet::CASE`] is masked out here: case folding is handled by the precise
    /// [`case_fold_deny`](Self::case_fold_deny) instead, so an uppercase byte alone
    /// never denies positionally (only an actual fold relocation does).
    fn positional_deny(
        &self,
        path: &str,
        method: &http::Method,
        raw_rule: &impl Fn() -> Option<RuleId>,
    ) -> Option<ResolveError> {
        let enabled = self.enabled.without(ClassSet::CASE);
        let scan = scan(path, enabled, self.enc);
        let present = scan.classes.intersect(enabled);
        if present.is_empty() {
            return None;
        }
        if path.len() > MAX_PATH_LEN {
            return Some(ResolveError::TooLong);
        }
        if present.contains_any(ClassSet::TRUNCATION) {
            return Some(ResolveError::Structural(primary_class(present)));
        }
        // `present` non-empty guarantees an offset (a fuzzed ScanResult invariant);
        // fail closed rather than panic if it ever doesn't.
        let Some(offset) = scan.earliest else {
            return Some(ResolveError::Structural(primary_class(present)));
        };
        let anchor = self.anchor_for(path, &scan, offset);
        let matched = raw_rule().unwrap_or(DEFAULT_RULE);
        if self.router.anchor_cover(anchor, method) == Cover::Uniform(matched) {
            None
        } else {
            Some(ResolveError::Structural(primary_class(present)))
        }
    }

    /// The **anchor** for a flagged `path`: the prefix the reachable-set argument
    /// treats as invariant under every modeled transform, so that whatever a backend
    /// does to this path, the result still starts here.
    ///
    /// That invariance is the load-bearing premise of the whole positional verdict —
    /// it is why bounding `anchor_cover` bounds the relocation. It holds because:
    ///
    /// - Boundary-shift and climb transforms act at or after their own (enabled)
    ///   occurrence, which `offset` bounds.
    /// - A *content* transform rewrites bytes with no structural class — a
    ///   percent-escape decodes (`%61`→`a`, possibly to bytes that are not valid UTF-8,
    ///   which [`content_decode_deny`](Self::content_decode_deny) routes as bytes rather
    ///   than declining) and an uppercase
    ///   byte folds under a declared case-folding backend — so the anchor is cut
    ///   before the first such byte too. Everything ahead of it is a literal,
    ///   canonical byte no modeled backend rewrites, so every reinterpretation extends
    ///   the anchor and `anchor_cover` bounds it. Bounding by the config-independent
    ///   `%` position is also what keeps the verdict monotone in the configuration: an
    ///   enabled encoding moving `offset` earlier can only raise the anchor further,
    ///   never uncover a laxer one (the `l2_monotone` law).
    /// - Dot-segments climb, so each `..`-capable segment pops one level of the stable
    ///   prefix and `k` of them raise the anchor `k` segments toward the root (see
    ///   [`ScanResult::dot_pops`]; overcounting only denies more).
    ///
    /// A premise, not a theorem: it is a property of the *current* transform set, and
    /// a class that rewrote **before** its own trigger would break it silently. So it
    /// is also asserted directly, against the executable backend model — see
    /// `path_confusion_proptest`'s anchor-invariance property, which reaches this
    /// function through `structural_anchor` (test-only).
    fn anchor_for<'p>(&self, path: &'p str, scan: &ScanResult, offset: usize) -> &'p str {
        let bound = first_content_byte(path, self.case_insensitive)
            .map_or(offset, |content| offset.min(content));
        raise(stable_prefix(path, bound), scan.dot_pops)
    }

    /// The anchor [`positional_deny`](Self::positional_deny) would reason over for
    /// `path`, or `None` where it never reaches the anchor check — a clean path, an
    /// over-length one, or an unconditional truncation deny. Diagnostic window onto
    /// [`anchor_for`](Self::anchor_for), so the premise above can be asserted against
    /// the reference backend rather than trusted.
    ///
    /// The early-return conditions are mirrored from `positional_deny` (the anchor
    /// *computation* is shared, so only the reachability guard is restated); a mirror
    /// that drifted would make this return `Some` where production denies outright,
    /// which costs a stricter test, never a weaker one.
    pub(crate) fn structural_anchor<'p>(&self, path: &'p str) -> Option<&'p str> {
        let enabled = self.enabled.without(ClassSet::CASE);
        let scan = scan(path, enabled, self.enc);
        let present = scan.classes.intersect(enabled);
        if present.is_empty()
            || path.len() > MAX_PATH_LEN
            || present.contains_any(ClassSet::TRUNCATION)
        {
            return None;
        }
        Some(self.anchor_for(path, &scan, scan.earliest?))
    }

    /// Case-fold verdict: model a case-folding backend (declared via
    /// [`CaseSensitivity::Insensitive`]) and deny iff lowercasing the path **relocates**
    /// it to a different rule than the raw path matched. Precise, like the
    /// content-decode check — `/files/ReadMe.TXT` folds within its own rule and keeps
    /// flowing; `/ADMIN` folding onto a distinct `/admin` rule is denied.
    ///
    /// Sound on two build-time invariants: patterns are all-lowercase under
    /// `Insensitive` (uppercase is a build error), so the folded path re-routes through
    /// the very table the backend resolves against; and folding composed with
    /// percent-decoding is covered by [`content_decode_deny`](Self::content_decode_deny),
    /// which folds the decoded path before re-routing. Only ASCII case is modeled,
    /// mirroring [`CaseSensitivity`].
    fn case_fold_deny(
        &self,
        path: &str,
        method: &http::Method,
        raw_rule: &impl Fn() -> Option<RuleId>,
    ) -> Option<ResolveError> {
        if !self.case_insensitive || !path.bytes().any(|b| b.is_ascii_uppercase()) {
            return None;
        }
        if path.len() > MAX_PATH_LEN {
            return Some(ResolveError::TooLong);
        }
        let folded = path.to_ascii_lowercase();
        (self.router.resolve(&folded, method) != raw_rule())
            .then_some(ResolveError::CaseFoldRuleChange)
    }

    /// Positional verdict for [`GuardMode::RequireCanonical`]: every position live,
    /// opaque declarations ignored, so any enabled structural byte denies.
    fn noncanonical_deny(&self, path: &str) -> Option<ResolveError> {
        let present = classes_present(path, self.enabled, self.enc).intersect(self.enabled);
        if present.is_empty() {
            return None;
        }
        if path.len() > MAX_PATH_LEN {
            return Some(ResolveError::TooLong);
        }
        Some(ResolveError::NonCanonical(primary_class(present)))
    }

    /// Content-decode verdict: model every possible complete-path result — one decode
    /// pass, plus two under [`DecodeDepth::UpToTwo`] — and deny if any possible result
    /// **relocates** the path to a different rule than the raw path matched. Precise —
    /// results that all land on the same rule (`/foo%20bar`) are allowed, so opaque
    /// content flows.
    fn content_decode_deny(
        &self,
        path: &str,
        method: &http::Method,
        raw_rule: &impl Fn() -> Option<RuleId>,
    ) -> Option<ResolveError> {
        if !path.contains('%') {
            return None;
        }
        if path.len() > MAX_PATH_LEN {
            return Some(ResolveError::TooLong);
        }
        let passes = if self.enc.double_decode { 2 } else { 1 };
        let raw = path.as_bytes();
        let raw_rule = raw_rule();
        let mut decoded = raw.to_vec();
        for _ in 0..passes {
            decoded = percent_decode_once(&decoded);
            let decoded_rule = if self.case_insensitive {
                let mut folded = decoded.clone();
                folded.make_ascii_lowercase();
                self.router.resolve_bytes(&folded, method)
            } else {
                self.router.resolve_bytes(&decoded, method)
            };
            if decoded_rule != raw_rule {
                return Some(ResolveError::DecodeRuleChange);
            }
        }
        None
    }
}

/// Offset of the first byte a modeled **content** transform could rewrite: any `%`
/// (a percent-escape — counted even when malformed, since a lenient decoder may
/// still consume it) and, under a case-folding backend, any ASCII uppercase.
/// `None` when the path carries neither. Bounds the positional verdict's anchor
/// alongside the earliest enabled structural occurrence.
fn first_content_byte(path: &str, case_insensitive: bool) -> Option<usize> {
    path.bytes()
        .position(|b| b == b'%' || (case_insensitive && b.is_ascii_uppercase()))
}

/// The clean prefix of `path` up to and **including** the last `/` strictly before
/// `offset` — everything a boundary-shift transform triggered at `offset` or later
/// provably cannot rewrite. `"/"` when no such separator exists (the occurrence sits
/// in the first segment, or the path is degenerate).
///
/// `offset` always lands on a char boundary (it is the first byte of a scanner
/// occurrence or an ASCII content byte), but the lookup stays `get`-based so a bad
/// offset degrades to the root anchor — the fail-closed direction — instead of
/// panicking.
fn stable_prefix(path: &str, offset: usize) -> &str {
    path.get(..offset)
        .and_then(|p| p.rfind('/'))
        .and_then(|i| path.get(..=i))
        .unwrap_or("/")
}

/// Raise a `/`-terminated anchor prefix by `k` segments — the dot-segment climb
/// radius. Each pop drops the last segment (`"/a/b/"` → `"/a/"`); the root absorbs
/// any excess (`..` cannot climb above `/`). Pure slicing, allocation-free.
fn raise(prefix: &str, k: usize) -> &str {
    let mut p = prefix;
    for _ in 0..k {
        if p == "/" {
            break;
        }
        // Drop the trailing `/`, then cut after the previous one.
        p = p
            .get(..p.len() - 1)
            .and_then(|q| q.rfind('/').and_then(|i| q.get(..=i)))
            .unwrap_or("/");
    }
    p
}

/// Whether `path` carries any complete `%XX` escape — the [`GuardMode::RequireCanonical`]
/// "any escape is non-canonical" rule.
fn escape_present(path: &str) -> bool {
    let b = path.as_bytes();
    (0..b.len()).any(|i| crate::percent::byte_at(b, i).is_some())
}

/// Percent-decode every complete `%XX` escape once (one pass: `%252F` → `%2F`).
///
/// Yields raw **bytes**, and is total. Decoding can produce sequences that are not valid
/// UTF-8 (`%FF`, a lone surrogate, a truncated multi-byte form); a backend decodes to
/// bytes and routes on bytes regardless, so refusing to model those inputs would leave
/// the relocation check unevaluated on exactly the paths an attacker controls.
fn percent_decode_once(path: &[u8]) -> Vec<u8> {
    if !path.contains(&b'%') {
        return path.to_vec();
    }
    let mut out = Vec::with_capacity(path.len());
    let mut i = 0;
    while i < path.len() {
        let Some(&cur) = path.get(i) else { break };
        if let Some(byte) = crate::percent::byte_at(path, i) {
            out.push(byte);
            i += 3;
        } else {
            out.push(cur);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::cast_possible_truncation,
        clippy::needless_pass_by_value,
        clippy::struct_excessive_bools
    )]
    // ── liveness runtime ──────────────────────────────────────────────────────

    use super::*;
    use crate::{
        config::{CaseSensitivity, DecodeDepth, StructuralClasses},
        route_tree::{BuildError, MethodMatch, parse_pattern},
    };

    fn guard(
        rows: &[(&str, RuleId, bool)],
        mode: GuardMode,
        classes: StructuralClasses,
        case: CaseSensitivity,
    ) -> PathConfusionGuard {
        guard_layers(rows, mode, classes, DecodeDepth::UpToOne, case)
    }

    fn guard_layers(
        rows: &[(&str, RuleId, bool)],
        mode: GuardMode,
        classes: StructuralClasses,
        layers: DecodeDepth,
        case: CaseSensitivity,
    ) -> PathConfusionGuard {
        let entries: Vec<_> = rows
            .iter()
            .map(|(p, id, op)| (parse_pattern(p).expect("parse"), *id, *op, MethodMatch::Any))
            .collect();
        PathConfusionGuard::new(
            Router::build(&entries).expect("build"),
            GuardConfig {
                mode,
                structural_classes: classes,
                decode_depth: layers,
                case_sensitivity: case,
            },
        )
    }

    /// L1: a path with no enabled structural byte is never denied.
    #[test]
    fn clean_paths_allowed() {
        let g = guard(
            &[("/admin/*", 0, false), ("/users/*", 1, false)],
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(!g.ambiguous("/admin/users"));
        assert!(!g.ambiguous("/users/42"));
        assert!(!g.ambiguous("/nope/clean"));
    }

    /// The scoped relaxation: a **fully-registered, uniformly-ruled** subtree tolerates
    /// boundary-shift bytes beneath it (no other rule is reachable past the anchor),
    /// while dot-segments still anchor wide and deny against this multi-rule table.
    /// No opaque declaration needed — uniformity is derived from the table.
    #[test]
    fn uniform_subtree_allows_separator_denies_dotdot() {
        let g = guard(
            &[
                ("/files", 0, false),
                ("/files/", 0, false),
                ("/files/*", 0, false),
            ],
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(
            !g.ambiguous("/files/a%2fb"),
            "encoded slash in a uniform subtree"
        );
        assert!(
            !g.ambiguous("/files/a;b"),
            "matrix param in a uniform subtree"
        );
        // Dot-segments anchor `k` levels wider (one per `..`-capable segment): a climb
        // that provably resolves *within* the subtree flows, one that can reach the
        // root — where this table is not uniform — denies.
        assert!(
            !g.ambiguous("/files/a/../b"),
            "one `..` under /files/a/ climbs at most to /files/"
        );
        assert!(
            !g.ambiguous("/files/a/%2e%2e/b"),
            "encoded form of the same in-subtree climb"
        );
        assert!(
            g.ambiguous("/files/../b"),
            "one `..` under /files/ can climb out"
        );
        assert!(
            g.ambiguous("/files/%2e%2e/b"),
            "encoded climb out of the subtree"
        );
        assert!(
            g.ambiguous("/files/a/../../b"),
            "two `..` under /files/a/ can climb out"
        );
        // The relaxation is anchored: the same separator byte in the *first* segment
        // has the root as its anchor, where the table is not uniform.
        assert!(g.ambiguous("/fi%2fles/a"), "separator before the subtree");
    }

    /// A lone catch-all pattern is **not** a uniform subtree: without its `/files/`
    /// (and `/files`) companions, the empty remainder — reachable via a `;`-strip —
    /// falls to the default rule, so boundary-shift bytes keep denying. Register the
    /// full subtree (`subtree`/`exclusive_subtree` do) to get the relaxation.
    #[test]
    fn lone_catchall_is_not_uniform() {
        let g = guard(
            &[("/files/*", 0, true)],
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(g.ambiguous("/files/a%2fb"), "gap to the default rule");
        assert!(!g.ambiguous("/files/clean"), "clean paths still flow");
    }

    /// An *encoded* matrix param that reveals a dot-segment (`..%3bx` — a `;`-stripping
    /// servlet backend climbs out of the blob) is denied just like the literal `..;x`.
    /// The blob tolerates a `;` as a boundary-shift byte, but never the traversal it hides.
    #[test]
    fn opaque_blob_denies_encoded_param_traversal() {
        let g = guard(
            &[
                ("/files", 0, false),
                ("/files/", 0, false),
                ("/files/*", 0, true),
            ],
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        // A plain matrix param on a real segment stays tolerated.
        assert!(
            !g.ambiguous("/files/a;b/c"),
            "matrix param on a real key segment"
        );
        // The literal Tomcat `..;` vector is denied even in the blob.
        assert!(g.ambiguous("/files/..;x/secret"), "literal `..;x`");
        // The encoded equivalents must be denied too — the bug this closes.
        assert!(g.ambiguous("/files/..%3bx/secret"), "encoded `..%3bx`");
        assert!(g.ambiguous("/files/..%3Bx/secret"), "encoded `..%3Bx`");
    }

    /// Incomplete coverage denies everywhere: a lone `/files/*/*` leaves gaps (the
    /// one-segment and empty remainders fall to the default rule), so no anchor under
    /// it is uniform — boundary-shift bytes deny in the tail and in the preceding
    /// wildcard alike. (Under the old span model the tail was tolerated; the scoped
    /// model is stricter exactly because a `;`-strip could shorten the tail into the
    /// default rule.)
    #[test]
    fn incomplete_coverage_denies_boundary_shift_everywhere() {
        let g = guard(
            &[("/files/*/*", 0, true)],
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(g.ambiguous("/files/ab/c%2fd"), "%2f in the catch-all tail");
        assert!(
            g.ambiguous("/files/a%2fb/c"),
            "%2f in the preceding wildcard"
        );
        assert!(!g.ambiguous("/files/ab/cd"), "clean paths still flow");
    }

    /// Unrouted URL space is uniformly the default rule: a structural byte there
    /// cannot relocate between rules, so it flows. (Deliberate behavior change from
    /// the uniform-live model; the default rule governs those paths either way.)
    #[test]
    fn unrouted_space_tolerates_structural_bytes() {
        let g = guard(
            &[
                ("/admin", 0, false),
                ("/admin/", 0, false),
                ("/admin/*", 0, false),
            ],
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(
            !g.ambiguous("/public/a%2fb"),
            "everything under /public/ is the default rule"
        );
        // At the root the table is not uniform (admin vs default), so a first-segment
        // separator still denies…
        assert!(g.ambiguous("/pub%2flic/a"), "root anchor is mixed");
        // …as does a dot-segment (root-anchored), and NUL everywhere.
        assert!(g.ambiguous("/public/../x"), "dot-segment anchors at root");
        assert!(g.ambiguous("/public/a%00b"), "NUL denies unconditionally");
    }

    /// The `//`-merge root regression: `/` (root leaf) and `/{*rest}` carry different
    /// rules, and slash-merging `//` → `/` relocates between them — the root anchor
    /// must count the bare leaf. With one shared rule the same path flows.
    #[test]
    fn root_leaf_merge_relocation_denied() {
        let split = guard(
            &[("/", 1, false), ("/*", 0, false)],
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(
            split.ambiguous("//"),
            "merge relocates catch-all → root leaf"
        );
        let uniform = guard(
            &[("/", 0, false), ("/*", 0, false)],
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(!uniform.ambiguous("//"), "one-rule table cannot relocate");
    }

    /// A method-qualified route inside an otherwise-uniform subtree resolves other
    /// methods to the default rule at that path. Its new identity for POST and its
    /// default-rule gap for GET both keep the surrounding region mixed.
    #[test]
    fn method_only_route_keeps_subtree_denying() {
        let entries = vec![
            (
                parse_pattern("/files").expect("p"),
                0,
                false,
                MethodMatch::Any,
            ),
            (
                parse_pattern("/files/").expect("p"),
                0,
                false,
                MethodMatch::Any,
            ),
            (
                parse_pattern("/files/*").expect("p"),
                0,
                false,
                MethodMatch::Any,
            ),
            (
                parse_pattern("/files/upload").expect("p"),
                1,
                false,
                MethodMatch::from(http::Method::POST),
            ),
        ];
        let g = PathConfusionGuard::new(
            Router::build(&entries).expect("build"),
            GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne),
        );
        assert!(
            g.ambiguous("/files/a%2fb"),
            "method-split terminal keeps the subtree mixed"
        );
    }

    /// Strict mode ignores opaque declarations and treats any escape as non-canonical.
    #[test]
    fn noncanonical_ignores_opaque_and_denies_escapes() {
        let g = guard(
            &[("/files/*", 0, true)],
            GuardMode::RequireCanonical,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(g.ambiguous("/files/a%2fb"), "opaque ignored when strict");
        assert!(g.ambiguous("/files/a%20b"), "any escape is non-canonical");
        assert!(!g.ambiguous("/files/ab"), "clean path still allowed");
    }

    /// Case is structural only under a case-folding backend.
    #[test]
    fn case_sensitivity_gates_uppercase() {
        let rows = &[("/admin", 0, false)];
        let sensitive = guard(
            rows,
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(
            !sensitive.ambiguous("/Admin"),
            "case ignored when sensitive"
        );

        let insensitive = guard(
            rows,
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            CaseSensitivity::Insensitive,
        );
        assert!(insensitive.ambiguous("/Admin"), "/Admin folds onto /admin");
        assert!(
            !insensitive.ambiguous("/admin"),
            "lowercase clean path allowed"
        );
    }

    /// The case-fold check is **precise** (fold-and-reroute, like content-decode), not a
    /// presence deny: uppercase that folds *within its own rule* is allowed; uppercase
    /// that folds onto a *different* rule is denied.
    #[test]
    fn case_fold_is_precise_not_presence() {
        let g = guard(
            &[
                ("/files", 0, false),
                ("/files/", 0, false),
                ("/files/*", 0, false),
                ("/users/*", 1, false),
                ("/users/admin", 2, false),
            ],
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            CaseSensitivity::Insensitive,
        );
        // Same-rule folds keep flowing: the capital sits in a capture and the folded
        // path lands on the same rule.
        assert!(
            !g.ambiguous("/files/ReadMe.TXT"),
            "mixed-case content within one rule"
        );
        assert!(
            !g.ambiguous("/users/Alice"),
            "folds to /users/alice — same catch-all rule"
        );
        // Cross-rule folds deny: the folded path reaches a rule the raw path missed.
        assert!(
            g.ambiguous("/users/ADMIN"),
            "folds onto the /users/admin literal — a different rule"
        );
        assert!(
            g.ambiguous("/Files/x"),
            "folds onto the /files subtree from the default rule"
        );
        // Strict mode stays blunt: any uppercase is non-canonical there.
        let strict = guard(
            &[("/files/*", 0, false)],
            GuardMode::RequireCanonical,
            StructuralClasses::new(),
            CaseSensitivity::Insensitive,
        );
        assert!(
            strict.ambiguous("/files/ReadMe.TXT"),
            "strict denies on presence"
        );
    }

    /// A mixed-case key inside an opaque blob folds within the blob's own rule and is
    /// allowed; folding can never *escape* the blob (a differently-cased prefix that
    /// folds onto the blob is still denied — it relocates from the default rule).
    #[test]
    fn opaque_blob_allows_mixed_case_keys() {
        let g = guard(
            &[
                ("/files", 0, false),
                ("/files/", 0, false),
                ("/files/*", 0, true),
            ],
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            CaseSensitivity::Insensitive,
        );
        assert!(!g.ambiguous("/files/Key%2FPart"), "mixed-case opaque key");
        assert!(
            g.ambiguous("/FILES/x"),
            "folding prefix relocates into the blob"
        );
        assert!(
            g.ambiguous("/files/A/../b"),
            "dot-segment still denied in the blob"
        );
    }

    /// Regression (found by the `guard_relocation` fuzz target): under a NUL-truncating
    /// backend, a *raw* NUL must be denied — `/a\0junk` matched the default rule and was
    /// allowed, while the backend truncates it to `/a` (a different rule). Raw and encoded
    /// NUL are treated alike, mirroring raw vs encoded `;`/`\` — and the class is
    /// **always-on** (NUL has no legitimate use in a path, so denying it by default
    /// costs nothing while an undeclared C-string backend is a silent bypass).
    #[test]
    fn raw_nul_truncation_denied_by_default() {
        let g = guard(
            &[("/a", 0, false), ("/a/", 0, false), ("/a/*", 0, false)],
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(g.ambiguous("/a\u{0}b"), "raw NUL truncates to /a");
        assert!(g.ambiguous("/a%00b"), "encoded NUL truncates to /a");
        assert!(!g.ambiguous("/a"), "clean path allowed");
        // Denied even inside an opaque blob — truncation, like a dot-segment,
        // escapes any span.
        let blob = guard(
            &[("/files/*", 0, true)],
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(blob.ambiguous("/files/a%00b"), "NUL denied in a blob key");
    }

    /// Up-to-two decode is a required declaration, not a class toggle: under
    /// [`DecodeDepth::UpToTwo`] the double-encoded traversal that slips a single-pass
    /// front (the CVE-2025-0108 shape) is denied; under `UpToOne` a `%252e` reaches the
    /// lone backend as the literal `%2e` and is not structure.
    #[test]
    fn decode_layers_gates_double_encoding() {
        let rows: &[(&str, RuleId, bool)] = &[
            ("/public", 0, false),
            ("/public/", 0, false),
            ("/public/*", 0, false),
            ("/admin", 1, false),
        ];
        let up_to_two = guard_layers(
            rows,
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            DecodeDepth::UpToTwo,
            CaseSensitivity::Sensitive,
        );
        assert!(
            up_to_two.ambiguous("/public/%252e%252e/admin"),
            "double-encoded traversal denied under UpToTwo"
        );
        // A double-encoded separator *before* any rule boundary (first segment →
        // root anchor, where /public and /admin diverge) is structure under UpToTwo…
        assert!(
            up_to_two.ambiguous("/pub%252flic/a"),
            "double-encoded separator at a rule boundary denied under UpToTwo"
        );
        // …but inside the uniform /public subtree it cannot relocate: scoped-allowed
        // even under UpToTwo (this is the blob-key case UpToTwo's docs promise).
        assert!(
            !up_to_two.ambiguous("/public/a%252fb"),
            "double-encoded separator inside a uniform subtree stays tolerated"
        );
        let single = guard_layers(
            rows,
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            DecodeDepth::UpToOne,
            CaseSensitivity::Sensitive,
        );
        assert!(
            !single.ambiguous("/pub%252flic/a"),
            "a lone backend sees literal %2f content — not structure"
        );
    }

    /// Content-decode catches a relocation the positional scan cannot see.
    #[test]
    fn content_decode_relocation_denied() {
        let g = guard(
            &[
                ("/admin", 0, false),
                ("/admin/", 0, false),
                ("/admin/*", 0, false),
            ],
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(g.ambiguous("/%61dmin"), "/%61dmin decodes to /admin");
        // Precise: a same-rule decode (opaque content) is allowed.
        assert!(!g.ambiguous("/admin/a%20b"), "encoded space under /admin");
        assert!(!g.ambiguous("/admin/x"), "clean path allowed");
    }

    /// Regression: a decode yielding **invalid UTF-8** must still be routed, not waved
    /// through. Treating it as "undecodable, therefore not a modeled relocation" let a
    /// single trailing `%FF` anywhere in the path suppress the whole content-decode
    /// check: `/%61dmin/x%FF` was authorized under the *default* rule and forwarded raw,
    /// and any backend that decodes to bytes served it inside `/admin`.
    #[test]
    fn content_decode_relocation_survives_invalid_utf8() {
        let g = guard(
            &[
                ("/admin", 0, false),
                ("/admin/", 0, false),
                ("/admin/*", 0, false),
            ],
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        for p in [
            "/%61dmin/x%FF",       // lone continuation byte
            "/%61dmin/x%C0",       // truncated two-byte lead
            "/%61dmin/x%E2%82",    // truncated three-byte sequence
            "/%61dmin/x%ED%A0%80", // encoded surrogate half
        ] {
            assert!(g.ambiguous(p), "{p} decodes into the /admin subtree");
        }
        // Still precise: invalid UTF-8 that does *not* relocate stays allowed, so the fix
        // is byte-routing rather than a blanket deny on undecodable input.
        assert!(
            !g.ambiguous("/admin/caf%E9.txt"),
            "latin-1 content decodes to the same rule"
        );
    }

    /// The other half of the detection-table audit's CASE row: *encoded* uppercase is not a
    /// positional concern (the byte scan flags only raw `A-Z`) — it is the content-decode
    /// check's job under a case-folding backend. `/%41dmin` → `/Admin` → `/admin` relocates.
    #[test]
    fn content_decode_catches_encoded_uppercase() {
        let g = guard(
            &[
                ("/admin", 0, false),
                ("/admin/", 0, false),
                ("/admin/*", 0, false),
            ],
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            CaseSensitivity::Insensitive,
        );
        assert!(
            g.ambiguous("/%41dmin"),
            "/%41dmin → /Admin → /admin under case folding"
        );
        // A case-sensitive backend distinguishes /Admin from /admin, so it is not a relocation.
        let sensitive = guard(
            &[
                ("/admin", 0, false),
                ("/admin/", 0, false),
                ("/admin/*", 0, false),
            ],
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(
            !sensitive.ambiguous("/%41dmin"),
            "/%41dmin → /Admin, a distinct path when case-sensitive"
        );
    }

    /// `Disabled` disables the guard entirely.
    #[test]
    fn off_allows_everything() {
        let g = guard(
            &[("/files/*", 0, false)],
            GuardMode::Disabled,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(!g.ambiguous("/files/a/../b"));
    }

    // ── metamorphic laws ──────────────────────────────────────────────────────
    //
    // The matcher has an oracle (matchit); the liveness verdict has none, so these are
    // invariants the verdict must satisfy for *all* inputs, plus a CVE ground-truth
    // corpus. The generators are constructive (a vocabulary mixing clean segments and
    // structural payloads, biased to hit the route prefixes) — random strings would pass
    // every law vacuously by never being denied.

    use proptest::prelude::*;

    use crate::config::StructuralChar;

    /// A structural configuration, with a monotone `tighten` for the L2 law.
    #[derive(Clone, Debug)]
    struct Cfg {
        mode: GuardMode,
        insensitive: bool,
        backslash: bool,
        up_to_two: bool,
        unicode: bool,
        overlong: bool,
    }

    impl Cfg {
        /// The default-config baseline: positional reject, standard alphabet, sensitive.
        fn structural() -> Self {
            Self {
                mode: GuardMode::RejectAmbiguous,
                insensitive: false,
                backslash: false,
                up_to_two: false,
                unicode: false,
                overlong: false,
            }
        }

        fn classes(&self) -> StructuralClasses {
            let mut c = StructuralClasses::new();
            if self.backslash {
                c = c.with_backslash();
            }
            if self.unicode {
                c = c.with_fullwidth_structure();
            }
            if self.overlong {
                c = c.with_overlong([StructuralChar::Slash, StructuralChar::Dot]);
            }
            c
        }

        fn layers(&self) -> DecodeDepth {
            if self.up_to_two {
                DecodeDepth::UpToTwo
            } else {
                DecodeDepth::UpToOne
            }
        }

        fn case(&self) -> CaseSensitivity {
            if self.insensitive {
                CaseSensitivity::Insensitive
            } else {
                CaseSensitivity::Sensitive
            }
        }
    }

    /// One knob, in its safe (deny-more) direction — the L2 monotonicity steps.
    #[derive(Clone, Copy, Debug)]
    enum Tighten {
        Insensitive,
        Backslash,
        UpToTwo,
        Unicode,
        Overlong,
        NonCanonical,
    }

    impl Tighten {
        fn apply(self, base: &Cfg) -> Cfg {
            let mut c = base.clone();
            match self {
                Tighten::Insensitive => c.insensitive = true,
                Tighten::Backslash => c.backslash = true,
                Tighten::UpToTwo => c.up_to_two = true,
                Tighten::Unicode => c.unicode = true,
                Tighten::Overlong => c.overlong = true,
                Tighten::NonCanonical => c.mode = GuardMode::RequireCanonical,
            }
            c
        }
    }

    /// Segment vocabulary mixing clean names (hitting the tables) with structural
    /// payloads across every class — including opt-in forms that stay inert unless the
    /// matching toggle is on, so config tightening visibly changes the verdict.
    const SEG_VOCAB: &[&str] = &[
        "a", "b", "x", "admin", "users", "files", "edit", "super", "secret", "a%2fb", "..",
        "%2e%2e", "a;b", "..;x", "a%5cb", "a%00b", "a%252fb", "a%c0%afb", "Abc",
    ];

    fn arb_cfg() -> impl Strategy<Value = Cfg> {
        (
            prop_oneof![
                Just(GuardMode::RejectAmbiguous),
                Just(GuardMode::RequireCanonical)
            ],
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(
                |(mode, insensitive, backslash, up_to_two, unicode, overlong)| Cfg {
                    mode,
                    insensitive,
                    backslash,
                    up_to_two,
                    unicode,
                    overlong,
                },
            )
    }

    fn arb_tighten() -> impl Strategy<Value = Tighten> {
        prop_oneof![
            Just(Tighten::Insensitive),
            Just(Tighten::Backslash),
            Just(Tighten::UpToTwo),
            Just(Tighten::Unicode),
            Just(Tighten::Overlong),
            Just(Tighten::NonCanonical),
        ]
    }

    /// A request path of vocab segments — mixes clean and structural, hits the prefixes.
    fn arb_request_path() -> impl Strategy<Value = String> {
        proptest::collection::vec(0..SEG_VOCAB.len(), 1..4).prop_map(|idxs| {
            let segs: Vec<&str> = idxs.iter().map(|&i| SEG_VOCAB[i]).collect();
            format!("/{}", segs.join("/"))
        })
    }

    /// A clean path: lowercase alphanumerics, no escape, no structural byte — clean under
    /// every config, including `Insensitive` and `RequireCanonical`.
    fn arb_clean_path() -> impl Strategy<Value = String> {
        proptest::collection::vec("[a-z][a-z0-9]{0,4}", 1..4)
            .prop_map(|segs| format!("/{}", segs.join("/")))
    }

    /// A path under `/files` carrying a dot-segment in one of its forms — for L4.
    fn arb_dotty_path() -> impl Strategy<Value = String> {
        const DOTS: &[&str] = &[
            "..",
            "%2e%2e",
            "%2E%2e",
            ".%2e",
            "..;x",
            "..%3bx",
            "..%3Bx",
            "a%2f..%2fb",
        ];
        const TAILS: &[&str] = &["", "/x", "/admin"];
        (0..DOTS.len(), 0..TAILS.len()).prop_map(|(d, t)| format!("/files/{}{}", DOTS[d], TAILS[t]))
    }

    const GENERAL: &[(&str, RuleId, bool)] = &[
        ("/admin", 0, false),
        ("/admin/", 0, false),
        ("/admin/*", 0, false),
        ("/admin/super", 1, false),
        ("/users/*", 2, false),
        ("/a/*/edit", 3, false),
    ];

    fn guard_cfg(rows: &[(&str, RuleId, bool)], cfg: &Cfg) -> PathConfusionGuard {
        guard_layers(rows, cfg.mode, cfg.classes(), cfg.layers(), cfg.case())
    }

    fn files_rows(opaque: bool) -> Vec<(&'static str, RuleId, bool)> {
        vec![
            ("/files", 0, false),
            ("/files/", 0, false),
            ("/files/*", 0, opaque),
        ]
    }

    proptest! {
        /// L1: a path with no enabled structural byte is never denied, under any config.
        #[test]
        fn l1_clean_never_denied(cfg in arb_cfg(), path in arb_clean_path()) {
            let g = guard_cfg(GENERAL, &cfg);
            prop_assert!(!g.ambiguous(&path), "clean path denied: {:?}", path);
        }

        /// L2: tightening the config (a class on, case-fold on, or strict mode) only ever
        /// turns allows into denies — every knob's unsafe direction is the same direction.
        #[test]
        fn l2_monotone(cfg in arb_cfg(), step in arb_tighten(), path in arb_request_path()) {
            let base = guard_cfg(GENERAL, &cfg);
            let stricter = guard_cfg(GENERAL, &step.apply(&cfg));
            prop_assert!(
                !base.ambiguous(&path) || stricter.ambiguous(&path),
                "{:?} via {:?} turned a deny into an allow",
                path,
                step
            );
        }

        /// L3: the opaque flag is **runtime-irrelevant** — scoped denial derives the
        /// relaxation from subtree uniformity, which a validated blob has by
        /// construction, so declaring it changes no verdict. (Its value is the
        /// build-time sibling guarantee, pinned by L6.) And the relaxation is
        /// class-bounded: boundary-shift bytes are scoped to their anchor,
        /// dot-segments to their climb radius — but NUL truncation is **never**
        /// relaxed on any allowed path.
        #[test]
        fn l3_opaque_flag_is_runtime_irrelevant(path in arb_request_path()) {
            let cfg = Cfg::structural();
            let normal = guard_cfg(&files_rows(false), &cfg);
            let blob = guard_cfg(&files_rows(true), &cfg);
            prop_assert_eq!(
                normal.ambiguous(&path),
                blob.ambiguous(&path),
                "opaque flag changed a verdict on {:?}", path
            );

            let enabled = enabled_classes(&StructuralClasses::new());
            let enc = enabled_encodings(&StructuralClasses::new(), DecodeDepth::UpToOne);
            let present = classes_present(&path, enabled, enc).intersect(enabled);
            if !normal.ambiguous(&path) {
                prop_assert!(
                    !present.contains_any(ClassSet::TRUNCATION),
                    "truncation was relaxed: {:?} ({:?})", path, present
                );
            }
        }

        /// L4: a dot-segment is denied under RejectAmbiguous regardless of placement —
        /// opaque cannot reopen traversal.
        #[test]
        fn l4_dot_segment_inviolable(path in arb_dotty_path()) {
            let cfg = Cfg::structural();
            prop_assert!(guard_cfg(&files_rows(false), &cfg).ambiguous(&path), "normal: {:?}", path);
            prop_assert!(guard_cfg(&files_rows(true), &cfg).ambiguous(&path), "blob: {:?}", path);
        }

        /// L5: RequireCanonical denies a superset of RejectAmbiguous (same classes).
        #[test]
        fn l5_noncanonical_dominates(cfg in arb_cfg(), path in arb_request_path()) {
            let rs = guard_cfg(GENERAL, &Cfg { mode: GuardMode::RejectAmbiguous, ..cfg.clone() });
            let rn = guard_cfg(GENERAL, &Cfg { mode: GuardMode::RequireCanonical, ..cfg });
            prop_assert!(!rs.ambiguous(&path) || rn.ambiguous(&path), "{:?}", path);
        }

        /// L6: an opaque catch-all with a routing sibling is unconstructable.
        #[test]
        fn l6_opaque_with_sibling_rejected(leaf in "[a-z]{1,4}") {
            let entries = vec![
                (parse_pattern("/p/*").expect("blob"), 0, true, MethodMatch::Any),
                (
                    parse_pattern(&format!("/p/{leaf}")).expect("sibling"),
                    1,
                    false,
                    MethodMatch::Any,
                ),
            ];
            // Explicit message: prop_assert! stringifies its condition into a format
            // string, and the `{ .. }` pattern would break that.
            prop_assert!(
                matches!(Router::build(&entries), Err(BuildError::OpaqueTailHasSibling { .. })),
                "opaque catch-all with a routing sibling must be rejected"
            );
        }
    }

    /// L7: CVE ground truth — known-bad inputs must deny, and declaring the public prefix
    /// an opaque blob must not reopen any of them.
    #[test]
    fn cve_corpus_denied() {
        let classes = StructuralClasses::new();
        // CVE-2019-9901 (Envoy): `/public/../admin` climbs into a protected route.
        let envoy = |opaque| {
            guard(
                &[
                    ("/public", 0, false),
                    ("/public/", 0, false),
                    ("/public/*", 0, opaque),
                    ("/admin", 1, false),
                ],
                GuardMode::RejectAmbiguous,
                classes.clone(),
                CaseSensitivity::Sensitive,
            )
        };
        assert!(envoy(false).ambiguous("/public/../admin"));
        assert!(
            envoy(true).ambiguous("/public/../admin"),
            "opaque blob must not reopen the traversal"
        );

        // CVE-2021-31920 (Istio): `//admin` and `%2f`-escaped slashes bypass policy.
        let istio = guard(
            &[("/admin", 0, false)],
            GuardMode::RejectAmbiguous,
            classes.clone(),
            CaseSensitivity::Sensitive,
        );
        assert!(istio.ambiguous("//admin"));
        assert!(istio.ambiguous("/x%2fadmin"));

        // CVE-2021-41773 (Apache): encoded `%2e%2e` dot-segments escape an alias.
        let apache = guard(
            &[
                ("/cgi-bin", 0, false),
                ("/cgi-bin/", 0, false),
                ("/cgi-bin/*", 0, false),
                ("/secret", 1, false),
            ],
            GuardMode::RejectAmbiguous,
            classes.clone(),
            CaseSensitivity::Sensitive,
        );
        assert!(apache.ambiguous("/cgi-bin/%2e%2e/secret"));

        // CVE-2025-0108 (PAN-OS): nginx decoded `%252e%252e` once and let it past a
        // no-auth prefix; Apache decoded again and traversed. The topology is declared
        // (`DecodeDepth::UpToTwo`), and the double-encoded traversal is denied.
        let panos = guard_layers(
            &[
                ("/unauth", 0, false),
                ("/unauth/", 0, false),
                ("/unauth/*", 0, false),
                ("/php", 1, false),
            ],
            GuardMode::RejectAmbiguous,
            classes,
            DecodeDepth::UpToTwo,
            CaseSensitivity::Sensitive,
        );
        assert!(panos.ambiguous("/unauth/%252e%252e/php"));
        // The single-encoded form is caught by the default quartet regardless.
        assert!(panos.ambiguous("/unauth/%2e%2e/php"));

        // CVE-2026-73511 / GHSA-m745-gh6x-349x (Envoy): Envoy matched the raw `:path`
        // while a servlet backend (Tomcat) strips `;params` **per segment**, so
        // `/auth;x=y/` and `/;x=y/auth/` both reached a `/auth/` route that returned 403
        // for the literal path. Envoy's `ignore_path_parameters_in_path_matching` only
        // truncated at the *first* `;` in the whole path, which is why the second shape —
        // the param in a segment *before* the protected one — survived the option.
        //
        // Here the strip is a relocation *into* the protected rule from the default, and
        // PARAM is in the default quartet, so both shapes deny with no declaration.
        let servlet = |opaque| {
            guard(
                &[
                    ("/auth", 0, false),
                    ("/auth/", 0, false),
                    ("/auth/*", 0, opaque),
                ],
                GuardMode::RejectAmbiguous,
                StructuralClasses::new(),
                CaseSensitivity::Sensitive,
            )
        };
        assert!(servlet(false).ambiguous("/auth;x=y/"));
        assert!(
            servlet(false).ambiguous("/;x=y/auth/"),
            "the param sits in a segment before the protected one — the shape Envoy's \
             first-`;` truncation missed"
        );
        // Every form the byte scan treats as PARAM introduces the strip, so an *encoded*
        // matrix param is denied exactly as the literal one is.
        assert!(servlet(false).ambiguous("/auth%3bx=y/"));
        assert!(servlet(false).ambiguous("/%3bx=y/auth/"));
        // An opaque blob beneath /auth must not reopen the relocation into it: the
        // boundary the param crosses is the subtree anchor, not a byte inside the blob.
        assert!(
            servlet(true).ambiguous("/auth;x=y/"),
            "opaque blob must not reopen the param strip at the anchor"
        );
        // The double-encoded form is a topology fact, not a default: under `UpToOne` a
        // `%253b` never becomes a `;`, so it routes to the default rule and is allowed;
        // declaring the second decoder denies it.
        let servlet_two = guard_layers(
            &[
                ("/auth", 0, false),
                ("/auth/", 0, false),
                ("/auth/*", 0, false),
            ],
            GuardMode::RejectAmbiguous,
            StructuralClasses::new(),
            DecodeDepth::UpToTwo,
            CaseSensitivity::Sensitive,
        );
        assert!(!servlet(false).ambiguous("/auth%253bx=y/"));
        assert!(servlet_two.ambiguous("/auth%253bx=y/"));
    }
}
