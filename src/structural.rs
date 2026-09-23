//! The structural-byte **alphabet scanner** for the path-confusion guard.
//!
//! This is the byte-level half of the guard: given a request path, which
//! [`ClassSet`] of structural byte families does it carry — encoded/empty
//! separators, dot-segments, matrix-params, NUL truncation, and the opt-in
//! backslash class, plus their alternate encodings (overlong-UTF-8, double-percent,
//! fullwidth confusables, gated by [`Encodings`]) — and the two positional facts the
//! scoped verdict anchors on: the earliest enabled occurrence and the dot-segment
//! pop count ([`ScanResult`])? It models no backend and consults no route table; it
//! only *recognises bytes*.
//!
//! The *routing* half — the anchor's coverage walk and the deny verdict — lives in
//! [`route_tree`](crate::route_tree)'s owned segment-tree matcher and
//! `PathConfusionGuard`, which call [`scan`] here. [`enabled_classes`] /
//! [`enabled_encodings`] derive the scan's masks from the configured
//! [`StructuralClasses`](crate::config::StructuralClasses).

use crate::percent::{Interpretation, fullwidth_at, interpretations, overlong_at};

/// A set of structural *classes* — byte families a backend parser may treat as
/// path structure. Used two ways with the same representation, so a deny check is
/// one bitwise AND: the classes **present** in a request path ([`classes_present`])
/// and the classes a configuration **enables** ([`enabled_classes`]).
///
/// The default classes — separator, dot-segment, param, truncation — are the byte
/// forms covered by
/// [`StructuralClasses::new`](crate::config::StructuralClasses::new).
/// [`BACKSLASH`](ClassSet::BACKSLASH) is opt-in (it maps one-for-one to
/// `with_backslash` and is turned on by [`enabled_classes`] when configured), and
/// [`CASE`](ClassSet::CASE) comes from the required `CaseSensitivity` declaration.
/// The *alternate encodings* a class can arrive in (overlong-UTF-8 and
/// double-percent-encoded `/`·`.`, …) are recognised by [`classes_present`] when the
/// matching [`Encodings`] switch is on.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ClassSet(u8);

impl ClassSet {
    /// An *encoded or alternate* form of the **`/`** separator (`%2F` today;
    /// overlong/fullwidth `/` later) that splits one router segment into two, **or**
    /// a literal empty segment (`//`) that slash-merging collapses — both shift
    /// segment boundaries the same way and are live in the same positions. A
    /// *single* literal `/` is not here: the router already saw it. Backslash
    /// (`\`/`%5C`) is deliberately **not** in this class — treating `\` as a
    /// separator is Windows/IIS-specific, so it gets its own opt-in class (mirroring
    /// [`StructuralClasses::with_backslash`](crate::config::StructuralClasses::with_backslash),
    /// excluded from the default) rather than riding on this default-on class.
    pub(crate) const SEPARATOR: ClassSet = ClassSet(1 << 0);
    /// A `.`/`..` segment (literal) or an encoded dot (`%2E`) that could form one —
    /// feeds RFC 3986 §5.2.4 resolution, which removes or climbs segments.
    pub(crate) const DOT_SEGMENT: ClassSet = ClassSet(1 << 1);
    /// A `;`/`%3B` matrix path-parameter — a servlet strip can empty a segment.
    pub(crate) const PARAM: ClassSet = ClassSet(1 << 2);
    /// A raw or `%00` NUL — a truncating backend exposes a shorter prefix.
    /// **Always-on**: NUL has essentially no legitimate use in a path, so the
    /// over-denial cost of assuming a C-string backend is ~nil, while the
    /// silent-allow cost of not assuming one is a truncation bypass.
    pub(crate) const TRUNCATION: ClassSet = ClassSet(1 << 3);
    /// ASCII uppercase — a case-folding backend. Opt-in.
    pub(crate) const CASE: ClassSet = ClassSet(1 << 4);
    /// A `\` or `%5C` — a Windows/IIS backend treats it as a path separator, so it
    /// shifts segment boundaries exactly as [`SEPARATOR`](Self::SEPARATOR) does. Its
    /// own class (not folded into `SEPARATOR`) so the default `/` separator never
    /// silently turns on Windows-specific `\` handling. Opt-in, mirroring
    /// [`StructuralClasses::with_backslash`](crate::config::StructuralClasses::with_backslash).
    pub(crate) const BACKSLASH: ClassSet = ClassSet(1 << 5);

    /// The empty set.
    pub(crate) const fn empty() -> Self {
        ClassSet(0)
    }

    /// Add the classes in `other`.
    pub(crate) fn insert(&mut self, other: ClassSet) {
        self.0 |= other.0;
    }

    /// Whether any class in `other` is also in `self` — the deny test
    /// (`present.contains_any(live)`), restricted to enabled classes by the caller.
    pub(crate) fn contains_any(self, other: ClassSet) -> bool {
        self.0 & other.0 != 0
    }

    /// The intersection of two sets (e.g. live ∩ enabled).
    pub(crate) fn intersect(self, other: ClassSet) -> ClassSet {
        ClassSet(self.0 & other.0)
    }

    /// The set difference `self ∖ other` (e.g. enabled classes minus the ones a
    /// precise check handles instead of the positional scan).
    pub(crate) fn without(self, other: ClassSet) -> ClassSet {
        ClassSet(self.0 & !other.0)
    }

    /// Whether the set is empty.
    pub(crate) fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl std::ops::BitOr for ClassSet {
    type Output = ClassSet;
    fn bitor(self, rhs: ClassSet) -> ClassSet {
        ClassSet(self.0 | rhs.0)
    }
}

impl std::fmt::Debug for ClassSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut names = Vec::new();
        for (bit, name) in [
            (Self::SEPARATOR, "Separator"),
            (Self::DOT_SEGMENT, "DotSegment"),
            (Self::PARAM, "Param"),
            (Self::TRUNCATION, "Truncation"),
            (Self::CASE, "Case"),
            (Self::BACKSLASH, "Backslash"),
        ] {
            if self.contains_any(bit) {
                names.push(name);
            }
        }
        write!(f, "ClassSet({})", names.join("|"))
    }
}

/// Alternate byte interpretations and the bounded percent-decode policy.
/// Only the interpretation driver consults `double_decode`; structural detectors
/// operate on the resulting bytes and never parse percent escapes themselves.
/// Derived by [`enabled_encodings`] from the deployment configuration.
// Each field is an independent, orthogonal alternate-encoding toggle — a flat set of
// booleans is the clearest representation here.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) struct Encodings {
    /// Recognise overlong UTF-8 forms of `/` (`%C0%AF`, `%E0%80%AF`, …) as
    /// [`SEPARATOR`](ClassSet::SEPARATOR). From
    /// [`OverlongUtf8 { slash: true, .. }`](crate::config::StructuralClasses::with_overlong).
    pub(crate) overlong_slash: bool,
    /// Recognise overlong UTF-8 forms of `.` (`%C0%AE`, …) as
    /// [`DOT_SEGMENT`](ClassSet::DOT_SEGMENT). From
    /// [`OverlongUtf8 { dot: true, .. }`](crate::config::StructuralClasses::with_overlong).
    pub(crate) overlong_dot: bool,
    /// Recognise double-percent-encoded structural bytes (`%252F` → `/`, `%253B`
    /// → `;`, …) as their class. From the required
    /// [`DecodeDepth`](crate::config::DecodeDepth) declaration
    /// ([`UpToTwo`](crate::config::DecodeDepth::UpToTwo)).
    pub(crate) double_decode: bool,
    /// Recognise the fullwidth-form structural confusables (`／`→`/`, `．`→`.`, `；`→`;`,
    /// `＼`→`\`) that NFKC normalization folds to a delimiter, in raw or percent-encoded
    /// form. From
    /// [`with_fullwidth_structure`](crate::config::StructuralClasses::with_fullwidth_structure).
    pub(crate) unicode: bool,
}

impl Encodings {
    /// No alternate encodings — the default-config scan. Test-only since
    /// [`enabled_encodings`] now constructs the struct directly.
    #[cfg(test)]
    pub(crate) const fn none() -> Self {
        Self {
            overlong_slash: false,
            overlong_dot: false,
            double_decode: false,
            unicode: false,
        }
    }
}

/// The result of structural analysis: the classes present, plus the two positional
/// facts the scoped structural verdict anchors on.
///
/// `classes` keeps [`classes_present`]'s contract: recognized classes are recorded
/// before the caller intersects with the enabled set. `earliest` only records enabled
/// classes. `dot_pops` counts potential dot-segments using the enabled separators
/// and parameter handling; dot-segment detection is mandatory in production.
#[derive(Clone, Copy)]
pub(crate) struct ScanResult {
    /// The classes present — identical to [`classes_present`].
    pub(crate) classes: ClassSet,
    /// Byte offset of the first **enabled** structural occurrence: the `%` of an
    /// escape, the first byte of a fullwidth/overlong sequence, the raw byte itself,
    /// the first dot of a literal dot-segment — and for a `//` empty segment the
    /// **second** slash (a merge always keeps the first, so the first is stable).
    pub(crate) earliest: Option<usize>,
    /// Conservative count of dot-segment-capable segments (`k`): each segment whose
    /// bare content before parameters is exactly `.`/`..`, or that carries an encoded-dot
    /// form anywhere (`%2E`, `%252E`, overlong, fullwidth), counts as one `..` — one
    /// level of climb. Overcounting only widens the verdict's anchor (denies more);
    /// an undercount would be a traversal bypass. Invariant: `dot_pops >= 1` iff
    /// `classes` contains [`DOT_SEGMENT`](ClassSet::DOT_SEGMENT).
    pub(crate) dot_pops: usize,
}

impl ScanResult {
    pub(crate) fn empty() -> Self {
        Self {
            classes: ClassSet::empty(),
            earliest: None,
            dot_pops: 0,
        }
    }

    /// Union interpretations in original-input coordinates. The maximum climb
    /// count preserves every shallower interpretation without counting the same
    /// dot-segment again for each decoding pass.
    pub(crate) fn include(&mut self, other: Self) {
        self.classes.insert(other.classes);
        if let Some(offset) = other.earliest {
            self.earliest = Some(self.earliest.map_or(offset, |old| old.min(offset)));
        }
        self.dot_pops = self.dot_pops.max(other.dot_pops);
    }

    fn hit(&mut self, class: ClassSet, offset: usize, enabled: ClassSet) {
        self.classes.insert(class);
        if class.contains_any(enabled) {
            self.earliest = Some(self.earliest.map_or(offset, |old| old.min(offset)));
        }
    }
}

/// Scan all permitted interpretations, retaining original-input offsets.
/// Clean paths allocate nothing; percent decoding is bounded to one or two passes.
pub(crate) fn scan(path: &str, enabled: ClassSet, enc: Encodings) -> ScanResult {
    let mut result = ScanResult::empty();
    interpretations(path.as_bytes(), enc.double_decode, |view| {
        result.include(scan_interpretation(view, enabled, enc));
    });
    result
}

pub(crate) fn classes_present(path: &str, enabled: ClassSet, enc: Encodings) -> ClassSet {
    scan(path, enabled, enc).classes
}

/// Segment state shared by byte classification and climb counting. Encoded dots
/// count conservatively even inside content or parameters, as do alternate dots.
#[derive(Default)]
struct DotSegment {
    bare_len: usize,
    bare_dots: usize,
    in_param: bool,
    alternate_dot: bool,
    start: usize,
}

impl DotSegment {
    fn finish(&self, result: &mut ScanResult, enabled: ClassSet) {
        let literal = self.bare_len == self.bare_dots && (1..=2).contains(&self.bare_len);
        if literal {
            result.hit(ClassSet::DOT_SEGMENT, self.start, enabled);
        }
        if literal || self.alternate_dot {
            result.dot_pops += 1;
        }
    }
}

/// Classify bytes, never percent spellings. Adding a structural form here applies
/// it automatically at every configured decode depth, even for invalid UTF-8.
/// A decoded slash/dot retains its source provenance so it is still recognized as
/// structural even though the decoded spelling looks canonical.
pub(crate) fn scan_interpretation(
    view: &Interpretation<'_>,
    enabled: ClassSet,
    enc: Encodings,
) -> ScanResult {
    let bytes = view.bytes.as_ref();
    let mut result = ScanResult::empty();
    let mut segment = DotSegment::default();
    let mut previous_slash = false;
    let mut i = 0;
    while let Some(&raw) = bytes.get(i) {
        let fullwidth = enc.unicode.then(|| fullwidth_at(bytes, i)).flatten();
        let overlong = if enc.overlong_slash || enc.overlong_dot {
            overlong_at(bytes, i).filter(|(c, _)| {
                (*c == b'/' && enc.overlong_slash) || (*c == b'.' && enc.overlong_dot)
            })
        } else {
            None
        };
        let alternate = fullwidth.or(overlong);
        let (byte, width) = alternate.unwrap_or((raw, 1));
        let source = view.source_offset(i);
        let encoded = alternate.is_some() || view.escaped(i);
        let class = match byte {
            b'/' if encoded || previous_slash => ClassSet::SEPARATOR,
            b'.' if encoded => ClassSet::DOT_SEGMENT,
            b';' => ClassSet::PARAM,
            b'\\' => ClassSet::BACKSLASH,
            0 => ClassSet::TRUNCATION,
            b'A'..=b'Z' => ClassSet::CASE,
            _ => ClassSet::empty(),
        };
        result.hit(class, source, enabled);
        let separator = (byte == b'/' && (!encoded || enabled.contains_any(ClassSet::SEPARATOR)))
            || (byte == b'\\' && enabled.contains_any(ClassSet::BACKSLASH));
        if separator {
            segment.finish(&mut result, enabled);
            segment = DotSegment {
                start: view.source_offset(i + width),
                ..DotSegment::default()
            };
        } else if byte == b';' && enabled.contains_any(ClassSet::PARAM) {
            segment.in_param = true;
        } else {
            if !segment.in_param {
                segment.bare_len += 1;
                segment.bare_dots += usize::from(byte == b'.');
            }
            segment.alternate_dot |= byte == b'.' && encoded;
        }
        previous_slash = byte == b'/';
        i += width;
    }
    segment.finish(&mut result, enabled);
    result
}

#[cfg(test)]
fn has_dot_segment(path: &str, enabled: ClassSet, enc: Encodings) -> bool {
    scan(path, enabled, enc)
        .classes
        .contains_any(ClassSet::DOT_SEGMENT)
}

/// The structural classes a [`StructuralClasses`](crate::config::StructuralClasses)
/// set makes dangerous — the `structural_enabled` mask for the structural modes.
///
/// The default quartet (separator, dot-segment, param, truncation) is **always on**;
/// the opt-in backslash toggle adds its mirror class one-for-one:
/// [`with_backslash`](crate::config::StructuralClasses::with_backslash) →
/// [`BACKSLASH`](ClassSet::BACKSLASH). The [`CASE`](ClassSet::CASE) class is **not**
/// derived here — the structural guard adds it from the required
/// [`CaseSensitivity`](crate::config::CaseSensitivity) declaration, where it
/// gates the strict mode's presence-deny and triggers the precise case-fold check
/// (it is masked out of the default mode's positional scan).
///
/// The *alternate encodings* those classes can also arrive in — overlong-UTF-8 and
/// double-percent forms — are recognised by the scanner only when the matching
/// toggle/declaration is set; see [`enabled_encodings`]. A custom
/// [`StructuralProbe`](crate::config::StructuralProbe) is opaque to the class
/// machinery and instead reaches the structural modes through the whole-path
/// break-glass scan in [`RuleRouter`](crate::path_router); it does not refine the
/// class masks computed here.
pub(crate) fn enabled_classes(classes: &crate::config::StructuralClasses) -> ClassSet {
    // The always-on quartet, then the opt-in backslash class (case is added
    // separately by the router from the CaseSensitivity declaration).
    let mut enabled =
        ClassSet::SEPARATOR | ClassSet::DOT_SEGMENT | ClassSet::PARAM | ClassSet::TRUNCATION;
    if classes.backslash {
        enabled.insert(ClassSet::BACKSLASH);
    }
    enabled
}

/// The alternate-encoding scans the configuration calls for — the per-request switch
/// [`classes_present`] consults so it recognises `%C0%AF`/`%252F` only when a backend
/// that decodes them is being modelled. The companion to [`enabled_classes`]: that
/// picks *which classes* deny, this picks *which encoded forms* of them the scanner
/// even looks at. Double-percent forms come from the required
/// [`DecodeDepth`](crate::config::DecodeDepth)
/// declaration, not from the opt-in class set.
pub(crate) fn enabled_encodings(
    classes: &crate::config::StructuralClasses,
    layers: crate::config::DecodeDepth,
) -> Encodings {
    Encodings {
        overlong_slash: classes.overlong_slash,
        overlong_dot: classes.overlong_dot,
        double_decode: layers.is_up_to_two(),
        unicode: classes.unicode,
    }
}

/// The [`StructuralClass`](crate::config::StructuralClass) reported for a
/// denying [`ClassSet`] — the attribution carried by
/// [`ResolveError`](crate::config::ResolveError). More than one class can be
/// present; the most consequential is reported, in the fixed order dot-segment >
/// truncation > separator > param > backslash > case.
pub(crate) fn primary_class(present: ClassSet) -> crate::config::StructuralClass {
    use crate::config::StructuralClass;
    if present.contains_any(ClassSet::DOT_SEGMENT) {
        StructuralClass::DotSegment
    } else if present.contains_any(ClassSet::TRUNCATION) {
        StructuralClass::NulTruncation
    } else if present.contains_any(ClassSet::SEPARATOR) {
        StructuralClass::Separator
    } else if present.contains_any(ClassSet::PARAM) {
        StructuralClass::MatrixParam
    } else if present.contains_any(ClassSet::BACKSLASH) {
        StructuralClass::Backslash
    } else {
        StructuralClass::Uppercase
    }
}

/// Invariants of the byte scanner, stated **once** as assertion-bearing checkers so a
/// single statement of truth can be driven by more than one regime: today the proptest
/// drivers feed them random inputs (every `cargo test`); a coverage-guided fuzz target can
/// reuse the same checkers for unbounded, raw-byte inputs. Writing each property here —
/// rather than inline in a test — is what makes that reuse cheap.
///
/// These cover the scanner half of the guard (no router, no liveness); the routing/verdict
/// laws live with the matchit oracle and the metamorphic proptests in [`route_tree`].
#[cfg(test)]
pub(crate) mod properties {
    use super::*;

    /// Totality: the scanner terminates without panic or out-of-bounds access on **any**
    /// input, for any class/encoding configuration — a panic in an authz filter is a
    /// fail-open / `DoS` risk, so it is worth pinning even though the code indexes by checked
    /// `get`.
    ///
    /// Calls only [`scan`], the top-level entry: it already invokes the segmentation
    /// walk on the same `(path, enabled, enc)`, so its panic-freedom entails the
    /// helpers'. Also asserts the [`ScanResult`] internal consistency the verdict
    /// relies on: an enabled class is present iff an earliest offset exists (and that
    /// offset is in bounds), and `dot_pops >= 1` iff the DOT class is present.
    pub(crate) fn check_total(path: &str, enabled: ClassSet, enc: Encodings) {
        let s = scan(path, enabled, enc);
        assert_eq!(
            s.classes.intersect(enabled).is_empty(),
            s.earliest.is_none(),
            "earliest must exist exactly when an enabled class is present"
        );
        if let Some(at) = s.earliest {
            assert!(at < path.len(), "earliest offset out of bounds");
        }
        assert_eq!(
            s.dot_pops >= 1,
            s.classes.contains_any(ClassSet::DOT_SEGMENT),
            "dot_pops and the DOT class must agree"
        );
    }

    /// Monotonicity (the scanner-level core of L2/L5): widening the enabled classes or
    /// the recognised encodings can only ever *add* present-bits, never remove one. Given
    /// `e1 ⊆ e2` and `enc1 ≤ enc2`, the effective (enabled-masked) classes found under the
    /// looser config are a subset of those found under the tighter one — so every "tighten
    /// a knob" step is safe-by-construction (it can only deny more).
    ///
    /// The positional facts obey the same order, in the direction that widens the
    /// scoped verdict's anchor: a wider config recognises a superset of occurrences,
    /// so `earliest` can only move **earlier** (`None` = +∞) and `dot_pops` can only
    /// **grow** — both of which enlarge the anchored subtree, i.e. deny more.
    pub(crate) fn check_monotone(
        path: &str,
        e1: ClassSet,
        enc1: Encodings,
        e2: ClassSet,
        enc2: Encodings,
    ) {
        // Preconditions: cfg2 dominates cfg1 on both axes.
        assert!(e1.intersect(e2) == e1, "precondition: e1 ⊆ e2");
        assert!(enc_le(enc1, enc2), "precondition: enc1 ≤ enc2");

        let s1 = scan(path, e1, enc1);
        let s2 = scan(path, e2, enc2);
        let p1 = s1.classes.intersect(e1);
        let p2 = s2.classes.intersect(e2);
        assert!(
            p1.intersect(p2) == p1,
            "monotonicity violated: {p1:?} not a subset of {p2:?}"
        );
        assert!(
            s2.earliest.unwrap_or(usize::MAX) <= s1.earliest.unwrap_or(usize::MAX),
            "earliest moved later under a wider config: {:?} -> {:?}",
            s1.earliest,
            s2.earliest
        );
        assert!(
            s2.dot_pops >= s1.dot_pops,
            "dot_pops shrank under a wider config: {} -> {}",
            s1.dot_pops,
            s2.dot_pops
        );
    }

    /// Fieldwise `≤` on encodings (`false ≤ true`) — the order `check_monotone` requires.
    pub(crate) fn enc_le(a: Encodings, b: Encodings) -> bool {
        (!a.overlong_slash || b.overlong_slash)
            && (!a.overlong_dot || b.overlong_dot)
            && (!a.double_decode || b.double_decode)
            && (!a.unicode || b.unicode)
    }

    /// **Detection** (not just well-behavedness): a `.`/`..` segment present in `path` —
    /// delimited as its own path segment by the caller's witness scaffolding — is flagged
    /// as [`DOT_SEGMENT`](ClassSet::DOT_SEGMENT) under `(enabled, enc)`.
    ///
    /// This is the property [`check_total`]/[`check_monotone`] deliberately do **not** give:
    /// a scanner that returns `ClassSet::empty()` unconditionally passes both (it never
    /// panics, and `∅ ⊆ ∅` is monotone), yet detects nothing. For an authorization boundary
    /// the floor must be *fail-closed* — the drivers use the separator/dot/parameter
    /// subset of the mandatory classes, and [`check_monotone`] lifts it to richer
    /// configurations (which detect ≥ as
    /// much). Floor-detection ∘ monotonicity ⟹ every real config detects at least the core
    /// dot-segment forms.
    ///
    /// The assertion is "**contains** DOT", so arbitrary surrounding context can only *add*
    /// detections, never mask the witnessed one — which is what lets the drivers quantify
    /// over a random neighbourhood. This is the scanner-level slice only; end-to-end "every
    /// attacker-inducible relocation is denied" is the guard-level
    /// `guard_denies_every_modeled_relocation` proptest, which walks the full router.
    pub(crate) fn check_detects_dot(path: &str, enabled: ClassSet, enc: Encodings) {
        assert!(
            classes_present(path, enabled, enc).contains_any(ClassSet::DOT_SEGMENT),
            "dot-segment not detected in {path:?} (enabled={enabled:?}, enc={enc:?})"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every class enabled, no alternate encodings — exercises maximal detection
    /// (incl. separator-revealed dot-segments) for the default-config scan.
    fn all_enabled() -> ClassSet {
        ClassSet::SEPARATOR
            | ClassSet::DOT_SEGMENT
            | ClassSet::PARAM
            | ClassSet::TRUNCATION
            | ClassSet::CASE
            | ClassSet::BACKSLASH
    }

    fn present(path: &str) -> ClassSet {
        classes_present(path, all_enabled(), Encodings::none())
    }

    // ---- step 1: the alphabet scanner ----

    #[test]
    fn classes_present_detects_default_alphabet() {
        assert!(present("/files/users").is_empty());
        assert!(present("/files/a.txt").is_empty()); // in-segment dot is not a dot-segment
        assert!(present("/files/a%2fb").contains_any(ClassSet::SEPARATOR));
        assert!(present("/a/../b").contains_any(ClassSet::DOT_SEGMENT));
        assert!(present("/a/%2e%2e/b").contains_any(ClassSet::DOT_SEGMENT));
        assert!(present("/a/.").contains_any(ClassSet::DOT_SEGMENT));
        assert!(present("/a;jsessionid=1").contains_any(ClassSet::PARAM));
        assert!(present("/a%3bx").contains_any(ClassSet::PARAM));
        assert!(present("/Admin").contains_any(ClassSet::CASE));
        assert!(present("/a%00b").contains_any(ClassSet::TRUNCATION));
    }

    #[test]
    fn classes_present_detects_raw_nul() {
        // Regression (found by the `guard_relocation` fuzz target): a *raw* NUL truncates a
        // C-string backend exactly as `%00` does, so it must flag TRUNCATION on its own —
        // not only in percent-encoded form. The fuzzer hit `/a\0…`, which matched the
        // default rule and was allowed, while a NUL-truncating backend served it as `/a`.
        assert!(
            present("/a\u{0}b").contains_any(ClassSet::TRUNCATION),
            "raw NUL"
        );
        assert!(
            present("/a\u{0}").contains_any(ClassSet::TRUNCATION),
            "trailing raw NUL"
        );
        // Both raw and encoded forms now flag, consistent with raw vs encoded `;`/`\`.
        assert!(
            present("/a%00b").contains_any(ClassSet::TRUNCATION),
            "encoded NUL"
        );
    }

    /// **Detection-table audit.** Every structural class must be flagged in *every*
    /// representation the scanner models — raw byte, `%XX`, double `%25XX`, overlong (for
    /// `/`·`.`), and fullwidth (raw + percent-encoded) — under the flags that enable that
    /// representation. The `..%3b` (encoded param) and raw-NUL bugs were both *missing cells*
    /// in this table; this pins the whole grid so a future asymmetry breaks the build.
    ///
    /// The invariant that matters most: a *raw* structural byte must be flagged here, because
    /// the content-decode relocation check only runs on paths containing `%` and so cannot
    /// back-stop raw bytes (that was exactly the raw-NUL hole).
    #[test]
    fn detection_table_complete() {
        let enabled = all_enabled();
        let enc = Encodings {
            overlong_slash: true,
            overlong_dot: true,
            double_decode: true,
            unicode: true,
        };

        // (label, path, class that must be present)
        let cells: &[(&str, &str, ClassSet)] = &[
            // ── SEPARATOR ──
            ("sep raw //", "/a//b", ClassSet::SEPARATOR),
            ("sep %2f", "/a%2fb", ClassSet::SEPARATOR),
            ("sep double %252f", "/a%252fb", ClassSet::SEPARATOR),
            ("sep overlong %c0%af", "/a%c0%afb", ClassSet::SEPARATOR),
            ("sep fullwidth raw", "/a／b", ClassSet::SEPARATOR),
            ("sep fullwidth pct", "/a%ef%bc%8fb", ClassSet::SEPARATOR),
            // ── DOT_SEGMENT (direct) ──
            ("dot raw ..", "/a/../b", ClassSet::DOT_SEGMENT),
            ("dot %2e", "/a/%2e/b", ClassSet::DOT_SEGMENT),
            ("dot double %252e", "/a/%252e/b", ClassSet::DOT_SEGMENT),
            ("dot overlong %c0%ae", "/a/%c0%ae/b", ClassSet::DOT_SEGMENT),
            ("dot fullwidth raw", "/a/．/b", ClassSet::DOT_SEGMENT),
            ("dot fullwidth pct", "/a/%ef%bc%8e/b", ClassSet::DOT_SEGMENT),
            // ── DOT_SEGMENT revealed: literal `..` flanked by an encoded delimiter ──
            ("dot via %2f sep", "/a%2f..%2fb", ClassSet::DOT_SEGMENT),
            ("dot via raw ; param", "/a/..;x/b", ClassSet::DOT_SEGMENT),
            ("dot via %3b param", "/a/..%3bx/b", ClassSet::DOT_SEGMENT),
            (
                "dot via double %252f",
                "/a%252f..%252fb",
                ClassSet::DOT_SEGMENT,
            ),
            ("dot via fullwidth sep", "/a／..／b", ClassSet::DOT_SEGMENT),
            ("dot via raw \\ sep", "/a\\..\\b", ClassSet::DOT_SEGMENT),
            // ── PARAM ──
            ("param raw ;", "/a;x", ClassSet::PARAM),
            ("param %3b", "/a%3bx", ClassSet::PARAM),
            ("param double %253b", "/a%253bx", ClassSet::PARAM),
            ("param fullwidth raw", "/a；x", ClassSet::PARAM),
            ("param fullwidth pct", "/a%ef%bc%9bx", ClassSet::PARAM),
            // ── BACKSLASH ──
            ("backslash raw", "/a\\b", ClassSet::BACKSLASH),
            ("backslash %5c", "/a%5cb", ClassSet::BACKSLASH),
            ("backslash double %255c", "/a%255cb", ClassSet::BACKSLASH),
            ("backslash fullwidth raw", "/a＼b", ClassSet::BACKSLASH),
            (
                "backslash fullwidth pct",
                "/a%ef%bc%bcb",
                ClassSet::BACKSLASH,
            ),
            // ── CASE (runtime coverage masks this out) ──
            ("case raw", "/Admin", ClassSet::CASE),
            // ── TRUNCATION ──
            ("nul raw", "/a\u{0}b", ClassSet::TRUNCATION),
            ("nul %00", "/a%00b", ClassSet::TRUNCATION),
            ("nul double %2500", "/a%2500b", ClassSet::TRUNCATION),
        ];
        for (label, path, class) in cells {
            assert!(
                classes_present(path, enabled, enc).contains_any(*class),
                "MISSING detection cell: {label} — {path:?} must flag {class:?}"
            );
        }

        // Every interpretation now uses the same scanner. Runtime positional
        // analysis masks CASE; exact rule comparison still handles case folding.
        assert!(classes_present("/%41dmin", enabled, enc).contains_any(ClassSet::CASE));

        // Known, documented scope limit (not a gap): overlong UTF-8 is modeled only for `/`
        // and `.` (the traversal vector; see `StructuralChar`), so overlong `;`/`\`/NUL are
        // intentionally not recognised — reach for a `StructuralProbe` if a backend needs it.
        assert!(
            classes_present("/a%c0%bbx", enabled, enc).is_empty(),
            "overlong `;` is out of the modeled set by design"
        );
    }

    #[test]
    fn classes_present_flags_param_revealed_dot_segment() {
        // `..;/` (Tomcat vector): `;`-strip turns `..;` into `..` → dot-segment.
        assert!(present("/admin/..;/secret").contains_any(ClassSet::DOT_SEGMENT));
        assert!(present("/a/.;x=1/b").contains_any(ClassSet::DOT_SEGMENT));
        // A `..` *after* a `;` is a param value, stripped away — not a dot-segment.
        let c = present("/a/x;..");
        assert!(!c.contains_any(ClassSet::DOT_SEGMENT));
        // An ordinary filename with dots is still not a dot-segment.
        assert!(!present("/files/v1..2.txt").contains_any(ClassSet::DOT_SEGMENT));
    }

    #[test]
    fn classes_present_detects_backslash() {
        assert!(present("/a\\b").contains_any(ClassSet::BACKSLASH));
        assert!(present("/a%5cb").contains_any(ClassSet::BACKSLASH));
        assert!(present("/a%5Cb").contains_any(ClassSet::BACKSLASH));
        assert!(!present("/a/b").contains_any(ClassSet::BACKSLASH));
    }

    #[test]
    fn classes_present_ignores_non_structural_escapes() {
        // %20 (space) is not structural; a literal `/` is the normal separator.
        let c = present("/files/a%20b/c");
        assert!(!c.contains_any(ClassSet::SEPARATOR));
        assert!(!c.contains_any(ClassSet::DOT_SEGMENT));
        assert!(!c.contains_any(ClassSet::PARAM));
    }

    #[test]
    fn classes_present_combines_multiple() {
        let c = present("/a%2fb/../c;d");
        assert!(c.contains_any(ClassSet::SEPARATOR));
        assert!(c.contains_any(ClassSet::DOT_SEGMENT));
        assert!(c.contains_any(ClassSet::PARAM));
    }

    #[test]
    fn dot_segment_revealed_through_encoded_matrix_param() {
        let all = all_enabled();
        let none = Encodings::none();
        // The `;` introducer must be honored in every form the byte scan calls a
        // PARAM, not just the literal one — else `..%3bx` flags only PARAM, which an
        // opaque blob tolerates, and a `;`-stripping backend climbs out of the blob.
        assert!(has_dot_segment("/files/..;x/y", all, none), "literal `;`");
        assert!(
            has_dot_segment("/files/..%3bx/y", all, none),
            "single `%3b`"
        );
        assert!(
            has_dot_segment("/files/..%3Bx/y", all, none),
            "uppercase `%3B`"
        );
        // A `..` that is the param *value* (after the `;`) is still not a dot-segment,
        // in encoded form just as in literal form.
        assert!(
            !has_dot_segment("/files/x%3b..", all, none),
            "`..` is the param value"
        );
        // Double-encoded `%253b` and fullwidth `；` are gated by their encoding switch,
        // mirroring the scanner.
        let double = Encodings {
            double_decode: true,
            ..Encodings::none()
        };
        assert!(
            has_dot_segment("/files/..%253bx/y", all, double),
            "double `%253b` on"
        );
        assert!(
            !has_dot_segment("/files/..%253bx/y", all, none),
            "double `%253b` off"
        );
        let uni = Encodings {
            unicode: true,
            ..Encodings::none()
        };
        assert!(
            has_dot_segment("/files/..；x/y", all, uni),
            "fullwidth `；` on"
        );
        assert!(
            !has_dot_segment("/files/..；x/y", all, none),
            "fullwidth `；` off"
        );
    }

    #[test]
    fn dot_segment_detected_through_encoded_separators() {
        let all = all_enabled();
        let none = Encodings::none();
        // A literal `..` flanked by *encoded* slashes is a dot-segment once the
        // backend decodes — must be flagged (the bypass this fix closes).
        assert!(has_dot_segment("/files/a%2f..%2fb", all, none));
        assert!(has_dot_segment("/files/..%2fadmin", all, none));
        // `;`-strip composed with an encoded slash (`a%2f..;x%2fb` → `a/../b`).
        assert!(has_dot_segment("/files/a%2f..;x%2fb", all, none));
        // In-segment dots and a plain encoded-slash blob key are NOT dot-segments.
        assert!(!has_dot_segment("/files/v1..2", all, none));
        assert!(!has_dot_segment("/files/a%2fb", all, none));

        // Gating: `%5C` reveals a dot-segment only when BACKSLASH is enabled, and
        // `%2F` only when SEPARATOR is enabled — matching what the backend models.
        let no_back = ClassSet::SEPARATOR | ClassSet::DOT_SEGMENT | ClassSet::PARAM;
        assert!(!has_dot_segment("/files/a%5c..%5cb", no_back, none));
        assert!(has_dot_segment("/files/a%5c..%5cb", all, none));
        assert!(!has_dot_segment(
            "/files/a%2f..%2fb",
            ClassSet::DOT_SEGMENT,
            none
        ));

        // Overlong slash reveals it only with the overlong encoding switch on.
        let overlong = Encodings {
            overlong_slash: true,
            overlong_dot: false,
            double_decode: false,
            unicode: false,
        };
        assert!(has_dot_segment("/files/a%c0%af..%c0%afb", all, overlong));
        assert!(!has_dot_segment("/files/a%c0%af..%c0%afb", all, none));
    }

    // ---- the positional facts (earliest offset + dot pops) ----

    #[test]
    fn earliest_offset_per_form() {
        let trio = ClassSet::SEPARATOR | ClassSet::DOT_SEGMENT | ClassSet::PARAM;
        let at = |path: &str, enc: Encodings| scan(path, trio, enc).earliest;
        // Escapes report the `%`; raw bytes report themselves.
        assert_eq!(at("/a%2fb", Encodings::none()), Some(2));
        assert_eq!(at("/ab;x", Encodings::none()), Some(3));
        // A `//` empty segment reports the *second* slash: a merge keeps the first,
        // so the stable prefix retains it.
        assert_eq!(at("/a//b", Encodings::none()), Some(3));
        assert_eq!(at("//a", Encodings::none()), Some(1));
        // A literal dot-segment reports its first dot.
        assert_eq!(at("/ab/../c", Encodings::none()), Some(4));
        // Multi-byte alternate forms report their first byte.
        let dd = Encodings {
            double_decode: true,
            ..Encodings::none()
        };
        assert_eq!(at("/ab%252fc", dd), Some(3));
        let ov = Encodings {
            overlong_slash: true,
            ..Encodings::none()
        };
        assert_eq!(at("/ab%c0%afc", ov), Some(3));
        let uni = Encodings {
            unicode: true,
            ..Encodings::none()
        };
        assert_eq!(at("/ab／c", uni), Some(3));
        // The earliest of several occurrences wins.
        assert_eq!(at("/a%2fb/../c", Encodings::none()), Some(2));
        // A clean path has no offset.
        assert_eq!(at("/clean/path", Encodings::none()), None);
    }

    #[test]
    fn earliest_gated_by_enabled_classes() {
        // The class is still *flagged* (caller gating unchanged), but a disabled
        // class must not place the anchor.
        let no_back = ClassSet::SEPARATOR | ClassSet::DOT_SEGMENT | ClassSet::PARAM;
        let s = scan("/a\\b", no_back, Encodings::none());
        assert!(s.classes.contains_any(ClassSet::BACKSLASH));
        assert_eq!(s.earliest, None);
        let s = scan("/a\\b", no_back | ClassSet::BACKSLASH, Encodings::none());
        assert_eq!(s.earliest, Some(2));
    }

    #[test]
    fn dot_pops_counts_capable_segments() {
        let pops = |path: &str| scan(path, all_enabled(), Encodings::none()).dot_pops;
        assert_eq!(pops("/a/b"), 0);
        assert_eq!(pops("/a/../b"), 1);
        assert_eq!(pops("/a/../../b"), 2);
        assert_eq!(pops("/./.."), 2); // `.` counts a full pop — conservative
        // An in-segment encoded dot counts one pop for its segment (conservative:
        // proving `a.b` cannot climb is the precise checks' job).
        assert_eq!(pops("/a%2eb/c"), 1);
        assert_eq!(pops("/%2e%2e/x"), 1); // one segment, one pop
        // Dot-segments revealed by encoded delimiters count per revealed segment.
        assert_eq!(pops("/a%2f..%2fb"), 1);
        assert_eq!(pops("/a/..;x/b"), 1);
        // In-segment literal dots are not dot-capable.
        assert_eq!(pops("/v1..2/a.b"), 0);
    }

    #[test]
    fn overlong_forms_detected_only_when_enabled() {
        let on = Encodings {
            overlong_slash: true,
            overlong_dot: true,
            double_decode: false,
            unicode: false,
        };
        // %C0%AF = overlong '/', %C0%AE = overlong '.', plus 3-/4-byte forms.
        assert!(classes_present("/a%c0%afb", all_enabled(), on).contains_any(ClassSet::SEPARATOR));
        assert!(
            classes_present("/a%c0%aeb", all_enabled(), on).contains_any(ClassSet::DOT_SEGMENT)
        );
        assert!(
            classes_present("/a%e0%80%afb", all_enabled(), on).contains_any(ClassSet::SEPARATOR)
        );
        assert!(
            classes_present("/a%f0%80%80%afb", all_enabled(), on).contains_any(ClassSet::SEPARATOR)
        );
        // Disabled by default: a standards-conforming backend doesn't decode overlong.
        assert!(!present("/a%c0%afb").contains_any(ClassSet::SEPARATOR));
        assert!(!present("/a%c0%aeb").contains_any(ClassSet::DOT_SEGMENT));
    }

    #[test]
    fn overlong_slash_and_dot_are_independent() {
        let slash_only = Encodings {
            overlong_slash: true,
            overlong_dot: false,
            double_decode: false,
            unicode: false,
        };
        assert!(
            classes_present("/a%c0%afb", all_enabled(), slash_only)
                .contains_any(ClassSet::SEPARATOR)
        );
        // dot scan off → overlong '.' not flagged
        assert!(
            !classes_present("/a%c0%aeb", all_enabled(), slash_only)
                .contains_any(ClassSet::DOT_SEGMENT)
        );
    }

    #[test]
    fn double_encoded_forms_detected_only_when_enabled() {
        let on = Encodings {
            overlong_slash: false,
            overlong_dot: false,
            double_decode: true,
            unicode: false,
        };
        // %25 is a literal `%`; a second decode pass reveals the inner byte's class.
        assert!(classes_present("/a%252fb", all_enabled(), on).contains_any(ClassSet::SEPARATOR));
        assert!(classes_present("/a%252eb", all_enabled(), on).contains_any(ClassSet::DOT_SEGMENT));
        assert!(classes_present("/a%253bb", all_enabled(), on).contains_any(ClassSet::PARAM));
        assert!(classes_present("/a%255cb", all_enabled(), on).contains_any(ClassSet::BACKSLASH));
        assert!(classes_present("/a%2500b", all_enabled(), on).contains_any(ClassSet::TRUNCATION));
        // Disabled by default: a single backend pass leaves `%252f` as `%2f`.
        assert!(!present("/a%252fb").contains_any(ClassSet::SEPARATOR));
        // A plain single-encoded `%2f` is still detected without double_decode.
        assert!(present("/a%2fb").contains_any(ClassSet::SEPARATOR));
    }

    #[test]
    fn unicode_confusables_detected_only_when_enabled() {
        let on = Encodings {
            overlong_slash: false,
            overlong_dot: false,
            double_decode: false,
            unicode: true,
        };
        // Raw fullwidth forms fold to their class.
        assert!(classes_present("/a／b", all_enabled(), on).contains_any(ClassSet::SEPARATOR));
        assert!(classes_present("/a．b", all_enabled(), on).contains_any(ClassSet::DOT_SEGMENT));
        assert!(classes_present("/a；b", all_enabled(), on).contains_any(ClassSet::PARAM));
        assert!(classes_present("/a＼b", all_enabled(), on).contains_any(ClassSet::BACKSLASH));
        // Percent-encoded fullwidth solidus (`%EF%BC%8F`) too.
        assert!(
            classes_present("/a%ef%bc%8fb", all_enabled(), on).contains_any(ClassSet::SEPARATOR)
        );
        // Disabled by default: a backend that doesn't normalize sees opaque bytes.
        assert!(!present("/a／b").contains_any(ClassSet::SEPARATOR));
        assert!(!present("/a%ef%bc%8fb").contains_any(ClassSet::SEPARATOR));
    }

    #[test]
    fn dot_segment_revealed_through_fullwidth_separators() {
        let all = all_enabled();
        let uni = Encodings {
            overlong_slash: false,
            overlong_dot: false,
            double_decode: false,
            unicode: true,
        };
        // A literal `..` flanked by fullwidth solidi is a dot-segment once folded.
        assert!(has_dot_segment("/files/a／..／b", all, uni));
        assert!(has_dot_segment("/files/a%ef%bc%8f..%ef%bc%8fb", all, uni));
        // Not when the unicode encoding is off (the backend wouldn't fold it).
        assert!(!has_dot_segment("/files/a／..／b", all, Encodings::none()));
    }

    // ---- opt-in classes wired to config ----

    #[test]
    fn enabled_classes_default_is_the_quartet() {
        use crate::config::StructuralClasses;
        let e = enabled_classes(&StructuralClasses::new());
        assert!(e.contains_any(ClassSet::SEPARATOR));
        assert!(e.contains_any(ClassSet::DOT_SEGMENT));
        assert!(e.contains_any(ClassSet::PARAM));
        // NUL truncation is always-on: its legitimate-use rate is ~nil, so denying
        // it by default costs nothing while an undeclared C-string backend is a
        // silent truncation bypass.
        assert!(e.contains_any(ClassSet::TRUNCATION));
        // opt-in / separately-declared classes stay off
        assert!(!e.contains_any(ClassSet::CASE));
        assert!(!e.contains_any(ClassSet::BACKSLASH));
    }

    #[test]
    fn opt_in_classes_enable_their_class() {
        use crate::config::StructuralClasses;
        // CASE is not derived from StructuralClasses (it comes from CaseSensitivity);
        // the backslash opt-in is.
        assert!(
            enabled_classes(&StructuralClasses::new().with_backslash())
                .contains_any(ClassSet::BACKSLASH)
        );
    }

    #[test]
    fn probes_and_encodings_enable_no_extra_class() {
        use crate::config::{StructuralClasses, StructuralProbe};

        struct Noop;
        impl StructuralProbe for Noop {
            fn name(&self) -> &'static str {
                "noop"
            }
            fn matches(&self, _path: &str) -> bool {
                false
            }
        }

        // The default set is exactly the quartet.
        let quartet =
            ClassSet::SEPARATOR | ClassSet::DOT_SEGMENT | ClassSet::PARAM | ClassSet::TRUNCATION;
        assert_eq!(enabled_classes(&StructuralClasses::new()), quartet);
        // A probe is opaque to the class machinery (it acts via the break-glass scan)
        // and an encoding toggle changes recognised forms, not classes.
        assert_eq!(
            enabled_classes(
                &StructuralClasses::new()
                    .with_probe(Noop)
                    .with_overlong([crate::config::StructuralChar::Slash])
            ),
            quartet
        );
    }

    #[test]
    fn enabled_encodings_derived_from_config() {
        use crate::config::{DecodeDepth, StructuralChar, StructuralClasses};

        // Default set + UpToOne models no overlong / double-decoding backend.
        assert_eq!(
            enabled_encodings(&StructuralClasses::new(), DecodeDepth::UpToOne),
            Encodings::none()
        );

        let overlong = enabled_encodings(
            &StructuralClasses::new().with_overlong([StructuralChar::Slash]),
            DecodeDepth::UpToOne,
        );
        assert!(overlong.overlong_slash);
        assert!(!overlong.overlong_dot, "only slash was requested");
        assert!(!overlong.double_decode);

        // The double-percent scan comes from the DecodeDepth declaration alone.
        let up_to_two = enabled_encodings(&StructuralClasses::new(), DecodeDepth::UpToTwo);
        assert!(up_to_two.double_decode);
        assert!(!up_to_two.overlong_slash);
    }

    #[test]
    fn primary_class_reports_most_consequential() {
        use crate::config::StructuralClass;
        let all = all_enabled();
        assert_eq!(
            primary_class(ClassSet::DOT_SEGMENT | ClassSet::SEPARATOR),
            StructuralClass::DotSegment
        );
        assert_eq!(
            primary_class(ClassSet::SEPARATOR | ClassSet::PARAM),
            StructuralClass::Separator
        );
        assert_eq!(primary_class(ClassSet::CASE), StructuralClass::Uppercase);
        // A real scan: `..` flanked by encoded separators reports the dot-segment.
        assert_eq!(
            primary_class(classes_present("/a%2f..%2fb", all, Encodings::none())),
            StructuralClass::DotSegment
        );
    }

    #[test]
    fn intersect_models_enabled_classes() {
        // With only the boundary-shift classes enabled, a live CASE bit does not
        // cause denial — gating is the caller's intersect against enabled_classes.
        let enabled = ClassSet::SEPARATOR | ClassSet::DOT_SEGMENT | ClassSet::PARAM;
        let live = ClassSet::SEPARATOR | ClassSet::CASE;
        let effective = live.intersect(enabled);
        assert!(effective.contains_any(ClassSet::SEPARATOR));
        assert!(!effective.contains_any(ClassSet::CASE));
    }

    // ---- shared scanner properties (random driver over the `properties` checkers) ----

    use proptest::prelude::*;

    /// Build an [`Encodings`] from four low bits — a cheap way for the random driver to
    /// sweep the encoding configurations.
    fn enc_from_bits(b: u8) -> Encodings {
        Encodings {
            overlong_slash: b & 1 != 0,
            overlong_dot: b & 2 != 0,
            double_decode: b & 4 != 0,
            unicode: b & 8 != 0,
        }
    }

    /// Fieldwise OR — used to construct an `enc2 ≥ enc1` for the monotonicity driver.
    fn enc_or(a: Encodings, b: Encodings) -> Encodings {
        Encodings {
            overlong_slash: a.overlong_slash || b.overlong_slash,
            overlong_dot: a.overlong_dot || b.overlong_dot,
            double_decode: a.double_decode || b.double_decode,
            unicode: a.unicode || b.unicode,
        }
    }

    /// Paths built from a structural-byte-rich vocabulary, assembled into whole segments so
    /// random sampling actually hits dot-segments, encoded separators, and matrix params
    /// rather than inert noise.
    fn arb_path() -> impl Strategy<Value = String> {
        const VOCAB: &[&str] = &[
            "a", "b", "admin", "..", ".", "a%2fb", "%2e%2e", "a;b", "..;x", "..%3bx", "a%5cb",
            "a%00b", "a%252fb", "a%c0%afb", "Abc",
        ];
        proptest::collection::vec(0..VOCAB.len(), 1..4).prop_map(|idxs| {
            format!(
                "/{}",
                idxs.iter().map(|&i| VOCAB[i]).collect::<Vec<_>>().join("/")
            )
        })
    }

    proptest! {
        /// P-total: the scanner never panics, under any config, on any vocab path.
        #[test]
        fn prop_total(path in arb_path(), bits in any::<u8>(), enc_bits in any::<u8>()) {
            properties::check_total(&path, ClassSet(bits), enc_from_bits(enc_bits));
        }

        /// P-monotone: widening the config only ever adds present-bits.
        #[test]
        fn prop_monotone(
            path in arb_path(),
            e1 in any::<u8>(),
            add in any::<u8>(),
            enc1 in any::<u8>(),
            enc_add in any::<u8>(),
        ) {
            let e1 = ClassSet(e1);
            let e2 = ClassSet(e1.0 | add);
            let enc1 = enc_from_bits(enc1);
            let enc2 = enc_or(enc1, enc_from_bits(enc_add));
            properties::check_monotone(&path, e1, enc1, e2, enc2);
        }
    }

    /// Core dot-segment forms the default configuration detects without opt-in encodings:
    /// literal, single-percent dot, and the param/separator-revealed forms. The driver
    /// sweeps the whole set against random neighbourhoods, so detection cannot depend on a
    /// particular adjacent byte.
    const FLOOR_TOKENS: &[&str] = &[
        "..",
        ".",
        "%2e%2e",
        "%2e",
        ".%2e",
        "..;x",
        "..%3bx",
        "..%3Bx",
        "a%2f..%2fb",
    ];

    /// Dot-segment forms that need an encoding switch on, each paired with the minimal
    /// config that reveals it — including raw and percent-encoded fullwidth (the high-byte
    /// forms that only appear once the unicode normalization is declared).
    fn encoded_dot_tokens() -> Vec<(&'static str, Encodings)> {
        let ov = Encodings {
            overlong_slash: true,
            ..Encodings::none()
        };
        let dd = Encodings {
            double_decode: true,
            ..Encodings::none()
        };
        let uni = Encodings {
            unicode: true,
            ..Encodings::none()
        };
        vec![
            ("a%c0%af..%c0%afb", ov), // overlong slashes flank `..`
            ("a%252f..%252fb", dd),   // double-encoded slashes flank `..`
            ("..%253bx", dd),         // double-encoded matrix param reveals `..`
            ("..／x", uni),           // raw fullwidth solidus
            ("..%ef%bc%8fx", uni),    // percent-encoded fullwidth solidus
            ("..；x", uni),           // raw fullwidth semicolon (param) reveals `..`
        ]
    }

    proptest! {
        /// P-detect (floor): every core form, delimited as its own segment between arbitrary
        /// neighbour segments, is flagged DOT at the trio config — the absolute fail-closed
        /// floor that totality and monotonicity alone do not give.
        #[test]
        fn prop_detect_floor(
            lead in "[a-zA-Z0-9.;%]{0,4}",
            tail in "[a-zA-Z0-9.;%]{0,4}",
            t in 0..FLOOR_TOKENS.len(),
        ) {
            let trio = ClassSet::SEPARATOR | ClassSet::DOT_SEGMENT | ClassSet::PARAM;
            let path = format!("/{lead}/{}/{tail}z", FLOOR_TOKENS[t]);
            properties::check_detects_dot(&path, trio, Encodings::none());
        }

        /// P-detect (encoded): each encoding-gated form is flagged DOT once its switch is on.
        #[test]
        fn prop_detect_encoded(
            lead in "[a-zA-Z0-9.;%]{0,4}",
            tail in "[a-zA-Z0-9.;%]{0,4}",
            t in 0..encoded_dot_tokens().len(),
        ) {
            let trio = ClassSet::SEPARATOR | ClassSet::DOT_SEGMENT | ClassSet::PARAM;
            let (tok, enc) = encoded_dot_tokens()[t];
            let path = format!("/{lead}/{tok}/{tail}z");
            properties::check_detects_dot(&path, trio, enc);
        }
    }

    // ---- fuzz target (engine-agnostic body; driven below by proptest, later by a fuzzer)
    //
    // A fuzz target is just `fn(&[u8])`. This one derives a config + a raw-byte path from
    // the input and asserts the scanner's totality and monotonicity — the unbounded, full-
    // byte-range version of `prop_total`/`prop_monotone` (no length cap, no ASCII mask).
    // To wire an engine later: bolero → `bolero::check!().for_each(fuzz_scanner)` in a
    // `#[test]`; cargo-fuzz → re-export `fuzz_scanner` and call it from a `fuzz_target!`.

    /// Engine-agnostic fuzz body for the scanner checkers. Input layout:
    /// `[enabled, e2_extra, enc1, enc2_extra, path bytes…]` (missing bytes default to 0).
    pub(crate) fn fuzz_scanner(data: &[u8]) {
        let g = |i: usize| data.get(i).copied().unwrap_or(0);
        let e1 = ClassSet(g(0));
        let e2 = ClassSet(g(0) | g(1)); // e2 ⊇ e1 by construction
        let enc1 = enc_from_bits(g(2));
        let enc2 = enc_or(enc1, enc_from_bits(g(3)));
        // Real input (`uri.path()`) is always valid UTF-8; lossy keeps valid sequences
        // (incl. raw fullwidth) and maps stray bytes to U+FFFD.
        let path = String::from_utf8_lossy(data.get(4..).unwrap_or(&[]));
        properties::check_total(&path, e1, enc1);
        properties::check_monotone(&path, e1, enc1, e2, enc2);
    }

    /// Bolero harness for [`fuzz_scanner`]. Runs under `cargo test` (generated inputs +
    /// corpus replay) and as a coverage-guided fuzzer under `cargo bolero test scanner`.
    #[test]
    fn scanner() {
        bolero::check!().for_each(|data: &[u8]| fuzz_scanner(data));
    }
}
