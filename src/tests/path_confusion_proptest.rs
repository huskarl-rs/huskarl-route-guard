//! Property-based bypass fuzzing for the path-confusion guard.
//!
//! This tests the guard's *security claim* directly, not its parsing: the guard
//! returns a checked rule or a denial; the caller forwards allowed paths unchanged.
//! A bypass is a parser differential —
//! the proxy authorizes a request as one rule while a backend, after normalizing
//! the path, would route it to a *different* rule. The soundness invariant:
//!
//! > For a route table + structural config, and for **every backend in the
//! > modeled transform family**, if normalizing the request path relocates it to
//! > a different rule than the raw path matched, the guard **must deny**.
//!
//! A violation (relocation exists, guard allowed) is a real authorization
//! bypass — a false *negative*. Over-denial (a false positive) is only an
//! availability issue, so the hard assertion here is one-sided.
//!
//! The oracle's value is that the reference backend ([`normalize`]) is a
//! **concrete, executable** model — it actually decodes `%2F`→`/`, resolves
//! `..`, strips `;`-params, folds case, etc., then re-routes through the same
//! table. The guard instead bounds structural rewrites with positional analysis,
//! while decoding and case-folding internal copies for exact rule comparisons.
//! The structural algorithms are independent; both use the same route table and
//! declared interpretation vocabulary.
//!
//! The one rule that keeps it honest: the reference backend's transforms are
//! **gated by the same [`StructuralClasses`]/[`DecodeDepth`]/[`CaseSensitivity`]**
//! the guard was built with. A relocation via a transform the config does not
//! declare (e.g. `\`→`/` with `without_backslash()`, or a second decode pass
//! under `DecodeDepth::UpToOne`) is operator under-declaration, not a guard bug,
//! so those transforms stay off in the sampled backends too. NUL truncation is
//! always-on in the guard, so the truncating backend is always in the family.
//!
//! The family has two axes and they are swept differently. *Which* transforms a
//! backend performs is **enumerated** (the power set, all 2⁹). The *order* it
//! composes them in is **sampled** — a fresh permutation per backend per case —
//! because enumerating it too would cost `8!` per subset. Order matters: it is
//! not a no-op the fixpoint washes out (see [`normalize_ordered`] for a worked
//! divergence). What makes sampling sufficient rather than merely cheap is that
//! the guard's structure axis bounds a *region* instead of simulating transforms,
//! and that bound holds under every composition order; the sampling is a tripwire
//! on that argument's premise, not the reason it holds.
//! [`transform_order_tests`] pins both ends deterministically.

use proptest::prelude::*;

use crate::{
    config::{
        CaseSensitivity, DecodeDepth, GuardConfig, GuardMode, StructuralChar, StructuralClasses,
    },
    path_router::{PathRegistration, RuleRouter, RuleRouterError},
};

// ── Route-table catalog ────────────────────────────────────────────────────

/// `(kind, path)` route specs the generator samples from. `kind` is `'s'` for a
/// `subtree` (registered via [`PathRegistration::subtree`]) or `'e'` for an exact route.
/// All lowercase, all canonical, and chosen to mostly coexist in `matchit` — a
/// subset that conflicts just fails to build and is skipped.
const CATALOG: &[(char, &str)] = &[
    ('s', "/admin"),
    ('s', "/public"),
    ('s', "/api"),
    ('e', "/health"),
    ('e', "/admin/super"),
    ('e', "/users/{id}"),
    ('s', "/a"),
    ('e', "/a/b"),
    // Guaranteed-uniform subtrees (nothing else registers beneath them): the scoped
    // verdict's *allow* paths, where the soundness property does its hardest work —
    // structural bytes under these flow, and every modeled normalization must agree.
    ('s', "/blob"),
    ('s', "/deep/nested"),
    // Overlapping wildcard and literal subtrees exercise precedence changes:
    // a new literal subtree can shadow a wildcard branch and restore uniformity.
    ('s', "/{tenant}/private"),
    ('s', "/files"),
    ('s', "/{tenant}/shared"),
    ('s', "/files/{folder}"),
];

/// Path-segment vocabulary, mixing names that hit the catalog with structural
/// mutators (literal and encoded separators, dot-segments, matrix-params,
/// backslashes, NULs, overlong/double-encoded forms, and case variants).
const VOCAB: &[&str] = &[
    "files",
    "private",
    "shared",
    "admin",
    "public",
    "api",
    "health",
    "super",
    "secret",
    "users",
    "a",
    "b",
    "42",
    "id",
    "v1",
    "img-1.png",
    "",
    "..",
    ".",
    "%2e",
    "%2e%2e",
    // Sanitizer bait: segments the modeled family treats as **inert** — RFC
    // dot-resolution ignores `....`, so the scanner flags no DOT here and the anchor
    // does not climb for them. A strip-and-rescan backend would manufacture a real
    // `../` out of them (`....//` → `../`), reaching behind the anchor. That shape is
    // out of family by design (see `coverage`), and these entries are what make
    // `no_modeled_transform_rewrites_inside_the_anchor` notice if it ever comes *in*.
    "....",
    "...",
    "....;",
    "a%2fb",
    "%2fadmin",
    "..%2fadmin",
    ";x",
    "..;",
    "admin;jsessionid=1",
    "a\\b",
    "%5cadmin",
    "..%5cadmin",
    "a%00b",
    "admin%00",
    "%252e%252e",
    "%252fadmin",
    "%c0%afadmin",
    "%c0%ae%c0%ae",
    "ADMIN",
    "Admin",
    "PUBLIC",
    // Content-encoded forms that decode onto a catalog literal — exercise the
    // content-decode relocation path (`%61dmin` → `admin`, `%41dmin` → `Admin`).
    "%61dmin",
    "%41dmin",
    "%73uper",
    "%70ublic",
    "%68ealth",
    "%61pi",
    "v%31",
    // Fullwidth structural confusables (raw and percent-encoded) — exercise the
    // `with_fullwidth_structure` path (`／` folds to `/`, `．` to `.`).
    "a／b",
    "／admin",
    "..／admin",
    "．．",
    "a；b",
    "%ef%bc%8fadmin",
    // Multi-segment tails with structural bytes at depth — land the scoped verdict's
    // anchor *inside* a subtree (`blob`/`deep/nested` above are uniform, so these
    // exercise its allow paths, including in-subtree `..` climbs at varying radii).
    "blob",
    "deep/nested",
    "k1/k2/k3",
    "k1/k2%2fk3",
    "k1/../k2",
    "k1/k2/..%2fk3",
    "k1/../../k2",
    "k1;v=1/k2",
];

fn build_router(
    specs: &[(char, &str)],
    classes: StructuralClasses,
    layers: DecodeDepth,
    case: CaseSensitivity,
) -> Result<RuleRouter<u32>, RuleRouterError> {
    // Rule ids are positional, so spec `i` gets rule id `i` — the rule value below
    // (`enumerate`'s index) matches it, which the properties' messages rely on.
    let registrations: Vec<PathRegistration<u32>> = specs
        .iter()
        .enumerate()
        .map(|(id, (kind, path))| {
            (if *kind == 's' {
                PathRegistration::subtree(path)
            } else {
                PathRegistration::path(*path)
            })
            .all(u32::try_from(id).expect("catalog is small"))
        })
        .collect();
    RuleRouter::from_registrations(
        u32::MAX,
        GuardConfig::new(case, layers)
            .with_mode(GuardMode::RejectAmbiguous)
            .with_structural_classes(classes),
        registrations,
    )
}

// ── Reference backend (the executable normalization model) ──────────────────

/// One sampled backend: which modeled transforms it performs. Each toggle is
/// only ever set when the corresponding structural class/encoding is enabled in
/// the config the guard was built with.
// Each field is an independent transform toggle — a flat set of booleans is the
// clearest representation (mirroring `StructuralClasses`).
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug)]
struct Backend {
    decode_sep: bool,        // `%2F` (and `\`/`%5C` when backslash is enabled) → `/`
    decode_dot: bool,        // `%2E` → `.`
    decode_unreserved: bool, // every other `%XX` (content) → its byte
    fold_unicode: bool,      // fullwidth `／`·`．`·`；`·`＼` → `/`·`.`·`;`·`\`
    strip_params: bool,      // drop `;…` in each segment
    merge_slashes: bool,     // `//` → `/`
    resolve_dots: bool,      // RFC 3986 §5.2.4 dot-segment removal
    case_fold: bool,         // ASCII lowercase
    truncate_nul: bool,      // cut at the first NUL (`%00`)
}

impl Backend {
    /// The identity backend — every transform off. The base for a hand-built
    /// backend in a unit test (`Backend { merge_slashes: true, ..Backend::NONE }`),
    /// so the toggles a case actually exercises are the only ones it names.
    const NONE: Self = Self {
        decode_sep: false,
        decode_dot: false,
        decode_unreserved: false,
        fold_unicode: false,
        strip_params: false,
        merge_slashes: false,
        resolve_dots: false,
        case_fold: false,
        truncate_nul: false,
    };
}

/// Every backend in the modeled family for `classes`/`case`: the power set of
/// the available transforms. A transform is available only where the matching
/// class is enabled (case folding under `Insensitive`, unicode folding under
/// `with_fullwidth_structure()`); the always-on quartet's transforms —
/// including NUL truncation — are always available.
fn modeled_backends(classes: &StructuralClasses, case: CaseSensitivity) -> Vec<Backend> {
    let case_avail = case.is_insensitive();
    let uni_avail = classes.unicode;
    let mut backends = Vec::new();
    for mask in 0u32..(1 << 9) {
        let case_fold = mask & (1 << 5) != 0;
        let truncate_nul = mask & (1 << 6) != 0;
        let fold_unicode = mask & (1 << 8) != 0;
        if (case_fold && !case_avail) || (fold_unicode && !uni_avail) {
            continue; // out of model for this config
        }
        backends.push(Backend {
            decode_sep: mask & 1 != 0,
            decode_dot: mask & (1 << 1) != 0,
            strip_params: mask & (1 << 2) != 0,
            merge_slashes: mask & (1 << 3) != 0,
            resolve_dots: mask & (1 << 4) != 0,
            case_fold,
            truncate_nul,
            // Content decoding is always available in the family, but each
            // backend mask selects whether to perform it.
            decode_unreserved: mask & (1 << 7) != 0,
            fold_unicode,
        });
    }
    backends
}

/// One transform of the reference backend. A backend is a *set* of these
/// ([`Backend`]) plus an **order** to compose them in — the second axis, kept as
/// data so the properties can vary it (see [`normalize_ordered`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Trunc,
    DecodeStruct,
    DecodeUnres,
    FoldUni,
    Strip,
    Merge,
    Dots,
    Case,
    // Negative control only: excluded from canonical_order and modeled_backends.
    StripTraversalControl,
}

fn apply(
    step: Step,
    t: &str,
    backend: Backend,
    classes: &StructuralClasses,
    layers: DecodeDepth,
    case_insensitive: bool,
) -> String {
    match step {
        Step::StripTraversalControl => t.replace("../", ""),
        Step::Trunc => truncate_at_nul(t),
        Step::DecodeStruct => decode_pass(t, backend, classes, layers),
        Step::DecodeUnres => decode_unreserved(t),
        Step::FoldUni => fold_unicode(t),
        Step::Strip => strip_params(t),
        Step::Merge => merge_slashes(t),
        Step::Dots => remove_dot_segments(t),
        Step::Case => {
            if case_insensitive {
                t.to_ascii_lowercase()
            } else {
                t.to_owned()
            }
        }
    }
}

/// The steps `backend` performs, in the reference order — NUL truncation, decode,
/// Unicode folding, structural rewrites, then ASCII case folding. This is the
/// *canonical* member of the backend's ordering family, and [`normalize`] uses
/// exactly this order; the properties permute it.
fn canonical_order(backend: Backend) -> Vec<Step> {
    let mut steps = Vec::with_capacity(8);
    if backend.truncate_nul {
        steps.push(Step::Trunc);
    }
    if backend.decode_sep || backend.decode_dot {
        steps.push(Step::DecodeStruct);
    }
    if backend.decode_unreserved {
        steps.push(Step::DecodeUnres);
    }
    if backend.fold_unicode {
        steps.push(Step::FoldUni);
    }
    if backend.strip_params {
        steps.push(Step::Strip);
    }
    if backend.merge_slashes {
        steps.push(Step::Merge);
    }
    if backend.resolve_dots {
        steps.push(Step::Dots);
    }
    if backend.case_fold {
        steps.push(Step::Case);
    }
    steps
}

/// Normalize `path` as `backend` would, composing its steps in `order` and
/// iterating to a fixpoint. Independent of the guard's own scanner by
/// construction — it rewrites bytes and routing follows.
///
/// # Why order is a sampled axis, not a fixed one
///
/// [`Backend`] enumerates *which* transforms a backend performs — the power set,
/// all 2⁹ of it. It cannot also enumerate the order it performs them in: that
/// would multiply the family by up to `8!` per subset. Order is therefore
/// **sampled** rather than enumerated — [`guard_denies_every_modeled_relocation`]
/// draws a fresh permutation per backend per case, and the fuzz body sticks to
/// the canonical order.
///
/// A fixpoint recovers *most* order variation on its own, because a step that
/// merely exposes work for another (decode `%2E%2E` → `..`, which dot-resolution
/// then consumes) gets its consumer re-run next round regardless of who went
/// first. What it does **not** recover is a step that *destroys* another's
/// trigger, and those genuinely diverge:
///
/// ```text
/// /admin;x//../b   with strip-params + merge-slashes + resolve-dots
///   merge before dots (the canonical order)  →  /admin;x/../b  →  /b        (default rule)
///   dots before merge                        →  /admin//b      →  /admin/b  (the admin rule!)
/// ```
///
/// So a single order would leave the oracle covering a *strict subset* of the
/// family the guard claims, and the missing members can reach rules the covered
/// ones never do. That is not a hole in the soundness argument — the guard never
/// picks a normalization: it bounds every structural rewrite by an **anchor** and
/// denies unless the whole region past that anchor is one rule
/// ([`crate::guard::PathConfusionGuard`]'s positional verdict). That bound is
/// order-agnostic by construction, resting only on "a structural byte rewrites at
/// or after its own position, and each dot-segment climbs one level", which holds
/// under *every* composition order. Reordering changes where inside the anchored
/// region a path lands; it cannot move it outside.
///
/// Sampling the axis anyway is cheap insurance on that premise, which is a
/// property of today's transform set, also checked directly by
/// `no_modeled_transform_rewrites_inside_the_anchor`. A future
/// class that rewrites *before* its trigger — the strip-and-rescan sanitizers
/// [coverage](crate::_docs::reference::coverage) puts out of family, where
/// `....//` collapses to `../` — would break the anchor argument silently under a
/// fixed order. Order-sensitivity is the symptom of exactly that, so the
/// permutation draw is aimed at it.
fn normalize_ordered(
    path: &str,
    backend: Backend,
    classes: &StructuralClasses,
    layers: DecodeDepth,
    case_insensitive: bool,
    order: &[Step],
) -> String {
    let mut s = path.to_owned();
    for _ in 0..24 {
        let mut t = s.clone();
        for &step in order {
            t = apply(step, &t, backend, classes, layers, case_insensitive);
        }
        if t == s {
            break;
        }
        s = t;
    }
    s
}

/// [`normalize_ordered`] in the canonical order — the reference backend as the
/// fuzz body and the unit tests use it.
fn normalize(
    path: &str,
    backend: Backend,
    classes: &StructuralClasses,
    layers: DecodeDepth,
    case_insensitive: bool,
) -> String {
    normalize_ordered(
        path,
        backend,
        classes,
        layers,
        case_insensitive,
        &canonical_order(backend),
    )
}

/// A permutation of `steps` drawn from `seed` (Fisher–Yates over a `SplitMix64`
/// stream). Deterministic in the seed, so a proptest failure replays exactly and
/// shrinks like any other input.
fn permuted_order(steps: &[Step], seed: u64) -> Vec<Step> {
    let mut state = seed;
    let mut next = move || {
        // SplitMix64 — a whole PRNG in three lines, which is all a shuffle needs.
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    let mut out = steps.to_vec();
    for i in (1..out.len()).rev() {
        let j = usize::try_from(next() % (i as u64 + 1)).unwrap_or(0);
        out.swap(i, j);
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn pct(b: &[u8], i: usize) -> Option<u8> {
    if *b.get(i)? != b'%' {
        return None;
    }
    Some(hex_val(*b.get(i + 1)?)? * 16 + hex_val(*b.get(i + 2)?)?)
}

/// Case-insensitive ASCII prefix match of `pat` (lowercase) at `b[i..]`.
fn starts_ci(b: &[u8], i: usize, pat: &[u8]) -> bool {
    pat.iter()
        .enumerate()
        .all(|(k, &p)| b.get(i + k).is_some_and(|c| c.to_ascii_lowercase() == p))
}

/// One percent-decoding pass for the modeled structural bytes only (never
/// general unreserved octets — see the module-level discussion of why that is a
/// deliberate scope line). Double-encoding is peeled one `%25` layer per pass
/// (only under a declared [`DecodeDepth::UpToTwo`] model); the fixpoint loop
/// re-runs the decode.
fn decode_pass(t: &str, backend: Backend, c: &StructuralClasses, layers: DecodeDepth) -> String {
    let b = t.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            // Double-encoding: peel `%25` → `%`, let the next pass decode it.
            if layers.is_up_to_two() && starts_ci(b, i, b"%25") {
                out.push(b'%');
                i += 3;
                continue;
            }
            // Overlong UTF-8 (2-byte canonical forms `%C0%AF` / `%C0%AE`).
            if backend.decode_sep && c.overlong_slash && starts_ci(b, i, b"%c0%af") {
                out.push(b'/');
                i += 6;
                continue;
            }
            if backend.decode_dot && c.overlong_dot && starts_ci(b, i, b"%c0%ae") {
                out.push(b'.');
                i += 6;
                continue;
            }
            if let Some(byte) = pct(b, i) {
                let decoded = match byte {
                    b'/' if backend.decode_sep => Some(b'/'),
                    b'\\' if backend.decode_sep && c.backslash => Some(b'/'),
                    b'.' if backend.decode_dot => Some(b'.'),
                    _ => None,
                };
                if let Some(d) = decoded {
                    out.push(d);
                    i += 3;
                    continue;
                }
            }
            out.push(b[i]);
            i += 1;
        } else if b[i] == b'\\' && backend.decode_sep && c.backslash {
            out.push(b'/');
            i += 1;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| t.to_owned())
}

/// Percent-decode the *content* escapes — every complete `%XX` except those that
/// decode to a structural byte (`/ . ; \ NUL`) or to the `%` double-encode wrapper.
/// One pass and idempotent (it produces no new `%`), so it composes safely inside
/// the normalization fixpoint; the structural and double-decode forms are handled by
/// their own steps so this never implies them.
fn decode_unreserved(t: &str) -> String {
    if !t.contains('%') {
        return t.to_owned();
    }
    let b = t.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(byte) = pct(b, i)
            && !matches!(byte, b'/' | b'.' | b';' | b'\\' | 0 | b'%')
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| t.to_owned())
}

/// NFKC-fold the fullwidth structural confusables to their ASCII byte — the Phase-1
/// `with_fullwidth_structure` set. Letters and other compatibility forms are *not*
/// folded (Phase 1 is structural only), so the oracle never generates a content
/// relocation the structural class cannot catch.
fn fold_unicode(t: &str) -> String {
    if t.is_ascii() {
        return t.to_owned();
    }
    t.replace('／', "/")
        .replace('．', ".")
        .replace('；', ";")
        .replace('＼', "\\")
}

fn truncate_at_nul(t: &str) -> String {
    let cut = [t.find("%00"), t.find('\0')].into_iter().flatten().min();
    match cut {
        Some(i) => t[..i].to_owned(),
        None => t.to_owned(),
    }
}

fn strip_params(t: &str) -> String {
    t.split('/')
        .map(|seg| seg.split(';').next().unwrap_or(seg))
        .collect::<Vec<_>>()
        .join("/")
}

fn merge_slashes(t: &str) -> String {
    let mut out = String::with_capacity(t.len());
    let mut prev_slash = false;
    for ch in t.chars() {
        if ch == '/' {
            if prev_slash {
                continue;
            }
            prev_slash = true;
        } else {
            prev_slash = false;
        }
        out.push(ch);
    }
    out
}

/// RFC 3986 §5.2.4 `remove_dot_segments`.
fn remove_dot_segments(path: &str) -> String {
    let mut input = path.to_owned();
    let mut output = String::new();
    while !input.is_empty() {
        if let Some(rest) = input.strip_prefix("../") {
            input = rest.to_owned();
        } else if let Some(rest) = input.strip_prefix("./") {
            input = rest.to_owned();
        } else if let Some(rest) = input.strip_prefix("/./") {
            input = format!("/{rest}");
        } else if input == "/." {
            input = "/".to_owned();
        } else if let Some(rest) = input.strip_prefix("/../") {
            input = format!("/{rest}");
            pop_last_segment(&mut output);
        } else if input == "/.." {
            input = "/".to_owned();
            pop_last_segment(&mut output);
        } else if input == "." || input == ".." {
            input.clear();
        } else {
            // Move the first path segment (leading `/` plus up to the next `/`).
            let after = if let Some(idx) = input[1..].find('/') {
                idx + 1
            } else {
                input.len()
            };
            output.push_str(&input[..after]);
            input = input[after..].to_owned();
        }
    }
    output
}

fn pop_last_segment(output: &mut String) {
    if let Some(idx) = output.rfind('/') {
        output.truncate(idx);
    } else {
        output.clear();
    }
}

// ── Strategies ──────────────────────────────────────────────────────────────

fn config_strategy() -> impl Strategy<Value = (StructuralClasses, DecodeDepth, CaseSensitivity)> {
    (
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(back, over_s, over_d, up_to_two, uni, ci)| {
            let mut c = StructuralClasses::new();
            if !back {
                c = c.without_backslash();
            }
            let mut overlong = Vec::new();
            if over_s {
                overlong.push(StructuralChar::Slash);
            }
            if over_d {
                overlong.push(StructuralChar::Dot);
            }
            if !overlong.is_empty() {
                c = c.with_overlong(overlong);
            }
            if uni {
                c = c.with_fullwidth_structure();
            }
            let layers = if up_to_two {
                DecodeDepth::UpToTwo
            } else {
                DecodeDepth::UpToOne
            };
            let case = if ci {
                CaseSensitivity::Insensitive
            } else {
                CaseSensitivity::Sensitive
            };
            (c, layers, case)
        })
}

fn specs_strategy() -> impl Strategy<Value = Vec<(char, &'static str)>> {
    proptest::sample::subsequence(CATALOG.to_vec(), 1..=CATALOG.len())
}

fn path_strategy() -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::sample::select(VOCAB), 1..5)
        .prop_map(|segs| format!("/{}", segs.join("/")))
}

/// A focused content transform that moves a wildcard match onto a literal match.
/// These cases cover single/up-to-two decoding, case folding, and their composition.
#[derive(Clone, Copy, Debug)]
struct PreciseTransform {
    raw_leaf: &'static str,
    canonical_leaf: &'static str,
    layers: DecodeDepth,
    case: CaseSensitivity,
    backend: Backend,
}

fn precise_transform_strategy() -> impl Strategy<Value = PreciseTransform> {
    proptest::sample::select(vec![
        PreciseTransform {
            raw_leaf: "%61",
            canonical_leaf: "a",
            layers: DecodeDepth::UpToOne,
            case: CaseSensitivity::Sensitive,
            backend: Backend {
                decode_unreserved: true,
                ..Backend::NONE
            },
        },
        PreciseTransform {
            raw_leaf: "%61dmin",
            canonical_leaf: "admin",
            layers: DecodeDepth::UpToOne,
            case: CaseSensitivity::Sensitive,
            backend: Backend {
                decode_unreserved: true,
                ..Backend::NONE
            },
        },
        PreciseTransform {
            raw_leaf: "%2561dmin",
            canonical_leaf: "admin",
            layers: DecodeDepth::UpToTwo,
            case: CaseSensitivity::Sensitive,
            backend: Backend {
                // The structural decode step peels the `%25` wrapper under a
                // up-to-two model; the content step then decodes `%61`.
                decode_sep: true,
                decode_unreserved: true,
                ..Backend::NONE
            },
        },
        PreciseTransform {
            raw_leaf: "A",
            canonical_leaf: "a",
            layers: DecodeDepth::UpToOne,
            case: CaseSensitivity::Insensitive,
            backend: Backend {
                case_fold: true,
                ..Backend::NONE
            },
        },
        PreciseTransform {
            raw_leaf: "ADMIN",
            canonical_leaf: "admin",
            layers: DecodeDepth::UpToOne,
            case: CaseSensitivity::Insensitive,
            backend: Backend {
                case_fold: true,
                ..Backend::NONE
            },
        },
        PreciseTransform {
            raw_leaf: "%41DMIN",
            canonical_leaf: "admin",
            layers: DecodeDepth::UpToOne,
            case: CaseSensitivity::Insensitive,
            backend: Backend {
                decode_unreserved: true,
                case_fold: true,
                ..Backend::NONE
            },
        },
    ])
}

fn method_from_index(index: u8) -> http::Method {
    match index % 5 {
        0 => http::Method::GET,
        1 => http::Method::POST,
        2 => http::Method::PUT,
        3 => http::Method::PATCH,
        _ => http::Method::DELETE,
    }
}

// ── Fuzz target: the guard's soundness claim (engine-agnostic body) ──────────
//
// `guard_denies_every_modeled_relocation` re-expressed as a `fn(&[u8])` so a coverage-
// guided fuzzer can drive arbitrary (table, config, path) triples at the *executable
// backend model*. This is the security boundary — router + verdict together — and the
// reason fuzzing earns its keep over the bounded model checker, which couldn't get past
// the router's `HashMap`. Wire later via bolero/cargo-fuzz; the body is the engine.

/// Decode a config from one byte's bits (mirrors [`config_strategy`]).
fn config_from_bits(bits: u8) -> (StructuralClasses, DecodeDepth, CaseSensitivity) {
    let mut c = StructuralClasses::new();
    if bits & 1 == 0 {
        c = c.without_backslash();
    }
    let mut overlong = Vec::new();
    if bits & 2 != 0 {
        overlong.push(StructuralChar::Slash);
    }
    if bits & 4 != 0 {
        overlong.push(StructuralChar::Dot);
    }
    if !overlong.is_empty() {
        c = c.with_overlong(overlong);
    }
    let layers = if bits & 8 != 0 {
        DecodeDepth::UpToTwo
    } else {
        DecodeDepth::UpToOne
    };
    if bits & 16 != 0 {
        c = c.with_fullwidth_structure();
    }
    let case = if bits & 32 != 0 {
        CaseSensitivity::Insensitive
    } else {
        CaseSensitivity::Sensitive
    };
    (c, layers, case)
}

/// Engine-agnostic fuzz body: if the guard *allows* the path, assert no modeled backend
/// relocates it to a different rule. A failure is a real authorization bypass. Input
/// layout: `[specs_mask, config_bits, path bytes…]`.
pub(crate) fn fuzz_guard_relocation(data: &[u8]) {
    let specs_mask = data.first().copied().unwrap_or(0xFF);
    let (classes, layers, case) = config_from_bits(data.get(1).copied().unwrap_or(0));
    // The guard only ever sees `uri.path()`, which is origin-form (a leading `/`). Model
    // that so the fuzzer explores realistic inputs — and so the reference backend's
    // dot-segment resolver, which assumes a rooted path, is never handed an impossible one.
    // A bare `/` prepend preserves `//` and every structural byte; it only roots the path.
    let raw = String::from_utf8_lossy(data.get(2..).unwrap_or(&[]));
    let path = if raw.starts_with('/') {
        raw.into_owned()
    } else {
        format!("/{raw}")
    };

    // The first 8 entries are mask-controlled; any beyond are always included
    // (mirroring `fuzz_matcher_differential` — and keeping the shift in u8 range).
    let specs: Vec<(char, &str)> = CATALOG
        .iter()
        .enumerate()
        .filter(|(i, _)| *i >= 8 || specs_mask & (1 << i) != 0)
        .map(|(_, s)| *s)
        .collect();
    if specs.is_empty() {
        return;
    }
    let Ok(router) = build_router(&specs, classes.clone(), layers, case) else {
        return; // unbuildable subset (matchit conflict) — skip
    };

    // Rule identity for the oracle: the matched registration's id, or `None` for the
    // default rule — which participates as a rule of its own (a relocation onto or off
    // the default rule is a bypass like any other).
    let raw_rule = router.raw_identity_for_test(&path, &http::Method::GET);
    if router.denial_for_test(&path, &http::Method::GET).is_some() {
        return; // denied — sound regardless of any backend
    }
    for backend in modeled_backends(&classes, case) {
        let normalized = normalize(&path, backend, &classes, layers, case.is_insensitive());
        if normalized == path {
            continue;
        }
        let reloc_rule = router.raw_identity_for_test(&normalized, &http::Method::GET);
        assert_eq!(
            reloc_rule, raw_rule,
            "BYPASS: guard allowed {path:?} (rule {raw_rule:?}) but backend {backend:?} \
             normalizes it to {normalized:?}, which routes to rule {reloc_rule:?}"
        );
    }
}

// ── Properties ──────────────────────────────────────────────────────────────

fn guard_proptest_config() -> ProptestConfig {
    let mut config = ProptestConfig::default();
    if std::env::var_os("PROPTEST_CASES").is_none() {
        config.cases = 2048;
    }
    config
}

proptest! {
    #![proptest_config(guard_proptest_config())]

    /// Soundness: if the guard *allows* a path, no modeled backend may relocate
    /// it to a different rule.
    ///
    /// The family is swept on both axes: every transform *subset* (enumerated —
    /// the power set), each in both its canonical order and a **sampled**
    /// permutation, since order cannot be enumerated too (`8!` per subset — see
    /// [`normalize_ordered`]). `order_seed` derives one permutation per backend
    /// per case, so a run covers ~2⁹ distinct orders rather than one, and 2048
    /// cases keep redrawing them.
    ///
    /// Its present-day yield is **zero, and structurally so**: a path whose
    /// normalization is order-sensitive needs two interacting structural bytes,
    /// which either denies (the anchored region is not one rule) or sits inside a
    /// uniform anchor where every resolution shares a rule by definition. So the
    /// permuted draw is a regression tripwire on the anchor argument's premise,
    /// not additional coverage of today's behaviour — do not read a silent branch
    /// here as the order axis having been searched.
    #[test]
    fn guard_denies_every_modeled_relocation(
        specs in specs_strategy(),
        (classes, layers, case) in config_strategy(),
        path in path_strategy(),
        order_seed in any::<u64>(),
        method_qualified in any::<bool>(),
        method_masks in prop::collection::vec(0u8..32, CATALOG.len()),
        request_method in 0u8..6,
        inheritance in prop::collection::vec(any::<bool>(), CATALOG.len()),
    ) {
        // Under a case-folding backend the catalog (lowercase) builds fine; an
        // unbuildable subset (matchit conflict) is simply skipped.
        let method = if request_method == 5 {
            http::Method::from_bytes(b"CUSTOM").expect("valid method")
        } else {
            method_from_index(request_method)
        };
        let registrations = specs.iter().zip(&method_masks).enumerate().map(|(id, ((kind, path), mask))| {
            let registration = if *kind == 's' {
                PathRegistration::subtree(path)
            } else {
                PathRegistration::path(*path)
            };
            let registration = if !method_qualified || *mask == 0 {
                registration.all(id)
            } else {
                registration.methods((0u8..5).filter(|bit| mask & (1 << bit) != 0)
                    .map(method_from_index), id)
            };
            registration.fallback_inherit(inheritance[id])
        });
        let Ok(router) = RuleRouter::from_registrations(
            usize::MAX,
            GuardConfig::new(case, layers).with_structural_classes(classes.clone()),
            registrations,
        ) else {
            return Ok(());
        };

        // Rule identity via `id()`: the default rule (`None`) participates as a rule
        // of its own, so relocations onto or off it are caught like any other.
        let raw_rule = router.raw_identity_for_test(&path, &method);
        if router.denial_for_test(&path, &method).is_some() {
            return Ok(()); // denied — sound regardless of any backend
        }

        // Guard allowed `path`: assert it is genuinely unambiguous across the
        // whole modeled backend family.
        for (i, backend) in modeled_backends(&classes, case).into_iter().enumerate() {
            let canonical = canonical_order(backend);
            // Mixing the backend index in gives each subset its own permutation
            // stream, so one case samples the order axis ~2⁹ times over, not once.
            let permuted = permuted_order(
                &canonical,
                order_seed ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15),
            );
            for order in [&canonical, &permuted] {
                let normalized = normalize_ordered(
                    &path, backend, &classes, layers, case.is_insensitive(), order,
                );
                if normalized == path {
                    continue;
                }
                let reloc_rule = router.raw_identity_for_test(&normalized, &method);
                prop_assert_eq!(
                    reloc_rule,
                    raw_rule,
                    "BYPASS: guard allowed {:?} (rule {:?}) but backend {:?} applying {:?} \
                     normalizes it to {:?}, which routes to rule {:?} — table {:?}, \
                     classes {:?}, case {:?}, method {:?}, method masks {:?}",
                    path, raw_rule, backend, order, normalized, reloc_rule, specs, classes, case, method, method_masks
                );
            }
        }
    }

    /// Method-qualified overlap must be judged using the request method, not a
    /// stable representative from the terminal. The generated table deliberately
    /// gives one method the same registration at both wildcard and literal terminals,
    /// while a different method has distinct registrations there. Every sampled
    /// transform moves the raw wildcard path onto the literal path.
    #[test]
    fn method_qualified_relocations_are_denied(
        prefix in proptest::sample::select(vec!["x", "users", "api", "tenant"]),
        transform in precise_transform_strategy(),
        representative_index in 0u8..5,
        actual_offset in 1u8..5,
    ) {
        let representative = method_from_index(representative_index);
        let actual = method_from_index(representative_index.wrapping_add(actual_offset));
        prop_assert_ne!(&representative, &actual);

        let wildcard = format!("/{prefix}/{{id}}");
        let literal = format!("/{prefix}/{}", transform.canonical_leaf);
        let raw = format!("/{prefix}/{}", transform.raw_leaf);
        let registrations = vec![
            PathRegistration::patterns([wildcard.clone(), literal.clone()]).method(representative.clone(), 0),
            PathRegistration::path(wildcard).method(actual.clone(), 1),
            PathRegistration::path(literal.clone()).method(actual.clone(), 2),
        ];
        let router = RuleRouter::from_registrations(u32::MAX, GuardConfig::new(transform.case, transform.layers).with_mode(GuardMode::RejectAmbiguous), registrations)?;

        let normalized = normalize(
            &raw,
            transform.backend,
            &StructuralClasses::new(),
            transform.layers,
            transform.case.is_insensitive(),
        );
        prop_assert_eq!(&normalized, &literal);

        let raw_rule = router.raw_identity_for_test(&raw, &actual);
        let normalized_rule = router.raw_identity_for_test(&normalized, &actual);
        prop_assert_ne!(raw_rule, normalized_rule);
        prop_assert!(
            router.denial_for_test(&raw, &representative).is_none(),
            "representative method should stay within registration 0: raw={:?}, normalized={:?}, method={:?}",
            raw,
            normalized,
            representative,
        );
        prop_assert!(
            router.denial_for_test(&raw, &actual).is_some(),
            "BYPASS: guard allowed {:?} for {:?} (rule {:?}), but the modeled backend normalized it to {:?} (rule {:?})",
            raw,
            actual,
            raw_rule,
            normalized,
            normalized_rule,
        );
        prop_assert!(router.resolve(&raw, &actual).is_err());
    }

    /// Every modeled transform must preserve the anchor prefix, including on paths
    /// denied for unrelated reasons. The relocation property alone cannot check this
    /// premise because it only constrains accepted requests. A deterministic mutation
    /// control below verifies that the shared assertion detects a sanitizer that
    /// manufactures traversal from otherwise inert dots.
    #[test]
    fn no_modeled_transform_rewrites_inside_the_anchor(
        specs in specs_strategy(),
        (classes, layers, case) in config_strategy(),
        path in path_strategy(),
        order_seed in any::<u64>(),
    ) {
        let Ok(router) = build_router(&specs, classes.clone(), layers, case) else {
            return Ok(());
        };
        // `None` where the verdict never consults an anchor: a clean path, or one
        // denied outright (over-length, NUL truncation). Nothing to keep invariant.
        let Some(anchor) = router.structural_anchor(&path) else {
            return Ok(());
        };

        for (i, backend) in modeled_backends(&classes, case).into_iter().enumerate() {
            let canonical = canonical_order(backend);
            let permuted = permuted_order(
                &canonical,
                order_seed ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15),
            );
            for order in [&canonical, &permuted] {
                let normalized = normalize_ordered(
                    &path, backend, &classes, layers, case.is_insensitive(), order,
                );
                check_anchor_preserved(&path, anchor, &normalized)?;
            }
        }
    }

    /// Robustness: building with an arbitrary pattern, and matching/judging an
    /// arbitrary path against a fixed table, must never panic or hang (the crate
    /// is `deny(clippy::panic)`, but that cannot see runtime slicing/UTF-8 edges).
    #[test]
    fn never_panics_on_arbitrary_input(pattern in ".*", path in ".*") {
        let _ = RuleRouter::from_registrations(u32::MAX, GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne).with_mode(GuardMode::RejectAmbiguous), vec![PathRegistration::path(pattern).all(0u32)]);

        let router = build_router(
            &[('s', "/admin"), ('e', "/users/{id}")],
            StructuralClasses::new().with_backslash(),
            DecodeDepth::UpToTwo,
            CaseSensitivity::Insensitive,
        )
        .expect("fixed table builds");
        let _ = router.raw_identity_for_test(&path, &http::Method::GET);
        let _ = router.denial_for_test(&path, &http::Method::GET);
    }
}

/// Shared assertion for generated backends and the deterministic mutation control.
fn check_anchor_preserved(
    path: &str,
    anchor: &str,
    normalized: &str,
) -> proptest::test_runner::TestCaseResult {
    prop_assert!(
        normalized.starts_with(anchor),
        "ANCHOR VIOLATED: {:?} has anchor {:?}, but normalizes to {:?}",
        path,
        anchor,
        normalized
    );
    Ok(())
}

#[test]
fn anchor_property_detects_strip_and_rescan_mutation() {
    let classes = StructuralClasses::new();
    let layers = DecodeDepth::UpToOne;
    let router = build_router(
        &[('s', "/safe")],
        classes.clone(),
        layers,
        CaseSensitivity::Sensitive,
    )
    .expect("fixed table builds");
    let path = "/safe/....//admin";
    let anchor = router
        .structural_anchor(path)
        .expect("witness must exercise an anchor");
    assert_eq!(anchor, "/safe/..../");
    let backend = Backend {
        merge_slashes: true,
        resolve_dots: true,
        ..Backend::NONE
    };
    let ordinary = normalize(path, backend, &classes, layers, false);
    assert_eq!(ordinary, "/safe/..../admin");
    check_anchor_preserved(path, anchor, &ordinary).expect("modeled transforms preserve anchor");

    // A single-pass sanitizer manufactures ../ from ....//. Dot resolution then
    // removes a segment before the original trigger, outside the modeled family.
    let mutated = normalize_ordered(
        path,
        backend,
        &classes,
        layers,
        false,
        &[Step::StripTraversalControl, Step::Merge, Step::Dots],
    );
    assert_eq!(mutated, "/admin");
    let error = check_anchor_preserved(path, anchor, &mutated)
        .expect_err("the same property must reject the incompatible transform");
    assert!(error.to_string().contains("ANCHOR VIOLATED"));
}

/// Bolero harness for [`fuzz_guard_relocation`] — the guard's soundness claim against the
/// executable backend model. Runs under `cargo test` and as a coverage-guided fuzzer under
/// `cargo bolero test guard_relocation`.
#[test]
fn guard_relocation() {
    bolero::check!().for_each(|data: &[u8]| fuzz_guard_relocation(data));
}

#[cfg(test)]
mod reference_backend_tests {
    use super::*;

    #[test]
    fn remove_dot_segments_matches_rfc_examples() {
        // RFC 3986 §5.2.4 worked examples.
        assert_eq!(remove_dot_segments("/a/b/c/./../../g"), "/a/g");
        assert_eq!(remove_dot_segments("/a/../admin"), "/admin");
        assert_eq!(remove_dot_segments("/admin/../.."), "/");
        assert_eq!(remove_dot_segments("/public/file.txt"), "/public/file.txt");
    }

    #[test]
    fn decode_pass_is_scoped_to_structural_bytes() {
        let c = StructuralClasses::new().without_backslash();
        let all_decode = Backend {
            decode_sep: true,
            decode_dot: true,
            ..Backend::NONE
        };
        let single = DecodeDepth::UpToOne;
        assert_eq!(decode_pass("/a%2fb", all_decode, &c, single), "/a/b");
        assert_eq!(decode_pass("/a%2eb", all_decode, &c, single), "/a.b");
        // A non-structural unreserved escape is left intact — by design.
        assert_eq!(decode_pass("/%61dmin", all_decode, &c, single), "/%61dmin");
        // Backslash only decodes when the class is enabled.
        assert_eq!(decode_pass("/a\\b", all_decode, &c, single), "/a\\b");
        let with_back = StructuralClasses::new().with_backslash();
        assert_eq!(decode_pass("/a\\b", all_decode, &with_back, single), "/a/b");
        // The %25 double-encode wrapper peels only under an UpToTwo declaration.
        assert_eq!(decode_pass("/a%252fb", all_decode, &c, single), "/a%252fb");
        assert_eq!(
            decode_pass("/a%252fb", all_decode, &c, DecodeDepth::UpToTwo),
            "/a%2fb"
        );
    }

    #[test]
    fn decode_unreserved_decodes_content_not_structure() {
        // Content escapes decode to their byte…
        assert_eq!(decode_unreserved("/%61dmin"), "/admin");
        assert_eq!(decode_unreserved("/a%20b"), "/a b");
        // …but structural bytes and the %25 double-encode wrapper are left to their
        // own steps, so this never produces `/`, `.`, `;`, `\`, NUL, or a fresh `%`.
        assert_eq!(decode_unreserved("/a%2fb"), "/a%2fb");
        assert_eq!(decode_unreserved("/a%2eb"), "/a%2eb");
        assert_eq!(decode_unreserved("/a%252fb"), "/a%252fb");
        // Idempotent (no new escapes appear).
        assert_eq!(decode_unreserved(&decode_unreserved("/%61%20b")), "/a b");
    }

    #[test]
    fn fold_unicode_folds_structural_confusables_only() {
        assert_eq!(fold_unicode("/api／secret"), "/api/secret");
        assert_eq!(fold_unicode("/a／..／b"), "/a/../b");
        assert_eq!(fold_unicode("/a．b；c"), "/a.b;c");
        // Fullwidth *letters* are content (Phase 2), not folded by the Phase-1 model.
        assert_eq!(fold_unicode("/ＡＤＭＩＮ"), "/ＡＤＭＩＮ");
        // ASCII fast-path is a no-op.
        assert_eq!(fold_unicode("/plain/path"), "/plain/path");
    }

    #[test]
    fn strip_and_merge_helpers() {
        assert_eq!(strip_params("/a;x=1/b;y/c"), "/a/b/c");
        assert_eq!(merge_slashes("/a//b///c"), "/a/b/c");
        assert_eq!(truncate_at_nul("/public%00/admin"), "/public");
    }
}

/// The ordering axis, pinned at both ends: the divergence is real, and exhausting
/// it finds nothing.
///
/// [`guard_denies_every_modeled_relocation`] *samples* one permutation per backend
/// per case, which buys breadth over runs but never certainty on any single one.
/// These tests are the deterministic complement — a fixed divergence that must stay
/// divergent, and a bounded **exhaustive** sweep that must stay empty.
#[cfg(test)]
mod transform_order_tests {
    use super::*;

    /// Every ordering of `steps`. Callers keep `steps` short — this is `n!`.
    fn permutations(steps: &[Step]) -> Vec<Vec<Step>> {
        if steps.is_empty() {
            return vec![Vec::new()];
        }
        let mut out = Vec::new();
        for i in 0..steps.len() {
            let mut rest = steps.to_vec();
            let head = rest.remove(i);
            for mut tail in permutations(&rest) {
                tail.insert(0, head);
                out.push(tail);
            }
        }
        out
    }

    /// The shortcut is a real one: fixpoint iteration does **not** wash out step
    /// order, and the orders [`normalize`] skips can reach rules its own order
    /// never produces. Pinned so nobody later "simplifies" the oracle on the
    /// assumption that one order is as good as another.
    #[test]
    fn fixed_order_fixpoint_is_not_order_independent() {
        let c = StructuralClasses::new();
        let backend = Backend {
            strip_params: true,
            merge_slashes: true,
            resolve_dots: true,
            ..Backend::NONE
        };
        let path = "/admin;x//../b";

        // `normalize` merges `//` first, so the `..` climbs out of `/admin` entirely.
        assert_eq!(
            normalize(path, backend, &c, DecodeDepth::UpToOne, false),
            "/b"
        );
        // A backend that resolves dot-segments on the raw path first has its `..`
        // consume the *empty* segment instead — landing inside `/admin`, a rule the
        // model's own order never reaches from this input.
        assert_eq!(
            normalize_ordered(
                path,
                backend,
                &c,
                DecodeDepth::UpToOne,
                false,
                &[Step::Strip, Step::Dots, Step::Merge],
            ),
            "/admin/b"
        );

        // Why that gap is not a hole in the soundness claim: the guard never had to
        // pick a normalization. Both resolutions live past the same anchor, the
        // anchored region is not one rule, so the path is denied and neither
        // resolution is ever reachable.
        let router = build_router(
            &[('s', "/admin"), ('e', "/b")],
            c,
            DecodeDepth::UpToOne,
            CaseSensitivity::Sensitive,
        )
        .expect("table builds");
        assert!(router.denial_for_test(path, &http::Method::GET).is_some());
        // The two transform orders reach different rules, requiring denial.
        assert_ne!(
            router.raw_identity_for_test("/b", &http::Method::GET),
            router.raw_identity_for_test("/admin/b", &http::Method::GET),
        );
    }

    /// The discharge: run the orderings [`normalize`] omits against every path the
    /// guard **allows**, and assert none of them relocates it. This is the same
    /// one-sided soundness property as
    /// [`guard_denies_every_modeled_relocation`](super::guard_denies_every_modeled_relocation),
    /// extended along the axis the backend sampling does not cover.
    ///
    /// Exhaustive rather than sampled, but deliberately bounded — backends of at
    /// most four transforms (≤ 24 orderings each) over a fixed path set — to stay
    /// inside a `cargo test` budget. The coverage that matters is the *shapes*:
    /// each path carries a structural byte, and the prefixes span an anchor that
    /// is uniform (`/blob`, `/deep/nested` — where the guard allows and every
    /// order must therefore agree) and one that is not.
    #[test]
    fn no_permuted_order_relocates_an_allowed_path() {
        // Structural mutators crossed with prefixes that land the anchor in each
        // interesting place: inside a uniform subtree, inside a partially-registered
        // one, and at the root.
        const PREFIXES: &[&str] = &["", "/blob", "/deep/nested", "/admin", "/a", "/users/4"];
        const TAILS: &[&str] = &[
            "k1//../k2",
            "k1/..//k2",
            "k1;v//../k2",
            "k1;v/../k2",
            "a%2fb",
            "..%2fadmin",
            "%2e%2e//admin",
            "a%252fb",
            "k1/./k2",
            "a;x/../..;/b",
            "ADMIN;x//b",
            "a／..／b",
            // Sanitizer bait — inert to the modeled family, structure-bearing to a
            // strip-and-rescan backend (see the VOCAB entries of the same shape).
            "....//k2",
            "..../k2",
            "k1/....//../k2",
        ];

        let classes = StructuralClasses::new().with_backslash();
        let layers = DecodeDepth::UpToTwo;
        let case = CaseSensitivity::Insensitive;
        let router = build_router(CATALOG, classes.clone(), layers, case).expect("catalog builds");
        let paths: Vec<String> = PREFIXES
            .iter()
            .flat_map(|p| TAILS.iter().map(move |t| format!("{p}/{t}")))
            .collect();

        let backends: Vec<Backend> = modeled_backends(&classes, case)
            .into_iter()
            .filter(|b| canonical_order(*b).len() <= 4)
            .collect();

        let mut allowed = 0usize;
        for path in &paths {
            // Denied paths are sound under any ordering — nothing is forwarded.
            if router.denial_for_test(path, &http::Method::GET).is_some() {
                continue;
            }
            allowed += 1;
            let raw_rule = router.raw_identity_for_test(path, &http::Method::GET);
            for backend in &backends {
                for order in permutations(&canonical_order(*backend)) {
                    let normalized =
                        normalize_ordered(path, *backend, &classes, layers, true, &order);
                    if normalized == *path {
                        continue;
                    }
                    let reloc_rule = router.raw_identity_for_test(&normalized, &http::Method::GET);
                    assert_eq!(
                        reloc_rule, raw_rule,
                        "BYPASS: guard allowed {path:?} (rule {raw_rule:?}) but backend \
                         {backend:?} applying {order:?} normalizes it to {normalized:?}, \
                         which routes to rule {reloc_rule:?}"
                    );
                }
            }
        }
        // The property is vacuous if the guard denied everything — this test only
        // means something over paths that were actually forwarded.
        assert!(
            allowed >= 12,
            "only {allowed} of {} paths were allowed — the permuted-order check has \
             nothing to bite on; refresh the path set",
            paths.len()
        );
    }
}

/// The precision claim of the [security contract](crate::_docs::reference::contract), made executable:
/// *which* denials are genuine and which are the structure axis over-approximating.
///
/// The soundness properties above are one-sided — they only ever catch an allow that
/// should have been a deny. These go the other way and measure the cost side, using
/// the same reference backend as the oracle: a deny is an over-approximation exactly
/// when **no** modeled backend relocates the path. That number is a design budget, so
/// it deserves pinning: the documented over-denials stay documented, and the cases the
/// scoped verdict was built to rescue stay rescued.
#[cfg(test)]
mod over_approximation_tests {
    use super::*;

    /// Every modeled backend's resolution of `path`, for tables where we want to
    /// assert a deny is *pure* cost — no relocation exists to justify it.
    fn relocations(
        router: &RuleRouter<u32>,
        path: &str,
        classes: &StructuralClasses,
    ) -> Vec<String> {
        let raw = router.raw_identity_for_test(path, &http::Method::GET);
        modeled_backends(classes, CaseSensitivity::Sensitive)
            .into_iter()
            .map(|b| normalize(path, b, classes, DecodeDepth::UpToOne, false))
            .filter(|n| n != path)
            .filter(|n| router.raw_identity_for_test(n, &http::Method::GET) != raw)
            .collect()
    }

    /// The headline residual over-denial from
    /// [security contract](crate::_docs::reference::contract): a matrix param under a lone
    /// `/users/{id}` route. The only transform a `;` enables is param-strip, which
    /// never crosses a separator, so `/users/4;2` resolves to `/users/4` — inside its
    /// own rule. The guard denies anyway: it bounds the `;`'s reach by the anchor
    /// `/users/` and that region is *not* uniform (unregistered siblings fall through
    /// to the default rule), so it cannot tell this `;` from one that escapes.
    #[test]
    fn a_matrix_param_under_a_lone_param_route_is_denied_without_a_relocation() {
        let classes = StructuralClasses::new();
        let router = build_router(
            &[('e', "/users/{id}")],
            classes.clone(),
            DecodeDepth::UpToOne,
            CaseSensitivity::Sensitive,
        )
        .expect("table builds");

        assert!(
            router
                .denial_for_test("/users/4;2", &http::Method::GET)
                .is_some()
        );
        assert_eq!(
            relocations(&router, "/users/4;2", &classes),
            Vec::<String>::new(),
            "the deny is pure over-approximation — no modeled backend leaves the rule"
        );

        // Axiom 6 is what makes that cost escapable: the canonical spelling of the
        // same request is never denied.
        assert!(
            router
                .denial_for_test("/users/4", &http::Method::GET)
                .is_none()
        );
    }

    /// The documented remedy, and the reason it works: registering the prefix as a
    /// subtree makes its uniformity *visible* to the anchor check, which is the only
    /// thing the guard was missing. Same byte, same backend family, deny → allow.
    #[test]
    fn subtree_registration_removes_the_over_denial() {
        let classes = StructuralClasses::new();
        let router = build_router(
            &[('s', "/users")],
            classes.clone(),
            DecodeDepth::UpToOne,
            CaseSensitivity::Sensitive,
        )
        .expect("table builds");

        for path in ["/users/4;2", "/users/a%2fb", "/users/4/../x"] {
            assert!(
                router.denial_for_test(path, &http::Method::GET).is_none(),
                "{path} should flow under a uniform subtree"
            );
            assert_eq!(
                relocations(&router, path, &classes),
                Vec::<String>::new(),
                "…and it is sound to let it: nothing relocates out of the subtree"
            );
        }
    }

    /// The scoped verdict's *win*, stated as a contrast — the same structural bytes
    /// deny outside a uniform subtree and flow inside one, so the tolerance is earned
    /// from the table's shape rather than from relaxing a class. NUL is the deliberate
    /// exception: always denied in active guard modes, uniform anchor or not.
    #[test]
    fn uniformity_is_what_buys_the_tolerance_and_nul_is_exempt() {
        let classes = StructuralClasses::new();
        let router = build_router(
            &[('s', "/blob"), ('e', "/health")],
            classes,
            DecodeDepth::UpToOne,
            CaseSensitivity::Sensitive,
        )
        .expect("table builds");

        assert!(
            router
                .denial_for_test("/blob/a%2fb", &http::Method::GET)
                .is_none()
        );
        assert!(
            router
                .denial_for_test("/blob/k1/../k2", &http::Method::GET)
                .is_none()
        );
        // The same encoded separator against an exact route, where the anchored region
        // holds another rule and the default fall-through.
        assert!(
            router
                .denial_for_test("/health%2fx", &http::Method::GET)
                .is_some()
        );
        // NUL keeps its unconditional deny even where the anchor is uniform.
        assert!(
            router
                .denial_for_test("/blob/a%00b", &http::Method::GET)
                .is_some()
        );
    }

    /// The other axis, for contrast: the content-decode check *applies* its transform,
    /// so it denies iff a relocation exists in this table — no over-approximation. The
    /// same path flips verdict purely because the table gained a target.
    #[test]
    fn the_content_axis_denies_only_on_an_actual_relocation() {
        let classes = StructuralClasses::new();
        let build = |specs: &[(char, &str)]| {
            build_router(
                specs,
                classes.clone(),
                DecodeDepth::UpToOne,
                CaseSensitivity::Sensitive,
            )
            .expect("table builds")
        };

        assert!(
            build(&[('e', "/health")])
                .denial_for_test("/%61dmin", &http::Method::GET)
                .is_none()
        );
        assert!(
            build(&[('s', "/admin")])
                .denial_for_test("/%61dmin", &http::Method::GET)
                .is_some()
        );
    }
}

/// Regenerate the committed fuzz **seed corpus** under `fuzz-corpus/<bolero-dir>/`.
///
/// `#[ignore]` because it writes files; run it explicitly when the seed set changes, then
/// commit the result:
///
/// ```text
/// cargo test regenerate_fuzz_corpus -- --ignored --nocapture
/// ```
///
/// Seeds are the security-relevant inputs we want every fuzz run to start *warm* on — CVE
/// traversal shapes, the encoded-`;` and raw-NUL regressions, and the matcher's
/// backtracking edges — so a cold/evicted cache still reaches the interesting branches
/// immediately. Each file is the raw `&[u8]` a target's `fuzz_*` body decodes; the dir
/// names match bolero's live corpus dirs (`::` → `__`) so priming a run is a plain copy.
#[test]
#[ignore = "side-effecting: regenerates committed seed files on demand"]
fn regenerate_fuzz_corpus() {
    use std::{fs, path::Path};

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz-corpus");
    let write = |dir: &str, name: &str, bytes: &[u8]| {
        let d = root.join(dir);
        fs::create_dir_all(&d).expect("create seed dir");
        fs::write(d.join(name), bytes).expect("write seed");
    };

    // Each closure prepends the fixed control-byte prefix its `fuzz_*` body decodes.
    let scanner = |path: &str| {
        // [enabled = 0x3f (all classes), e2_extra = 0, enc1 = 0x0f (all encodings), enc2_extra = 0]
        [&[0x3f, 0x00, 0x0f, 0x00], path.as_bytes()].concat()
    };
    let matcher = |probe: &str| [&[0xFFu8], probe.as_bytes()].concat(); // [include = all routes]
    let guard = |path: &str| {
        // [specs_mask = 0xFF (all routes), config_bits = 0x3F (every opt-in class,
        //  up-to-two decode, case-insensitive)]
        [&[0xFFu8, 0x3F], path.as_bytes()].concat()
    };

    // scanner — one of each structural form, incl. the `..%3b` and raw-NUL regressions.
    for (name, path) in [
        ("dot_segment", "/a/../b"),
        ("encoded_sep_dot", "/a%2f..%2fb"),
        ("encoded_param_dot", "/files/..%3bx/secret"),
        ("matrix_param_leading_segment", "/;x=y/auth/"),
        ("raw_nul", "/a\u{0}b"),
        ("encoded_nul", "/a%00b"),
        ("overlong", "/a%c0%afb"),
        ("double_encoded", "/a%252fb"),
        ("fullwidth", "/a／b"),
        ("uppercase", "/Admin"),
        ("clean", "/admin/users"),
    ] {
        write("structural__tests__scanner", name, &scanner(path));
    }

    // matcher — backtracking, trailing slash, catch-all, empty segments, the default.
    for (name, probe) in [
        ("exact", "/health"),
        ("trailing_slash", "/admin/"),
        ("catchall", "/admin/x/y"),
        ("nested_param", "/users/42/posts"),
        ("interior_wildcard", "/a/x/edit"),
        ("empty_segment", "//admin"),
        ("backtrack", "/a/b"),
        ("default", "/nope"),
    ] {
        write(
            "route_tree__tests__matcher_differential",
            name,
            &matcher(probe),
        );
    }

    // guard — CVE traversal shapes + the regressions, against the lowercase catalog.
    for (name, path) in [
        ("traversal", "/public/../admin"),
        ("encoded_traversal", "/api/%2e%2e/admin"),
        ("raw_nul_trunc", "/a\u{0}b"),
        ("encoded_nul_trunc", "/a%00b"),
        ("encoded_sep_dot", "/public/..%2fadmin"),
        ("empty_segment", "//admin"),
        ("trailing_encoded_sep", "/admin%2f"),
        ("fullwidth", "/api／secret"),
        ("double_traversal", "/public/%252e%252e/admin"),
        // Scoped-denial shapes: the uniform-subtree allow paths and their edges —
        // an encoded slash deep in the /blob subtree (allowed; the fuzzer mutates
        // from here toward relocations), an in-subtree `..` at radius one (allowed)
        // vs at the subtree root (denied), and the `//`-merge root-leaf edge.
        ("blob_encoded_sep", "/blob/k1/k2%2fk3"),
        ("blob_inner_climb", "/blob/k1/../k2"),
        ("blob_escape_climb", "/blob/../admin"),
        ("root_leaf_merge", "//"),
        ("decoding_prefix", "/%61dmin/%c0%afadmin"),
        // CVE-2026-73511: a per-segment `;` strip relocating *into* a protected rule,
        // both in the protected segment and in one before it (the shape Envoy's
        // first-`;` truncation missed).
        ("matrix_param_strip", "/admin;x=y/"),
        ("matrix_param_leading_segment", "/;x=y/admin/"),
    ] {
        write(
            "path_confusion_proptest__guard_relocation",
            name,
            &guard(path),
        );
    }

    eprintln!("seed corpus written under {}", root.display());
}
