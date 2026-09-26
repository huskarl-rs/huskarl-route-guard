//! Inputs derived from URI grammar, independently of the guard's model.
use std::collections::{BTreeMap, BTreeSet};

// RFC 3986 gen-delims and sub-delims, plus percent, backslash, dot and NUL.
const DELIMITERS: &[u8] = b":/?#[]@!$&'()*+,;=%\\.\0";
const SEEDS: &[&str] = &[
    "/public/probe.txt",
    "/admin/probe.txt",
    "/files/probe.txt",
    "/files/private/probe.txt",
    "/files/a/b.txt",
    "/exact.txt",
    "/foo/secret/bar",
    "/foo/other/bar",
    // Dot-prefix seeds let delimiter insertion expose traversal after reparsing.
    "/files/../suffix",
    "/files/.%2e/suffix",
];

pub fn grammar_paths() -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    for &seed in SEEDS {
        paths.insert(seed.to_owned());
        // Both segment boundaries, each midpoint, and the final suffix. Keep
        // the leading '/' so every target remains origin-form.
        let mut offsets = BTreeSet::new();
        let mut start = 1;
        for segment in seed[1..].split('/') {
            let end = start + segment.len();
            offsets.extend([start, start + segment.len() / 2, end]);
            start = end + 1;
        }
        for offset in offsets {
            for &byte in DELIMITERS {
                for token in spellings(byte) {
                    paths.insert(format!("{}{token}{}", &seed[..offset], &seed[offset..]));
                }
            }
        }
    }
    paths
}

/// Raw, encoded and double-encoded spellings of one byte, in both hex cases.
fn spellings(byte: u8) -> [String; 5] {
    [
        char::from(byte).to_string(),
        format!("%{byte:02X}"),
        format!("%{byte:02x}"),
        format!("%25{byte:02X}"),
        format!("%25{byte:02x}"),
    ]
}

// Multi-character forms whose interactions single-byte insertion cannot reach.
const SEPARATORS: &[&str] = &[
    "//", "/./", "/x/../", "%2f", "%2F", "%252f", "%252F", "\\", "%5c", "%5C", "%255c",
];
const DOT_SEGMENTS: &[&str] = &[
    ".",
    "..",
    "%2e",
    "%2E%2e",
    ".%2e",
    "%252e%252e",
    "..;",
    "..;x=1",
    "..%3b",
    "x/..",
];
const PARAMETERS: &[&str] = &[";", ";x=1", "%3bx", "%3Bx", "%253bx"];

/// Mutation families recorded against seeded paths, for per-family reporting.
pub const MUTATIONS: &[&str] = &[
    "seeded/delimiter",
    "seeded/separator",
    "seeded/escape",
    "seeded/case",
    "seeded/dot-segment",
    "seeded/parameter",
    "seeded/trailing-slash",
];

/// SplitMix64: small, dependency-free, and stable across platforms and releases.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// Byte offsets matching `predicate`, excluding the leading `/`.
fn offsets(path: &str, predicate: impl Fn(usize, u8) -> bool) -> Vec<usize> {
    path.bytes()
        .enumerate()
        .skip(1)
        .filter(|&(index, byte)| path.is_char_boundary(index) && predicate(index, byte))
        .map(|(index, _)| index)
        .collect()
}

fn insert(path: &str, at: usize, token: &str) -> String {
    format!("{}{token}{}", &path[..at], &path[at..])
}

fn replace(path: &str, at: usize, len: usize, token: &str) -> String {
    format!("{}{token}{}", &path[..at], &path[at + len..])
}

/// Applies mutation `index` of [`MUTATIONS`], or returns `None` when it has no site.
fn mutate(path: &str, index: usize, rng: &mut Rng) -> Option<String> {
    let choose = |rng: &mut Rng, sites: Vec<usize>| (!sites.is_empty()).then(|| *rng.pick(&sites));
    match MUTATIONS[index] {
        "seeded/delimiter" => {
            let at = 1 + rng.below(path.len());
            let at = (at..=path.len()).find(|&i| path.is_char_boundary(i))?;
            let spellings = spellings(*rng.pick(DELIMITERS));
            Some(insert(path, at, rng.pick(&spellings)))
        }
        "seeded/separator" => {
            let at = choose(rng, offsets(path, |_, b| b == b'/'))?;
            Some(replace(path, at, 1, rng.pick(SEPARATORS)))
        }
        "seeded/escape" => {
            let at = choose(rng, offsets(path, |_, b| b.is_ascii_graphic() && b != b'%'))?;
            let spellings = spellings(path.as_bytes()[at]);
            Some(replace(path, at, 1, rng.pick(&spellings[1..])))
        }
        "seeded/case" => {
            let at = choose(rng, offsets(path, |_, b| b.is_ascii_alphabetic()))?;
            let flipped = char::from(path.as_bytes()[at] ^ 0x20).to_string();
            Some(replace(path, at, 1, &flipped))
        }
        "seeded/dot-segment" => {
            // After any separator, including the leading one.
            let at = choose(
                rng,
                (0..path.len())
                    .filter(|&i| path.as_bytes()[i] == b'/')
                    .collect(),
            )?;
            Some(insert(
                path,
                at + 1,
                &format!("{}/", rng.pick(DOT_SEGMENTS)),
            ))
        }
        "seeded/parameter" => {
            let mut ends = offsets(path, |_, b| b == b'/');
            ends.push(path.len());
            let at = choose(rng, ends)?;
            Some(insert(path, at, rng.pick(PARAMETERS)))
        }
        "seeded/trailing-slash" => Some(match path.strip_suffix('/') {
            Some(trimmed) if !trimmed.is_empty() => trimmed.to_owned(),
            _ => format!("{path}/"),
        }),
        other => unreachable!("unknown mutation {other}"),
    }
}

/// Deterministic composed mutations: `budget` attempts, each applying two or three
/// mutations to a grammar seed. Returns each distinct path with the mutation
/// families that produced it.
pub fn seeded_paths(seed: u64, budget: usize) -> BTreeMap<String, BTreeSet<&'static str>> {
    let mut rng = Rng(seed);
    let mut paths: BTreeMap<String, BTreeSet<&'static str>> = BTreeMap::new();
    for _ in 0..budget {
        let mut path = (*rng.pick(SEEDS)).to_owned();
        let mut applied = BTreeSet::new();
        let wanted = 2 + rng.below(2);
        let mut steps = 0;
        // Retry mutations without a site, with a bound so every attempt terminates.
        for _ in 0..wanted * 4 {
            let index = rng.below(MUTATIONS.len());
            if let Some(next) = mutate(&path, index, &mut rng) {
                path = next;
                applied.insert(MUTATIONS[index]);
                steps += 1;
                if steps == wanted {
                    break;
                }
            }
        }
        paths.entry(path).or_default().extend(applied);
    }
    paths
}

#[test]
fn seeded_paths_are_deterministic_and_well_formed() {
    let first = seeded_paths(20260926, 500);
    assert_eq!(first, seeded_paths(20260926, 500));
    assert_ne!(first, seeded_paths(20260927, 500));
    assert!(first.len() > 400, "too many duplicates: {}", first.len());
    let mut families: BTreeSet<&str> = BTreeSet::new();
    for (path, applied) in &first {
        assert!(path.starts_with('/'), "{path:?}");
        assert!(!path.bytes().any(|b| b.is_ascii_whitespace()), "{path:?}");
        assert!(!applied.is_empty(), "{path:?}");
        families.extend(applied);
    }
    // Every mutation family is reachable at this budget.
    assert_eq!(families.len(), MUTATIONS.len());
}

#[test]
fn seeded_paths_compose_multiple_mutations() {
    let composed = seeded_paths(7, 1000)
        .values()
        .filter(|applied| applied.len() >= 2)
        .count();
    assert!(
        composed > 500,
        "only {composed} paths combine distinct families"
    );
}

#[test]
fn grammar_reaches_truncation_and_traversal_witnesses() {
    let paths = grammar_paths();
    for witness in [
        "/foo/secret%23/bar",
        "/foo/secret%3F/bar",
        "/foo/secret%253f/bar",
        "/files/..%23/suffix",
        "/files/.%2e%253F/suffix",
        "/exact.txt\0",
    ] {
        assert!(paths.contains(witness), "missing {witness:?}");
    }
    assert!(
        paths
            .iter()
            .all(|p| p.starts_with('/') && !p.bytes().any(|b| b.is_ascii_whitespace()))
    );
}
