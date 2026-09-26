//! Inputs derived from URI grammar, independently of the guard's model.
use std::collections::BTreeSet;

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
                for token in [
                    char::from(byte).to_string(),
                    format!("%{byte:02X}"),
                    format!("%{byte:02x}"),
                    format!("%25{byte:02X}"),
                    format!("%25{byte:02x}"),
                ] {
                    paths.insert(format!("{}{token}{}", &seed[..offset], &seed[offset..]));
                }
            }
        }
    }
    paths
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
