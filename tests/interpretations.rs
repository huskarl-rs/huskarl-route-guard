//! An independent whole-path decoder followed by structural transformations.
//! Do not use production escape readers or scanner helpers in this oracle.
use http::Method;
use huskarl_route_guard::{
    CaseSensitivity, DecodeDepth, GuardConfig, GuardMode, PathRegistration, ResolveError,
    RuleRouter, StructuralChar, StructuralClass, StructuralClasses,
};
use proptest::prelude::*;

fn config(depth: DecodeDepth) -> GuardConfig {
    GuardConfig::new(CaseSensitivity::Insensitive, depth).with_structural_classes(
        StructuralClasses::new()
            .with_fullwidth_structure()
            .with_backslash()
            .with_overlong([StructuralChar::Slash, StructuralChar::Dot]),
    )
}

fn router(depth: DecodeDepth) -> RuleRouter<&'static str> {
    RuleRouter::builder("default", config(depth))
        .register_subtree("/admin", |path| path.all("admin"))
        .register_subtree("/files", |path| path.all("files"))
        .register(PathRegistration::path("/files/private").method(Method::POST, "post-only"))
        .build()
        .unwrap()
}

fn decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cursor = 0;
    while cursor < input.len() {
        if input[cursor] == b'%'
            && let Some(pair) = input.get(cursor + 1..cursor + 3)
            && let Ok(hex) = std::str::from_utf8(pair)
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            cursor += 3;
        } else {
            out.push(input[cursor]);
            cursor += 1;
        }
    }
    out
}

fn normalize(bytes: &[u8]) -> Vec<u8> {
    let replacements: &[(&[u8], u8)] = &[
        ("／".as_bytes(), b'/'),
        ("．".as_bytes(), b'.'),
        ("；".as_bytes(), b';'),
        ("＼".as_bytes(), b'/'),
        (b"\xc0\xaf", b'/'),
        (b"\xe0\x80\xaf", b'/'),
        (b"\xf0\x80\x80\xaf", b'/'),
        (b"\xc0\xae", b'.'),
        (b"\xe0\x80\xae", b'.'),
        (b"\xf0\x80\x80\xae", b'.'),
    ];
    let mut folded = Vec::new();
    let mut remaining = bytes;
    while let Some((&byte, tail)) = remaining.split_first() {
        if byte == 0 {
            break;
        }
        if let Some((from, to)) = replacements
            .iter()
            .find(|(from, _)| remaining.starts_with(from))
        {
            folded.push(*to);
            remaining = &remaining[from.len()..];
        } else {
            folded.push(if byte == b'\\' {
                b'/'
            } else {
                byte.to_ascii_lowercase()
            });
            remaining = tail;
        }
    }
    // Dot removal preserves a trailing directory separator. Dropping an
    // ordinary trailing slash would add an unmodeled content transformation.
    let last = folded.rsplit(|b| *b == b'/').next().unwrap();
    let last_bare = last.split(|b| *b == b';').next().unwrap();
    let trailing_slash = matches!(last_bare, b"" | b"." | b"..");
    let mut segments = Vec::new();
    for segment in folded.split(|b| *b == b'/') {
        let bare = segment.split(|b| *b == b';').next().unwrap();
        match bare {
            b"" | b"." => {}
            b".." => {
                segments.pop();
            }
            _ => segments.push(bare),
        }
    }
    let mut result = vec![b'/'];
    result.extend(segments.join(&b'/'));
    if trailing_slash && result.last() != Some(&b'/') {
        result.push(b'/');
    }
    result
}

#[test]
fn normalization_preserves_directory_separators() {
    for (raw, expected) in [
        ("/files/private/", "/files/private/"),
        ("/files/private/.", "/files/private/"),
        ("/files/private/child/..", "/files/private/"),
        ("/files/private", "/files/private"),
    ] {
        assert_eq!(normalize(raw.as_bytes()), expected.as_bytes());
    }
}

fn encode(bytes: &[u8], mask: &[bool]) -> String {
    let mut out = String::new();
    for (index, &byte) in bytes.iter().enumerate() {
        if !byte.is_ascii() || byte == b'%' || (byte != b'/' && mask[index % mask.len()]) {
            use std::fmt::Write;
            write!(out, "%{byte:02X}").unwrap();
        } else {
            out.push(char::from(byte));
        }
    }
    out
}

#[test]
fn double_encoded_structure_is_checked_after_decoding() {
    let router = router(DecodeDepth::UpToTwo);
    for (path, expected) in [
        ("/admin%25EF%25BC%258Fusers", "/admin/users"),
        ("/files/%25EF%25BC%258E%25EF%25BC%258E/admin", "/admin"),
        ("/files/..%25EF%25BC%259Bx/admin", "/admin"),
        ("/admin%25EF%25BC%25BCusers", "/admin/users"),
        ("/admin%25C0%25AFusers", "/admin/users"),
        ("/files/%25C0%25AE%25C0%25AE/admin", "/admin"),
        ("/files/%25%32%65%25%32%65/admin", "/admin"),
        (
            "/files/%FF/%25EF%25BC%258E%25EF%25BC%258E/../admin",
            "/admin",
        ),
    ] {
        assert_eq!(
            normalize(&decode(&decode(path.as_bytes()))),
            expected.as_bytes()
        );
        assert_ne!(
            router.inspect_raw(path, &Method::GET).unwrap(),
            router.inspect_raw(expected, &Method::GET).unwrap()
        );
        assert!(
            router.resolve(path, &Method::GET).is_err(),
            "allowed {path}"
        );
        let explanation = router.explain(path, &Method::GET).unwrap();
        assert!(explanation.denial.is_some());
        assert_eq!(explanation.structural.unwrap().anchor, "/");
    }
}

#[test]
fn decoded_nul_denies_even_when_every_path_has_the_same_rule() {
    let router = RuleRouter::builder("same", config(DecodeDepth::UpToTwo))
        .build()
        .unwrap();
    for path in ["/a%00b", "/a%2500b", "/a%25%30%30b"] {
        assert_eq!(
            router.resolve(path, &Method::GET).unwrap_err(),
            ResolveError::Structural(StructuralClass::NulTruncation)
        );
    }
}

#[test]
fn normalization_between_decoders_preserves_policy_or_denies() {
    let router = RuleRouter::builder("default", config(DecodeDepth::UpToTwo))
        .register_subtree("/admin", |path| path.all("admin"))
        .register_subtree("/files", |path| path.all("files"))
        .build()
        .unwrap();
    for (raw, forwarded, destination, allowed) in [
        (
            "/files/a%2f..%2f%252e%252e/admin",
            "/files/%2e%2e/admin",
            "/admin",
            false,
        ),
        ("/files/..%3bx/%2561dmin", "/%61dmin", "/admin", false),
        (
            "/files/a%5c..%5c%252e%252e/admin",
            "/files/%2e%2e/admin",
            "/admin",
            false,
        ),
        (
            "/files/a%EF%BC%8F..%EF%BC%8F%252e%252e/admin",
            "/files/%2e%2e/admin",
            "/admin",
            false,
        ),
        (
            "/files/a%2f%2fchild%252fleaf",
            "/files/a/child%2fleaf",
            "/files/a/child/leaf",
            true,
        ),
    ] {
        let first = normalize(&decode(raw.as_bytes()));
        assert_eq!(first, forwarded.as_bytes(), "first server: {raw}");
        let second = normalize(&decode(&first));
        assert_eq!(second, destination.as_bytes(), "second server: {raw}");
        let same_rule = router.inspect_raw(raw, &Method::GET).unwrap()
            == router.inspect_raw(destination, &Method::GET).unwrap();
        assert_eq!(same_rule, allowed, "policy boundary: {raw}");
        assert_eq!(router.resolve(raw, &Method::GET).is_ok(), allowed, "{raw}");
    }
}

/// Negative control: general NFKC is outside `with_fullwidth_structure`.
/// Compatibility folding can manufacture escape syntax between decode passes.
#[test]
fn fullwidth_digits_between_decoders_are_outside_the_structural_model() {
    let raw = "/%25%EF%BC%96%EF%BC%91dmin";
    let once = String::from_utf8(decode(raw.as_bytes())).unwrap();
    assert_eq!(once, "/%６１dmin");
    // These two substitutions are the NFKC mappings for this fixture, not a
    // general Unicode normalizer or part of the supported structural oracle.
    let forwarded = once.replace('６', "6").replace('１', "1");
    assert_eq!(forwarded, "/%61dmin");
    let destination = String::from_utf8(decode(forwarded.as_bytes())).unwrap();
    assert_eq!(destination, "/admin");

    let router = router(DecodeDepth::UpToTwo);
    assert!(router.resolve(raw, &Method::GET).is_ok());
    assert_ne!(
        router.inspect_raw(raw, &Method::GET).unwrap(),
        router.inspect_raw(&destination, &Method::GET).unwrap()
    );
    let strict = RuleRouter::builder(
        "default",
        config(DecodeDepth::UpToTwo).with_mode(GuardMode::RequireCanonical),
    )
    .register_subtree("/admin", |path| path.all("admin"))
    .build()
    .unwrap();
    assert!(strict.resolve(raw, &Method::GET).is_err());
}

#[test]
fn depth_limits_and_uniform_subtree_tolerance_are_preserved() {
    let once = router(DecodeDepth::UpToOne);
    assert!(
        once.resolve("/admin%25EF%25BC%258Fusers", &Method::GET)
            .is_ok()
    );
    let twice = router(DecodeDepth::UpToTwo);
    assert!(
        twice
            .resolve("/admin%2525EF%2525BC%25258Fusers", &Method::GET)
            .is_ok()
    );
    for depth in [DecodeDepth::UpToOne, DecodeDepth::UpToTwo] {
        let uniform = RuleRouter::builder("default", config(depth))
            .register_subtree("/files", |path| path.all("files"))
            .build()
            .unwrap();
        for path in [
            "/files/a%25EF%25BC%258Fb",
            "/files/a%25C0%25AFb",
            "/files/a%25%32%66b",
            "/files/%FF/a%25EF%25BC%258Fb",
        ] {
            assert_eq!(
                *uniform.resolve(path, &Method::GET).unwrap().rule(),
                "files"
            );
        }
    }
    let strict = RuleRouter::builder(
        "default",
        config(DecodeDepth::UpToTwo).with_mode(GuardMode::RequireCanonical),
    )
    .build()
    .unwrap();
    assert!(
        strict
            .resolve("/admin%25EF%25BC%258Fusers", &Method::GET)
            .is_err()
    );
}

proptest! {
    #[test]
    fn composed_whole_path_decoding_cannot_change_an_allowed_rule(
        seed in prop::sample::select(vec![
            b"/admin/users".to_vec(), "/admin／users".as_bytes().to_vec(),
            "/files/．．/admin".as_bytes().to_vec(), "/files/..；x/admin".as_bytes().to_vec(),
            b"/files/\xc0\xae\xc0\xae/admin".to_vec(), b"/admin\xe0\x80\xafusers".to_vec(),
            b"/files/\xf0\x80\x80\xae\xf0\x80\x80\xae/admin".to_vec(),
            "/files/%FF/．．/../admin".as_bytes().to_vec(),
            b"/files/private".to_vec(), b"/FILES/private".to_vec(), b"/admin\0ignored".to_vec(),
        ]),
        first in prop::collection::vec(any::<bool>(), 1..40),
        second in prop::collection::vec(any::<bool>(), 1..40),
        twice in any::<bool>(),
        post in any::<bool>(),
    ) {
        let depth = if twice { DecodeDepth::UpToTwo } else { DecodeDepth::UpToOne };
        let router = router(depth);
        let method = if post { Method::POST } else { Method::GET };
        let once = encode(&seed, &first);
        let raw = if twice { encode(once.as_bytes(), &second) } else { once };
        for interleave in [false, true] {
            let mut decoded = raw.as_bytes().to_vec();
            for _ in 0..if twice { 2 } else { 1 } {
                decoded = decode(&decoded);
                let normalized = normalize(&decoded);
                if let Ok(path) = std::str::from_utf8(&normalized)
                    && let Ok(allowed) = router.resolve(&raw, &method)
                {
                    let downstream = router.inspect_raw(path, &method).unwrap();
                    prop_assert_eq!(downstream, router.inspect_raw(&raw, &method).unwrap(),
                        "allowed {:?} as {:?}, transformed to {:?}, interleave={}",
                        raw, allowed.id(), path, interleave);
                }
                if interleave {
                    decoded = normalized;
                }
            }
        }
    }

    #[test]
    fn mixed_depth_paths_remain_safe_through_two_normalizing_servers(
        prefix in prop::sample::select(vec!["/", "/files/", "/admin/"]),
        parts in prop::collection::vec(prop::sample::select(vec![
            "admin", "files", "private", "a", "/", "//", ".", "..", ";x", "\\",
            "%", "%25", "%2e", "%252e", "%2f", "%252f", "%3b", "%253b",
            "%61", "%2561", "%5c", "%255c", "%00", "%2500", "%FF",
            "．", "／", "；", "%EF%BC%8E", "%25EF%25BC%258E", "%C0%AE",
        ]), 1..12),
        post in any::<bool>(),
    ) {
        let raw = format!("{prefix}{}", parts.concat());
        let router = router(DecodeDepth::UpToTwo);
        let method = if post { Method::POST } else { Method::GET };
        if let Ok(allowed) = router.resolve(&raw, &method) {
            let mut forwarded = raw.as_bytes().to_vec();
            for server in 1..=2 {
                forwarded = normalize(&decode(&forwarded));
                if let Ok(path) = std::str::from_utf8(&forwarded) {
                    prop_assert_eq!(
                        router.inspect_raw(path, &method).unwrap(),
                        router.inspect_raw(&raw, &method).unwrap(),
                        "allowed {:?} as {:?}, server {} reached {:?}",
                        raw, allowed.id(), server, path
                    );
                }
            }
        }
    }
}
