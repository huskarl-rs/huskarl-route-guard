//! Reduced path-confusion witnesses, not reproductions of the vulnerable products.
//! Keep the interpretation oracle independent of production scanner helpers.
use http::{Method, Uri};
use huskarl_route_guard::{
    CaseSensitivity, DecodeDepth, GuardConfig, GuardMode, ResolveError, RuleRouter,
    StructuralClasses,
};

fn config(depth: DecodeDepth) -> GuardConfig {
    GuardConfig::new(CaseSensitivity::Sensitive, depth)
}

// A permissive whole-path decode: malformed escapes survive this pass, while
// valid escapes following them still decode (important for CVE-2021-42013).
fn decode(path: &str) -> String {
    let mut result = Vec::new();
    let mut bytes = path.as_bytes().iter().copied().peekable();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let mut lookahead = bytes.clone();
            if let (Some(a), Some(b)) = (lookahead.next(), lookahead.next())
                && let (Some(a), Some(b)) = (char::from(a).to_digit(16), char::from(b).to_digit(16))
            {
                result.push(u8::try_from(a * 16 + b).unwrap());
                bytes = lookahead;
                continue;
            }
        }
        result.push(byte);
    }
    String::from_utf8(result).unwrap()
}

fn normalize(path: &str) -> String {
    let mut segments = Vec::new();
    for segment in path.split('/') {
        let bare = segment.split(';').next().unwrap();
        match bare {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            _ => segments.push(bare),
        }
    }
    format!("/{}", segments.join("/"))
}

fn assert_denied_relocation(router: &RuleRouter<&str>, raw: &str, downstream: &str) {
    assert_ne!(
        router.inspect_raw(raw, &Method::GET).unwrap(),
        router.inspect_raw(downstream, &Method::GET).unwrap(),
        "fixture must cross a rule boundary: {raw} -> {downstream}"
    );
    assert_eq!(
        *router.resolve(downstream, &Method::GET).unwrap().rule(),
        "protected"
    );
    assert!(router.resolve(raw, &Method::GET).is_err(), "allowed {raw}");
}

#[test]
fn cve_2021_41773_mixed_literal_and_encoded_dots() {
    // https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013
    for exclusive in [false, true] {
        let builder = RuleRouter::builder("public", config(DecodeDepth::UpToOne))
            .register_path("/secret", |path| path.all("protected"));
        let router = if exclusive {
            builder.register_exclusive_subtree("/cgi-bin", |path| path.all("cgi"))
        } else {
            builder.register_subtree("/cgi-bin", |path| path.all("cgi"))
        }
        .build()
        .unwrap();
        for raw in ["/cgi-bin/.%2e/secret", "/cgi-bin/.%2E/secret"] {
            let decoded = decode(raw);
            assert_eq!(decoded, "/cgi-bin/../secret");
            let downstream = normalize(&decoded);
            assert_eq!(downstream, "/secret");
            assert_denied_relocation(&router, raw, &downstream);
        }
    }
}

#[test]
fn cve_2021_42013_encoded_hex_digits_reveal_traversal_on_second_pass() {
    // https://eissing.org/icing/posts/httpd-2.4.50/
    // UpToTwo is required: the first pass only manufactures encoded dots.
    for exclusive in [false, true] {
        for depth in [DecodeDepth::UpToOne, DecodeDepth::UpToTwo] {
            let builder = RuleRouter::builder("public", config(depth))
                .register_path("/secret", |path| path.all("protected"));
            let router = if exclusive {
                builder.register_exclusive_subtree("/cgi-bin", |path| path.all("cgi"))
            } else {
                builder.register_subtree("/cgi-bin", |path| path.all("cgi"))
            }
            .build()
            .unwrap();
            for raw in [
                "/cgi-bin/%%32%65%%32%65/secret",
                "/cgi-bin/%25%32%65%25%32%65/secret",
            ] {
                let once = decode(raw);
                assert_eq!(once, "/cgi-bin/%2e%2e/secret");
                let twice = decode(&once);
                assert_eq!(twice, "/cgi-bin/../secret");
                let downstream = normalize(&twice);
                assert_eq!(downstream, "/secret");
                if depth == DecodeDepth::UpToTwo {
                    assert_denied_relocation(&router, raw, &downstream);
                } else {
                    assert_eq!(*router.resolve(raw, &Method::GET).unwrap().rule(), "cgi");
                }
            }
        }
    }
}

#[test]
fn cve_2020_1957_parameter_stripping_exposes_parent_segment() {
    // Adapted Shiro/Spring semicolon-removal witness:
    // https://shiro.apache.org/security-reports.html#CVE-2020-1957
    // https://yuanxzhang.github.io/paper/uabscan-ccs25-long.pdf
    let router = RuleRouter::builder("public", config(DecodeDepth::UpToOne))
        .register_exclusive_subtree("/public", |path| path.all("public-files"))
        .register_path("/admin", |path| path.all("protected"))
        .build()
        .unwrap();
    for raw in ["/public/..;x/admin", "/public/..%3bx/admin"] {
        assert_eq!(decode(raw), "/public/..;x/admin");
        let downstream = normalize(&decode(raw));
        assert_eq!(downstream, "/admin");
        assert_denied_relocation(&router, raw, &downstream);
    }
}

#[test]
fn cve_2021_31920_separator_witnesses_reach_the_protected_route() {
    // https://istio.io/latest/news/security/istio-security-2021-005/
    let router = RuleRouter::builder("public", config(DecodeDepth::UpToOne))
        .register_path("/admin", |path| path.all("protected"))
        .build()
        .unwrap();
    for raw in ["//admin", "/%2fadmin", "/%2Fadmin"] {
        let downstream = normalize(&decode(raw));
        assert_eq!(downstream, "/admin");
        assert_denied_relocation(&router, raw, &downstream);
    }
}

#[test]
fn cve_2021_29492_escaped_separators_cross_rule_boundaries() {
    // https://github.com/envoyproxy/envoy/security/advisories/GHSA-4987-27fx-x6cf
    // Model a backend that decodes and treats backslashes as separators.
    let router = RuleRouter::builder("public", config(DecodeDepth::UpToOne))
        .register_subtree("/admin", |path| path.all("protected"))
        .build()
        .unwrap();
    for raw in [
        "/admin%2Fsecret",
        "/admin%2fsecret",
        "/admin%5Csecret",
        "/admin%5csecret",
    ] {
        let downstream = decode(raw).replace('\\', "/");
        assert_eq!(downstream, "/admin/secret");
        assert_denied_relocation(&router, raw, &downstream);
    }
}

#[test]
fn cve_2025_54576_query_suffix_cannot_select_a_public_route() {
    // https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-7rh7-c77v-6434
    // A reduced equivalent of ^/foo/.*/bar$, using a single wildcard segment.
    for mode in [GuardMode::RejectAmbiguous, GuardMode::Disabled] {
        let router = RuleRouter::builder("protected", config(DecodeDepth::UpToOne).with_mode(mode))
            .register_path("/foo/{segment}/bar", |path| path.all("public"))
            .build()
            .unwrap();
        assert_eq!(
            *router
                .resolve("/foo/something/bar", &Method::GET)
                .unwrap()
                .rule(),
            "public"
        );
        let raw = "/foo/critical_endpoint?param=/bar";
        assert_eq!(
            router.resolve(raw, &Method::GET).unwrap_err(),
            ResolveError::InvalidPathInput
        );
        let uri: Uri = raw.parse().unwrap();
        assert_eq!(uri.path(), "/foo/critical_endpoint");
        assert_eq!(
            *router.resolve(uri.path(), &Method::GET).unwrap().rule(),
            "protected"
        );
    }
}

#[test]
fn cve_2026_41059_decoded_fragment_truncation_denied_by_default() {
    // https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-pxq7-h93f-9jrg
    // A reduced equivalent of ^/foo/.*/bar$, not OAuth2 Proxy's regex matcher.
    for depth in [DecodeDepth::UpToOne, DecodeDepth::UpToTwo] {
        let router = RuleRouter::builder(
            "protected",
            config(depth)
                .with_structural_classes(StructuralClasses::new().without_fragment_truncation()),
        )
        .register_path("/foo/{segment}/bar", |path| path.all("public"))
        .build()
        .unwrap();
        assert_eq!(
            router
                .resolve("/foo/secret#/bar", &Method::GET)
                .unwrap_err(),
            ResolveError::InvalidPathInput
        );
        let guarded = RuleRouter::builder("protected", config(depth))
            .register_path("/foo/{segment}/bar", |path| path.all("public"))
            .build()
            .unwrap();
        for raw in ["/foo/secret%23/bar", "/foo/secret%2523/bar"] {
            if raw.contains("%2523") && depth == DecodeDepth::UpToOne {
                assert_eq!(
                    *guarded.resolve(raw, &Method::GET).unwrap().rule(),
                    "public"
                );
                continue;
            }
            let decoded = decode(raw);
            let decoded = if depth == DecodeDepth::UpToTwo {
                decode(&decoded)
            } else {
                decoded
            };
            assert_eq!(decoded, "/foo/secret#/bar");
            let downstream = decoded.split_once('#').unwrap().0;
            assert_eq!(downstream, "/foo/secret");
            assert_denied_relocation(&guarded, raw, downstream);
            assert_ne!(
                router.inspect_raw(raw, &Method::GET).unwrap(),
                router.inspect_raw(downstream, &Method::GET).unwrap()
            );
            // Decoding alone preserves the public match; downstream truncation does not.
            assert_eq!(*router.resolve(raw, &Method::GET).unwrap().rule(), "public");
            assert_eq!(
                *router.resolve(downstream, &Method::GET).unwrap().rule(),
                "protected"
            );
        }
    }
}

#[test]
fn cve_2020_17523_inspired_segment_trimming_is_outside_the_model() {
    // https://shiro.apache.org/security-reports.html#CVE-2020-17523
    // https://github.com/apache/shiro/commit/ab1ea4a
    // A reduced whitespace-tokenization example, not Shiro's Ant matcher.
    // Our exact /admin registration deliberately excludes /admin/<space>.
    let router = RuleRouter::builder("public", config(DecodeDepth::UpToOne))
        .register_path("/admin", |path| path.all("protected"))
        .build()
        .unwrap();
    let raw = "/admin/%20";
    let decoded = decode(raw);
    assert_eq!(decoded, "/admin/ ");
    let trimmed = decoded
        .split('/')
        .map(|segment| segment.trim_matches(' '))
        .collect::<Vec<_>>()
        .join("/");
    let downstream = normalize(&trimmed);
    assert_eq!(downstream, "/admin");
    assert_ne!(
        router.inspect_raw(raw, &Method::GET).unwrap(),
        router.inspect_raw(&downstream, &Method::GET).unwrap()
    );
    assert!(router.resolve(raw, &Method::GET).unwrap().is_default());
    assert_eq!(
        *router.resolve(&downstream, &Method::GET).unwrap().rule(),
        "protected"
    );
}
