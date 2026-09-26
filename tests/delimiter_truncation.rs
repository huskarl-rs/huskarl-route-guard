use http::Method;
use huskarl_route_guard::{
    CaseSensitivity, DecodeDepth, GuardConfig, GuardMode, ResolveError, RuleRouter,
    StructuralClass, StructuralClasses,
};

fn config(depth: DecodeDepth) -> GuardConfig {
    GuardConfig::new(CaseSensitivity::Sensitive, depth)
}

#[test]
fn uniform_subtrees_allow_fragments_but_truncation_cannot_escape_them() {
    for exclusive in [false, true] {
        let builder = RuleRouter::builder("outside", config(DecodeDepth::UpToTwo));
        let router = if exclusive {
            builder.register_exclusive_subtree("/files", |path| path.all("files"))
        } else {
            builder.register_subtree("/files", |path| path.all("files"))
        }
        .build()
        .unwrap();
        for path in [
            "/files/a%23suffix",
            "/files/%2523suffix",
            "/files/a/..%23suffix",
        ] {
            assert_eq!(
                *router.resolve(path, &Method::GET).unwrap().rule(),
                "files",
                "{path}"
            );
        }
        for path in [
            "/files%23suffix",
            "/files/..%23suffix",
            "/files/..%2523suffix",
            "/files/.%2e%23suffix",
            "/files/a/../..%23suffix",
        ] {
            assert!(router.resolve(path, &Method::GET).is_err(), "{path}");
        }
    }
}

#[test]
fn fragment_scope_includes_method_denials_and_reports_its_class() {
    let router = RuleRouter::builder("public", config(DecodeDepth::UpToOne))
        .register_path("/files/private", |path| {
            path.method(Method::POST, "post-only")
        })
        .build()
        .unwrap();
    let raw = "/files/private%23suffix";
    assert_eq!(
        router.resolve("/files/private", &Method::GET).unwrap_err(),
        ResolveError::MethodNotConfigured
    );
    for method in [Method::GET, Method::POST] {
        assert_eq!(
            router.resolve(raw, &method).unwrap_err(),
            ResolveError::Structural(StructuralClass::FragmentTruncation)
        );
        let explanation = router.explain(raw, &method).unwrap();
        assert_eq!(
            explanation.denial,
            Some(ResolveError::Structural(
                StructuralClass::FragmentTruncation
            ))
        );
    }
}

#[test]
fn fragment_handling_respects_modes_and_input_boundary() {
    for mode in [
        GuardMode::Disabled,
        GuardMode::RejectAmbiguous,
        GuardMode::RequireCanonical,
    ] {
        let router = RuleRouter::builder("public", config(DecodeDepth::UpToTwo).with_mode(mode))
            .register_subtree("/files", |path| path.all("files"))
            .build()
            .unwrap();
        assert_eq!(
            router.resolve("/files/a#suffix", &Method::GET).unwrap_err(),
            ResolveError::InvalidPathInput
        );
        let result = router.resolve("/files/a%23suffix", &Method::GET);
        if mode == GuardMode::RequireCanonical {
            assert_eq!(
                result.unwrap_err(),
                ResolveError::NonCanonical(StructuralClass::FragmentTruncation)
            );
        } else {
            assert_eq!(*result.unwrap().rule(), "files");
        }
        assert_eq!(
            router.resolve("/files%23suffix", &Method::GET).is_ok(),
            mode == GuardMode::Disabled
        );
    }
}

#[test]
fn fragment_composes_with_case_folding_and_preserves_analysis_budget() {
    let router = RuleRouter::builder(
        "public",
        config(DecodeDepth::UpToTwo).with_max_analysis_path_len(64),
    )
    .register_subtree("/admin", |path| path.all("protected"))
    .build()
    .unwrap();
    assert!(router.resolve("/%61dmin%23suffix", &Method::GET).is_err());
    assert!(router.resolve("/admin%23%FF", &Method::GET).is_err());
    let long = format!("/admin%23{}", "x".repeat(64));
    assert_eq!(
        router.resolve(&long, &Method::GET).unwrap_err(),
        ResolveError::TooLong
    );
    let folded = RuleRouter::builder(
        "public",
        GuardConfig::new(CaseSensitivity::Insensitive, DecodeDepth::UpToOne)
            .with_structural_classes(StructuralClasses::new().with_fragment_truncation()),
    )
    .register_subtree("/admin", |path| path.all("protected"))
    .build()
    .unwrap();
    assert!(folded.resolve("/ADMIN%23suffix", &Method::GET).is_err());
}

#[test]
fn query_truncation_defaults_depth_limits_and_independent_opt_outs() {
    // Analogous decode-and-reparse behavior for '?'; this is additional coverage,
    // not a claim that CVE-2026-41059 describes query truncation.
    for depth in [DecodeDepth::UpToOne, DecodeDepth::UpToTwo] {
        for classes in [
            StructuralClasses::new(),
            StructuralClasses::new().without_fragment_truncation(),
        ] {
            let router =
                RuleRouter::builder("protected", config(depth).with_structural_classes(classes))
                    .register_path("/foo/{segment}/bar", |path| path.all("public"))
                    .build()
                    .unwrap();
            for raw in [
                "/foo/secret%3F/bar",
                "/foo/secret%3f/bar",
                "/foo/secret%253F/bar",
                "/foo/secret%253f/bar",
            ] {
                let expected_deny = !raw.contains("%25") || depth == DecodeDepth::UpToTwo;
                let result = router.resolve(raw, &Method::GET);
                if expected_deny {
                    assert_eq!(
                        result.unwrap_err(),
                        ResolveError::Structural(StructuralClass::QueryTruncation)
                    );
                } else {
                    assert_eq!(*result.unwrap().rule(), "public");
                }
            }
        }
        let router = RuleRouter::builder(
            "protected",
            config(depth)
                .with_structural_classes(StructuralClasses::new().without_query_truncation()),
        )
        .register_path("/foo/{segment}/bar", |path| path.all("public"))
        .build()
        .unwrap();
        assert_eq!(
            *router
                .resolve("/foo/secret%3F/bar", &Method::GET)
                .unwrap()
                .rule(),
            "public"
        );
        assert!(router.resolve("/foo/secret%23/bar", &Method::GET).is_err());
        assert_eq!(
            router
                .resolve("/foo/secret?/bar", &Method::GET)
                .unwrap_err(),
            ResolveError::InvalidPathInput
        );
    }
}

#[test]
fn query_truncation_exposes_traversal_and_preserves_uniform_subtrees() {
    let router = RuleRouter::builder("outside", config(DecodeDepth::UpToTwo))
        .register_subtree("/files", |path| path.all("files"))
        .register_path("/files/private", |path| {
            path.method(Method::POST, "private")
        })
        .build()
        .unwrap();
    for raw in [
        "/files/private%3Fsuffix",
        "/files/..%3Fsuffix",
        "/files/..%253Fsuffix",
    ] {
        assert!(router.resolve(raw, &Method::GET).is_err(), "{raw}");
    }
    // Use a separate uniform subtree to exercise accepted requests.
    let uniform = RuleRouter::builder("outside", config(DecodeDepth::UpToTwo))
        .register_subtree("/files", |path| path.all("files"))
        .build()
        .unwrap();
    for raw in [
        "/files/a%3Fsuffix",
        "/files/%253Fsuffix",
        "/files/a/..%3Fsuffix",
    ] {
        assert_eq!(*uniform.resolve(raw, &Method::GET).unwrap().rule(), "files");
    }
}
