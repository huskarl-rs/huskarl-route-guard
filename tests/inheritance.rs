use http::Method;
use huskarl_route_guard::{
    CaseSensitivity, DecodeDepth, GuardConfig, GuardMode, PathRegistration, RawMatch, ResolveError,
    RuleRouter,
};

fn config() -> GuardConfig {
    GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToTwo)
}

#[test]
fn inherited_rules_keep_identity_and_encoded_key_coverage() {
    // Rule values need neither Clone nor equality for inheritance.
    #[derive(Debug)]
    struct Policy;
    let router = RuleRouter::builder(Policy, config())
        .register_subtree("/files", |p| p.methods([Method::GET, Method::HEAD], Policy))
        .register_path("/files/special", |p| {
            p.fallback_inherit(true).method(Method::POST, Policy)
        })
        .build()
        .unwrap();
    let parent = router.resolve("/files/ordinary", &Method::GET).unwrap();
    for path in [
        "/files",
        "/files/",
        "/files/special",
        "/files/%73pecial",
        "/files/hello%20world",
        "/files/a%2fb",
        "/files/a%252fb",
        "/files/a/../special",
    ] {
        for method in [Method::GET, Method::HEAD] {
            let inherited = router.resolve(path, &method).unwrap();
            assert_eq!(inherited.id(), parent.id(), "{method} {path}");
            assert!(std::ptr::eq(inherited.rule(), parent.rule()));
        }
    }
    assert_ne!(
        router
            .resolve("/files/special", &Method::POST)
            .unwrap()
            .id(),
        parent.id()
    );
    assert_eq!(
        router
            .resolve("/files/special", &Method::DELETE)
            .unwrap_err(),
        ResolveError::MethodNotConfigured
    );
}

#[test]
fn every_intermediate_path_controls_continuation() {
    for middle_inherits in [false, true] {
        for reverse in [false, true] {
            let mut paths = vec![
                PathRegistration::subtree("/").method(Method::GET, "root-get"),
                PathRegistration::subtree("/files")
                    .fallback_inherit(middle_inherits)
                    .method(Method::POST, "files-post"),
                PathRegistration::path("/files/private")
                    .fallback_inherit(true)
                    .method(Method::PUT, "private-put"),
            ];
            if reverse {
                paths.reverse();
            }
            let router = RuleRouter::from_registrations("default", config(), paths).unwrap();
            let result = router.resolve("/files/private", &Method::GET);
            if middle_inherits {
                assert_eq!(*result.unwrap().rule(), "root-get");
            } else {
                assert_eq!(result.unwrap_err(), ResolveError::MethodNotConfigured);
            }
            assert_eq!(
                *router
                    .resolve("/files/private", &Method::POST)
                    .unwrap()
                    .rule(),
                "files-post"
            );
            assert_eq!(
                *router
                    .resolve("/files/private", &Method::PUT)
                    .unwrap()
                    .rule(),
                "private-put"
            );
        }
    }
}

#[test]
fn closer_all_beats_farther_method_and_local_method_beats_all() {
    let router = RuleRouter::builder("default", config())
        .register_subtree("/", |p| p.method(Method::GET, "root-get"))
        .register_subtree("/files", |p| {
            p.all("files-all").method(Method::POST, "files-post")
        })
        .register_path("/files/private", |p| {
            p.fallback_inherit(true)
                .method(Method::DELETE, "private-delete")
        })
        .build()
        .unwrap();
    for (method, expected) in [
        (Method::GET, "files-all"),
        (Method::POST, "files-post"),
        (Method::DELETE, "private-delete"),
    ] {
        assert_eq!(
            *router.resolve("/files/private", &method).unwrap().rule(),
            expected
        );
    }
}

#[test]
fn inheritance_uses_matching_precedence_not_directory_ancestors() {
    let router = RuleRouter::builder("default", config())
        .register_path("/files", |p| p.all("not-a-parent-match"))
        .register_path("/{tenant}/private", |p| p.method(Method::GET, "wildcard"))
        .register_path("/files/{*rest}", |p| p.fallback_inherit(true))
        .register_path("/files/private", |p| p.fallback_inherit(true))
        .build()
        .unwrap();
    assert_eq!(
        *router
            .resolve("/files/private", &Method::GET)
            .unwrap()
            .rule(),
        "wildcard"
    );
    assert_eq!(
        router.resolve("/files/private", &Method::POST).unwrap_err(),
        ResolveError::MethodNotConfigured
    );
    assert!(
        router
            .resolve("/files/other", &Method::GET)
            .unwrap()
            .is_default()
    );
}

#[test]
fn no_rules_can_block_or_inherit_including_root_and_trailing_slash() {
    for mode in [
        GuardMode::RejectAmbiguous,
        GuardMode::RequireCanonical,
        GuardMode::Disabled,
    ] {
        for inherit in [false, true] {
            let router = RuleRouter::builder("default", config().with_mode(mode))
                .register_subtree("/", |p| p.fallback_inherit(inherit))
                .build()
                .unwrap();
            for path in ["/", "/files", "/files/"] {
                for method in [
                    Method::GET,
                    Method::POST,
                    Method::from_bytes(b"CUSTOM").unwrap(),
                ] {
                    if inherit {
                        assert!(router.resolve(path, &method).unwrap().is_default());
                    } else {
                        assert_eq!(
                            router.resolve(path, &method).unwrap_err(),
                            ResolveError::MethodNotConfigured
                        );
                        assert_eq!(
                            router.inspect_raw(path, &method).unwrap(),
                            RawMatch::MethodDenied
                        );
                        assert_eq!(
                            router.explain(path, &method).unwrap().denial,
                            Some(ResolveError::MethodNotConfigured)
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn transformed_method_denials_remain_rule_boundaries() {
    let router = RuleRouter::builder("public", config())
        .register_subtree("/files", |p| p.method(Method::GET, "read"))
        .register_path("/files/private", |p| p.method(Method::POST, "write"))
        .build()
        .unwrap();
    assert_eq!(
        router
            .resolve("/files/%70rivate", &Method::GET)
            .unwrap_err(),
        ResolveError::DecodeRuleChange
    );
    let explanation = router.explain("/files/a%2fb", &Method::GET).unwrap();
    let coverage = explanation.structural.unwrap();
    assert!(coverage.includes_method_denial);
    assert!(!coverage.includes_default);
    assert_eq!(coverage.registrations, [0]);
}

#[test]
fn path_tables_validate_duplicates_and_empty_definitions() {
    for path in [
        PathRegistration::path("/x")
            .method(Method::GET, 1)
            .method(Method::GET, 2),
        PathRegistration::path("/x").all(1).all(2),
        PathRegistration::path("/x").methods([], 1),
        PathRegistration::patterns(Vec::<String>::new()).all(1),
        PathRegistration::path("/x/../y").fallback_inherit(true),
    ] {
        assert!(RuleRouter::from_registrations(0, config(), [path]).is_err());
    }
    assert!(
        RuleRouter::builder(0, config())
            .register_path("/x", |p| p.fallback_inherit(true).method(Method::GET, 1))
            .register_path("/x", |p| p.method(Method::POST, 2))
            .build()
            .is_err()
    );
    // Even a path with no concrete rule can override an exclusive tail by denying.
    assert!(
        RuleRouter::builder(0, config())
            .register_exclusive_subtree("/files", |p| p.all(1))
            .register_path("/files/private", |p| p)
            .build()
            .is_err()
    );
}

#[test]
fn diagnostics_report_the_stopping_path_even_without_concrete_rules() {
    let router = RuleRouter::builder("default", config())
        .register_subtree("/", |p| p.all("root"))
        .register_subtree("/files", |p| p)
        .register_path("/files/private", |p| p.fallback_inherit(true))
        .build()
        .unwrap();
    let diagnostics = router.diagnostics();
    assert!(!diagnostics.is_empty());
    for gap in diagnostics {
        assert_ne!(gap.pattern, "/files/private");
        assert_eq!(gap.shadowed_registration, 0);
        for method in gap.methods {
            assert_eq!(
                router.resolve(&gap.example_path, &method).unwrap_err(),
                ResolveError::MethodNotConfigured
            );
        }
    }
}
