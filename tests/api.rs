use http::Method;
use huskarl_route_guard::{
    CaseSensitivity, DecodeDepth, GuardConfig, GuardMode, PathRegistration, ResolveError,
    RuleRouter, StructuralClasses,
};

fn config() -> GuardConfig {
    GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne)
}

#[test]
fn method_gap_diagnostics_report_witnesses_without_changing_resolution() {
    let router = RuleRouter::builder("default", config())
        .register_subtree("/files", |path| path.all("files"))
        .register(PathRegistration::path("/files/special").method(Method::POST, "post"))
        .build()
        .unwrap();
    let diagnostics = router.diagnostics();
    assert_eq!(diagnostics.len(), 1);
    let gap = &diagnostics[0];
    assert_eq!(gap.pattern, "/files/special");
    assert_eq!(gap.example_path, "/files/special");
    assert_eq!(gap.shadowed_registration, 0);
    assert!(gap.methods.contains(&Method::GET));
    assert!(!gap.methods.contains(&Method::POST));
    for method in &gap.methods {
        assert_eq!(
            router.resolve(&gap.example_path, method).unwrap_err(),
            ResolveError::MethodNotConfigured
        );
    }
    assert!(gap.to_string().contains("encoded paths"));
    assert!(
        router
            .resolve("/files/hello%2fworld", &Method::GET)
            .is_err()
    );
    assert_eq!(router.diagnostics(), diagnostics);
}

#[test]
fn method_gap_diagnostics_honor_same_terminal_rules_and_identity_repairs() {
    let repaired = RuleRouter::builder("default", config())
        .register(
            PathRegistration::subtree("/files")
                .with_path("/files/special")
                .all("files"),
        )
        .register(PathRegistration::path("/files/special").method(Method::POST, "post"))
        .build()
        .unwrap();
    assert!(repaired.diagnostics().is_empty());
    assert!(
        repaired
            .resolve("/files/hello%2fworld", &Method::GET)
            .is_ok()
    );

    let get_only = RuleRouter::builder("default", config())
        .register(PathRegistration::subtree("/files").method(Method::GET, "files"))
        .build()
        .unwrap();
    assert!(get_only.diagnostics().is_empty());
    assert!(
        get_only
            .resolve("/files/hello%2fworld", &Method::GET)
            .is_ok()
    );
}

#[test]
fn method_gap_diagnostics_follow_overlapping_branches_and_extension_methods() {
    let custom = Method::from_bytes(b"PURGE").unwrap();
    let registrations = [
        PathRegistration::path("/{tenant}/special").method(custom.clone(), "fallback"),
        PathRegistration::path("/files/{name}").method(Method::POST, "post"),
        PathRegistration::path("/files/{other}").method(Method::GET, "get"),
    ];
    for mode in [GuardMode::RejectAmbiguous, GuardMode::Disabled] {
        let router = RuleRouter::from_registrations(
            "default",
            config().with_mode(mode),
            registrations.clone(),
        )
        .unwrap();
        let gaps = router.diagnostics();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].pattern, "/files/{name}");
        assert_eq!(gaps[0].example_path, "/files/special");
        assert_eq!(gaps[0].methods, std::slice::from_ref(&custom));
        assert_eq!(gaps[0].shadowed_registration, 0);
    }
}

#[test]
fn method_gap_diagnostics_ignore_unrelated_and_fully_shadowed_patterns() {
    let router = RuleRouter::builder("default", config())
        .register_path("/{tenant}/special", |path| path.all("fallback"))
        .register(PathRegistration::path("/files/{name}").method(Method::POST, "post"))
        .register_path("/files/special", |path| path.all("override"))
        .register(PathRegistration::path("/unrelated").method(Method::POST, "post"))
        .build()
        .unwrap();
    assert!(router.diagnostics().is_empty());
}

#[test]
fn raw_inspection_exposes_only_identity_and_explanations_attribute_method_gaps() {
    let router = RuleRouter::builder("default", config())
        .register_subtree("/files", |path| path.all("files"))
        .register(PathRegistration::path("/files/special").method(Method::POST, "post"))
        .build()
        .unwrap();
    let path = "/files/hello%2fworld";
    assert_eq!(
        router.inspect_raw(path, &Method::GET).unwrap(),
        huskarl_route_guard::RawMatch::Matched { id: 0 }
    );
    let explanation = router.explain(path, &Method::GET).unwrap();
    assert_eq!(explanation.denial, router.resolve(path, &Method::GET).err());
    assert_eq!(explanation.raw_match.id(), Some(0));
    let structural = explanation.structural.unwrap();
    assert_eq!(structural.anchor, "/files/");
    assert_eq!(structural.registrations, [0]);
    assert!(!structural.includes_default);
    assert!(structural.includes_method_denial);

    let post = router
        .explain(path, &Method::POST)
        .unwrap()
        .structural
        .unwrap();
    assert_eq!(post.registrations, [0, 1]);
    assert!(!post.includes_default);
}

#[test]
fn explanations_preserve_denial_order_and_omit_inapplicable_anchors() {
    for mode in [
        GuardMode::RejectAmbiguous,
        GuardMode::RequireCanonical,
        GuardMode::Disabled,
    ] {
        let router = RuleRouter::builder("default", config().with_mode(mode))
            .register_subtree("/files", |path| path.all("files"))
            .register_path("/admin", |path| path.all("admin"))
            .build()
            .unwrap();
        for path in ["/files/key", "/files/a%2fb", "/files/%00", "/%61dmin"] {
            let explanation = router.explain(path, &Method::GET).unwrap();
            assert_eq!(explanation.denial, router.resolve(path, &Method::GET).err());
            assert!(explanation.structural.is_none(), "{mode:?}: {path}");
        }
        assert_eq!(
            router.explain("/files?query", &Method::GET),
            Err(ResolveError::InvalidPathInput)
        );
    }
    let router = RuleRouter::builder(
        "default",
        GuardConfig::new(CaseSensitivity::Insensitive, DecodeDepth::UpToOne),
    )
    .register_path("/admin", |path| path.all("admin"))
    .build()
    .unwrap();
    let explanation = router.explain("/ADMIN", &Method::GET).unwrap();
    assert_eq!(explanation.denial, Some(ResolveError::CaseFoldRuleChange));
    assert!(explanation.structural.is_none());
}

#[test]
fn grouped_patterns_share_identity_but_equal_values_do_not() {
    let grouped = RuleRouter::builder("default", config())
        .register(PathRegistration::patterns(["/a", "/%61"]).all("same-value"))
        .build()
        .unwrap();
    assert_eq!(
        grouped.resolve("/a", &Method::GET).unwrap().id(),
        grouped.resolve("/%61", &Method::GET).unwrap().id()
    );

    let separate = RuleRouter::builder("default", config())
        .register_path("/a", |path| path.all("same-value"))
        .register_path("/%61", |path| path.all("same-value"))
        .build()
        .unwrap();
    assert_eq!(
        separate.resolve("/%61", &Method::GET),
        Err(ResolveError::DecodeRuleChange)
    );
}

#[test]
fn iterator_and_builder_preserve_methods_and_registration_order() {
    let registrations = [
        PathRegistration::path("/health").methods([Method::GET, Method::HEAD], "health"),
        PathRegistration::exclusive_subtree("/files").all("files"),
    ];
    let direct =
        RuleRouter::from_registrations("default", config(), registrations.clone()).unwrap();
    let built = RuleRouter::builder("default", config())
        .register_all(registrations)
        .build()
        .unwrap();
    for (path, method) in [
        ("/health", Method::GET),
        ("/health", Method::POST),
        ("/files/a%2fb", Method::GET),
    ] {
        assert_eq!(direct.resolve(path, &method), built.resolve(path, &method));
    }
    assert_eq!(
        built.resolve("/health", &Method::POST).unwrap_err(),
        ResolveError::MethodNotConfigured
    );
}

#[test]
fn diagnostics_validate_input_without_authorizing_ambiguous_paths() {
    let router = RuleRouter::builder("public", config())
        .register_subtree("/admin", |path| path.all("admin"))
        .build()
        .unwrap();
    assert!(
        router
            .inspect_raw("/admin%2fusers", &Method::GET)
            .unwrap()
            .is_default()
    );
    assert!(router.resolve("/admin%2fusers", &Method::GET).is_err());
    assert_eq!(
        router.inspect_raw("/admin?x=1", &Method::GET),
        Err(ResolveError::InvalidPathInput)
    );
}

#[test]
fn reused_configuration_carries_enforcement_and_structural_options() {
    let config = config().with_structural_classes(StructuralClasses::new().with_backslash());
    let default = RuleRouter::builder("public", config.clone())
        .register_subtree("/admin", |path| path.all("admin"))
        .build()
        .unwrap();
    assert!(default.resolve("/admin\\secret", &Method::GET).is_err());
    assert!(default.resolve("/admin/a%2fb", &Method::GET).is_ok());
    let strict = RuleRouter::builder("public", config.with_mode(GuardMode::RequireCanonical))
        .register_subtree("/admin", |path| path.all("admin"))
        .build()
        .unwrap();
    assert!(strict.resolve("/admin/a%2fb", &Method::GET).is_err());
}

#[test]
fn adding_a_literal_subtree_can_restore_rule_agreement() {
    let existing = PathRegistration::subtree("/{tenant}/private").all("private");
    let before = RuleRouter::builder("default", config())
        .register(existing.clone())
        .build()
        .unwrap();
    let after = RuleRouter::builder("default", config())
        .register(existing)
        .register_subtree("/files", |path| path.all("files"))
        .build()
        .unwrap();

    assert!(before.resolve("/files/a%2fb", &Method::GET).is_err());
    let raw = after.resolve("/files/a%2fb", &Method::GET).unwrap();
    assert_eq!(*raw.rule(), "files");
    assert_eq!(raw, after.resolve("/files/a/b", &Method::GET).unwrap());
    // The literal subtree also shadows the formerly reachable private branch.
    assert_eq!(
        raw,
        after.resolve("/files/private/key", &Method::GET).unwrap()
    );
    assert_eq!(
        *after
            .resolve("/other/private/key", &Method::GET)
            .unwrap()
            .rule(),
        "private"
    );
}

#[test]
fn exclusive_subtrees_reject_overriding_paths_in_either_registration_order() {
    for (exclusive, nested) in [
        ("/files", "/files/private"),
        ("/files/", "/files/{name}"),
        ("/{tenant}", "/files/private"),
        ("/{tenant}", "/files/private/"),
        ("/{tenant}", "/files/{*rest}"),
        ("/{tenant}/files", "/acme/files/private"),
        ("/{tenant}/files", "/acme/{folder}/private"),
        ("/{tenant}/files", "/acme/{*rest}"),
        ("/files/{folder}", "/files/private/key"),
        ("/{tenant}/{folder}", "/acme/{folder}/{*rest}"),
        ("/", "/health"),
    ] {
        // Even disjoint method sets cannot make a path override safe: path
        // precedence is resolved before method lookup.
        for methods in [None, Some((Method::GET, Method::POST))] {
            let protected = PathRegistration::exclusive_subtree(exclusive);
            let other = PathRegistration::path(nested);
            let (protected, other) = if let Some((a, b)) = methods {
                (
                    protected.method(a, "exclusive"),
                    other.method(b, "override"),
                )
            } else {
                (protected.all("exclusive"), other.all("override"))
            };
            for reverse in [false, true] {
                let mut registrations = [protected.clone(), other.clone()];
                if reverse {
                    registrations.reverse();
                }
                let result = RuleRouter::from_registrations("default", config(), registrations);
                assert!(
                    matches!(
                        result,
                        Err(huskarl_route_guard::RuleRouterError::Route { .. })
                    ),
                    "exclusive {exclusive}, nested {nested}, reverse {reverse}: {result:?}"
                );
            }
        }
    }
}

#[test]
fn exclusive_subtrees_allow_unrelated_and_lower_priority_routes() {
    for (exclusive, other, protected_path) in [
        ("/files", "/health", "/files/key"),
        ("/files", "/files-extra/private", "/files/key"),
        ("/files", "/{*rest}", "/files/key"),
        ("/files", "/{tenant}/private", "/files/private"),
        (
            "/files/{folder}",
            "/{tenant}/private/key",
            "/files/private/key",
        ),
        ("/{tenant}/files", "/acme/other/key", "/acme/files/key"),
        ("/{tenant}/files", "/{tenant}/{*rest}", "/acme/files/key"),
        ("/{tenant}/files", "/acme", "/acme/files/key"),
        ("/files/", "/files", "/files/key"),
    ] {
        for reverse in [false, true] {
            let mut registrations = [
                PathRegistration::exclusive_subtree(exclusive).all("exclusive"),
                PathRegistration::path(other).all("other"),
            ];
            if reverse {
                registrations.reverse();
            }
            let router = RuleRouter::from_registrations("default", config(), registrations)
                .unwrap_or_else(|e| panic!("exclusive {exclusive}, other {other}: {e}"));
            assert_eq!(
                *router.resolve(protected_path, &Method::GET).unwrap().rule(),
                "exclusive"
            );
        }
    }
}

#[test]
fn exclusive_subtrees_allow_method_rules_at_the_same_paths() {
    let router = RuleRouter::builder("default", config())
        .register_exclusive_subtree("/{tenant}", |path| path.all("all-methods"))
        .register(PathRegistration::subtree("/{name}").method(Method::GET, "get"))
        .build()
        .unwrap();
    for path in ["/files", "/files/", "/files/key"] {
        assert_eq!(*router.resolve(path, &Method::GET).unwrap().rule(), "get");
        assert_eq!(
            *router.resolve(path, &Method::POST).unwrap().rule(),
            "all-methods"
        );
    }
}

#[test]
fn structural_coverage_uses_each_requests_method() {
    let custom = Method::from_bytes(b"READ-KEY").unwrap();
    let router = RuleRouter::builder("default", config())
        .register_exclusive_subtree("/files", |path| path.all("fallback"))
        .register(PathRegistration::subtree("/files").methods([Method::GET, Method::HEAD], "read"))
        .register(PathRegistration::subtree("/files").method(Method::POST, "write"))
        .register(PathRegistration::subtree("/files").method(custom.clone(), "custom"))
        .build()
        .unwrap();
    for (method, expected) in [
        (Method::GET, "read"),
        (Method::HEAD, "read"),
        (Method::POST, "write"),
        (custom, "custom"),
        (Method::DELETE, "fallback"),
        (Method::from_bytes(b"OTHER").unwrap(), "fallback"),
    ] {
        for path in [
            "/files/a%2fb",
            "/files/a/b",
            "/files/a;v=1",
            "/files/a/../b",
        ] {
            assert_eq!(*router.resolve(path, &method).unwrap().rule(), expected);
        }
        assert!(router.resolve("/files/../outside", &method).is_err());
        assert!(router.resolve("/files/a%00b", &method).is_err());
    }
}

#[test]
fn another_method_only_affects_get_when_it_changes_path_precedence() {
    let read = PathRegistration::subtree("/files").method(Method::GET, "read");
    let original = RuleRouter::builder("default", config())
        .register(read.clone())
        .build()
        .unwrap();
    let same_paths = RuleRouter::builder("default", config())
        .register(read.clone())
        .register(PathRegistration::subtree("/files").method(Method::POST, "write"))
        .build()
        .unwrap();
    assert_eq!(
        original.resolve("/files/a%2fb", &Method::GET),
        same_paths.resolve("/files/a%2fb", &Method::GET)
    );
    assert_eq!(
        original.resolve("/files/a%2fb", &Method::POST).unwrap_err(),
        ResolveError::MethodNotConfigured
    );

    for nested_method in [Method::GET, Method::POST] {
        let nested = RuleRouter::builder("default", config())
            .register(read.clone())
            .register(
                PathRegistration::path("/files/private").method(nested_method.clone(), "private"),
            )
            .build()
            .unwrap();
        // GET either reaches another GET rule, or a denial at a POST-only
        // terminal. Both are different from the surrounding GET subtree.
        assert!(nested.resolve("/files/a%2fb", &Method::GET).is_err());
        assert!(nested.resolve("/files/private;x", &Method::GET).is_err());
        if nested_method == Method::POST {
            assert_eq!(
                nested.resolve("/files/private", &Method::GET).unwrap_err(),
                ResolveError::MethodNotConfigured
            );
        }
    }
}

#[test]
fn structural_coverage_respects_method_gaps_in_a_shadowing_branch() {
    let ancestor = PathRegistration::subtree("/{tenant}").method(Method::GET, "read");
    let complete = RuleRouter::builder("default", config())
        .register(ancestor.clone())
        .register(PathRegistration::subtree("/files").method(Method::POST, "write"))
        .build()
        .unwrap();
    // The entire literal branch denies GET; it must not fall back
    // to the ancestor's wildcard, even though that branch has a GET rule.
    assert_eq!(
        complete.resolve("/files/a%2fb", &Method::GET).unwrap_err(),
        ResolveError::MethodNotConfigured
    );
    assert_eq!(
        *complete
            .resolve("/files/a%2fb", &Method::POST)
            .unwrap()
            .rule(),
        "write"
    );

    let incomplete = RuleRouter::builder("default", config())
        .register(ancestor)
        .register(PathRegistration::path("/files/{*rest}").method(Method::POST, "write"))
        .build()
        .unwrap();
    // Without the trailing-slash terminal, /files/ reaches the wildcard's GET
    // rule, while /files/key claims the POST-only catch-all and denies GET.
    assert_eq!(
        *incomplete.resolve("/files/", &Method::GET).unwrap().rule(),
        "read"
    );
    assert_eq!(
        incomplete.resolve("/files/key", &Method::GET).unwrap_err(),
        ResolveError::MethodNotConfigured
    );
    assert!(incomplete.resolve("/files/a%2fb", &Method::GET).is_err());
}

#[test]
fn composed_paths_share_method_identities_and_subtree_boundaries() {
    let router = RuleRouter::builder("default", config())
        .register(
            PathRegistration::path("/health")
                .method(Method::GET, "read")
                .with_subtree("/files")
                .with_subtree("/archive/")
                .with_path("/ready")
                .method(Method::POST, "write"),
        )
        .build()
        .unwrap();
    for method in [Method::GET, Method::POST] {
        let expected = router.resolve("/health", &method).unwrap();
        for path in [
            "/ready",
            "/files",
            "/files/",
            "/files/a%2fb",
            "/archive/",
            "/archive/a%2fb",
        ] {
            assert_eq!(router.resolve(path, &method).unwrap(), expected, "{path}");
        }
        assert_eq!(
            *router.resolve("/archive", &method).unwrap().rule(),
            "default"
        );
    }
    assert_ne!(
        router.resolve("/health", &Method::GET).unwrap().id(),
        router.resolve("/health", &Method::POST).unwrap().id()
    );
    assert_eq!(
        router.resolve("/ready", &Method::DELETE).unwrap_err(),
        ResolveError::MethodNotConfigured
    );
}
