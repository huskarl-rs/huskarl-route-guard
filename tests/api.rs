use http::Method;
use huskarl_route_guard::{
    CaseSensitivity, DecodeDepth, GuardConfig, GuardMode, Registration, ResolveError, RuleRouter,
    StructuralClasses,
};

fn config() -> GuardConfig {
    GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne)
}

#[test]
fn grouped_patterns_share_identity_but_equal_values_do_not() {
    let grouped = RuleRouter::builder("default", config())
        .register(Registration::patterns(["/a", "/%61"], "same-value"))
        .build()
        .unwrap();
    assert_eq!(
        grouped.resolve("/a", &Method::GET).unwrap().id(),
        grouped.resolve("/%61", &Method::GET).unwrap().id()
    );

    let separate = RuleRouter::builder("default", config())
        .route("/a", "same-value")
        .route("/%61", "same-value")
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
        Registration::route("/health", "health").for_methods([Method::GET, Method::HEAD]),
        Registration::exclusive_subtree("/files", "files"),
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
    assert!(
        built
            .resolve("/health", &Method::POST)
            .unwrap()
            .is_default()
    );
}

#[test]
fn diagnostics_validate_input_without_authorizing_ambiguous_paths() {
    let router = RuleRouter::builder("public", config())
        .subtree("/admin", "admin")
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
        .subtree("/admin", "admin")
        .build()
        .unwrap();
    assert!(default.resolve("/admin\\secret", &Method::GET).is_err());
    assert!(default.resolve("/admin/a%2fb", &Method::GET).is_ok());
    let strict = RuleRouter::builder("public", config.with_mode(GuardMode::RequireCanonical))
        .subtree("/admin", "admin")
        .build()
        .unwrap();
    assert!(strict.resolve("/admin/a%2fb", &Method::GET).is_err());
}

#[test]
fn adding_a_literal_subtree_can_restore_rule_agreement() {
    let existing = Registration::subtree("/{tenant}/private", "private");
    let before = RuleRouter::builder("default", config())
        .register(existing.clone())
        .build()
        .unwrap();
    let after = RuleRouter::builder("default", config())
        .register(existing)
        .subtree("/files", "files")
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
            let mut protected = Registration::exclusive_subtree(exclusive, "exclusive");
            let mut other = Registration::route(nested, "override");
            if let Some((a, b)) = methods {
                protected = protected.for_methods(a);
                other = other.for_methods(b);
            }
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
                Registration::exclusive_subtree(exclusive, "exclusive"),
                Registration::route(other, "other"),
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
        .exclusive_subtree("/{tenant}", "all-methods")
        .register(Registration::subtree("/{name}", "get").for_methods(Method::GET))
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
        .exclusive_subtree("/files", "fallback")
        .register(Registration::subtree("/files", "read").for_methods([Method::GET, Method::HEAD]))
        .register(Registration::subtree("/files", "write").for_methods(Method::POST))
        .register(Registration::subtree("/files", "custom").for_methods(custom.clone()))
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
    let read = Registration::subtree("/files", "read").for_methods(Method::GET);
    let original = RuleRouter::builder("default", config())
        .register(read.clone())
        .build()
        .unwrap();
    let same_paths = RuleRouter::builder("default", config())
        .register(read.clone())
        .register(Registration::subtree("/files", "write").for_methods(Method::POST))
        .build()
        .unwrap();
    assert_eq!(
        original.resolve("/files/a%2fb", &Method::GET),
        same_paths.resolve("/files/a%2fb", &Method::GET)
    );
    assert!(
        original
            .resolve("/files/a%2fb", &Method::POST)
            .unwrap()
            .is_default()
    );

    for nested_method in [Method::GET, Method::POST] {
        let nested = RuleRouter::builder("default", config())
            .register(read.clone())
            .register(
                Registration::route("/files/private", "private").for_methods(nested_method.clone()),
            )
            .build()
            .unwrap();
        // GET either reaches another GET rule, or the default at a POST-only
        // terminal. Both are different from the surrounding GET subtree.
        assert!(nested.resolve("/files/a%2fb", &Method::GET).is_err());
        assert!(nested.resolve("/files/private;x", &Method::GET).is_err());
        if nested_method == Method::POST {
            assert!(
                nested
                    .resolve("/files/private", &Method::GET)
                    .unwrap()
                    .is_default()
            );
        }
    }
}

#[test]
fn structural_coverage_respects_method_gaps_in_a_shadowing_branch() {
    let ancestor = Registration::subtree("/{tenant}", "read").for_methods(Method::GET);
    let complete = RuleRouter::builder("default", config())
        .register(ancestor.clone())
        .register(Registration::subtree("/files", "write").for_methods(Method::POST))
        .build()
        .unwrap();
    // The entire literal branch selects default for GET; it must not fall back
    // to the ancestor's wildcard, even though that branch has a GET rule.
    assert!(
        complete
            .resolve("/files/a%2fb", &Method::GET)
            .unwrap()
            .is_default()
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
        .register(Registration::route("/files/{*rest}", "write").for_methods(Method::POST))
        .build()
        .unwrap();
    // Without the trailing-slash terminal, /files/ reaches the wildcard's GET
    // rule, while /files/key claims the POST-only catch-all and defaults for GET.
    assert_eq!(
        *incomplete.resolve("/files/", &Method::GET).unwrap().rule(),
        "read"
    );
    assert!(
        incomplete
            .resolve("/files/key", &Method::GET)
            .unwrap()
            .is_default()
    );
    assert!(incomplete.resolve("/files/a%2fb", &Method::GET).is_err());
}
