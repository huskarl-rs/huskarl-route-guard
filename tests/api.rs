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
