use huskarl_route_guard::{ResolveError, ResolveErrorKind, StructuralClass};

#[test]
fn response_categories_preserve_policy_and_internal_failures() {
    assert_eq!(
        ResolveError::InvalidRuleId.kind(),
        ResolveErrorKind::Internal
    );
    assert_eq!(
        ResolveError::MethodNotConfigured.kind(),
        ResolveErrorKind::PolicyDenied
    );
    for error in [
        ResolveError::InvalidPathInput,
        ResolveError::Structural(StructuralClass::Separator),
        ResolveError::CaseFoldRuleChange,
        ResolveError::DecodeRuleChange,
        ResolveError::NonCanonical(StructuralClass::Separator),
        ResolveError::NonCanonicalEscape,
        ResolveError::Probe("custom".into()),
        ResolveError::TooLong,
    ] {
        assert_eq!(error.kind(), ResolveErrorKind::InvalidInput);
    }
}

#[test]
fn runtime_probe_name_survives_router_drop() {
    use huskarl_route_guard::{
        CaseSensitivity, DecodeDepth, GuardConfig, RuleRouter, StructuralClasses, StructuralProbe,
    };
    struct ConfiguredProbe(String);
    impl StructuralProbe for ConfiguredProbe {
        fn name(&self) -> &str {
            &self.0
        }
        fn matches(&self, path: &str) -> bool {
            path == "*"
        }
    }
    let name = ["configured", "probe"].join("-");
    let router = RuleRouter::builder(
        (),
        GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne).with_structural_classes(
            StructuralClasses::new().with_probe(ConfiguredProbe(name.clone())),
        ),
    )
    .build()
    .unwrap();
    let error = router.resolve("*", &http::Method::GET).unwrap_err();
    drop(router);
    assert_eq!(error, ResolveError::Probe(name));
    assert!(error.to_string().contains("configured-probe"));
    assert_eq!(error.kind(), ResolveErrorKind::InvalidInput);
}

#[test]
fn asterisk_selects_default_for_any_method_when_checks_pass() {
    use huskarl_route_guard::{CaseSensitivity, DecodeDepth, GuardConfig, GuardMode, RuleRouter};
    for mode in [
        GuardMode::Disabled,
        GuardMode::RejectAmbiguous,
        GuardMode::RequireCanonical,
    ] {
        let router = RuleRouter::builder(
            "default",
            GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne).with_mode(mode),
        )
        .register_path("/", |p| p.all("root"))
        .build()
        .unwrap();
        for method in [
            http::Method::OPTIONS,
            http::Method::GET,
            http::Method::POST,
            http::Method::from_bytes(b"CUSTOM").unwrap(),
        ] {
            assert_eq!(*router.resolve("*", &method).unwrap().rule(), "default");
            assert!(router.inspect_raw("*", &method).unwrap().is_default());
        }
    }
}
