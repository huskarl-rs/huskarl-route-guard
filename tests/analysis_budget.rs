use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use huskarl_route_guard::{
    CaseSensitivity, DecodeDepth, GuardConfig, GuardMode, ResolveError, RuleRouter,
    StructuralClasses, StructuralProbe,
};

fn router(config: GuardConfig) -> RuleRouter<()> {
    RuleRouter::builder((), config)
        .register_subtree("/", |path| path.all(()))
        .build()
        .expect("valid routes")
}

#[test]
fn budget_counts_original_bytes_and_can_be_raised_for_encoded_keys() {
    let config = GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToTwo);
    assert_eq!(config.max_analysis_path_len, 8192);
    let path = format!("/{}%2561", "a".repeat(8192));
    assert_eq!(
        router(config.clone())
            .resolve(&path, &http::Method::GET)
            .unwrap_err(),
        ResolveError::TooLong
    );
    let at_limit = router(config.clone().with_max_analysis_path_len(path.len()));
    assert!(at_limit.resolve(&path, &http::Method::GET).is_ok());
    assert_eq!(
        router(config.with_max_analysis_path_len(path.len() - 1))
            .resolve(&path, &http::Method::GET)
            .unwrap_err(),
        ResolveError::TooLong
    );
}

#[test]
fn budget_applies_to_each_analysis_mode_but_not_clean_paths() {
    for mode in [GuardMode::RejectAmbiguous, GuardMode::RequireCanonical] {
        let config = GuardConfig::new(CaseSensitivity::Insensitive, DecodeDepth::UpToOne)
            .with_mode(mode)
            .with_max_analysis_path_len(4);
        let router = router(config);
        for path in ["/aaaa%61", "/aaaa//b", "/AAAA"] {
            assert_eq!(
                router.resolve(path, &http::Method::GET).unwrap_err(),
                ResolveError::TooLong,
                "{mode:?}: {path}"
            );
        }
        assert!(router.resolve("/aaaaaaa", &http::Method::GET).is_ok());
    }
    let zero = router(
        GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne)
            .with_max_analysis_path_len(0),
    );
    assert!(zero.resolve("/clean", &http::Method::GET).is_ok());
    assert_eq!(
        zero.resolve("/%61", &http::Method::GET).unwrap_err(),
        ResolveError::TooLong
    );
}

struct CountingProbe(Arc<AtomicUsize>);
impl StructuralProbe for CountingProbe {
    fn name(&self) -> &'static str {
        "counting"
    }
    fn matches(&self, path: &str) -> bool {
        self.0.fetch_add(1, Ordering::Relaxed);
        path.ends_with('x')
    }
}

#[test]
fn probes_never_receive_oversized_paths_even_when_they_would_not_match() {
    for mode in [
        GuardMode::RejectAmbiguous,
        GuardMode::RequireCanonical,
        GuardMode::Disabled,
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let config = GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne)
            .with_mode(mode)
            .with_max_analysis_path_len(4)
            .with_structural_classes(
                StructuralClasses::new().with_probe(CountingProbe(calls.clone())),
            );
        let router = router(config);
        for path in ["/aaaa", "/aaax"] {
            let result = router.resolve(path, &http::Method::GET);
            if mode == GuardMode::Disabled {
                assert!(result.is_ok());
            } else {
                assert_eq!(result.unwrap_err(), ResolveError::TooLong);
            }
        }
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(router.resolve("/aaa", &http::Method::GET).is_ok());
        let result = router.resolve("/aax", &http::Method::GET);
        if mode == GuardMode::Disabled {
            assert!(result.is_ok());
            assert_eq!(calls.load(Ordering::Relaxed), 0);
        } else {
            assert_eq!(result.unwrap_err(), ResolveError::Probe("counting".into()));
            assert_eq!(calls.load(Ordering::Relaxed), 2);
        }
    }
}

#[test]
fn analysis_budget_is_inclusive_for_structural_and_case_checks() {
    for path in ["/a//b", "/a/../b", "/a;b", "/AAAA", "/a%2fb"] {
        for mode in [GuardMode::RejectAmbiguous, GuardMode::RequireCanonical] {
            for limit in [path.len() - 1, path.len(), path.len() + 1] {
                let router = router(
                    GuardConfig::new(CaseSensitivity::Insensitive, DecodeDepth::UpToOne)
                        .with_mode(mode)
                        .with_max_analysis_path_len(limit),
                );
                let result = router.resolve(path, &http::Method::GET);
                if limit < path.len() {
                    assert_eq!(
                        result.unwrap_err(),
                        ResolveError::TooLong,
                        "{path}, {mode:?}"
                    );
                } else if mode == GuardMode::RejectAmbiguous {
                    assert!(result.is_ok(), "{path}, {limit}: {result:?}");
                } else {
                    assert!(
                        matches!(result, Err(ResolveError::NonCanonical(_))),
                        "{path}, {limit}: {result:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn structural_explanations_include_paths_exactly_at_the_analysis_budget() {
    let path = "/admin//x";
    for limit in [path.len() - 1, path.len(), path.len() + 1] {
        let router = RuleRouter::builder(
            (),
            GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne)
                .with_max_analysis_path_len(limit),
        )
        .register_path("/admin/x", |p| p.all(()))
        .build()
        .unwrap();
        let explanation = router.explain(path, &http::Method::GET).unwrap();
        if limit < path.len() {
            assert_eq!(explanation.denial, Some(ResolveError::TooLong));
            assert!(explanation.structural.is_none());
        } else {
            assert!(matches!(
                explanation.denial,
                Some(ResolveError::Structural(_))
            ));
            assert!(explanation.structural.is_some());
        }
    }
}
