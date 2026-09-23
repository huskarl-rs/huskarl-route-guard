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
        ResolveError::Probe("custom"),
        ResolveError::TooLong,
    ] {
        assert_eq!(error.kind(), ResolveErrorKind::InvalidInput);
    }
}
