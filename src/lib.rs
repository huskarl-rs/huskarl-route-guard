#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(
    not(test),
    deny(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used
    )
)]
#![warn(clippy::pedantic)]

//! Match a request path to an authorization rule. Reject it if downstream path
//! parsing could select a different rule. The guard checks the parsing behaviors
//! you configure and never rewrites the path.
//!
//! For example, `/admin%2fusers` may select a public default rule here but become
//! `/admin/users` after downstream decoding. This crate detects possible rule
//! changes before your application enforces the selected policy and forwards the
//! request with its path unchanged.
//!
//! The crate returns a rule or a denial; it does not enforce policies or forward
//! requests. Its checks are limited to the configured parsing model. It cannot
//! discover or certify how your deployment handles paths.
//!
//! # Example
//!
//! ```
//! use huskarl_route_guard::{
//!     RuleRouter,
//!     config::{CaseSensitivity, DecodeDepth, GuardConfig},
//! };
//!
//! // For this example, downstream routing distinguishes ASCII case and decodes
//! // the path at most once. Set these assumptions for your actual deployment.
//! let router = RuleRouter::builder(
//!     "public",
//!     GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne),
//! )
//! .subtree("/admin", "admin")
//! .route("/health", "health")
//! .build()
//! .expect("valid route table");
//!
//! let matched = router
//!     .resolve("/admin/users", &http::Method::GET)
//!     .expect("ordinary path");
//! assert_eq!(*matched.rule(), "admin");
//!
//! // Decoding this slash could change the rule from public to admin.
//! assert!(
//!     router
//!         .resolve("/admin%2fusers", &http::Method::GET)
//!         .is_err()
//! );
//!
//! // Here, splitting the segment stays inside the same admin rule.
//! assert!(router.resolve("/admin/a%2fb", &http::Method::GET).is_ok());
//! ```
//!
//! The string values above are application data, not built-in policies. Each
//! registration has a distinct identity even when its value equals another's.
//! The guard compares those identities.
//!
//! # Integration essentials
//!
//! - Pass the request path alone, normally `uri.path()`, without a query string or
//!   fragment. `resolve` validates this boundary.
//! - Use `resolve` for request handling. On `Ok`, enforce the returned rule's policy;
//!   on `Err`, deny the request. Forward allowed requests with the path unchanged.
//! - Path matching happens before method lookup. A more-specific path with no rule
//!   for the request method uses an all-method rule at that path or the default;
//!   it does not fall back to a less-specific path.
//! - The default mode, `RejectAmbiguous`, accepts some structural forms when they
//!   cannot cross a rule boundary. `exclusive_subtree` adds a build-time restriction on
//!   nested paths; it does not disable checks.
//!
//! # Documentation
//!
//! - **Learn:** [Getting started](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/tutorial/).
//! - **Apply:** [Choose a configuration](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/guide/configuring/),
//!   [register routes](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/guide/registering/),
//!   or [handle a denial](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/guide/handling_denials/).
//! - **Understand:** [How the guard decides](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/explanation/decision/).
//! - **Look up:** [Routing behavior](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/reference/routing/),
//!   [security contract](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/reference/contract/),
//!   [supported parsing behaviors](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/reference/coverage/),
//!   [tested deployments](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/reference/deployments/),
//!   and [glossary](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/reference/glossary/).
//!
//! This framework-independent crate powers `huskarl-pingora`'s `Guard` and
//! `LoginProxy` route tables. Its only runtime dependency is `http`.

pub mod _docs;
pub mod config;
mod diagnostics;
mod guard;
#[cfg(test)]
mod path_confusion_proptest;
mod path_router;
mod percent;
mod route_tree;
mod structural;

pub use config::{
    CaseSensitivity, DecodeDepth, GuardConfig, GuardMode, ResolveError, StructuralChar,
    StructuralClass, StructuralClasses, StructuralProbe,
};
pub use diagnostics::{
    MethodGapDiagnostic, RawMatch, ResolutionExplanation, StructuralExplanation,
};
pub use path_router::{Registration, RuleMatch, RuleRouter, RuleRouterBuilder, RuleRouterError};
pub use route_tree::MethodMatch;

/// Expands a path into the `matchit` patterns that cover that path
/// and everything beneath it — the expansion behind
/// [`RuleRouterBuilder::subtree`] and `subtree`-style builder methods downstream.
///
/// - `/blah`  → `/blah`, `/blah/`, `/blah/{*rest}`
/// - `/blah/` → `/blah/`, `/blah/{*rest}` (the bare `/blah` is *not* included)
/// - `/`      → `/`, `/{*rest}` (the whole tree)
///
/// A trailing slash on the input therefore means "this directory and its
/// contents, but not the bare name". `matchit`'s catch-all matches neither the
/// empty remainder nor the bare path, so the literal and trailing-slash
/// patterns must be inserted explicitly alongside it.
#[must_use]
pub fn subtree_patterns(path: &str) -> Vec<String> {
    if path.ends_with('/') {
        vec![path.to_owned(), format!("{path}{{*rest}}")]
    } else {
        vec![
            path.to_owned(),
            format!("{path}/"),
            format!("{path}/{{*rest}}"),
        ]
    }
}

#[cfg(test)]
mod subtree_patterns_tests {
    use super::subtree_patterns;

    #[test]
    fn no_trailing_slash_expands_to_three() {
        assert_eq!(
            subtree_patterns("/blah"),
            vec!["/blah", "/blah/", "/blah/{*rest}"]
        );
    }

    #[test]
    fn trailing_slash_omits_bare_path() {
        assert_eq!(subtree_patterns("/blah/"), vec!["/blah/", "/blah/{*rest}"]);
    }

    #[test]
    fn root_covers_whole_tree() {
        assert_eq!(subtree_patterns("/"), vec!["/", "/{*rest}"]);
    }

    #[test]
    fn nested_path() {
        assert_eq!(
            subtree_patterns("/a/b"),
            vec!["/a/b", "/a/b/", "/a/b/{*rest}"]
        );
    }
}
