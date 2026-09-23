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
//! .register_subtree("/admin", |path| path.all("admin"))
//! .register_path("/health", |path| path.all("health"))
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
//! `.all(rule)` supplies a concrete rule for every method without a specific override.
//!
//! The string values above are application data, not built-in policies. Each concrete
//! rule definition has a distinct identity even when its value equals another's.
//! Inheritance returns the original defining rule and identity.
//!
//! # Integration essentials
//!
//! - Pass the request path alone, normally `uri.path()`, without a query string or
//!   fragment. `resolve` validates this boundary.
//! - Use `resolve` for request handling. On `Ok`, enforce the returned rule's policy;
//!   on `Err`, deny the request. Forward allowed requests with the path unchanged.
//! - At each matching path, use the method override, then its ALL rule. Otherwise
//!   continue only with explicit `fallback_inherit(true)`; a stopped lookup denies.
//!   Matching exhaustion uses the default. `register_path` and `register_subtree`
//!   group method definitions and inheritance in one path table.
//! - The default mode, `RejectAmbiguous`, accepts some structural forms when they
//!   cannot cross a rule boundary. `register_exclusive_subtree` adds a build-time restriction on
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
#[path = "tests/path_confusion_proptest.rs"]
mod path_confusion_proptest;
mod path_router;
mod percent;
mod route_tree;
mod structural;

pub use config::{
    CaseSensitivity, DecodeDepth, GuardConfig, GuardMode, ResolveError, ResolveErrorKind,
    StructuralChar, StructuralClass, StructuralClasses, StructuralProbe,
};
pub use diagnostics::{
    MethodGapDiagnostic, RawMatch, ResolutionExplanation, StructuralExplanation,
};
pub use path_router::{
    PathRegistration, RuleMatch, RuleRouter, RuleRouterBuilder, RuleRouterError,
};
