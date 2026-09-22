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

//! Path-to-rule routing with a path-confusion (parser differential) guard, for
//! authorization layers that match a request path to a per-path rule and then forward
//! the **raw** path upstream.
//!
//! An authorization proxy and the backend behind it each parse the request path; when
//! they disagree about what a path *means*, a request can be authorized as one path
//! while the backend acts on another (`/x/../admin/secret`, `/admin%2fsecret`,
//! `/%61dmin`, …). This crate provides the two pieces such a layer needs:
//!
//! - [`RuleRouter`](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/struct.RuleRouter.html)
//!   — a `path → rule` table with **rule-granularity identity**: every pattern
//!   registered by one
//!   [`route`](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/struct.RuleRouterBuilder.html#method.route) /
//!   [`subtree`](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/struct.RuleRouterBuilder.html#method.subtree) /
//!   [`blob_subtree`](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/struct.RuleRouterBuilder.html#method.blob_subtree)
//!   call shares a rule id, so movement *within* a subtree is never treated as a
//!   relocation. Patterns use `matchit`-style syntax (`/users/{id}`, `/files/{*rest}`),
//!   matched by an owned segment-tree matcher (property-tested and fuzzed against
//!   `matchit` as an oracle).
//! - The **path-confusion guard**, built into the router and configured by the types in
//!   [`path_confusion`](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/path_confusion/)
//!   — it denies a path when an interpretation in the declared model could route it to
//!   a different rule from the raw path. It never rewrites a path.
//!
//! The guard enforces the declaration; it cannot discover or certify how a deployed
//! backend behaves. Start with the
//! [tutorial](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/tutorial/),
//! then consult the exact
//! [security contract](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/reference/contract/)
//! and
//! [coverage table](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/reference/coverage/)
//! before making a security claim.
//!
//! This crate is the engine behind `huskarl-pingora`'s `Guard` and `LoginProxy` route
//! tables; its only runtime dependency is [`http`](https://docs.rs/http) (plus
//! [`bon`](https://docs.rs/bon) for builder codegen). It is framework-independent, but
//! assumes authorization can be represented by this crate's path-to-rule table.
//!
//! # Input: the request path only
//!
//! Every entry point takes the **request path alone** — `uri.path()`, never a full
//! request-target.
//! [`resolve`](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/struct.RuleRouter.html#method.resolve)
//! validates that boundary: the input must start with `/` (or be the special `*`
//! request target) and contain no query or fragment delimiter. A full request-target
//! such as `/admin?x=1` is denied with
//! [`InvalidPathInput`](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/enum.DenyReason.html#variant.InvalidPathInput)
//! rather than silently falling through to the default rule.
//!
//! # Path precedence comes before method matching
//!
//! Route shape is selected first (literal, then wildcard, then catch-all); the request
//! method is resolved only at that selected terminal. A more-specific path registered
//! for one method therefore still owns that path for every method: when its method does
//! not match, resolution uses a method-wildcard rule at the **same path**, or the default
//! rule. It does not fall back to a less-specific wildcard or catch-all path.
//!
//! ```
//! use huskarl_route_guard::{
//!     RuleRouter,
//!     path_confusion::{CaseSensitivity, DecodeLayers},
//! };
//!
//! let router = RuleRouter::builder()
//!     .default("default-rule")
//!     .case_sensitivity(CaseSensitivity::Sensitive)
//!     .decode_layers(DecodeLayers::Single)
//!     .route("/items/{id}", "generic-item")
//!     .route_for(http::Method::GET, "/items/special", "get-special")
//!     .build()
//!     .expect("valid route table");
//!
//! assert_eq!(
//!     *router
//!         .resolve("/items/special", &http::Method::GET)
//!         .expect("clean path")
//!         .rule(),
//!     "get-special"
//! );
//! // The literal path wins before method resolution. Because it has no POST rule,
//! // POST uses the default; it does not fall back to `/items/{id}`.
//! assert!(
//!     router
//!         .resolve("/items/special", &http::Method::POST)
//!         .expect("clean path")
//!         .is_default()
//! );
//! ```
//!
//! # Usage sketch
//!
//! ```
//! use huskarl_route_guard::{
//!     RuleRouter,
//!     path_confusion::{CaseSensitivity, DecodeLayers},
//! };
//!
//! // Each registration (`route`/`subtree`/`blob_subtree`) gets one rule id, so the
//! // guard treats the whole subtree as one rule. The path-confusion guard defaults to
//! // `RejectStructural`; the case and decode-depth declarations are required and have
//! // no default — the library will not guess either.
//! let router = RuleRouter::builder()
//!     .default("default-rule")
//!     .case_sensitivity(CaseSensitivity::Sensitive)
//!     .decode_layers(DecodeLayers::Single)
//!     .subtree("/admin", "admin-rule")
//!     .route("/health", "public-rule")
//!     .build()
//!     .expect("valid route table");
//!
//! // One call per request: the guard's verdict, then the rule match. A path a
//! // declared interpretation could relocate is denied (`Err(reason)`) before any rule
//! // applies: the `%2f` below sits in the first segment, where a decoded slash
//! // could re-divide the path between the admin, health, and default rules.
//! let matched = router
//!     .resolve("/admin/users", &http::Method::GET)
//!     .expect("clean path");
//! assert_eq!(*matched.rule(), "admin-rule");
//! assert!(
//!     router
//!         .resolve("/admin%2fusers", &http::Method::GET)
//!         .is_err()
//! );
//! // Scoped, not blanket: deeper inside the single-rule /admin subtree the same
//! // byte cannot reach any other rule, so an encoded key flows.
//! assert!(router.resolve("/admin/a%2fb", &http::Method::GET).is_ok());
//! ```

pub mod _docs;
pub mod path_confusion;
#[cfg(test)]
mod path_confusion_proptest;
mod path_router;
mod percent;
mod route_tree;
mod structural;

pub use path_confusion::{DenyReason, StructuralClass};
pub use path_router::{
    Registration, RuleMatch, RuleRouter, RuleRouterBuilder, RuleRouterError, rule_router_builder,
};
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
