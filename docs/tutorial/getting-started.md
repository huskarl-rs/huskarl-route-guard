# Getting started

This tutorial builds a small authorization route table, observes one denied path,
and then adds an opaque-key area where encoded separators may safely flow.

The crate is intended for a specific architecture: this layer chooses an
authorization rule from the request path, then forwards the **unchanged** path to
another component. If authorization and request handling already use the same parsed
path in one trusted component, you do not need this guard.

## 1. Build a route table

Each registration is one authorization rule. Use `subtree` when a policy owns a URL
prefix, and `route` for a single exact path.

```rust
use huskarl_route_guard::{
    RuleRouter,
    path_confusion::{CaseSensitivity, DecodeLayers},
};

let router = RuleRouter::builder()
    .default("public")
    // These are statements about everything that may parse the path downstream.
    .case_sensitivity(CaseSensitivity::Sensitive)
    .decode_layers(DecodeLayers::Single)
    .subtree("/admin", "admin")
    .route("/health", "health")
    .build()
    .expect("valid route table");

let matched = router
    .resolve("/admin/users", &http::Method::GET)
    .expect("ordinary path");
assert_eq!(*matched.rule(), "admin");
```

`default("public")` is also a rule. Moving from an unmatched path to `/admin`, or
from `/admin` to an unmatched path, crosses a rule boundary.

### Path precedence comes before method matching

Method-qualified registrations do not change path precedence. The router first picks
the most-specific path terminal (literal, then wildcard, then catch-all), and only then
looks up the request method at that terminal. If the terminal has no matching method
and no method-wildcard rule, the default applies; routing does not backtrack to a
less-specific path pattern.

```rust
use huskarl_route_guard::{
    RuleRouter,
    path_confusion::{CaseSensitivity, DecodeLayers},
};

let router = RuleRouter::builder()
    .default("public")
    .case_sensitivity(CaseSensitivity::Sensitive)
    .decode_layers(DecodeLayers::Single)
    .route("/items/{id}", "generic-item")
    .route_for(http::Method::GET, "/items/special", "get-special")
    .build()
    .expect("valid route table");

assert_eq!(
    *router
        .resolve("/items/special", &http::Method::GET)
        .expect("ordinary path")
        .rule(),
    "get-special"
);
assert!(
    router
        .resolve("/items/special", &http::Method::POST)
        .expect("ordinary path")
        .is_default()
);
```

If POST should use the generic item rule, register that behavior explicitly at the
literal path (for example with a method-wildcard `route`) or avoid adding the
method-specific literal carve-out.

## 2. Observe a parser disagreement

The raw path `/admin%2fusers` does not match the `/admin` subtree. A downstream
component that decodes `%2f` as `/` may instead route it as `/admin/users`. Because
those interpretations select different rules, `resolve` denies the request:

```rust
# use huskarl_route_guard::{RuleRouter, path_confusion::{CaseSensitivity, DecodeLayers}};
# let router = RuleRouter::builder()
#     .default("public")
#     .case_sensitivity(CaseSensitivity::Sensitive)
#     .decode_layers(DecodeLayers::Single)
#     .subtree("/admin", "admin")
#     .route("/health", "health")
#     .build().unwrap();
let denial = router
    .resolve("/admin%2fusers", &http::Method::GET)
    .expect_err("the decoded interpretation crosses a rule boundary");

assert_eq!(denial.message(), "Ambiguous request path");
```

Log the denial's `Display` form for the detailed reason. Return `message()` to the
client if you want a deliberately less revealing response.

## 3. Allow opaque keys without weakening the whole table

Suppose `/files` forwards object keys unchanged and the entire prefix has one policy.
`blob_subtree` records that fact and prevents later routes from being nested beneath
it:

```rust
use huskarl_route_guard::{
    RuleRouter,
    path_confusion::{CaseSensitivity, DecodeLayers},
};

let router = RuleRouter::builder()
    .default("public")
    .case_sensitivity(CaseSensitivity::Sensitive)
    .decode_layers(DecodeLayers::Single)
    .subtree("/admin", "admin")
    .blob_subtree("/files", "files")
    .build()
    .expect("valid route table");

// Splitting this key differently cannot leave the one-rule /files area.
assert!(router.resolve("/files/a%2fb", &http::Method::GET).is_ok());

// A traversal that could leave /files is still denied.
assert!(router.resolve("/files/../admin", &http::Method::GET).is_err());
```

## 4. State only what you know

`CaseSensitivity`, `DecodeLayers`, and `StructuralClasses` describe a set of path
interpretations that may occur downstream. The library enforces agreement across
that declared set; it does not inspect the deployment or prove the declaration
complete.

If you do not know how the complete downstream chain handles paths, use the strictest
configuration your legitimate traffic permits and obtain platform-specific evidence
before claiming broader protection. Continue with
[Choosing a configuration](crate::_docs::guide::configuring), then consult the
[Security contract](crate::_docs::reference::contract) for the exact guarantee.
