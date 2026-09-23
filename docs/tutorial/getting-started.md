# Getting started

Build a small route table, observe a rejected request, and add an area for file
keys that contain encoded slashes. Run the examples in a Rust project with
`huskarl-route-guard` and `http` as dependencies.

The router returns an authorization rule or a denial. Your application enforces
the rule and forwards allowed requests with their paths unchanged. The guard is
useful when a downstream component may parse the path differently.

## 1. Build a route table

For this example, assume the downstream service distinguishes ASCII case and
percent-decodes paths at most once. Use `register_subtree` to cover `/admin` and everything
beneath it, and `register_path` to cover just `/health`. Each `.all(...)` defines
the rule for methods without a specific override. The strings are rule values for
your application to act on; the crate does not enforce their policies.

```rust
use huskarl_route_guard::{
    RuleRouter,
    config::{CaseSensitivity, DecodeDepth, GuardConfig},
};

let router = RuleRouter::builder("public", GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
    .register_subtree("/admin", |path| path.all("admin"))
    .register_path("/health", |path| path.all("health"))
    .build()
    .expect("valid route table");

let matched = router
    .resolve("/admin/users", &http::Method::GET)
    .expect("ordinary path");
assert_eq!(*matched.rule(), "admin");
```

The `"public"` default passed to `RuleRouter::builder` is also a rule. Moving from
an unmatched path to `/admin`, or from `/admin` to an unmatched path, crosses a
rule boundary.

## 2. Observe a parser disagreement

The raw path `/admin%2fusers` does not match the `/admin` subtree. A downstream
component that decodes `%2f` as `/` may instead route it as `/admin/users`. Because
those interpretations select different rules, `resolve` denies the request:

```rust
# use huskarl_route_guard::{RuleRouter, config::{CaseSensitivity, DecodeDepth, GuardConfig}};
# let router = RuleRouter::builder("public", GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
#     .register_subtree("/admin", |path| path.all("admin"))
#     .register_path("/health", |path| path.all("health"))
#     .build().unwrap();
let denial = router
    .resolve("/admin%2fusers", &http::Method::GET)
    .expect_err("the decoded interpretation crosses a rule boundary");

assert_eq!(denial.message(), "Ambiguous request path");
```

Log the denial's `Display` form for the detailed reason. Return `message()` to the
client if you want a deliberately less revealing response.

## 3. Allow encoded slashes inside file keys

Suppose `/files` forwards object keys unchanged and the entire prefix has one policy.
Rebuild the router with `register_exclusive_subtree`. It covers the prefix like
`register_subtree` and
also rejects configurations that put more-specific paths beneath it:

```rust
use huskarl_route_guard::{
    RuleRouter,
    config::{CaseSensitivity, DecodeDepth, GuardConfig},
};

let router = RuleRouter::builder("public", GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
    .register_subtree("/admin", |path| path.all("admin"))
    .register_exclusive_subtree("/files", |path| path.all("files"))
    .build()
    .expect("valid route table");

// Splitting this key differently cannot leave the one-rule /files area.
assert!(router.resolve("/files/a%2fb", &http::Method::GET).is_ok());

// A traversal that could leave /files is still denied.
assert!(router.resolve("/files/../admin", &http::Method::GET).is_err());
```

## What to do next

You have matched an ordinary path, rejected a path that could select a different
rule, and allowed an encoded slash that stays inside one rule.

Before using this in a service, follow [Choosing a configuration](crate::_docs::guide::configuring)
for your actual downstream parsing behaviors. The guard checks only its configured
behaviors; it cannot discover what your deployment does.

For method-specific routes, follow [Registering routes](crate::_docs::guide::registering).
For the exact guarantees and exclusions, consult the
[Security contract](crate::_docs::reference::contract) and
[Supported path interpretations](crate::_docs::reference::coverage).
