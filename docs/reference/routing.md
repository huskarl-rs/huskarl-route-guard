# Routing behavior

This page specifies pattern matching, registration identity, and method precedence.
For help choosing registrations, use [Registering routes](crate::_docs::guide::registering).

## Patterns and registrations

A pattern matches a path: `/health` is literal, `/users/{id}` captures one non-empty
segment, and `/files/{*rest}` captures a non-empty remainder. Parameters must occupy
whole segments; in-segment parameters such as `/v{version}` are not supported.
Trailing slashes are significant.

Each registration associates one or more patterns and a method selection with a
caller-provided rule value. Its patterns share one rule ID. Separate registrations
have different IDs even if their values compare equal. The guard compares IDs,
not rule values or application policies.

| Registration | Paths covered |
|---|---|
| `route("/files", rule)` | `/files` only |
| `subtree("/files", rule)` | `/files`, `/files/`, and paths below `/files/` |
| `subtree("/files/", rule)` | `/files/` and paths below it; excludes `/files` |
| `subtree("/", rule)` | All slash-prefixed request paths |
| `exclusive_subtree("/files", rule)` | Same paths as `subtree`; nested paths are rejected at build time |

`Registration::for_methods` restricts a registration to selected HTTP methods.
Add it with `builder.register(...)`. An exclusive subtree does not override
method restrictions or disable any check.

## Path precedence comes before method matching

Method-qualified registrations do not change path precedence. The router first picks
the matching path, preferring literal segments, then wildcards, then catch-alls.
A path branch that cannot complete a match can fall back to a lower-priority branch.
Once a path matches, the router looks up the request method at that position. If
there is no matching method and no all-method rule, the default applies; routing does not backtrack to a
less-specific path pattern.

```rust
use huskarl_route_guard::{
    Registration, RuleRouter,
    config::{CaseSensitivity, DecodeDepth, GuardConfig},
};

let router = RuleRouter::builder("public", GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
    .route("/items/{id}", "generic-item")
    .register(Registration::route("/items/special", "get-special").for_methods(http::Method::GET))
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

## Default rule

The default applies when no path pattern matches, or when the selected path has
neither the requested method nor an all-method rule. The default has its own
identity for ambiguity checks. A change between a registration and the default
counts as a rule change in either direction.

## Methods and ambiguity checks

Case-folding and percent-decoding compare rules for the request's actual method.
Structural ambiguity checks require every path and **every method** in the analyzed
region to select the same rule. A GET-only subtree leaves default-rule gaps for
other methods, so `/files/a%2fb` is denied even for GET under a lone GET-only
`/files` subtree. The same applies to an exclusive subtree with restricted methods.
