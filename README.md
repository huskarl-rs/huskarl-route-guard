<!--
Generated from src/lib.rs by `mise run readme`.
Do not edit README.md by hand.
-->

# huskarl-route-guard

Match a request path to an authorization rule. Reject it if downstream path
parsing could select a different rule. The guard checks the parsing behaviors
you configure and never rewrites the path.

For example, `/admin%2fusers` may select a public default rule here but become
`/admin/users` after downstream decoding. This crate detects possible rule
changes before your application enforces the selected policy and forwards the
request with its path unchanged.

The crate returns a rule or a denial; it does not enforce policies or forward
requests. Its checks are limited to the configured parsing model. It cannot
discover or certify how your deployment handles paths.

## Example

```rust
use huskarl_route_guard::{
    RuleRouter,
    config::{CaseSensitivity, DecodeDepth, GuardConfig},
};

// For this example, downstream routing distinguishes ASCII case and decodes
// the path at most once. Set these assumptions for your actual deployment.
let router = RuleRouter::builder(
    "public",
    GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne),
)
.subtree("/admin", "admin")
.route("/health", "health")
.build()
.expect("valid route table");

let matched = router
    .resolve("/admin/users", &http::Method::GET)
    .expect("ordinary path");
assert_eq!(*matched.rule(), "admin");

// Decoding this slash could change the rule from public to admin.
assert!(
    router
        .resolve("/admin%2fusers", &http::Method::GET)
        .is_err()
);

// Here, splitting the segment stays inside the same admin rule.
assert!(router.resolve("/admin/a%2fb", &http::Method::GET).is_ok());
```

The string values above are application data, not built-in policies. Each
registration has a distinct identity even when its value equals another's.
The guard compares those identities.

## Integration essentials

- Pass the request path alone, normally `uri.path()`, without a query string or
  fragment. `resolve` validates this boundary.
- Use `resolve` for request handling. On `Ok`, enforce the returned rule's policy;
  on `Err`, deny the request. Forward allowed requests with the path unchanged.
- Path matching happens before method lookup. A more-specific path with no rule
  for the request method uses an all-method rule at that path or the default;
  it does not fall back to a less-specific path.
- The default mode, `RejectAmbiguous`, accepts some structural forms when they
  cannot cross a rule boundary. `exclusive_subtree` adds a build-time restriction on
  nested paths; it does not disable checks.

## Documentation

- **Learn:** [Getting started](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/tutorial/).
- **Apply:** [Choose a configuration](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/guide/configuring/),
  [register routes](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/guide/registering/),
  or [handle a denial](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/guide/handling_denials/).
- **Understand:** [How the guard decides](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/explanation/decision/).
- **Look up:** [Routing behavior](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/reference/routing/),
  [security contract](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/reference/contract/),
  [supported parsing behaviors](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/reference/coverage/),
  and [glossary](https://docs.rs/huskarl-route-guard/latest/huskarl_route_guard/_docs/reference/glossary/).

This framework-independent crate powers `huskarl-pingora`'s `Guard` and
`LoginProxy` route tables. Its only runtime dependency is `http`.

License: MIT OR Apache-2.0
