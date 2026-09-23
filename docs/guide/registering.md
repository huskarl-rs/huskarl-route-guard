# Registering routes

Use this guide when mapping your application's authorization policies to paths.
Start with the [tutorial](crate::_docs::tutorial) if you have not built a router yet.

## Choose the paths each rule covers

Use `register_path` for an exact path or pattern. Use `register_subtree` when the same
method table applies to a prefix and everything beneath it. For example,
`register_subtree("/admin", |path| path.all(rule))`
covers `/admin`, `/admin/`, and `/admin/users` under one identity.

Check trailing slashes deliberately. `register_subtree("/admin/", |path| path.all(rule))` excludes the bare
`/admin`. If the backend treats those spellings as equivalent, give them the same
registration. The guard does not detect trailing-slash equivalence for you.

Keep patterns that should share an identity in one registration. Two calls with
equal rule values still create different identities. If the helper methods cannot
express your group of patterns, assemble a [`PathRegistration`](crate::PathRegistration)
and use [`from_registrations`](crate::RuleRouter::from_registrations).

## Set the default policy explicitly

The default handles paths for which matching is exhausted, including through
explicit inheritance. An unresolved method at a non-inheriting path is denied.

## Define each path's method table

Group overrides and fallback behavior in one registration:

```rust
use huskarl_route_guard::{CaseSensitivity, DecodeDepth, GuardConfig, ResolveError, RuleRouter};
use http::Method;
let router = RuleRouter::builder("default", GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
    .register_subtree("/files", |p| p.methods([Method::GET, Method::HEAD], "read"))
    .register_path("/files/special", |p| p.fallback_inherit(true).method(Method::POST, "write"))
    .build().unwrap();
let parent = router.resolve("/files/ordinary", &Method::GET).unwrap();
assert_eq!(router.resolve("/files/special", &Method::GET).unwrap(), parent);
assert!(router.resolve("/files/hello%20world", &Method::GET).is_ok());
assert!(router.resolve("/files/hello%2fworld", &Method::GET).is_ok());
assert_eq!(router.resolve("/files/special", &Method::DELETE).unwrap_err(), ResolveError::MethodNotConfigured);
```

At a matching path the requested method wins, then `.all(rule)`, then inheritance
if enabled, otherwise denial. Inheritance continues through matching-pattern
precedence with the same path and method. Each intermediate path can stop it.
The inherited rule retains its original identity, preserving uniform coverage.

Use `register_subtree` to share the method table across the prefix, trailing slash,
and catch-all, or `register_exclusive_subtree` to additionally forbid overriding
paths. For dynamically assembled tables, pass `PathRegistration` values to `register`,
`register_all`, or `from_registrations`.

Include HEAD explicitly where the backend serves GET handlers for HEAD; inheritance
does not convert methods. If the backend falls through to a broader handler, enable
inheritance deliberately or supply the appropriate concrete method rule. Missing
method declarations now fail closed, but can prevent legitimate requests from being
served. See the [deployment method recommendations](crate::_docs::reference::deployments#method-specific-registrations).

### Inspect method gaps at startup

Call [`diagnostics()`](crate::RuleRouter::diagnostics) after construction to find
method gaps that hide a less-specific rule. Construction still succeeds, and the
lint does not change routing. Applications can log the structured reports or treat
them as configuration errors:

```rust
use huskarl_route_guard::{CaseSensitivity, DecodeDepth, GuardConfig, RuleRouter};

let router = RuleRouter::builder("default",
    GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
    .register_subtree("/files", |path| path.all("files"))
    .register_path("/files/special", |path| path.method(http::Method::POST, "write"))
    .build().expect("valid routes");
let diagnostics = router.diagnostics();
assert_eq!(diagnostics[0].example_path, "/files/special");
assert!(diagnostics[0].methods.contains(&http::Method::GET));
assert_eq!(diagnostics[0].shadowed_registration, 0);
for diagnostic in diagnostics {
    eprintln!("{diagnostic}");
}
```

The lint checks standard HTTP methods and explicitly registered extension methods
at representative pairwise pattern overlaps. Each report has a concrete raw-routing
witness; this is not an exhaustive analysis of all paths or extension methods.
An empty list does not prove there are no gaps. Analysis runs only when called and
examines pattern pairs; the router retains pattern metadata for this purpose.

If the child should preserve broader policies for other methods, enable
`fallback_inherit(true)` on its path registration. The original broader rule is
returned without copying its value or assigning a child identity. Alternatively,
provide a concrete method or ALL rule when the child needs its own policy.

## Register areas that accept encoded keys

If one rule applies to an entire file-key prefix for the methods it serves, use
`register_exclusive_subtree("/files", |path| path.all(rule))`. Encoded slashes such as `/files/a%2fb` can then be
accepted when every supported interpretation stays in that rule. The exclusive
declaration rejects more-specific paths that can take precedence beneath it,
regardless of registration order. This includes overlaps between literal and
wildcard branches: `register_exclusive_subtree("/{tenant}", |path| path.all(rule))` cannot coexist with
`register_path("/files/private", |path| path.all(other_rule))`. Unrelated routes and lower-priority fallback
routes remain valid. Method-specific rules at the same path patterns remain valid;
exclusivity restricts nested paths, not method slots. Use `register_subtree` instead if nested
routes are intentional.

Restrict the registration to the methods its policy serves. Structural checks use
the request method, so a GET-only subtree can accept GET encoded keys. For example:

```rust
use huskarl_route_guard::{CaseSensitivity, DecodeDepth, GuardConfig, RuleRouter};

let router = RuleRouter::builder("default", GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
    .register_exclusive_subtree("/files", |path| path.methods([http::Method::GET, http::Method::HEAD], "read-files"))
    .build()
    .expect("valid routes");
assert_eq!(*router.resolve("/files/a%2fb", &http::Method::GET).unwrap().rule(), "read-files");
assert_eq!(router.resolve("/files/a%2fb", &http::Method::POST).unwrap_err(), huskarl_route_guard::ResolveError::MethodNotConfigured);
```

POST is denied in this example because the subtree has no POST or ALL rule and does not inherit.
Adding a POST rule at the same subtree patterns does not change GET coverage.
Adding a more-specific POST-only path under an ordinary subtree can change GET
coverage: GET is denied there unless the child explicitly inherits the broader GET rule.

## Correct a route-table build error

Use the pattern and reason in the build error to locate the registration. Consult
the [forbidden-registration examples](crate::_docs::reference::routing) for the
exact restrictions.

- For a grammar error, use whole-segment parameters and put catch-alls last. Escape
  literal braces as `{{` and `}}`.
- For a duplicate path/method slot, remove the duplicate or combine its method sets
  without repetitions. Changing a parameter name or repeating the same rule value
  does not make a second registration distinct at that routing position.
- For an empty pattern or method set, fix the input that generated it or omit the
  registration.
- For a non-canonical literal, register the canonical spelling that the configured
  parsing model expects. Keep uppercase parameter names if useful; only literal
  request-path bytes participate in this check.
- For an exclusive-subtree conflict, remove or move the overlapping route. If the
  exception is intentional, change the exclusive declaration to `register_subtree`, then
  recheck encoded-key requests because the new rule boundary can add denials.

## Verify the table through `resolve`

Exercise ordinary paths, trailing slashes, overlapping patterns, unmatched paths,
and each relevant method. For encoded keys, include examples that should stay in
the rule and examples that could escape it. The
[denial guide](crate::_docs::guide::handling_denials) includes a regression-test
example and steps for investigating unexpected results.
