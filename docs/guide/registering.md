# Registering routes

Use this guide when mapping your application's authorization policies to paths.
Start with the [tutorial](crate::_docs::tutorial) if you have not built a router yet.

## Choose the paths each rule covers

Use `route` for an exact path or pattern. Use `subtree` when the same policy applies
to a prefix and everything beneath it. For example, `subtree("/admin", rule)`
covers `/admin`, `/admin/`, and `/admin/users` under one identity.

Check trailing slashes deliberately. `subtree("/admin/", rule)` excludes the bare
`/admin`. If the backend treats those spellings as equivalent, give them the same
registration. The guard does not detect trailing-slash equivalence for you.

Keep patterns that should share an identity in one registration. Two calls with
equal rule values still create different identities. If the helper methods cannot
express your group of patterns, assemble a [`Registration`](crate::Registration)
and use [`from_registrations`](crate::RuleRouter::from_registrations).

## Set the default policy explicitly

The default rule handles unmatched paths and methods that have no rule at the
selected path. Choose a value your application can enforce safely in both cases.
Test unmatched requests as well as registered paths.

## Add method-specific rules

Construct a registration and call `for_methods`, then add it with `register`:

```rust
use huskarl_route_guard::{CaseSensitivity, DecodeDepth, GuardConfig, Registration, RuleRouter};

let config = GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne);
let router = RuleRouter::builder("default", config)
    .register(Registration::route("/health", "health").for_methods([http::Method::GET, http::Method::HEAD]))
    .build()
    .expect("valid routes");
assert!(router.resolve("/health", &http::Method::POST).unwrap().is_default());
```

Check each method you serve at an overlapping path: path matching happens before
method lookup. `register_all` accepts an iterator for tables assembled dynamically.

For example, with `/items/{id}` and a GET-only `/items/special`, POST to
`/items/special` selects the default. It does not use `/items/{id}`. If POST needs a
rule there, register it explicitly at `/items/special`, or add an all-method
`route` at that exact path. See [Routing behavior](crate::_docs::reference::routing)
for the executable example and precedence rules.

### Inspect method gaps at startup

Call [`diagnostics()`](crate::RuleRouter::diagnostics) after construction to find
method gaps that hide a less-specific rule. Construction still succeeds, and the
lint does not change routing. Applications can log the structured reports or treat
them as configuration errors:

```rust
use huskarl_route_guard::{CaseSensitivity, DecodeDepth, GuardConfig, Registration, RuleRouter};

let router = RuleRouter::builder("default",
    GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
    .subtree("/files", "files")
    .register(Registration::route("/files/special", "write").for_methods(http::Method::POST))
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

Adding a same-path all-method rule repairs the default gap. To also preserve the
surrounding rule's identity for GET encoded keys, include that path in the existing
registration instead of creating a separate rule:

```rust
use huskarl_route_guard::{CaseSensitivity, DecodeDepth, GuardConfig, Registration, RuleRouter, subtree_patterns};

let patterns = subtree_patterns("/files").into_iter()
    .chain(["/files/special".to_owned()]);
let router = RuleRouter::builder("default",
    GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
    .register(Registration::patterns(patterns, "files"))
    .register(Registration::route("/files/special", "write").for_methods(http::Method::POST))
    .build().expect("valid routes");
assert!(router.diagnostics().is_empty());
assert!(router.resolve("/files/hello%2fworld", &http::Method::GET).is_ok());
```

## Register areas that accept encoded keys

If one rule applies to an entire file-key prefix for the methods it serves, use
`exclusive_subtree("/files", rule)`. Encoded slashes such as `/files/a%2fb` can then be
accepted when every supported interpretation stays in that rule. The exclusive
declaration rejects more-specific paths that can take precedence beneath it,
regardless of registration order. This includes overlaps between literal and
wildcard branches: `exclusive_subtree("/{tenant}", rule)` cannot coexist with
`route("/files/private", other_rule)`. Unrelated routes and lower-priority fallback
routes remain valid. Method-specific rules at the same path patterns remain valid;
exclusivity restricts nested paths, not method slots. Use `subtree` instead if nested
routes are intentional.

Restrict the registration to the methods its policy serves. Structural checks use
the request method, so a GET-only subtree can accept GET encoded keys. For example:

```rust
use huskarl_route_guard::{CaseSensitivity, DecodeDepth, GuardConfig, Registration, RuleRouter};

let router = RuleRouter::builder("default", GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
    .register(Registration::exclusive_subtree("/files", "read-files").for_methods([http::Method::GET, http::Method::HEAD]))
    .build()
    .expect("valid routes");
assert_eq!(*router.resolve("/files/a%2fb", &http::Method::GET).unwrap().rule(), "read-files");
assert!(router.resolve("/files/a%2fb", &http::Method::POST).unwrap().is_default());
```

An accepted POST in this example still requires enforcement of the default policy.
Adding a POST rule at the same subtree patterns does not change GET coverage.
Adding a more-specific POST-only path under an ordinary subtree can change GET
coverage: GET selects the default at that path, rather than the ancestor's GET rule.

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
  exception is intentional, change the exclusive declaration to `subtree`, then
  recheck encoded-key requests because the new rule boundary can add denials.

## Verify the table through `resolve`

Exercise ordinary paths, trailing slashes, overlapping patterns, unmatched paths,
and each relevant method. For encoded keys, include examples that should stay in
the rule and examples that could escape it. The
[denial guide](crate::_docs::guide::handling_denials) includes a regression-test
example and steps for investigating unexpected results.
