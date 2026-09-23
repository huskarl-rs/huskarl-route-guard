# Routing behavior

This page specifies pattern matching, registration identity, and method precedence.
For help choosing registrations, use [Registering routes](crate::_docs::guide::registering).

## Patterns and registrations

A pattern matches a path: `/health` is literal, `/users/{id}` captures one non-empty
segment, and `/files/{*rest}` captures a non-empty remainder. Parameters must occupy
whole segments; in-segment parameters such as `/v{version}` are not supported.
Trailing slashes are significant.

A path registration associates patterns with a method table and fallback setting.
Each concrete rule definition has one ID shared across those patterns. Separate
definitions have different IDs even if their values compare equal. The guard compares IDs,
not rule values or application policies.

| Registration | Paths covered |
|---|---|
| `PathRegistration::path("/files").all(rule)` | `/files` only |
| `PathRegistration::subtree("/files").all(rule)` | `/files`, `/files/`, and paths below `/files/` |
| `PathRegistration::subtree("/files/").all(rule)` | `/files/` and paths below it; excludes `/files` |
| `PathRegistration::subtree("/").all(rule)` | All slash-prefixed request paths |
| `PathRegistration::exclusive_subtree("/files").all(rule)` | Same paths as `subtree`; nested paths are rejected at build time |

`PathRegistration::method` and `methods` define concrete method overrides.
Add it with `builder.register(...)`. An exclusive subtree does not override
method restrictions or disable any check.

## Forbidden registrations

These are **build-time errors**, returned by `build` or `from_registrations`.
They are separate from a valid router denying an individual request at `resolve`.
For steps to correct a route table, see
[Registering routes](crate::_docs::guide::registering).

| Forbidden construction | Example | Reason |
|---|---|---|
| A pattern without a leading slash | `PathRegistration::path("admin").all(rule)` | Patterns describe slash-prefixed paths. |
| An empty interior segment | `PathRegistration::path("/files//key").all(rule)` | The route grammar has no empty interior segments; a single trailing slash is supported. |
| A parameter occupying part of a segment | `PathRegistration::path("/v{version}").all(rule)` or `PathRegistration::path("/files/{name}.json").all(rule)` | Parameters must occupy a whole segment. |
| A non-final catch-all | `PathRegistration::path("/files/{*rest}/metadata").all(rule)` or `PathRegistration::path("/files/{*rest}/").all(rule)` | A catch-all consumes the entire remaining path. |
| A malformed or unnamed parameter | `PathRegistration::path("/users/{id").all(rule)`, `PathRegistration::path("/users/{}").all(rule)`, or `PathRegistration::path("/files/{*}").all(rule)` | Parameters need balanced braces and a non-empty name; `*` is reserved for the catch-all marker. |
| Two registrations claiming the same path and method slot | Two all-method `/health` routes; or GET `/users/{id}` and GET `/users/{name}` | Parameter names do not distinguish routing positions. Each position has at most one all-method rule and one rule per specific method. Equal rule values do not remove the conflict. |
| A method repeated within one registration | `.methods([http::Method::GET, http::Method::GET], rule)` | The registration claims the same method slot twice. |
| An empty method set | `.methods(Vec::<http::Method>::new(), rule)` | The registration would match no methods. |
| An empty pattern set | `PathRegistration::patterns(Vec::<String>::new()).all(rule)` | The registration would match no paths. |
| Structural forms in a literal, while the guard is active | `PathRegistration::path("/files/..").all(rule)`, `PathRegistration::path("/admin%2Fusers").all(rule)`, or `PathRegistration::path("/files;v=1").all(rule)` | Registered literals cannot depend on spellings the configured guard treats as path structure. Opt-in structural classes extend this restriction. |
| Uppercase literals with active, case-insensitive parsing | `PathRegistration::path("/Admin").all(rule)` with `CaseSensitivity::Insensitive` | The registered spelling must already agree with ASCII lowercasing. Parameter names are metadata and may contain uppercase letters. |

The pattern grammar, slot-conflict checks, and exclusivity checks also apply in
`GuardMode::Disabled`. The structural-literal and case checks apply only while the
guard is active. Not every percent escape is forbidden in a registered literal:
content escapes such as `%61` are checked for rule agreement when resolving requests.

### Exclusive-subtree conflicts

An exclusive subtree rejects another pattern that can take precedence for a path
in its catch-all tail. Validation considers overlapping literal and wildcard
branches, independently of registration order and method restrictions.

| Exclusive subtree | Conflicting registration | Why it is forbidden |
|---|---|---|
| `/files` | Exact route `/files/private` | The exact descendant wins over the exclusive catch-all. |
| `/files` | Subtree `/files/private` | A nested subtree takes over part of the exclusive tail. |
| `/{tenant}` | Exact route `/files/private` | The literal `files` branch wins over `{tenant}`. |
| `/{tenant}` | Catch-all route `/files/{*rest}` | The literal branch takes over the entire tail for tenant `files`. |
| `/{tenant}/files` | Exact route `/acme/{folder}/private` | The earlier literal `acme` wins; the later wildcard does not reverse that precedence. |
| `/{tenant}/files` | Catch-all route `/acme/{*rest}` | Despite its shorter prefix, this catch-all wins through the earlier literal `acme`. |
| GET-only `/files` | POST-only exact route `/files/private` | Path matching happens before method lookup; disjoint method sets do not prevent the override. |
| `/` | Exact route `/health` | An exclusive root covers every descendant. |

For example, both registration orders are rejected:

```rust
use huskarl_route_guard::{CaseSensitivity, DecodeDepth, GuardConfig, PathRegistration, RuleRouter};

let config = GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne);
let registrations = [
    PathRegistration::exclusive_subtree("/{tenant}").all("tenant-rule"),
    PathRegistration::path("/files/private").all("private-rule"),
];
assert!(RuleRouter::from_registrations("default", config.clone(), registrations.clone()).is_err());
assert!(RuleRouter::from_registrations("default", config, registrations.into_iter().rev()).is_err());
```

Related combinations that **are allowed**:

| Exclusive subtree | Additional registration | Why it is allowed |
|---|---|---|
| `/files` | Exact route `/health` | The paths are disjoint. |
| `/files` | Catch-all route `/{*rest}` | The broader fallback cannot take precedence inside `/files`. |
| `/files` | Exact route `/{tenant}/private` | The literal `files` branch wins inside the exclusive subtree. |
| `/{tenant}/files` | Exact route `/acme/other/key` | The literal `other` cannot match the protected `files` segment. |
| `/files/` | Exact route `/files` | The exclusive registration excludes the bare path. |
| All-method `/files` | GET-only subtree `/files` | These fill different method slots at the same path patterns; no nested path is introduced. |

Exclusivity concerns the non-empty catch-all tail. An exact route at a concrete
instance of a wildcard prefix, such as `/acme` alongside an exclusive `/{tenant}`,
does not consume that tail. Ordinary terminal-slot conflict rules still apply.
For the rationale behind these restrictions, see
[How the guard decides](crate::_docs::explanation::decision).

## Path precedence and explicit inheritance

Match the original request path, preferring literal segments, then wildcards, then
catch-alls. A branch that cannot finish matching falls back to the next branch.
At each matching path:

1. Use the concrete override for the request method, if present.
2. Otherwise use the concrete `ALL` rule, if present.
3. Otherwise continue to the next matching path only if `fallback_inherit(true)`.
4. Otherwise deny with `MethodNotConfigured`.

Every intermediate path controls continuation. Inheritance keeps the original path
and method; it does not remove directory components or change GET to another method.
A closer path's `ALL` wins over a farther path's explicit GET. Method overrides
always supply concrete rules; inheritance is a path-level setting.

```rust
use huskarl_route_guard::{RuleRouter, GuardConfig, CaseSensitivity, DecodeDepth, ResolveError};
use http::Method;
let router = RuleRouter::builder("public", GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
    .register_subtree("/files", |p| p.method(Method::GET, "read"))
    .register_path("/files/special", |p| p.fallback_inherit(true).method(Method::POST, "write"))
    .register_path("/files/blocked", |p| p.method(Method::POST, "write-only"))
    .build().unwrap();
let parent = router.resolve("/files/ordinary", &Method::GET).unwrap();
assert_eq!(router.resolve("/files/special", &Method::GET).unwrap(), parent);
assert_eq!(*router.resolve("/files/special", &Method::POST).unwrap().rule(), "write");
assert_eq!(router.resolve("/files/blocked", &Method::GET).unwrap_err(), ResolveError::MethodNotConfigured);
assert_eq!(router.resolve("/files/special", &Method::DELETE).unwrap_err(), ResolveError::MethodNotConfigured);
```

`register_path`, `register_subtree`, and `register_exclusive_subtree` configure a
[`PathRegistration`](crate::PathRegistration). Use `.all(rule)`, `.method(method,
rule)`, or `.methods(methods, rule)` for concrete definitions. Duplicate methods or
ALL definitions are build errors. A method table may have no rules: it either
blocks all methods or inherits them. Omitting the inheritance setting means false.
A concrete ALL rule takes precedence even if inheritance is enabled.

Declarations merged at the same path must agree on the inheritance setting.

## Default rule and identity

The default applies only when matching exhausts the available paths, including
through explicit inheritance. A method gap at a non-inheriting path is a denial,
not a default match. This also applies with `GuardMode::Disabled`.

Each concrete rule definition receives one identity, shared across the registration's
patterns. In a subtree method table, a GET rule has the same identity at the bare
prefix, trailing slash, and catch-all. An inherited result is the original defining
rule and identity; the child creates no copied rule. Separately defined equal values
still have different identities.

## Methods and ambiguity checks

All checks use the request's method and the same inheritance semantics as matching.
A structural region must contain one allowed identity. A reachable method denial
prevents that region from being accepted as uniform with an allowed rule.

| Path tables | Request | Result in `RejectAmbiguous` |
|---|---|---|
| GET-only `/files` subtree | GET `/files/a%2fb` | Accepted with the GET rule. |
| GET-only `/files` subtree | POST `/files/a%2fb` | `MethodNotConfigured`. |
| GET and POST rules in the same `/files` subtree table | GET `/files/a%2fb` | Accepted with the GET rule. |
| GET-only `/files`, POST-only `/files/private` with inheritance enabled | GET `/files/a%2fb` | Accepted; the child inherits the same GET identity. |
| GET-only `/files`, POST-only `/files/private` with inheritance disabled | GET `/files/a%2fb` | Denied; the region contains a stopped GET lookup. |

Acceptance still requires enforcement of the returned policy. Exclusivity remains
a path-level build restriction: nested overriding paths are rejected even when
those paths inherit for some methods.
