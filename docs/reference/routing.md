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

## Forbidden registrations

These are **build-time errors**, returned by `build` or `from_registrations`.
They are separate from a valid router denying an individual request at `resolve`.
For steps to correct a route table, see
[Registering routes](crate::_docs::guide::registering).

| Forbidden construction | Example | Reason |
|---|---|---|
| A pattern without a leading slash | `route("admin", rule)` | Patterns describe slash-prefixed paths. |
| An empty interior segment | `route("/files//key", rule)` | The route grammar has no empty interior segments; a single trailing slash is supported. |
| A parameter occupying part of a segment | `route("/v{version}", rule)` or `route("/files/{name}.json", rule)` | Parameters must occupy a whole segment. |
| A non-final catch-all | `route("/files/{*rest}/metadata", rule)` or `route("/files/{*rest}/", rule)` | A catch-all consumes the entire remaining path. |
| A malformed or unnamed parameter | `route("/users/{id", rule)`, `route("/users/{}", rule)`, or `route("/files/{*}", rule)` | Parameters need balanced braces and a non-empty name; `*` is reserved for the catch-all marker. |
| Two registrations claiming the same path and method slot | Two all-method `/health` routes; or GET `/users/{id}` and GET `/users/{name}` | Parameter names do not distinguish routing positions. Each position has at most one all-method rule and one rule per specific method. Equal rule values do not remove the conflict. |
| A method repeated within one registration | `.for_methods([http::Method::GET, http::Method::GET])` | The registration claims the same method slot twice. |
| An empty method set | `.for_methods(Vec::<http::Method>::new())` | The registration would match no methods. |
| An empty pattern set | `Registration::patterns(Vec::<String>::new(), rule)` | The registration would match no paths. |
| Structural forms in a literal, while the guard is active | `route("/files/..", rule)`, `route("/admin%2Fusers", rule)`, or `route("/files;v=1", rule)` | Registered literals cannot depend on spellings the configured guard treats as path structure. Opt-in structural classes extend this restriction. |
| Uppercase literals with active, case-insensitive parsing | `route("/Admin", rule)` with `CaseSensitivity::Insensitive` | The registered spelling must already agree with ASCII lowercasing. Parameter names are metadata and may contain uppercase letters. |

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
use huskarl_route_guard::{CaseSensitivity, DecodeDepth, GuardConfig, Registration, RuleRouter};

let config = GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne);
let registrations = [
    Registration::exclusive_subtree("/{tenant}", "tenant-rule"),
    Registration::route("/files/private", "private-rule"),
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

All ambiguity checks compare rules for the request's actual method. Structural
checks require every path in the analyzed region to select the same rule for that
method. Methods without explicit registrations use the all-method rules and default.

| Route table | Request | Result in `RejectAmbiguous` |
|---|---|---|
| GET-only `/files` subtree | GET `/files/a%2fb` | Accepted with the GET rule: the region has uniform GET coverage. |
| GET-only `/files` subtree | POST `/files/a%2fb` | Accepted with the default: the region uniformly selects default for POST. |
| Separate GET and POST rules for the same `/files` subtree patterns | GET `/files/a%2fb` | Accepted with the GET rule; the POST rule does not change GET coverage. |
| GET-only `/files` subtree plus GET `/files/private` | GET `/files/a%2fb` | Denied: another GET identity is reachable in the analyzed region. |
| GET-only `/files` subtree plus POST `/files/private` | GET `/files/a%2fb` | Denied: the more-specific POST-only terminal selects default for GET. |

Acceptance still requires enforcement of the returned rule, including the default.
Exclusive subtrees use the same request-time checks, but reject the nested path
configurations in the last two rows at build time.
