# Tested deployments

These recommendations apply to the particular versions, configurations, and routing
scope below. The direct profiles have **no intermediate proxy between the guard
and the backend**; the separate NGINX–Apache profile specifies its entire chain.
The supported claim is that these configurations passed the downstream route-confusion
tests. This is bounded evidence, not an exhaustive safety guarantee or a claim about
every application using the same framework.

The harness simulates the authorization/forwarding boundary using this library
and a TCP client. It does not run a complete production gateway. Validate that your
gateway passes the original path and method to the guard and preserves accepted
request targets when forwarding. See
[Why downstream parsing matters](crate::_docs::explanation::topology) for the
tested topology and the implications of selecting among multiple backends.

## Direct versions and configurations

All fixtures run on Linux. Node-based fixtures use Node.js 24.21.0. Container image
digests and dependency lockfiles in `tests/downstream/` fix the complete tested
environment; version numbers alone do not describe the entire deployment.

Every row uses [`DecodeDepth::UpToOne`](crate::DecodeDepth::UpToOne), the default
[`GuardMode::RejectAmbiguous`](crate::GuardMode::RejectAmbiguous), and the built-in
structural classes. Case sensitivity is an explicit declaration, not a library
default. All profiles now use default backslash handling.

| Software | Tested backend configuration | Guard case declaration | Additional structural classes |
|---|---|---|---|
| Apache HTTP Server 2.4.68 | Static files; `AllowEncodedSlashes Off`; `MergeSlashes On` | `Sensitive` | None |
| Apache HTTP Server 2.4.68 | Static files; `AllowEncodedSlashes On`; `MergeSlashes On` | `Sensitive` | None |
| Apache HTTP Server 2.4.68 | Static files; `AllowEncodedSlashes NoDecode`; `MergeSlashes On` | `Sensitive` | None |
| Express 5.2.1 | `express.Router()` with default options | `Insensitive` | None |
| Express 5.2.1 | `express.Router({ caseSensitive: false, strict: true })` | `Insensitive` | None |
| Express 5.2.1 | `express.Router({ caseSensitive: true, strict: true })` | `Sensitive` | None |
| Axum 0.8.9 | Direct routes and fallback, without path-rewriting middleware | `Sensitive` | None |
| `SvelteKit` 2.70.3 | Production `adapter-node` 5.5.7; rest-parameter endpoints | `Sensitive` | None |

Apache uses a case-sensitive container filesystem, `AllowOverride None`,
`Options None`, and `AcceptPathInfo Off`. The fixture has no aliases, rewrite rules,
CGI handlers, or application-level decoding. These are explicit configurations;
the tests do not establish what happens when those directives are omitted.

Express registers specific child routes before their parents, with handlers for
each subtree root, trailing-slash root, and descendant path. Axum registers those
three forms with its native router. The `SvelteKit` fixture uses `[...rest]` endpoints
under the corresponding prefixes, with a public fallback. None authorizes individual
objects using decoded route captures. Full server setup lives alongside each fixture.

## Guard configuration

Use the row matching the backend setup:

```rust
use huskarl_route_guard::{CaseSensitivity, DecodeDepth, GuardConfig};

// Apache, Axum, or explicitly case-sensitive Express, as configured above.
let sensitive = GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne);

// Default Express, or the explicitly case-insensitive Express profile.
let express = GuardConfig::new(CaseSensitivity::Insensitive, DecodeDepth::UpToOne);

// The tested SvelteKit adapter-node deployment.
let sveltekit = GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne);
```

The tested guard tables have a public default and lowercase `/admin` and `/files`
subtree registrations. Layouts cover a uniform files subtree, a distinct private
child, a private child under an otherwise public namespace, and method-specific
registrations. The latter can use multiple registrations for one policy. This tests
authorization-scope agreement, not equality of resource names within one scope. Use subtree registrations where slash/no-slash
roots share a policy; exact-route trailing-slash equivalence is outside this baseline.

Apply the guard to the unmodified path and forward accepted requests without
rewriting it. Preserve the tested relationship between guard registrations and
backend authorization scopes. See [Registering routes](crate::_docs::guide::registering)
for registration semantics.

## Method-specific registrations

All fixtures exercise GET and HEAD, and POST is exercised in the method-specific
layout. Route IDs are returned in `X-Route-ID`, so HEAD can identify the handler
without a response body. Canonical probes assert successful handlers and expected
405 responses; a 405 is not counted as policy agreement.

- Include HEAD wherever the backend serves a protected GET route for HEAD.
  All tested fixtures do so. Removing HEAD from a non-inheriting method table now
  denies those requests with `MethodNotConfigured`, rather than authorizing public access.
- This Apache static-file configuration also serves POST. Protect those resources
  for POST as well, or enforce a separately tested method restriction. This applies
  to the Apache origin in the NGINX chain too.
- The framework fixtures register POST for `/files`, but only GET for its private
  child. Express falls through to the parent's POST handler. Mirror that with an
  explicit POST registration at `/files/private` using the files policy, or enable
  inheritance there to retain the parent POST rule and identity. Without either,
  the guard denies the method gap. Axum and `SvelteKit`
  return 405 for POST at the private child in these fixtures, so they need no
  corresponding fallback registration.

For example, the tested Express method layout includes:

```rust
use http::Method;
use huskarl_route_guard::{CaseSensitivity, DecodeDepth, GuardConfig, RuleRouter};

let router = RuleRouter::builder(
    "public",
    GuardConfig::new(CaseSensitivity::Insensitive, DecodeDepth::UpToOne),
)
.register_subtree("/files", |path|
    path.methods([Method::GET, Method::HEAD, Method::POST], "files"))
.register_subtree("/files/private", |path|
    path.methods([Method::GET, Method::HEAD], "private").method(Method::POST, "files"))
.build().unwrap();
assert_eq!(*router.resolve("/files/private/probe.txt", &Method::POST).unwrap().rule(), "files");
```

These are fixture-specific method recommendations. Other methods and framework
handlers need their own policy mapping and tests.

## Evidence for additional settings

The previously tested nine profiles passed with zero observed confusion. Those
runs enabled backslash handling only for SvelteKit; the current profiles enable
it for every backend by default. This stricter setting can only deny more
requests; it does not establish additional availability evidence. The shared
396-path corpus combines mixed case, content escapes, double escapes,
and separator transformations across four policy layouts. Each candidate uses the
same input corpus; the summary counts and per-request reports record its results.
Only requests accepted by the candidate guard are sent downstream. A denied request
supplies no downstream safety evidence; redirects and backend rejections supply no evidence
of policy agreement either.

Separate runs remove parsing settings and require accepted-request confusion.
Removing a method declaration instead must deny its named request safely: these
method entries are needed for availability, not to prevent default-rule fallthrough.

| Recommendation removed | Observed counterexample | Result |
|---|---|---|
| Case folding for default or explicitly insensitive Express | `/ADMIN/PROBE.TXT` | Guard authorizes public; backend reaches admin |
| Backslash handling for `SvelteKit` adapter-node | `/admin\probe.txt` | Guard authorizes public; backend reaches admin |
| Second decode for the specified NGINX–Apache chain | `/%2561dmin/probe.txt` | Guard authorizes public; origin serves admin |
| HEAD declarations | `HEAD /admin/probe.txt` | Guard denies with `MethodNotConfigured` |
| Apache POST declarations | `POST /admin/probe.txt` | Guard denies with `MethodNotConfigured` |
| Express child POST fallback registration | `POST /files/private/probe.txt` | Non-inheriting child denies with `MethodNotConfigured` |

The confusion witnesses justify the parsing settings; the method-denial witnesses
pin safe failure when an availability requirement is omitted. Backslash handling
is now a conservative default for all profiles; the SvelteKit witness demonstrates
why opting out can be unsafe. No additional fullwidth, overlong, or second-decode
setting is recommended for the other direct profiles. `UpToOne` is the minimum
available decode setting. Encoded-slash, dot-segment, matrix-param, and
NUL-truncation handling cannot be disabled. These tests make no claim about the
individual necessity of those mandatory behaviors.

If a recommended configuration permits confusion, correct the deployment advice
or model and preserve the counterexample. If removing an additional setting finds
no confusion, review and remove the unsupported recommendation for that tested
profile. Absence of a counterexample does not establish safety for other deployments.

## Scope and revalidation

The suite covers GET, HEAD, and the fixture POST policies, including Apache static-file
selection. It does not cover other methods, authorization based on captured
parameter values, custom middleware, arbitrary rewrites, other operating-system semantics, or arbitrary
route tables. The transport is HTTP/1.0 over TCP; this is not a protocol-wide HTTP
security assessment.

Changing a version, routing configuration, middleware, or filesystem mapping changes
the deployment being evaluated. Adding NGINX, Envoy, a CDN, or another intermediary
requires a separate profile for the complete chain; these direct recommendations
do not extend to it automatically.

## Tested two-decode chain: NGINX to Apache

The `nginx-apache/DecodedUri` profile pins NGINX 1.28.0 in front of Apache 2.4.68,
with Apache's `AllowEncodedSlashes On` and the static-file settings above. Only the
proxy port is published; Apache is reached over an isolated Docker network.
The relevant NGINX configuration is:

```nginx
upstream origin { server origin:8080; }
server {
    listen 8080;
    location / {
        proxy_pass http://origin$uri$is_args$args;
        proxy_set_header Host localhost;
        proxy_http_version 1.0;
    }
}
```

This deliberately forwards the normalized `$uri` as the upstream URI. NGINX documents
[`$uri` as normalized](https://nginx.org/en/docs/http/ngx_http_core_module.html#var_uri)
and [variable-URI forwarding in `proxy_pass`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass).
This is a configuration whose behavior we test, not a recommendation to introduce
extra decoding. It must not be generalized to every NGINX `proxy_pass` configuration.

The real chain converts `/%2561dmin/probe.txt` to `/%61dmin/probe.txt` before Apache
serves `/admin/probe.txt`. With `UpToOne`, the guard accepts this as public but the
origin serves admin. The removal run must reproduce this confusion;
the recommended `UpToTwo` profile must permit none. Proxy access logs record the incoming
and normalized paths, and separate origin logs are retained.

For this exact chain, use `Sensitive`, `UpToTwo`, default structural classes, and
`RejectAmbiguous`. Include HEAD and POST in the static-resource registrations as
above. The suite separately removes the second decode declaration, HEAD declaration,
and static-file POST declarations. The decode removal requires an outgoing-request
counterexample; the method removals require explicit method denial.

## Running the tests

Reproduce the baseline with `mise run test-downstream`, or select a backend with
`mise run test-downstream express`. The task uses a local Docker-compatible daemon
on macOS or Linux; GitHub Actions runs the same task on Ubuntu. Node dependencies
are installed with pnpm inside the fixtures. Per-request reports and server logs
are written to `target/downstream/` and retained as CI artifacts.

The repository's `tests/downstream/README.md` describes execution and report formats;
`tests/downstream/profiles.rs` records the guard configurations and removal runs.
See [How the security claim is tested](crate::_docs::explanation::testing) for the
relationship between these deployment tests and the in-process model tests.
