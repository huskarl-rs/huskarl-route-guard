# Tested deployments

These recommendations apply to the particular versions, configurations, and routing
scope below. The direct profiles have **no intermediate proxy between the guard
and the backend**; the separate NGINX profiles specify their entire chains.
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
| Tomcat 11.0.26 / Spring MVC 7.0.8 | Embedded Tomcat; explicit connector options; case-sensitive `PathPatternParser` | `Sensitive` | None |
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

The Tomcat–Spring fixture embeds Tomcat 11.0.26 with Spring MVC 7.0.8 on Java 21.
It explicitly sets UTF-8 URI decoding, `encodedSolidusHandling=reject`,
`encodedReverseSolidusHandling=decode`, `allowBackslash=false`, and
`rejectSuspiciousURIs=false`. The root `DispatcherServlet` uses a case-sensitive
`PathPatternParser`. Controllers return route IDs through native mappings, with
a general fallback; there is no custom path normalization. See the
[Tomcat connector reference](https://tomcat.apache.org/tomcat-11.0-doc/config/http.html)
and [Spring request mapping reference](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-requestmapping.html).
The fixture does not include Spring Boot, Spring Security filters, or the older
`AntPathMatcher`; those require separate profiles.

Fixed direct probes pin distinctions that guard filtering could hide:
`/admin;x=1/probe.txt` reaches admin, while `/admin%3Bx=1/probe.txt` and
`/public/..;x=1/admin/probe.txt` reach the public fallback. `/admin%2fprobe.txt`
returns 400. These are observations of the complete servlet/MVC combination,
not a claim that every servlet application treats these paths identically.
They are reported as characterization, separately from authorization evidence.

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

The subtree guard tables have a public default and lowercase `/admin` and `/files`
subtree registrations. Layouts cover a uniform files subtree, a distinct private
child, a private child under an otherwise public namespace, and method-specific
registrations. The latter can use multiple registrations for one policy. This tests
authorization-scope agreement, not equality of resource names within one scope. Use subtree registrations where slash/no-slash
roots share a policy. Two additional layouts use a protected default with a public
exact `/exact.txt` or parameterized `/foo/{segment}/bar` exception. Each explicitly
registers both trailing-slash spellings; backend rejection remains a no-resource
outcome. Frameworks serve native handlers and Apache serves fixed matching files.

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
  child. Express and the Tomcat–Spring fixture fall through to the parent's POST handler. Mirror that with an
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

All seventeen recommended profiles passed with zero observed policy mismatches.
The shared 7,024-path corpus combines grammar-generated delimiter injections,
mixed case, content escapes, double escapes, and separator transformations across
seven policy layouts, including one with a distinct policy for each fixture route
ID. The grammar table is independent of the guard's structural classes. Each
candidate uses the same input corpus; summary counts and per-target reports record
its results. A separate characterization pass sends every corpus path with GET,
HEAD, and POST to the backend regardless of guard acceptance. Its observations are
reused across candidates/layouts for the same method and target, but only accepted requests
contribute to safety comparisons. Characterization records actual behavior; it
does not assert an exact backend-model prediction or establish that denials are
unnecessary. A denied request supplies no downstream safety evidence;
redirects and backend rejections supply no evidence of policy agreement either.

Separate runs remove parsing settings and require accepted-request confusion.
Removing a method declaration instead must deny its named request safely: these
method entries are needed for availability, not to prevent default-rule fallthrough.

| Recommendation removed | Observed counterexample | Result |
|---|---|---|
| Case folding for default or explicitly insensitive Express | `/ADMIN/PROBE.TXT` | Guard authorizes public; backend reaches admin |
| Backslash handling for `SvelteKit` adapter-node | `/admin\probe.txt` | Guard authorizes public; backend reaches admin |
| Second decode for the specified NGINX–Apache chain | `/%2561dmin/probe.txt` | Guard authorizes public; origin serves admin |
| Query truncation for NGINX–Express | `/foo/secret%3F/bar` | Public exception matches at guard; origin reaches protected fallback |
| Fragment truncation for NGINX–Express | `/foo/secret%23/bar` | Public exception matches at guard; origin reaches protected fallback |
| HEAD declarations | `HEAD /admin/probe.txt` | Guard denies with `MethodNotConfigured` |
| Apache POST declarations | `POST /admin/probe.txt` | Guard denies with `MethodNotConfigured` |
| Express or Tomcat–Spring child POST fallback registration | `POST /files/private/probe.txt` | Non-inheriting child denies with `MethodNotConfigured` |

The confusion witnesses justify the parsing settings; the method-denial witnesses
pin safe failure when an availability requirement is omitted. Backslash handling
is now a conservative default for all profiles; the `SvelteKit` witness demonstrates
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

## Tested decode-and-reparse chain: NGINX to Express

The `nginx-express/DecodedUri` profile uses the same pinned NGINX configuration
above, with the case-sensitive, strict Express fixture as its isolated origin.
Use `Sensitive`, `UpToOne`, default structural classes, and `RejectAmbiguous`,
with the Express method registrations above. This profile does not establish a
second-decode requirement: decoding captures does not by itself reparse a URL.

In this chain, `/foo/secret%23/bar` and `/foo/secret%3F/bar` lose the `/bar`
suffix during downstream parsing. Both inputs match the guard's parameterized
public exception when the corresponding truncation class is disabled. Express
instead returns its fallback route ID, assigned the protected policy by this
layout. Separate removal runs require each witness to produce confusion; the
recommended configuration must produce none. No fixture implements a custom
truncation transform. These observations concern this specific URI-forwarding
configuration, not every NGINX or Express deployment.

## Additional proxy pairings and multiple hops

The runner separates proxy configurations from origin fixtures. The registry at
`tests/downstream/topologies.tsv` declares each full chain, in entry-to-origin
order, and `profiles.rs` assigns explicit guard settings and behavioral witnesses.

| Deployment | Chain after authorization | Decode declaration |
|---|---|---|
| `nginx-axum` | NGINX decoded URI → Axum | `UpToOne` |
| `nginx-raw-express` | NGINX original request URI → Express | `UpToOne` |
| `apache-proxy-express` | Apache reverse proxy → Express | `UpToOne` |
| `nginx-nginx-express` | NGINX decoded URI → NGINX decoded URI → Express | `UpToTwo` |
| `nginx-raw-nginx-apache` | NGINX original request URI → NGINX decoded URI → Apache | `UpToTwo` |
| `apache-proxy-nginx-express` | Apache reverse proxy → NGINX decoded URI → Express | `UpToOne` |

These profiles use the pinned versions above, `Sensitive`, default structural
classes, `RejectAmbiguous`, and their origin's method registrations. The Apache
reverse proxy uses native `mod_proxy_http`,
[`ProxyPass ... nocanon`](https://httpd.apache.org/docs/2.4/mod/mod_proxy.html#proxypass),
`AllowEncodedSlashes NoDecode`, and `MergeSlashes On`. NGINX original-URI forwarding
uses `$request_uri` in the same variable-URI proxy configuration. These are
specific fixture configurations, not claims about every deployment of either proxy.

The two decoded NGINX hops make `/%2561dmin/probe.txt` reach Express's admin
handler; removing the second-decode declaration must expose policy confusion.
Separate removal witnesses use `/foo/secret%253F/bar` and
`/foo/secret%2523/bar` for query and fragment truncation. The raw/decoded NGINX
chain to Apache retains the original second-decode witness. The mixed Apache/NGINX
chain to Express retains the single-encoded truncation witnesses.

The number of processes is not the decode depth. A chain requiring three
whole-path decode passes exceeds the library's supported model. The runner can
represent arbitrary ordered sequences, but a new composition needs its own full
chain validation and cannot inherit a safety claim from the component profiles.

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
