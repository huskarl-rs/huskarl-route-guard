# Real downstream deployment baselines

These tests validate the assumptions behind deployment recommendations. Only
requests accepted by each candidate guard configuration are sent downstream.
A reached route's independently assigned policy must agree with the authorized
policy. Removal runs weaken one setting or registration assumption and must expose
actual outgoing-request confusion for parsing settings. Removing a method
registration must instead deny its named request with `MethodNotConfigured`,
without introducing accepted-request confusion.

The user-facing reference is `docs/reference/deployments.md`.

## Running

```sh
mise run test                         # ordinary tests; no Docker
mise run test-downstream              # all nine deployment profiles
mise run test-downstream apache axum  # selected backends
mise run test-nginx-apache            # real two-decode chain
```

Aliases also include `test-apache`, `test-express`, `test-axum`, and `test-sveltekit`.
Requirements: Mise, Rust, Bash, and a running local Docker-compatible daemon.
Node, pnpm, and fixture build dependencies run inside containers. Initial builds
need network access; image digests and dependency locks are committed.

| Host | Execution |
|---|---|
| macOS | Docker Desktop, OrbStack, or another local Linux Docker VM |
| Linux | Docker Engine |
| GitHub Actions | Ubuntu runner, one matrix job per backend/chain, same Mise task |

All servers run on Linux, even on macOS. Images support ARM64 and x86-64. Fixture
files are copied into images to avoid inheriting host filesystem semantics. Remote
Docker daemons are unsupported: the published address must be local loopback.

## Setup, recommendations, and harness

- `scripts/test-downstream.sh` builds fixtures, publishes random loopback ports,
  runs the harness, saves logs, and removes containers and chain networks on exit.
  Images remain cached. The chain's Apache origin has no published port.
- Fixtures use native handlers or static-file mapping to return stable route IDs.
  No fixture imports this library. `X-Route-ID` identifies HEAD routes despite
  body suppression; Apache assigns the header using filesystem directory scope.
- `profiles.rs` declares guard settings, method-registration assumptions, and
  variants removing individual recommendations. Each removal pins a named
  method/path confusion or method-denial witness and runs the entire shared corpus.
- `tests/downstream.rs` contains the backend-independent transport and assertions.
  Each candidate receives the same input corpus before guard filtering. It has
  no branches identifying particular servers.

| Fixture | Profiles | Parsing configuration |
|---|---|---|
| Apache 2.4.68 | `Off`, `On`, `NoDecode` | `AllowEncodedSlashes` as named; `MergeSlashes On` |
| Express 5.2.1 | `Default`, `Sensitive`, `Insensitive` | Unmodified `express.Router()`, or explicit case declaration with `strict: true` |
| Axum 0.8.9 | `Sensitive` | Native routes and fallback; no rewriting middleware |
| SvelteKit 2.70.3 / adapter-node 5.5.7 | `Sensitive` | Production rest-parameter endpoints |
| NGINX 1.28.0 → Apache 2.4.68 | `DecodedUri` | `proxy_pass http://origin$uri$is_args$args`; origin encoded slashes `On` |

Direct guard profiles declare `UpToOne`; the chain declares `UpToTwo`. Express
Default/Insensitive declares `Insensitive`; all other profiles declare `Sensitive`.
SvelteKit adds backslash handling. All use default structural classes otherwise,
and default `RejectAmbiguous` mode. The normalized-URI proxy configuration is a
specific behavior under test, not a proposed safe proxy default.

Express registers child GET routes before parent GET routes and a parent POST
handler. Axum and SvelteKit use their native specificity/method selection. SvelteKit
retains minimal page/layout/error components so malformed requests have a working
error renderer. Apache serves real files with `AllowOverride None`, `Options None`,
and `AcceptPathInfo Off`; its static handler also accepts POST in this setup.

## Corpus, policy layouts, and methods

The deterministic 396-path corpus includes per-byte content escapes and double
escapes, mixed ASCII case, encoded/alternate separators, dot segments, matrix
parameters, malformed escapes, invalid bytes, and combinations of content encoding
with separator transformations. The same corpus is used for every candidate.

Common route IDs are `public`, `admin`, `files`, and `private`; a legacy Apache
literal-percent filename also belongs to the files policy. Four layouts vary the
independent policy assignment and guard registrations:

| Layout | Policy registration | Methods sent |
|---|---|---|
| Nested | Admin, files, distinct private child; public default | GET, HEAD |
| Uniform | Admin and files; private resource shares files policy | GET, HEAD |
| PrivateOnly | Only the private child is protected; everything else public | GET, HEAD |
| Methods | Nested scopes with explicit methods and fallback registrations | GET, HEAD, POST |

The method layout includes HEAD with GET. Apache includes POST for all static
scopes. Frameworks have a POST handler at `/files`; Express's private child falls
through to that handler and therefore needs an explicit child POST registration
in the guard. Axum and SvelteKit return 405 for that child method gap. Canonical
probes pin those distinctions and verify header identity and empty HEAD bodies.
These comparisons establish policy agreement, not resource identity within a policy.

The TCP client sends HTTP/1.0 with the original request target and zero-length body,
without a client URL parser or redirect following. Readiness and socket operations
have timeouts. Each layout/method must serve at least five corpus requests to
prevent a vacuous pass. Successful responses must contain known route IDs.
Redirects and 400/403/404/405 responses are `no-resource`, not agreement evidence.
A redirected request needs fresh authorization. Other statuses or network errors fail.

## Outcomes and recommendation changes

Recommended configurations must have zero policy mismatches. Each removal must
produce its declared outcome: parsing confusion or safe method denial, including
the named witness. If recommended settings
permit confusion, fix and document the configuration or model and retain the
counterexample. If a parsing-setting removal finds no confusion, review and remove the unsupported
recommendation for that tested profile. Absence of counterexamples in this finite
suite does not prove that a setting is unnecessary for arbitrary applications.

Mandatory built-in classes cannot be disabled individually, and `UpToOne` is the
minimum available decode depth. No individual necessity claim is made for those
built-in behaviors.

`target/downstream/<backend>-<profile>.tsv` records candidate, layout, method, path,
authorized policy, status, route ID, redirect location, and outcome: `agreement`,
`route-confusion`, `no-resource`, or `not-forwarded`. Denied requests have no
response fields and contribute no downstream evidence. String fields use Rust
debug-string escaping. Console output limits counterexample listings; reports
retain every result. Adjacent logs include the chain's origin separately, and CI
uploads all reports and logs.

## Scope

These are bounded GET/HEAD/POST baselines for the declared layouts, versions, and
configurations. Other methods, request bodies, application authorization based on
captures, arbitrary rewrites, native OS differences, and other proxy chains remain
outside the recommendations. Axum shares the matchit family with the in-process
matcher oracle. Proxy orchestration currently supports the specified NGINX–Apache
pair; it is not an arbitrary cross-product of proxies and origins.
