# Real downstream deployment baselines

These tests validate the assumptions behind deployment recommendations. For corpus comparisons, only
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
mise run test-downstream              # all eleven deployment profiles
mise run test-downstream apache axum  # selected backends
mise run test-nginx-apache            # real two-decode chain
mise run test-nginx-express           # real decode-and-reparse chain
mise run test-tomcat-spring           # native servlet + Spring MVC routing
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
  Images remain cached. Neither chain publishes its origin port.
- Fixtures use native handlers or static-file mapping to return stable route IDs.
  No fixture imports this library. `X-Route-ID` identifies HEAD routes despite
  body suppression; Apache assigns the header using filesystem directory scope.
- `profiles.rs` declares guard settings, method-registration assumptions, and
  variants removing individual recommendations. Each removal pins a named
  method/path confusion or method-denial witness and runs the entire shared corpus.
- `tests/downstream.rs` contains the backend-independent transport and assertions.
  Stateless fixture responses are cached by method/target across layouts and
  candidates; a target is fetched only after a candidate accepts it.
  Each candidate receives the same input corpus before guard filtering. It has
  no branches identifying particular servers.

| Fixture | Profiles | Parsing configuration |
|---|---|---|
| Apache 2.4.68 | `Off`, `On`, `NoDecode` | `AllowEncodedSlashes` as named; `MergeSlashes On` |
| Express 5.2.1 | `Default`, `Sensitive`, `Insensitive` | Unmodified `express.Router()`, or explicit case declaration with `strict: true` |
| Axum 0.8.9 | `Sensitive` | Native routes and fallback; no rewriting middleware |
| SvelteKit 2.70.3 / adapter-node 5.5.7 | `Sensitive` | Production rest-parameter endpoints |
| NGINX 1.28.0 → Apache 2.4.68 | `DecodedUri` | `proxy_pass http://origin$uri$is_args$args`; origin encoded slashes `On` |
| Tomcat 11.0.26 / Spring MVC 7.0.8 | `PathPattern` | Case-sensitive `PathPatternParser`; encoded slash rejected; backslash disabled |
| NGINX 1.28.0 → Express 5.2.1 | `DecodedUri` | Same proxy configuration; case-sensitive, strict Express router |

Direct guard profiles and NGINX–Express declare `UpToOne`; NGINX–Apache declares
`UpToTwo`. Express
Default/Insensitive declares `Insensitive`; all other profiles declare `Sensitive`.
All use default structural classes, including backslash handling,
and default `RejectAmbiguous` mode. The normalized-URI proxy configuration is a
specific behavior under test, not a proposed safe proxy default.

Tomcat–Spring uses explicit connector settings and native controller mappings;
see `tomcat-spring/README.md` for version pins and parsing probes.

Express registers child GET routes before parent GET routes and a parent POST
handler. Axum and SvelteKit use their native specificity/method selection. SvelteKit
retains minimal page/layout/error components so malformed requests have a working
error renderer. Apache serves real files with `AllowOverride None`, `Options None`,
and `AcceptPathInfo Off`; its static handler also accepts POST in this setup.

## Corpus, policy layouts, and methods

The deterministic 7,024-path corpus includes per-byte content escapes and double
escapes, mixed ASCII case, encoded/alternate separators, dot segments, matrix
parameters, malformed escapes, invalid bytes, and combinations of content encoding
with separator transformations. The same corpus is used for every candidate.

`corpus.rs` derives injections independently from RFC 3986's gen-delims and
sub-delims, plus `%`, backslash, dot, and NUL. It inserts each byte raw, encoded,
and double encoded (both hex cases) at segment boundaries, midpoints, and path
suffixes. Seeds include ordinary resources, exact/parameterized exceptions, and
dot-segment combinations. A sorted set deduplicates overlaps and gives stable
report ordering. Targeted cases in the harness supplement this grammar table.

Common route IDs are `public`, `admin`, `files`, `private`, `exact`, and `parameterized`; a legacy Apache
literal-percent filename also belongs to the files policy. Six layouts vary the
independent policy assignment and guard registrations:

| Layout | Policy registration | Methods sent |
|---|---|---|
| Nested | Admin, files, distinct private child; public default | GET, HEAD |
| Uniform | Admin and files; private resource shares files policy | GET, HEAD |
| PrivateOnly | Only the private child is protected; everything else public | GET, HEAD |
| Methods | Nested scopes with explicit methods and fallback registrations | GET, HEAD, POST |
| ExactException | Protected default, public `/exact.txt` and `/exact.txt/` | GET, HEAD |
| ParameterizedException | Protected default, public `/foo/{segment}/bar` and trailing-slash form | GET, HEAD |

The method layout includes HEAD with GET. Apache includes POST for all static
scopes. Frameworks have a POST handler at `/files`; Express's private child falls
through to that handler and therefore needs an explicit child POST registration
in the guard. Tomcat–Spring has the same parent POST fallback requirement. Axum and SvelteKit return 405 for that child method gap. Canonical
probes pin those distinctions and verify header identity and empty HEAD bodies.
The exception routes use native framework routing. Apache serves real files at
`/exact.txt`, `/foo/secret/bar`, and `/foo/other/bar`; directory/file scopes label
those resources without interpreting the incoming target. Both trailing-slash
spellings are authorized for exceptions; a backend may reject one. These
comparisons establish policy agreement, not resource identity within a policy.

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
`route-confusion`, `no-resource`, or `not-forwarded`. The `characterization` candidate contains fixed direct parsing probes with outcome
`observed`; these have no guard policy and never count as forwarding or agreement
evidence. They are separate from candidate corpus runs. Denied corpus requests have no
response fields and contribute no downstream evidence. String fields use Rust
debug-string escaping. Summary counts are logical accepted/served/denied comparisons, including reused
observations, rather than physical connection counts. Console output limits counterexample listings; reports
retain every result. Adjacent logs include the chain's origin separately, and CI
uploads all reports and logs.

## Scope

These are bounded GET/HEAD/POST baselines for the declared layouts, versions, and
configurations. Other methods, request bodies, application authorization based on
captures, arbitrary rewrites, native OS differences, and other proxy chains remain
outside the recommendations. Axum shares the matchit family with the in-process
matcher oracle. Proxy orchestration supports the specified NGINX–Apache and NGINX–Express
pairs; it is not an arbitrary cross-product of proxies and origins.

## Historical discovery check: `tmwxmztl`

The NGINX–Express profile provides real decode-and-reparse evidence for query and
fragment truncation. Removing either class must expose its independently
specified witness, `/foo/secret%3F/bar` or `/foo/secret%23/bar`. The generator
produces both from `/foo/secret/bar`; they are not injected as handpicked paths.
Express reaches its fallback after truncation, which is protected in the
parameterized-exception layout while the original path matches the public rule.

To check historical discovery, export parent commit
`b4e38bceca7230547a9ad837655aed3b0501bc27` into a temporary directory and overlay
this harness, corpus, profiles, fixtures, and runner. The only API adaptations are
removing the two class-builder toggles (which did not yet exist) and running only
the default candidate, without the new ablations. Run `nginx-express` there.
The expected failure is accepted-request policy confusion, not a compile failure
or a synthetic normalizer result. Keep its TSV and logs separately from current
baseline results. The normal suite continuously pins the two removal witnesses;
historical source export is a manual audit, not a CI dependency.

The audit on 2026-09-26 found 153 policy mismatches on that parent with `UpToOne`
and this 7,024-path corpus; the current recommended profile found zero. Current
removal runs found 102 query-truncation and 51 fragment-truncation mismatches.
These are method/layout comparisons, not counts of unique exploit paths.

Additional servlet configurations, Envoy, Go, and FastCGI profiles, fuzz-corpus replay, and direct
characterization of guard-rejected inputs remain follow-up work.
