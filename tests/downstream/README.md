# Real downstream deployment baselines

These tests validate the assumptions behind deployment recommendations. A separate
characterization pass sends every corpus path directly to the backend with GET,
HEAD, and POST, independently of guard acceptance. Safety comparisons use only
requests accepted by each candidate guard configuration.
A reached route's independently assigned policy must agree with the authorized
policy. Removal runs weaken one setting or registration assumption and must expose
actual outgoing-request confusion for parsing settings. Removing a method
registration must instead deny its named request with `MethodNotConfigured`,
without introducing accepted-request confusion.

The user-facing reference is `docs/reference/deployments.md`.

## Running

```sh
mise run test                         # ordinary tests; no Docker
mise run test-downstream              # all nineteen deployment profiles
mise run test-downstream apache axum  # selected backends
mise run test-nginx-apache            # real two-decode chain
mise run test-nginx-express           # real decode-and-reparse chain
mise run test-tomcat-spring           # native servlet + Spring MVC routing
mise run test-downstream-search       # adds a seeded composed-mutation search

# Reproduce a search run (seed and budget are printed and saved in search.txt):
ROUTE_GUARD_DOWNSTREAM_SEED=123 ROUTE_GUARD_DOWNSTREAM_BUDGET=10000 mise run test-downstream nginx-express
```

Aliases also include `test-apache`, `test-express`, `test-axum`, `test-sveltekit`,
`test-go`, and `test-nginx-go`.
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
  runs the harness, saves logs, and removes every hop and chain network on exit.
  Images remain cached. Only each chain's entry port is published.
- Fixtures use native handlers or static-file mapping to return stable route IDs.
  No fixture imports this library. `X-Route-ID` identifies HEAD routes despite
  body suppression; Apache assigns the header using filesystem directory scope.
- `profiles.rs` declares guard settings, method-registration assumptions, and
  variants removing individual recommendations. Each removal pins a named
  method/path confusion or method-denial witness and runs the entire shared corpus.
- `tests/downstream.rs` contains the backend-independent transport and assertions.
  The full-corpus characterization pass caches stateless fixture responses by
  method/target for reuse across layouts and candidates. Only accepted requests
  contribute to candidate safety comparisons.
  Each candidate receives the same input corpus before guard filtering. It has
  no branches identifying particular servers.

| Fixture | Profiles | Parsing configuration |
|---|---|---|
| Apache 2.4.68 | `Off`, `On`, `NoDecode` | `AllowEncodedSlashes` as named; `MergeSlashes On` |
| Express 5.2.1 | `Default`, `Sensitive`, `Insensitive` | Unmodified `express.Router()`, or explicit case declaration with `strict: true` |
| Go 1.27.1 | `ServeMux` | Standard-library `net/http.ServeMux`; modern method/wildcard patterns |
| NGINX 1.28.0 → Go 1.27.1 | `DecodedUri` | Normalized-URI forwarding to the same ServeMux fixture |
| Axum 0.8.9 | `Sensitive` | Native routes and fallback; no rewriting middleware |
| SvelteKit 2.70.3 / adapter-node 5.5.7 | `Sensitive` | Production rest-parameter endpoints |
| NGINX 1.28.0 → Apache 2.4.68 | `DecodedUri` | `proxy_pass http://origin$uri$is_args$args`; origin encoded slashes `On` |
| Tomcat 11.0.26 / Spring MVC 7.0.8 | `PathPattern` | Case-sensitive `PathPatternParser`; encoded slash rejected; backslash disabled |
| NGINX 1.28.0 → Express 5.2.1 | `DecodedUri` | Same proxy configuration; case-sensitive, strict Express router |

Direct guard profiles and NGINX–Express declare `UpToOne`; NGINX–Apache and
NGINX–Go declare `UpToTwo`. Express
Default/Insensitive declares `Insensitive`; all other profiles declare `Sensitive`.
All use default structural classes, including backslash handling,
and default `RejectAmbiguous` mode. The normalized-URI proxy configuration is a
specific behavior under test, not a proposed safe proxy default.

Go uses native `ServeMux` patterns and pins segment unescaping, escaped slashes,
path-cleaning redirects, and method fallback; see `go/README.md`. Its decoded-URI
NGINX chain declares `UpToTwo` and pins a second-decode confusion witness.

Tomcat–Spring uses explicit connector settings and native controller mappings;
see `tomcat-spring/README.md` for version pins and parsing probes.

Express registers child GET routes before parent GET routes and a parent POST
handler. Axum and SvelteKit use their native specificity/method selection. SvelteKit
retains minimal page/layout/error components so malformed requests have a working
error renderer. Apache serves real files with `AllowOverride None`, `Options None`,
and `AcceptPathInfo Off`; its static handler also accepts POST in this setup.

## Composing proxies and origins

`topologies.tsv` is the runner's registry. Each row has five whitespace-separated
fields: deployment name, guard profile name, origin fixture, origin profile, and
an entry-first comma-separated proxy list (`-` for a direct deployment). For example:

```text
nginx-nginx-express DecodedUri express Sensitive nginx-decoded,nginx-decoded
apache-proxy-nginx-express Mixed express Sensitive apache-proxy,nginx-decoded
```

The runner builds each fixture once per invocation, starts the origin and then
works outward, connects each proxy to its next hop through `UPSTREAM`, and publishes
only the entry on a random loopback port. Logs are saved for every hop and the
origin, including on test failure. `*-topology.txt` records the exact registry row.
The proxy fixtures are independent of the selected origin:

- `nginx-decoded`: the existing normalized `$uri$is_args$args` forwarding behavior.
- `nginx-raw`: the same pinned NGINX, forwarding `$request_uri`.
- `apache-proxy`: pinned Apache 2.4.68, native `mod_proxy_http`, `ProxyPass ... nocanon`,
  `AllowEncodedSlashes NoDecode`, and `MergeSlashes On`.

Add a row and a corresponding recommendation/probes/removal witnesses in
`profiles.rs` to test another coupling or hop sequence. No orchestration branches
are needed for new pairings of existing proxies and origins. New proxy
implementations need a fixture and a proxy-type entry in the runner. Arbitrary
sequences are representable; their guard settings are deliberately not inferred
from the number or names of their components. Add new deployments to both CI
matrices for continuous deterministic and seeded coverage.

```sh
mise run test-downstream nginx-axum nginx-raw-express apache-proxy-express
mise run test-downstream nginx-nginx-express nginx-raw-nginx-apache
mise run test-downstream apache-proxy-nginx-express
python3 -B scripts/test-downstream-runner.py  # wiring/cleanup checks without Docker
```

Additional baselines cover NGINX decoded → Axum, NGINX raw → Express, Apache proxy
→ Express, two decoded NGINX hops → Express, raw NGINX → decoded NGINX → Apache,
and Apache proxy → decoded NGINX → Express. Two decoded NGINX hops → Express and
the raw/decoded NGINX chain → Apache declare `UpToTwo`; the others declare
`UpToOne`. All declare `Sensitive` and retain the origin's method requirements.
Two-hop profiles pin decoding or truncation witnesses against the complete chain.
The raw NGINX and Apache-proxy profiles pin escaped-content and encoded-query
observations that distinguish them from normalized-URI forwarding.

The library supports at most two whole-path decode passes. A third decoding stage
is outside that model; it must not be declared safe by selecting `UpToTwo`.
Multiple hops can still fit: raw forwarding does not necessarily add a decode pass.
The two-NGINX/Express profile also probes a triple-escaped content byte to pin the
observed two-pass boundary.

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
literal-percent filename also belongs to the files policy. Seven layouts vary the
independent policy assignment and guard registrations:

| Layout | Policy registration | Methods sent |
|---|---|---|
| Distinct | Each of the six fixture route IDs has its own policy, including exact and parameterized routes | GET, HEAD |
| Nested | Admin, files, distinct private child; public default | GET, HEAD |
| Uniform | Admin and files; private resource shares files policy | GET, HEAD |
| PrivateOnly | Only the private child is protected; everything else public | GET, HEAD |
| Methods | Nested scopes with explicit methods and fallback registrations | GET, HEAD, POST |
| ExactException | Protected default, public `/exact.txt` and `/exact.txt/` | GET, HEAD |
| ParameterizedException | Protected default, public `/foo/{segment}/bar` and trailing-slash form | GET, HEAD |

The method layout includes HEAD with GET. Apache includes POST for all static
scopes. Frameworks have a POST handler at `/files`; Express's private child falls
through to that handler and therefore needs an explicit child POST registration
in the guard. Tomcat–Spring and Go ServeMux have the same parent POST fallback requirement. Axum and SvelteKit return 405 for that child method gap. Canonical
probes pin those distinctions and verify header identity and empty HEAD bodies.
The exception routes use native framework routing. Apache serves real files at
`/exact.txt`, `/foo/secret/bar`, and `/foo/other/bar`; directory/file scopes label
those resources without interpreting the incoming target. Both trailing-slash
spellings are authorized for exceptions; a backend may reject one. The distinct
layout retains each fixture route ID as a separate policy; the other layouts still exercise shared policies and different acceptance boundaries. These
comparisons establish policy agreement, not resource identity or capture values
within a handler. Adding registrations can cause more guard denials, so the
distinct layout supplements rather than replaces the existing layouts.

The TCP client sends HTTP/1.0 with the original request target and zero-length body,
without a client URL parser or redirect following. Readiness and socket operations
have timeouts. Each layout/method must serve at least five corpus requests to
prevent a vacuous pass. Successful responses must contain known route IDs.
Redirects and 400/403/404/405 responses are `no-resource`, not agreement evidence.
A redirected request needs fresh authorization. Other statuses or network errors fail.
Unexpected responses are saved in the observation report before validation, and
the failure identifies the method and target. For proxy errors such as 502, compare
that observation with the per-hop logs in `target/downstream/`; they are collected
even when the test fails.

## Regressions, seeded search, and shrinking

Every run replays `regressions.tsv`: one target per line as a Rust debug string
(the spelling used by all reports), a tab, and provenance. These targets join the
shared corpus for every profile, candidate, layout, and method, so a committed
mismatch stays covered even if the generators change.

The default suite stays deterministic. Setting `ROUTE_GUARD_DOWNSTREAM_SEED`
adds a seeded search (`corpus.rs`, `seeded_paths`): `ROUTE_GUARD_DOWNSTREAM_BUDGET`
attempts (default 2,000), each applying two or three composed mutations to a
grammar seed. Mutations are delimiter insertion (the grammar table's bytes and
spellings), separator substitution, single-byte escaping, case flips, dot-segment
insertion (including `..;` and encoded forms), matrix parameters, and trailing
slash toggling. The generator uses SplitMix64, so a seed reproduces the same
paths on any platform. `mise run test-downstream-search` draws a random seed
unless one is set; the nightly `downstream-search` workflow uses the run ID and
a budget of 10,000, and records the reproduction command in the job summary.
Runtime grows with paths multiplied by three characterization methods per profile,
while candidate comparisons reuse those observations.

Each target records its families: `targeted`, `grammar`, `regression`, `seeded`,
and one `seeded/<mutation>` entry per mutation that produced it. The console and
`<backend>-<profile>-families.tsv` report, per candidate and family, the guard
evaluations, accepted inputs, accepted inputs that reached a resource, and policy
mismatches. The `characterization` rows count direct method/target observations
and resources reached. A family whose inputs the guard denies exercises the
guard but provides no downstream evidence; compare `accepted` and `served`
before reading a family's zero mismatches as coverage.

An unexpected mismatch (any mismatch for the recommended configuration, or for a
method-registration removal) is shrunk against the live backend: at most five
cases per candidate, each within 400 predicate checks. Shrinking deletes
character ranges while the guard still accepts the target and the backend still
reaches a different policy; the minimized mismatch need not keep the original
policy pair. Removal witnesses are expected mismatches and are not shrunk.
Results go to the console and `<backend>-<profile>-shrunk.tsv`, in
`regressions.tsv` format with candidate, layout, method, policies, original
target, families, seed, budget, check count, and whether the budget ran out. The
file header records the reproduction command. After diagnosing and fixing a
mismatch, append its line to `regressions.tsv`.

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
`route-confusion`, `no-resource`, or `not-forwarded`. The `characterization`
candidate contains every corpus path for GET, HEAD, and POST with outcome
`observed` (21,072 corpus rows per profile, plus any fixed GET probes outside the
corpus). These rows have no guard policy and never count as forwarding or agreement
evidence. Fixed parsing probes reuse corpus observations where available and pin
known behavior. Denied candidate rows
retain empty response fields and contribute no downstream safety evidence; join
them to characterization rows by method/path to inspect backend behavior.
Characterization validates response statuses and successful route IDs, but does
not assert agreement with an exact backend model or prove that a denial is
unnecessary. Redirects are recorded without following them. String fields use Rust
debug-string escaping. Summary counts are logical accepted/served/denied comparisons, including reused
observations, rather than physical connection counts. Console output limits counterexample listings; reports
retain every result. Adjacent logs include the chain's origin separately, and CI
uploads all reports and logs.

## Scope

These are bounded GET/HEAD/POST baselines for the declared layouts, versions, and
configurations. Other methods, request bodies, application authorization based on
captures, arbitrary rewrites, native OS differences, and other proxy chains remain
outside the recommendations. Axum shares the matchit family with the in-process
matcher oracle. Proxy orchestration accepts an ordered list of proxy configurations for any fixture
origin. Each registered chain still requires its own measured guard profile;
passing individual components does not establish safety of their composition.

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
and this 7,024-path corpus; the recommended profile found zero. At that audit,
removal runs found 102 query-truncation and 51 fragment-truncation mismatches
across the original six layouts. These are method/layout comparisons, not counts
of unique exploit paths; adding the distinct layout changes the totals.

Additional servlet configurations, Envoy, and FastCGI profiles, replay of
decoded bolero fuzz inputs, and comparison of characterization results against
backend-specific reference predictions remain follow-up work.
