# How the security claim is tested

The guard and its test oracle approach the same question differently. The guard does
not rewrite a request path; it computes a conservative region of the route table that
downstream interpretations might reach. The reference backend concretely decodes,
merges, strips, resolves, and folds a copy of the path, then routes the result through
the same table. A generated case fails when the guard allows a path that the reference
backend relocates to another rule.

This is useful implementation independence: the guard performs positional analysis,
while the oracle transforms bytes. They still share the declared interpretation
vocabulary and route table. Consequently, the tests can find an implementation error
inside the model; they cannot prove that the model describes a real deployment.

## Transform selection and order

The reference model enumerates every subset of the nine supported transforms. It does
not enumerate every possible order for every subset: eight transforms have up to
`8!` orders. Property tests exercise the canonical order and a fresh sampled order for
each subset and generated case.

Order genuinely matters. For `/admin;x//../b`, merging `//` before resolving `..`
yields `/b`, while resolving before merging yields `/admin/b`. The runtime algorithm
does not choose either normalization. For recognized structural forms, it bounds all
reachable routes beneath an **anchor** and requires that region to contain one rule.

That argument depends on every supported structural transform leaving the anchor
prefix unchanged. The property
`no_modeled_transform_rewrites_inside_the_anchor` checks this premise directly across
the enumerated subsets and sampled orders. Separate tests exhaust every order for a
bounded set of paths and transform sets of at most four steps. This is substantial
regression coverage, not a formal proof over arbitrary paths and orders.

## Separate checks reduce shared mistakes

The owned route matcher is tested independently against `matchit`. The end-to-end
property tests then compare raw and transformed paths using that matcher. Additional
properties check that stricter configurations only add denials and clean paths
continue to flow. Generated route tables include overlapping literal and wildcard
subtrees, with all-method rules and generated method restrictions. The relocation
property holds the request method fixed while transforming the path, including a
custom method absent from the registrations. Regression tests cover uniform
method-specific subtrees, same-path method overrides, and default-rule gaps created
by more-specific paths. A regression test checks that adding a literal subtree can turn a denial
into acceptance by shadowing a wildcard branch, while preserving agreement between
the raw and decoded paths. Exclusive-subtree tests cover overriding paths, unrelated
routes, and lower-priority fallbacks in both registration orders.

Coverage-guided fuzz targets exercise the scanner, the matcher differential, and the
end-to-end relocation property. Committed regression inputs keep previously discovered
cases in ordinary test runs.

`tests/cve_regressions.rs` adds reduced, source-linked CVE witnesses through the
public API. An independent decoder and normalizer establish the downstream path;
each denial fixture also verifies that this path reaches a different rule identity.
The cases cover mixed encoded dots, encoded hex digits across two decode passes,
parameter stripping followed by traversal, and slash merging. Separate assertions
exercise decode-depth limits and exclusive subtrees. A whitespace-trimming example
documents a behavior outside the model rather than claiming the guard rejects it.

These layers support one bounded conclusion: the implementation has strong evidence
for its stated contract over the supported model. Platform behavior outside that model
requires separate evidence and remains outside the guarantee.

## Real downstream baselines

See [Tested deployments](crate::_docs::reference::deployments) for the
versioned configuration recommendations supported by these tests.

These tests challenge deployment assumptions behind configuration recommendations.
`mise run test-downstream` runs the ignored `tests/downstream.rs` integration test
against pinned Linux Apache, Express, Axum, and `SvelteKit` adapter-node fixtures,
plus a NGINX normalized-URI proxy to Apache chain.
The same command works on macOS and Linux with a local Docker daemon; an Ubuntu
GitHub Actions matrix runs it in CI. Ordinary tests use `mise run test` without Docker.

The same input corpus is evaluated against each recommended guard configuration
and four policy layouts. Only accepted requests are sent downstream, preserving
request-target bytes over TCP. Responses identify selected routes (static resources
for Apache), which the harness independently maps to authorization policies.
A forwarded request reaching a different policy invalidates the recommendation.
Denied requests are recorded as not forwarded and provide no downstream evidence.

Additional runs remove individual recommended settings. They must produce actual
accepted-request confusion to justify retaining the setting. Case folding for
default/insensitive Express, backslash handling for `SvelteKit`, and method
registration choices each have such counterexamples. The NGINX–Apache profile
requires `UpToTwo`; removing its second decode declaration also reproduces confusion.
The corpus combines content escapes, separator transformations, and case variants. GET and HEAD run across all
layouts; POST exercises a layout with method-specific registrations and gaps.
Route-ID headers identify HEAD handlers without relying on response bodies. If
removal reveals no confusion, the test fails for review and removal of that unsupported recommendation from the tested profile. The minimum
available decode setting and mandatory built-in structural classes are not
individually removable and have no necessity claim from these tests.

Canonical route probes and a minimum served-request count prevent vacuous passes.
Redirects and backend rejections establish no policy agreement. Reports separate
recommended and weakened configurations, including every accepted-request
counterexample. These are bounded GET/HEAD/POST routing and static-file baselines, not proof
for arbitrary deployments or all inputs. Setup, configuration advice, and report
format are documented in `tests/downstream/README.md` in the repository.

## Performance regression suite

`mise run bench` runs the Criterion suite in `benches/route_guard.rs`. It measures the
public `RuleRouter` API across clean-path guard overhead, representative allowed and
denied suspicious paths, path-length and route-count scaling, and route-table build
cost. Router construction stays outside request-resolution timings; generated
registration inputs stay outside build timings.

For a quick fixture check, run:

```console
cargo bench --bench route_guard -- --quick
```

The ordinary `cargo test --all-targets` CI step also executes each benchmark once as
a smoke test. Treat timing comparisons as meaningful only on comparable hardware and
toolchains; shared CI runners remain useful for correctness, not tight latency gates.
