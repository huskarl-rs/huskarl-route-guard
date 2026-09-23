# Apache differential baseline

From the repository root:

```sh
mise run test-apache
# Ordinary tests (without Docker):
mise run test
```

Requirements: Mise, Bash, Rust, and a running Docker-compatible daemon with the Docker
CLI. The first run needs network access to download the official Apache image.

| Environment | Execution |
|---|---|
| macOS | Docker Desktop, OrbStack, or another Linux Docker VM; run the Mise task on the host |
| Linux | Docker Engine; run the same Mise task on the host |
| GitHub Actions | The `downstream` matrix runs the same Mise task on an Ubuntu runner |

This tests **Linux Apache**, even on macOS. It does not certify native macOS or
Windows Apache. Docker must publish ports on the local host; remote Docker daemons
are not supported. The official multi-architecture image is pinned by release and
manifest digest in the Dockerfile, supporting both Apple Silicon and x86 hosts.
Upgrade that pin deliberately and review any behavioral changes.

The fixture is copied into the image instead of bind-mounted, avoiding macOS host
filesystem case sensitivity affecting routing. Each run publishes a dynamically
allocated port on `127.0.0.1` and cleans up its containers on exit. The image stays
in Docker's cache. Apache logs are printed on failure, and a readiness check has a
bounded timeout. No system Apache configuration or privileged host port is used.

## What the test establishes

`tests/downstream.rs` sends exact HTTP/1.0 request targets with `TcpStream`, without a
URL parser, client normalization, or redirect following. Apache independently
maps those paths to static files whose bodies and `X-Route-ID` headers identify the served resources, including HEAD.
There are no application dependencies, rewrite rules, or CGI handlers.

For each successful resource response, every accepting guard must select that
resource's expected policy. Four layouts cover uniform and nested policies, a protected private child in an
otherwise public namespace, and explicit method registrations. The uniform layout assigns all files the same
policy, including the private fixture file.

The suite runs `AllowEncodedSlashes Off`, `On`, and `NoDecode`, with slash merging
enabled, case-sensitive matching, and up to one percent-decode pass declared.
Only requests accepted by the configured guard are sent downstream; reaching a
different resource policy fails the recommendation.
Canonical probes require each resource to remain reachable with its expected rule.

The deterministic generated corpus includes content escapes, encoded separators,
dot segments, repeated slashes, double escapes, backslashes, matrix parameters,
case variants, malformed escapes, and encoded invalid bytes. Requests denied by
the guard are recorded as not forwarded and provide no downstream evidence.

Redirects and 400/403/404/405 responses are counted separately and never treated as
evidence of rule agreement. Redirect targets are not followed; a subsequent client
request must pass authorization again. Unexpected statuses, missing markers,
network failures, and unavailable Docker fail the explicit integration run.
Ordinary `mise run test` compiles this test but leaves it ignored, so it needs no Docker.

This baseline covers GET, HEAD, and POST static-file mapping, including method
registration gaps. This configuration serves POST too; omitting its protected
POST registrations has named confusion counterexamples. It does not cover
other methods, arbitrary policy tables, native OS differences, aliases,
rewrites, proxy chains, or every Apache module/configuration. It complements the
in-process model properties; it is not a general deployment certification.
