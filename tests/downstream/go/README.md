# Go standard-library router

This fixture uses Go 1.27.1's `net/http.Server` and `http.ServeMux`, with modern
method and wildcard patterns (`GODEBUG=httpmuxgo121=0`). The multi-platform Go
builder image is pinned by digest; the runtime contains only the static binary.
There are no third-party modules or path-rewriting middleware.

`GET` patterns also serve HEAD, with body suppression handled by `net/http`.
The `/admin`, `/files`, and `/files/private` prefixes have separate native exact
and subtree registrations. POST at `/files` and `/files/` selects the files
handler, including beneath the GET-only private child. The method-independent
`/` fallback is public. Exact and parameterized exceptions register both the
bare path and an end-anchored trailing-slash form (`/{$}`), so the latter does
not accidentally become a subtree exception. Handlers return only fixed route
identities; the Rust harness independently assigns policies.

The [ServeMux documentation](https://pkg.go.dev/net/http@go1.27.1#ServeMux)
describes segment-by-segment unescaping and path-cleaning redirects. Fixed probes
pin these differences in the actual server:

| Target | Direct ServeMux observation |
|---|---|
| `/%61dmin/probe.txt` | admin |
| `/%2561dmin/probe.txt` | public |
| `/admin%2fprobe.txt` | public; the escaped slash stays inside one segment |
| `/foo/secret%2Fother/bar` | parameterized handler; one wildcard segment |
| `/admin/../public/probe.txt` | 307 redirect |
| `/admin/%2e%2e/public/probe.txt` | admin; escaped dots do not trigger cleaning |
| `/admin//probe.txt` | 307 redirect |

The direct `go/ServeMux` profile declares `Sensitive` and `UpToOne`, with HEAD
and the child POST fallback registered. The `nginx-go/DecodedUri` chain uses
NGINX normalized-URI forwarding and declares `UpToTwo`: the real chain makes
`/%2561dmin/probe.txt` reach admin. Its second-decode removal must reproduce
policy confusion. Both profiles also check safe method denial when HEAD or the
child POST registration is removed. Redirects are recorded without following them.

```sh
mise run test-go
mise run test-nginx-go
# Equivalent combined run:
mise run test-downstream go nginx-go
```

These profiles do not cover the pre-Go-1.22 compatibility router, `http.FileServer`,
third-party Go routers, or application authorization using decoded wildcard values.
