# Why downstream parsing matters

The path-confusion gap exists only because **two systems parse the path** — the proxy
hosting this crate makes the authorization decision, a separate backend serves the
resource — and the two can disagree. The safest deployment *removes* the gap rather
than guarding it: when the authorization checks and the backend code they protect are
the **same system acting on the same parsed path**, there is no second parser at that
boundary. This guard mitigates the split topology only for the declared path
interpretations; it is not a reason to split when colocation is an option.

Colocation only helps if the authorization decision and the request dispatch share
**one** path interpretation: an in-process filter that checks the raw path while the
framework routes the decoded one has reintroduced the very same differential inside a
single process. The guarantee is "one parser," not "one binary."

## Topologies covered by the deployment tests

The direct profiles place the guard before one backend:

```text
client -> guard / authorization -> Apache, Express, Axum, or SvelteKit
```

There is no intermediate proxy after the guard in these profiles. The harness
evaluates the original path and method, then sends only accepted requests unchanged
to the server. The backend independently identifies the selected handler or file.
These fixtures validate the guard/backend pairing; they do not exercise a complete
production gateway or prove that its request extraction and forwarding preserve
the tested bytes.

The chain profile adds a specific normalization step after authorization:

```text
client -> guard / authorization -> NGINX normalized $uri -> Apache static files
```

NGINX forwards `/%2561dmin/probe.txt` as `/%61dmin/probe.txt`, and Apache serves
`/admin/probe.txt`. For this configuration, declaring `UpToOne` permits a request
authorized as public to reach admin. Declaring `UpToTwo` removes the observed
confusion. The requirement comes from that measured path transformation, not simply
from counting proxy processes. Other NGINX forwarding configurations need their
own validation.

Topology also includes method dispatch. In the tested fixtures, HEAD reaches GET
handlers, Apache serves static files for POST, and Express can fall through a
GET-only child to its parent's POST handler. Guard registrations must represent
those behaviors as well as the parsing settings. A decode-depth change cannot
repair a missing method-policy registration.

The [deployment reference](crate::_docs::reference::deployments) records the exact
versions, configurations, method-registration requirements, and removal-test
counterexamples. The [testing explanation](crate::_docs::explanation::testing)
describes how accepted requests supply the evidence. A new intermediary, middleware
rewrite, or dispatch configuration changes the deployment being evaluated.

## One configuration, because this layer cannot see the upstream

The structural configuration is set once, for the whole guard, and that is a
consequence of what the library knows. It has an authorization route table, but no
verified binding from a request to the backend that will serve it. In a gateway
where authorization runs **before** upstream selection, that choice happens lower
down and may depend on the host, headers, or other routing. The library does not
require that ordering, but it cannot verify the application's backend selection
even when selection occurs first.

That is why the configuration is global: it must include the relevant behavior of
**every** upstream a request might reach. When it does, the union is conservative no
matter where the request is routed. The required
[`CaseSensitivity`](crate::config::CaseSensitivity) declaration and the
[`DecodeDepth`](crate::config::DecodeDepth) declaration, together with the
[`StructuralClasses`](crate::config::StructuralClasses) toggles are facts you
assert about *all reachable downstream chains, collectively*; the guard applies them
everywhere because it cannot tell which one any given request will hit.

It is tempting to want per-route (≈ per-upstream) profiles — "stop applying IIS rules to
my Unix zone" — but the line between safe and unsafe refinement is the line between
tightening and relaxing, and it is drawn by this layer's blindness to the upstream:

- **Tightening a specific rule cannot create a new allow.** Attaching *extra* strictness (or a
  custom check) to one rule, as an approximate stand-in for "I think this area talks to
  a nastier backend," can only ever deny more — so a wrong approximation costs
  false-positive `400`s, never a bypass, whatever upstream the traffic truly hits.
- **Relaxing a specific rule is the dangerous direction**, because it is the only one
  that *depends* on the rule→upstream binding being what you assumed — and this layer
  cannot confirm it. "This zone is Unix, stop checking `\`" becomes a clean relocation
  bypass the moment any of that zone's traffic is routed to a Windows backend. Unlike
  the uniform-subtree tolerance (`subtree`/`exclusive_subtree`) — which is **bounded** by
  construction: it exists only where no other rule is reachable, and still denies
  NUL, any climb out, and any fold or decode that relocates, so even misuse cannot
  escape it — disabling a structural class removes that check when the guess turns
  out to be wrong.

So a global profile should conservatively combine the behavior of all reachable
upstreams. Add per-rule denials if needed; do not remove a global interpretation on
the strength of an upstream binding this layer cannot verify.

The independent test profiles do not implement automatic per-backend configuration
selection. If one guard can reach both a direct origin and the tested two-decode
chain, its decode declaration must cover both. Combining supported behaviors is
conservative within the model; passing separate profiles does not itself validate
a production gateway's selection or forwarding logic.

Whether you register a rule with `subtree`, `exclusive_subtree`, or `route` is a related
security decision, documented on the route-registration builders of the consuming
authorization layer (e.g. huskarl-pingora's `Guard` and `LoginProxy`).
