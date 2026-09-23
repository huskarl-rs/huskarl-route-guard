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

## One configuration, because this layer cannot see the upstream

The structural configuration is set once, for the whole guard, and that is a
consequence of *where this layer sits*, not a missing knob. The guard runs at
authorization time — **before** upstream selection, which happens lower down (the inner
proxy's peer choice) and may key on the host, headers, or its own routing, not just the
path. So this layer has an authorization route table; it does **not** have, and cannot verify,
the binding from a request to the backend that will actually serve it.

That is why the configuration is global: it must include the relevant behavior of
**every** upstream a request might reach. When it does, the union is conservative no
matter where the request is routed. The required
[`CaseSensitivity`](crate::config::CaseSensitivity) declaration and the
[`StructuralClasses`](crate::config::StructuralClasses) toggles are facts you
assert about *the backends behind you, collectively*; the guard then applies them
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

Whether you register a rule with `subtree`, `exclusive_subtree`, or `route` is a related
security decision, documented on the route-registration builders of the consuming
authorization layer (e.g. huskarl-pingora's `Guard` and `LoginProxy`).
