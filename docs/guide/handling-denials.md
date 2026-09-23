# Handling a denial

Use this guide when `resolve` returns a denial. First identify the reason, then
decide whether to fix the caller, reject the client input, or adjust the route
registrations. Your application sends the response; the crate does not send HTTP
responses itself. Most path denials map to `400`; `InvalidRuleId` is an internal
failure and should map to `500`.

*Background on why each verdict exists is in
[How the guard decides](crate::_docs::explanation::decision); this page is the
operational procedure.*

## 1. Attribute the denial

Every deny carries a [`ResolveError`](crate::ResolveError). Log its `Display` form —
that is the attributed line naming the check and byte class; the response body
(`message()`) is deliberately coarse and tells you nothing. Do not proceed on the
response body alone.

An `InvalidPathInput` attribution means the caller supplied a complete request-target,
absolute URI, or relative value instead of `uri.path()`. Fix the call site before
triaging structural classes.

## 2. Triage by reason

| `ResolveError` | What it means | What to do |
|---|---|---|
| `InvalidRuleId` | An internal invariant failed: the matched ID is absent from the rule table | Deny authorization, report a server error (`500`), and investigate the library failure. Never substitute the default rule. |
| `InvalidPathInput` | The supplied value was not a request path alone | Pass `uri.path()`; do not strip or reinterpret the input inside the authorization layer. |
| `Structural(NulTruncation)` | A raw or `%00` NUL — no legitimate path carries one | Treat as hostile or corrupt. No remedy by design. |
| `Structural(DotSegment)` | A `.`/`..` (in any enabled spelling) whose conservative reach extends outside the matched rule | Dot-segments that stay within a single-rule subtree already flow. A denial means another rule is reachable within the modeled bound, not that every backend would actually reach it. If legitimate keys carry `..`, see §3. |
| `Structural(Separator)` / `Structural(MatrixParam)` / `Structural(Backslash)` | The analyzed region contains another rule, possibly the default; the guard cannot establish that parsing keeps the same rule | Use the route-redesign checks in §3. If the boundary reflects a real policy boundary, keep the denial and fix the client. |
| `CaseFoldRuleChange` | Lowercasing changes the selected rule, including changes to or from the default | Fix the client's casing, or group the paths in one registration if they should share a policy. |
| `DecodeRuleChange` | Percent-decoding the path lands on a *different* rule | Same shape: `/%61dmin` vs a registered `/admin`. Client fix, or rethink why two rules disagree about one resource. |
| `NonCanonical(_)` / `NonCanonicalEscape` | The strict [`RequireCanonical`](crate::config::GuardMode::RequireCanonical) mode: presence-deny, table never consulted | Working as declared. If you serve opaque keys or encoded content, this deployment wants [`RejectAmbiguous`](crate::config::GuardMode::RejectAmbiguous) instead. |
| `Probe(name)` | Your own [`StructuralProbe`](crate::config::StructuralProbe) matched | Your predicate, your call — scope it to the dangerous sequence if it over-fires. |
| `TooLong` | A path already flagged as suspicious exceeds the length cap | Hostile or broken client; clean paths are never length-checked. |

Never respond to a `Structural(_)` denial by loosening a
[`StructuralClasses`](crate::config::StructuralClasses) toggle or turning
the guard off. If the assumption behind that change is wrong, the relevant behavior
is no longer checked (see
[Where the differential lives](crate::_docs::explanation::topology)). Every
route-table fix below makes an existing single-rule area visible to the guard rather
than switching a check off.

## 3. Can the routes be redesigned to handle it?

For a structural denial, check whether the affected area should select one rule
for every path and method. If so, make that grouping explicit in the table. Work
through these checks before changing the parsing configuration:

**Register the area as a whole subtree, not fragments.** An exact
`route("/files/{id}", …)` or a hand-written lone catch-all covers only its own
shape; everything else under `/files/` falls to the default rule, which is a
reachable *other* rule, so encoded keys deny.
[`subtree("/files", …)`](crate::RuleRouterBuilder::subtree) registers the bare
path, the trailing slash, and the catch-all under **one rule id** — gap-free, so
all those paths select the same rule and keys like `/files/a%2fb` can be accepted.
This assumes no nested registrations or method restrictions divide the area.

**One policy, one registration.** Rule identity is per registration call: two
`route` calls are two rules *even with identical policy values*, and the boundary
between them denies. If `/files/images` and `/files/docs` are genuinely the same
policy, let one `subtree("/files", …)` own them rather than registering them
separately.

**Move exceptions out from under file-key prefixes.** A nested registration —
`subtree("/files", A)` plus `route("/files/admin", B)` — makes `B` reachable from
inside the subtree. A path such as `/files/a%2fb` is then denied because its
analyzed region contains both rules, even if this particular decoded key would
keep its rule. If both policies must exist, consider moving the exception to a
sibling prefix (`/files-admin`, `/admin/files`). If the nesting is necessary, keep
it and accept the extra denials.

**Check method-specific rules too.** A
registration restricted with [`for_methods(POST)`](crate::Registration::for_methods) inside a subtree
resolves *other* methods to the default rule unless that path also has an
all-method rule. Different identities in either case prevent the structural check
from accepting the area as one rule. Consider moving the method-specific endpoint
outside the file-key prefix.
This also applies to a lone method-qualified subtree or blob subtree: a GET-only
blob denies structural keys even for GET because unlisted methods leave gaps.

**Declare blobs when you want the guarantee.**
[`exclusive_subtree`](crate::RuleRouterBuilder::exclusive_subtree) behaves like `subtree` at
runtime but rejects configurations with nested paths at build time. Use it to
prevent a later nested registration from making encoded keys start failing.
It does not remove method restrictions.

**Know what redesign cannot fix.** A recognized structural form in the *first* segment
requires analysis from the root, where the whole table must select one rule
— so on any real multi-rule table, `/%2fadmin`-style spellings deny regardless of
shape. Earlier escapes or uppercase under case folding can also expand the
analyzed region, but only as far as the earlier stable prefix requires; they do
not always expand it to the root. When the region crosses a necessary policy
boundary, keep the denial and ask the client to use an unambiguous spelling.

## 4. Verify the redesign

Pin the intended behavior with a unit test against the real builder, so a table
change that rejects previously accepted keys fails in CI:

```
use huskarl_route_guard::{RuleRouter, config::{CaseSensitivity, DecodeDepth, GuardConfig}};

let router = RuleRouter::builder("default", GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne))
    .exclusive_subtree("/files", "files-rule")
    .route("/health", "health-rule")
    .build()
    .expect("valid table");

// The opaque key flows; a climb out of the blob still denies.
assert!(router.resolve("/files/a%2fb", &http::Method::GET).is_ok());
assert!(router.resolve("/files/../health", &http::Method::GET).is_err());
```

If a denial you expected to disappear persists, the attribution changed for a
reason — re-read its `Display` line before touching anything else.
