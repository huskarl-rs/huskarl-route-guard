# Handling a denial

A request came back `400` from the guard and you need to decide what to do about
it. The short version: **attribute first** (which check, which byte class), then
decide whether you are looking at an attack, a client that must fix its spelling,
or a route table whose *shape* hides a uniformity the guard would otherwise honor —
and only in the last case, redesign the routes.

*Background on why each verdict exists is in
[How the guard decides](crate::_docs::explanation::decision); this page is the
operational procedure.*

## 1. Attribute the denial

Every deny carries a [`DenyReason`](crate::DenyReason). Log its `Display` form —
that is the attributed line naming the check and byte class; the response body
(`message()`) is deliberately coarse and tells you nothing. Do not proceed on the
response body alone.

An `InvalidPathInput` attribution means the caller supplied a complete request-target,
absolute URI, or relative value instead of `uri.path()`. Fix the call site before
triaging structural classes.

## 2. Triage by reason

| `DenyReason` | What it means | Sanctioned response |
|---|---|---|
| `InvalidPathInput` | The supplied value was not a request path alone | Pass `uri.path()`; do not strip or reinterpret the input inside the authorization layer. |
| `Structural(NulTruncation)` | A raw or `%00` NUL — no legitimate path carries one | Treat as hostile or corrupt. No remedy by design. |
| `Structural(DotSegment)` | A `.`/`..` (in any enabled spelling) whose conservative reach extends outside the matched rule | Dot-segments that stay within a single-rule subtree already flow. A denial means another rule is reachable within the modeled bound, not that every backend would actually reach it. If legitimate keys carry `..`, see §3. |
| `Structural(Separator)` / `Structural(MatrixParam)` / `Structural(Backslash)` | A separator-like form whose anchor is not a single-rule subtree — some other rule (often the default rule through a coverage gap) is reachable | Use the route-redesign checks in §3. If the boundary reflects a real policy boundary, keep the denial and fix the client. |
| `CaseFoldRelocation` | Folding the path lands on a *different* rule | Genuinely ambiguous between two registered spellings. Either the client fixes its casing, or — if both spellings are meant to be one policy — collapse them into one registration. |
| `DecodeRelocation` | Percent-decoding the path lands on a *different* rule | Same shape: `/%61dmin` vs a registered `/admin`. Client fix, or rethink why two rules disagree about one resource. |
| `NonCanonical(_)` / `NonCanonicalEscape` | The strict [`reject_non_canonical`](crate::path_confusion::PathConfusion::reject_non_canonical) mode: presence-deny, table never consulted | Working as declared. If you serve opaque keys or encoded content, this deployment wants [`reject_structural`](crate::path_confusion::PathConfusion::reject_structural) instead. |
| `Probe(name)` | Your own [`StructuralProbe`](crate::path_confusion::StructuralProbe) matched | Your predicate, your call — scope it to the dangerous sequence if it over-fires. |
| `TooLong` | A path already flagged as suspicious exceeds the length cap | Hostile or broken client; clean paths are never length-checked. |

Never respond to a `Structural(_)` denial by loosening a
[`StructuralClasses`](crate::path_confusion::StructuralClasses) toggle or turning
the guard off. If the assumption behind that change is wrong, the relevant behavior
is no longer checked (see
[Where the differential lives](crate::_docs::explanation::topology)). Every
route-table fix below makes an existing single-rule area visible to the guard rather
than switching a check off.

## 3. Can the routes be redesigned to handle it?

Boundary-shift tolerance is **derived from the table**: a byte flows exactly when
every rule reachable past its anchor is the rule the path already matched. So the
question "can I make this denial go away?" becomes "is the region this traffic
lives in *actually* one policy — and does the table say so?" Work through these in
order:

**Register the area as a whole subtree, not fragments.** An exact
`route("/files/{id}", …)` or a hand-written lone catch-all covers only its own
shape; everything else under `/files/` falls to the default rule, which is a
reachable *other* rule, so encoded keys deny.
[`subtree("/files", …)`](crate::RuleRouterBuilder::subtree) registers the bare
path, the trailing slash, and the catch-all under **one rule id** — gap-free, so
the subtree is uniform and keys like `/files/a%2fb` (or a `..` that resolves
inside `/files/`) flow.

**One policy, one registration.** Rule identity is per registration call: two
`route` calls are two rules *even with identical policy values*, and the boundary
between them denies. If `/files/images` and `/files/docs` are genuinely the same
policy, let one `subtree("/files", …)` own them rather than registering them
separately.

**Move carve-outs out from under key spaces.** A nested registration —
`subtree("/files", A)` plus `route("/files/admin", B)` — makes `B` reachable from
inside the subtree, so every encoded key under `/files` (correctly) denies: a
split key really could land on `/files/admin`. If both must exist, relocate the
carve-out to a sibling prefix (`/files-admin`, `/admin/files`) so the key space
stays uniform. If the nesting reflects a real policy boundary, keep it and accept
the denials — they are the protection.

**Method-qualified rules break uniformity too.** A
[`route_for(POST, …)`](crate::RuleRouterBuilder::route_for) inside a subtree
resolves *other* methods to the default rule, so the subtree stops being uniform
for everyone. Per-method policy inside an opaque-key space cannot be expressed
without paying that price; put the method-split endpoint outside the key space.

**Declare blobs when you want the guarantee.**
[`blob_subtree`](crate::RuleRouterBuilder::blob_subtree) behaves like `subtree` at
runtime but makes the uniformity a **build error to break**: someone nesting a
route under it next quarter gets a failed build, not a quiet production `400`
storm. Prefer it for any prefix whose keys are known to carry structural forms.

**Know what redesign cannot fix.** A recognized structural form in the *first* segment
anchors at the root, and the root is uniform only when the whole table is one rule
— so on any real multi-rule table, `/%2fadmin`-style spellings deny regardless of
shape. Likewise a stable prefix that itself carries escapes (or uppercase, under a
case-folding backend) widens to the root. Those denials are inherent to the
request, not the table; the client must send the canonical spelling (which, under
the built-in model's contract, flows).

## 4. Verify the redesign

Pin the intended behavior with a unit test against the real builder, so the next
table change that breaks uniformity fails in CI rather than in traffic:

```
use huskarl_route_guard::{RuleRouter, path_confusion::{CaseSensitivity, DecodeLayers}};

let router = RuleRouter::builder()
    .default("default")
    .case_sensitivity(CaseSensitivity::Sensitive)
    .decode_layers(DecodeLayers::Single)
    .blob_subtree("/files", "files-rule")
    .route("/health", "health-rule")
    .build()
    .expect("valid table");

// The opaque key flows; a climb out of the blob still denies.
assert!(router.resolve("/files/a%2fb", &http::Method::GET).is_ok());
assert!(router.resolve("/files/../health", &http::Method::GET).is_err());
```

If a denial you expected to disappear persists, the attribution changed for a
reason — re-read its `Display` line before touching anything else.
