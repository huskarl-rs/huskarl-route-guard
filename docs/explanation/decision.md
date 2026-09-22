# How the guard decides

*The property these checks enforce, and its assumptions, are stated in the
[Security contract](crate::_docs::reference::contract). The few library-specific
terms are defined in the [Glossary](crate::_docs::reference::glossary).*

For every request the guard matches the **raw** path to a rule, then runs the
following checks against that raw path. Each can only ever *deny* (`400`); if none
fires, the raw path is forwarded untouched.

Two definitions matter. A *rule* here is one `route`/`subtree` registration —
**identity, not policy**: two separate registrations are different rules even if
their policies are identical, and movement *within* a single `subtree` is never a
relocation (its patterns share one rule). And the checks run on
**every** request, whatever rule the raw path matched — a `public` or `optional`
route is guarded exactly like a protected one. That is the whole point: the danger
is a path the proxy authorizes under a *permissive* rule but the backend serves
under a *stricter* one (or the reverse). When a relocation is found the guard
**denies** rather than re-routing to the other rule — it cannot know which rule the
backend will actually resolve to, so this design refuses the request instead of
guessing.

1. **Scoped structural check** — deny a recognized *structural form* (encoded separator,
   dot-segment, matrix-param, …) unless the route table proves it harmless: every
   rule reachable past the byte's **anchor** (the last clean separator before it,
   raised one level per dot-segment) must be the very rule the raw path matched.
   Models **no particular backend** — only the shared shape of the supported structural
   family: such transforms rewrite the path at or after their own position.
2. **Case-fold reject** (under
   [`CaseSensitivity::Insensitive`](crate::path_confusion::CaseSensitivity::Insensitive)
   only) — lowercase the path, re-route the folded form, and deny if it lands on a
   *different* rule. Models the declared case-folding backend, precisely:
   `/files/ReadMe.TXT` folds within its own rule and is allowed; `/ADMIN` folding
   onto a distinct `/admin` rule is denied.
3. **Content-decode check** — percent-decode the path (lowercasing the result when
   the backend folds case), re-route every possible whole-path result, and deny if
   any lands on a *different* rule. This models the possibility of consistent
   whole-path percent decoding; selective decoders are outside the model.
4. **Custom probes** — any
   [`StructuralProbe`](crate::path_confusion::StructuralProbe) you registered,
   denied on presence.

The checks are complementary along a principled line. The scoped structural check covers
relocations that **shift segment boundaries or climb** the tree. It cannot apply
those transforms — slash-merging, `;`-strip, dot-resolution come in an open-ended
*family* of backend-specific orders and compositions — but it exploits the one
property every supported member shares: a structural form rewrites the path only **at or
after its own position**. So the check scopes the danger instead of simulating it:
everything before the byte's last clean separator is untouchable, the possible
rewrites all land in that separator's subtree (widened one level per dot-segment,
which pops at most one segment each), and if the table routes *everything* in that
subtree — gaps to the default rule included — to the rule the raw path already
matched, no member of the family can relocate the request. Case-fold and
content-decode cover relocations that **change which literal matches** — each
models a *deterministic declared transform* (fold, decode), so the guard simply
applies it, re-routes, and compares rules: precise, never an over-approximation. No
single check is sufficient; together they cover both axes of the declared model.

## Quick reference: deny on sight, or deny on reachability?

The practical question when reading a denied (or allowed) request: did this form
deny because it was *present*, or because of what the rest of the route table looks
like? Under the default mode
([`reject_structural`](crate::path_confusion::PathConfusion::reject_structural)):

| Found in the path | Verdict | Does the route table matter? |
|---|---|---|
| NUL — raw or `%00` (always-on) | deny on sight | no — denied everywhere, unconditionally |
| anything a registered [`StructuralProbe`](crate::path_confusion::StructuralProbe) matches | deny on sight | no — whole-path, unconditionally |
| dot-segment — `.`/`..` as a whole segment, encoded (`%2E`), or revealed by an enabled delimiter (`..%2Fx`, `..;x`) | deny unless **scoped**: the anchor, raised one level per dot-segment, still bounds a subtree the matched rule covers uniformly | yes — a climb that provably resolves *within* its own rule flows |
| encoded/alternate separator — `%2F`, empty segment `//`, plus `\`/`%5C`, overlong, `%252F`, `／` as enabled | deny unless **scoped**: every rule reachable past the anchor is the matched rule | yes — tolerated under a fully-registered single-rule subtree (`subtree`/`blob_subtree`), or in unrouted space |
| matrix param — `;`/`%3B` and enabled alternate forms | same scoped verdict | yes — same tolerance |
| ASCII uppercase (backend declared [`Insensitive`](crate::path_confusion::CaseSensitivity::Insensitive)) | deny **only on relocation** — fold, re-route, deny iff the matched rule changes | yes |
| any other percent-escape (`%61`, `%20`, …) | deny **only on relocation** — decode, re-route, deny iff the matched rule changes | yes |
| none of the above | allow | — |

The rule of thumb: **recognized structure denies on reachability; content denies on
relocation.** A form that could move a segment boundary or climb the tree is denied
wherever some *other* rule is reachable within its scope — the guard never asks
*which* transform would get there, because the family is open-ended, only whether
there is anywhere else to go. A form that only changes what a segment *says* is
judged by actually applying the declared transform and comparing rules.

Concretely:

- `/files/a%2fb` under a lone `subtree("/files", …)` is **allowed** — every path
  under `/files/` is that one rule, so no split, merge, or strip can leave it.
  Register anything else under `/files` and it flips to denied.
- `/users/4%2F2` with `route("/users/{id}", …)` is **denied**: an exact route covers
  only its own shape, so a split segment falls through to the default rule — a
  reachable *other* rule.
- An **unmatched** path carrying a recognized structural form flows when the surrounding
  unrouted space is itself uniform (everything reachable is the default rule), and
  denies where it borders a registered rule — e.g. `..` that could climb to the
  root of a multi-rule table.
- `/%61dmin` is **allowed** on a table with no `/admin` route (the decode changes no
  rule) — and flips to denied the moment an `/admin` registration is added.
- Uppercase alone never denies under the default mode, even when the backend is
  declared case-folding — only a fold that lands on a different rule does.

Two consequences worth naming. **Strictness is derived from the table, not
remembered by an operator**: a trivial table (one root subtree, or nothing but the
default rule) quiets the structural checks because there is nothing to relocate
*to*, and protection appears automatically, exactly at the boundaries, as rules are
registered. And **the table only ever tightens**: adding a registration can turn
allows into denies but never the reverse (a new registration that completes a
subtree's coverage brings its own rule id into the reachable set) — pinned as an
executable law alongside the configuration-monotonicity one.

The strict mode
([`reject_non_canonical`](crate::path_confusion::PathConfusion::reject_non_canonical))
collapses the whole table to deny on sight: every enabled structural form anywhere,
**any** percent-escape at all, and (under a case-folding backend) any uppercase
byte — the route table is never consulted and `blob_subtree` exemptions are ignored.

## 1. Scoped structural check

Rather than model what a backend *does* to a path, this asks a weaker,
backend-independent question: **where could the reinterpreted path possibly land,
and does the table route everything there to the same rule?** Registered patterns
are **canonical** — a pattern that itself carries a recognized structural form is a build
error — so the literal parts of a matched path match the pattern byte-for-byte,
which means any recognized structural form in the request necessarily lands inside a
**wildcard or catch-all**, and the prefix before it was matched literally.
That build-time guarantee is load-bearing for everything below.

The verdict, per flagged path:

1. **Anchor.** Every supported separator-like transform rewrites the path at or after the
   byte that triggers it, so the path up to the last clean separator before the
   *earliest* structural occurrence — the **stable prefix** — is untouchable.
   (For a `//` empty segment the occurrence is the *second* slash: a merge keeps
   the first.) Dot-segments climb: each `.`/`..`-capable segment pops at most one
   level, so `k` of them raise the anchor `k` segments toward the root. If the
   stable prefix itself carries content a declared transform could rewrite (a
   percent-escape, or uppercase under a case-folding backend), the anchor widens
   to the root — the prefix can no longer be trusted to stay put.
2. **Uniform coverage.** Walk the route tree under the anchor, following every
   branch the matcher's backtracking could take (literal *and* wildcard, plus any
   ancestor catch-all a dead-end would fall back to), and collect every reachable
   rule id — counting **fall-through to the default rule** wherever coverage has a
   gap: an uncovered remainder, a missing trailing-slash terminal, a
   method-qualified slot that other methods pass through. Allow iff that whole set
   is exactly the rule the raw path matched; otherwise deny.

Two classes opt out of the scoping. A raw or `%00` **NUL** denies unconditionally —
truncation could be scoped the same way, but no legitimate path carries a NUL, so
the library chooses not to support NUL as path content. ASCII **case** is not part of the scoped structural
check at all: under a case-folding backend it is handled by the precise case-fold
reject above, so uppercase content that folds within its own rule is never denied.

**Opaque key spaces.** A prefix that legitimately proxies opaque identifiers whose
keys contain encoded separators (object-store keys, …) gets its tolerance from
uniformity: a fully-registered single-rule subtree — which is exactly what
`subtree` and `blob_subtree` register — has no other rule reachable beneath it, so
`%2F`/`;`/`\` in keys flow, and even a `..` deep enough to resolve within the
subtree flows, while one that could climb out is denied (as is any fold or decode
that would relocate out — the precise checks still run). What `blob_subtree` adds
is a **build-time guarantee**: registering a more-specific route under it is a
build error, so its uniformity — and therefore its tolerance — cannot be silently
broken later; under a plain `subtree`, a nested registration simply (and safely)
flips the affected paths back to denied.

Within the declared structural family, the check is a **conservative
over-approximation**: the anchor's subtree is *every*
path under it, not just the ones actual transforms can produce. `/users/4;2` under
a lone `/users/{id}` route is denied because the anchor's subtree contains
default-rule gaps — even though param-strip, the only transform a `;` enables,
resolves it to `/users/4` inside its own rule. And a lone catch-all pattern without
its bare and trailing-slash companions still denies, because a `;`-strip could
shorten its tail into the default rule.

This coarseness is deliberate. Case folding and whole-path decoding are deterministic
interpretations, so the guard can apply them exactly. Structural behavior is a family:
slash merging, parameter stripping, and dot-segment resolution can occur in different
orders and combinations. The anchor needs only their shared constraint—that a
recognized form rewrites at or after its position, with each dot-segment removing at
most one preceding segment.

A finer simulation would put mistakes in the dangerous direction: an omitted
composition could become a silent allow. The broader reachable region can instead
produce only additional denials within the declared model. Single-rule subtrees keep
that cost away from opaque-key spaces, while the exact content checks allow ordinary
escapes such as `%20` when decoding stays within one rule.

## 2. Exact content-decode check

A backend that percent-decodes the path sees different *content* in a segment, so
`/%61dmin` may be served as `/admin`. No boundary moved, so
the scoped structural check cannot see it. The guard therefore decodes the path once
(and, under a declared
[`DecodeLayers::UpToTwo`](crate::path_confusion::DecodeLayers::UpToTwo)
topology, also twice), re-routes both possible complete-path results, and lowercases
each candidate when the backend is
[`CaseSensitivity::Insensitive`](crate::path_confusion::CaseSensitivity::Insensitive)
(a decoded escape can reveal an uppercase byte — `/%41dmin` → `/Admin` → `/admin`),
then denies **only if a matched rule changes**. Checking every pass matters: a route
sequence A → B → A is unsafe when the backend might decode once, even though a
twice-decoding backend would return to A. Each candidate decodes the whole path to
one consistent depth; depths are not mixed within a request. This is **precise**,
not an over-approximation: `/foo%20bar` decodes only to same-rule paths and is
allowed, so opaque encoded content keeps flowing.
