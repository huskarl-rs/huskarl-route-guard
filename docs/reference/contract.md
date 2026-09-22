# Security contract

What the guard promises, the conditions the promise rests on, and how close it gets
to the ideal of denying *only* genuinely ambiguous paths.

*The few library-specific terms used below are defined in the
[Glossary](crate::_docs::reference::glossary).*

## The property

**Rule-interpretation agreement.** The unit of meaning is the *rule* — one
`route`/`subtree` registration, with "unmatched" (the default rule) a real rule like
any other. The property the guard enforces:

> For every request it forwards, every path interpretation in the **declared set**
> resolves to the **same rule** selected from the raw path.

Equivalently: a request authorized as rule A must never be servable as rule B. B may
be the default rule (authorized under a policy, served as unmatched), and A may be
the default rule (authorized as unmatched, served under a real route — `/Files/x`
folding onto a `/files` subtree). Both directions are bypasses; both are denied.

The implementation exercises this property with an executable reference backend and
property-based tests. Those tests do not establish that a real deployment belongs to
the declared interpretation set. See
[How the security claim is tested](crate::_docs::explanation::testing) for the test
strategy and its limits.

## Conditions and invariants

1. **Rule identity, not policy equality.** Two registrations are distinct rules
   even if their policies are identical, movement *within* one registration's
   patterns is never a relocation, and the default rule counts as a rule.
2. **Raw forwarding.** The guard's only intervention is deny; it never rewrites what
   it forwards (see
   [The guard never rewrites the path](crate::_docs::explanation::no_rewrite)).
3. **A declared interpretation set.** The model is *this route table plus the path
   behaviors you declare* ([`CaseSensitivity`](crate::path_confusion::CaseSensitivity),
   [`DecodeLayers`](crate::path_confusion::DecodeLayers),
   [`StructuralClasses`](crate::path_confusion::StructuralClasses)). Behaviour outside
   that set is invisible; the guard is exactly as complete as the declaration
   (see [Supported interpretations](crate::_docs::reference::coverage)). NUL truncation is always in
   the set — it is the one interpretation assumed rather than declared. The library
   deliberately treats NUL as unsupported path content.
4. **Imprecision fails closed.** Within the declared model, imprecision lands on the deny side: a false positive
   costs availability (a `400` for a non-canonical spelling); a false negative is an
   authorization bypass. No mechanism in the crate may trade the latter for the
   former.
5. **Stricter settings only add denials.** Every knob's stricter setting denies a superset of the
   looser one. Within the declared model, tightening cannot create an allowed request,
   so an unsure operator can over-declare
   (see [Choosing a configuration](crate::_docs::guide::configuring)).
6. **Canonical request paths flow.** Within the built-in model, the deny set contains
   only non-canonical paths — ones carrying a recognized structural form, a
   percent-escape, or (under a declared case-folding backend) uppercase. A canonical
   request is not denied by the built-in checks. (Custom
   [`StructuralProbe`](crate::path_confusion::StructuralProbe)s are the one
   exception by design: an arbitrary deny-only predicate may reject content the
   built-in model considers clean.) This condition does not promise that every
   non-canonical resource identifier has an equivalent canonical spelling.

Conditions 4–6 are exercised as executable properties: the one-sided reference-backend
oracle, the configuration-monotonicity law, and the clean-path-never-denied law all
run under `cargo test`.

## How close to "deny only genuine ambiguity"?

The ideal guard denies a path exactly when some declared interpretation resolves it to a
different rule — no more. The real guard is exact on one axis and deliberately
over-approximate on the other:

- **Exact: the content axis.** The case-fold and content-decode checks *apply* the
  declared transform and compare rules, so they deny iff a relocation actually exists
  in this table. `/%61dmin` on a table with no `/admin` route is allowed; register
  `/admin` and it flips to denied. No gap.
- **Over-approximate: the structure axis.** Separator-like and traversal forms — encoded
  separators, `//`, `;`, `..`, and their enabled alternate encodings — deny on
  **anchored reachability**: the guard bounds where the supported structural family
  could move the path (nothing before the form's anchor, one level of climb per
  dot-segment) and denies iff the table routes anything in that bound to a
  *different* rule than the raw path matched. It never applies the transforms
  themselves, so the bound is coarse in a specific way: it treats **every** path
  under the anchor as reachable, not just actual transform images. The remaining
  over-denial is visible in this example: `/users/4;2` under a lone `/users/{id}`
  route is denied — the anchor's subtree
  contains default-rule fall-throughs — even though the only transform a `;` enables
  (param-strip, which never crosses a separator) resolves it to `/users/4`, inside
  its own rule. By contrast, `/files/a%2fb` under a lone `/files` subtree flows:
  the subtree contains one rule, so the form cannot relocate within the declared
  model.
  `over_approximation_tests` pins the `;` case as denied *while* no declared
  interpretation relocates it — the definition of
  an over-approximation — and pins the uniform-subtree case, and the subtree remedy
  below, as allowed. The over-denial is therefore documented and regression-tested.
  NUL keeps an unconditional deny because the library does not support it as path
  content.

Stated precisely, the over-denial surface is: **paths carrying a recognized structural form
whose every declared interpretation stays within its own rule, in a region the table does
not cover uniformly** — most commonly separator or param bytes under an exact route
or a partially-registered prefix. If that surface matters to a deployment, the
remedy is registering the prefix as a full subtree (`subtree`/`blob_subtree`) so its
uniformity is visible to the guard — never a relaxation of the structural classes,
which removes that check entirely (see
[Where the differential lives](crate::_docs::explanation::topology)).

The per-form split — which forms deny on sight and which deny only on relocation — is
tabulated in [How the guard decides](crate::_docs::explanation::decision).
