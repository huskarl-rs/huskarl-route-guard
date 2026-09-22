# Glossary

Most of this crate uses ordinary HTTP-routing terminology. Two terms are specific to
this library: **relocation** and **anchor**. They are named here because they recur in
the security contract and algorithm; operational use does not require memorizing the
implementation vocabulary.

## Routes and rules

**Pattern** — a registered path expression using `matchit` syntax: literal segments
(`/admin`), one-segment parameters (`/users/{id}`), and a trailing catch-all
(`/files/{*rest}`). A trailing slash is significant.

**Registration / rule** — one authorization identity created by a `route`, `subtree`,
or `blob_subtree` call. A `subtree` expands to several patterns, but those patterns
share one internal rule id. Two separate registrations remain different rules even
when their policy values are equal.

**Default rule** — the rule used when no registered pattern matches. It participates
in the security check like any other rule: moving from an unmatched path onto a
registered route, or the reverse, crosses a rule boundary.

**Route table** — the registrations, their internal rule identities, and the default
rule.

**Single-rule subtree** — a path prefix for which every possible suffix, including
otherwise-unmatched paths and every HTTP method, resolves to one rule. The algorithm
calls this *uniform coverage*. A lone exact route or catch-all is not a single-rule
subtree because gaps fall through to the default rule.

## Path interpretations

**Path interpretation** — the path a component routes after applying its own parsing
behavior, such as percent-decoding, merging slashes, resolving dot-segments, stripping
`;` parameters, folding case, or treating backslash as a separator.

**Path confusion / parser disagreement** — two components assign different meanings
to the same request path. In this crate's intended architecture, the authorization
layer routes the raw path while another component later interprets and serves it.

**Declared interpretation set** — the route table combined with the
path behaviors selected by `CaseSensitivity`, `DecodeLayers`, and
`StructuralClasses`. The guard considers subsets and compositions of those selected
behaviors. It cannot see behavior outside this declaration.

**Relocation** *(library term)* — a path interpretation selects a different rule from
the raw path. For example, `/public/../admin` may match the public rule as written but
the admin rule after dot-segment resolution. A changed path that remains within the
same rule is not a relocation.

**Canonical path** — a path spelling unchanged by the configured built-in
interpretations. In `reject_non_canonical` mode, the definition is deliberately
stricter: any percent escape is rejected. “Canonical” is always relative to the
configured model; it does not claim agreement with every possible downstream parser.

## Guard decisions

**Structural form / structural class** — syntax that a downstream parser may treat as
path structure rather than segment content. Examples include encoded separators,
empty segments, dot-segments, matrix parameters, NUL, and configured alternate forms
such as backslash or fullwidth separators. `StructuralClass` identifies the family
reported in a denial. A form may contain several bytes; the documentation therefore
uses *form* rather than the older shorthand *structural byte*.

**Anchor** *(library term)* — the earliest path prefix that the structural analysis
can prove will remain unchanged. The guard checks all routes reachable beneath that
prefix. Dot-segments move the anchor toward the root because they can remove preceding
segments. See [How the guard decides](crate::_docs::explanation::decision) for the
algorithm.

**Scoped structural check** — for a recognized structural form, deny unless every
route reachable beneath its anchor is the rule selected by the raw path. This is
conservative: it may deny paths that a particular backend would keep within one rule.

**Exact relocation check** — apply a deterministic modeled interpretation, such as
ASCII case folding or whole-path percent decoding, route the result, and deny only if
the rule changes.

**Opaque-key subtree** — a `blob_subtree` registration for a prefix whose keys may
legitimately contain separator-like forms. It behaves like a single-rule `subtree` at
runtime and additionally makes any nested registration a build error.

**Custom structural detector** — a user-provided `StructuralProbe`. It is a whole-path,
deny-only predicate for a platform-specific form that the built-in model does not
recognize. It can add denials but cannot establish that the rest of the model matches
the deployment.
