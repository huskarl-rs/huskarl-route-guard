# Glossary

## Routes and rules

**Pattern** — a path expression such as `/health`, `/users/{id}`, or
`/files/{*rest}`. See [Routing behavior](crate::_docs::reference::routing) for
the supported syntax.

**Rule value** — the caller-provided value of type `R` returned by a successful
match. It can be a policy, a policy identifier, or other application data. The
crate does not interpret it.

**Policy** — the authorization behavior the calling application enforces using
the selected rule value. Returning a rule does not itself authorize the request.

**Registration** — a group of patterns, a method selection, and one rule value.
Each `route`, `subtree`, or `exclusive_subtree` call creates a registration.

**Rule identity / rule ID** — the identity assigned to a registration. All its
patterns share that identity. Separate registrations have different identities
even if their rule values are equal. “Same rule” in the guard's contract means
the same identity.

**Default rule** — the caller-provided fallback value and its distinct identity.
It applies when no path matches or when the selected path has no rule for the
request method and no all-method rule.

**Route table** — the registrations and the default rule.

**Single-rule subtree / uniform coverage** — a region where every path and every
HTTP method selects the same rule identity. Gaps that select the default count
toward this check. A lone catch-all registration does not cover its bare prefix
or empty remainder.

## Path parsing

**Raw path** — the request path supplied to the router, before this crate applies
any checks to alternative spellings. Supply `uri.path()`, without a query string
or fragment. The caller must preserve this path when forwarding an allowed request.

**Path interpretation** — a path after a component's parsing behavior, such as
percent-decoding, slash merging, removing `..` segments, stripping path parameters,
or converting ASCII letters to lowercase.

**Path confusion / parser disagreement** — different components interpret the
same request path differently. The guard is concerned with disagreement that
could select a different rule.

**Configured downstream parsing behaviors** — the built-in behaviors and opt-ins
selected by `CaseSensitivity`, `DecodeDepth`, and `StructuralClasses`.
The contract calls their supported combinations the *declared interpretation set*.
Behavior outside this set is not checked.

**Rule change** — an interpretation selects a different rule identity from the raw
path. Errors such as `DecodeRuleChange` report this comparison. The algorithm and
tests also call it a *relocation*; the guard does not redirect the request.

**Canonical path** — in this crate, a slash-prefixed path containing no recognized
structural form, no percent escape, and no uppercase ASCII when case folding is
configured. This is relative to the configured checks, not a universal URL format.
The default mode also accepts some non-canonical paths when the checks establish
that they cannot change the selected rule.

## Guard checks

**Structural form** — syntax that may affect path boundaries or traversal, such
as `%2F`, `//`, `..`, or `;version=2`. NUL truncation is also classified here.
A **structural class** is the family reported in a denial, such as
`StructuralClass::Separator`.

**Path parameters / matrix parameters** — content starting with `;` in a path
segment, such as `/users/4;version=2`. Some parsers strip this content before routing.

**Stable prefix / anchor** — a prefix that remains unchanged under the supported
transformations. The structural analysis calls its conservatively chosen prefix
the *anchor*. See
[How the guard decides](crate::_docs::explanation::decision) for its calculation.

**Structural ambiguity check / scoped structural check** — reject a recognized
structural form unless every path and method in the analyzed region selects the
same rule. The analyzed region can be broader than actual parsing results, so
this check can reject requests that would keep their rule.

**Exact rule-change check** — apply a supported interpretation to a copy of the
path and compare rule identities for the request's method. Case-folding and
percent-decoding use this approach.

**Exclusive subtree** — an `exclusive_subtree` registration. It behaves like `subtree` during
requests and additionally forbids more-specific paths beneath it at build time.
It does not disable checks or remove method restrictions.

**Custom detector / probe** — a user-provided `StructuralProbe` that can reject
a path. It cannot allow a path rejected by another check or extend the built-in
model's guarantee.
