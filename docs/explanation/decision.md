# How the guard decides

The guard asks whether downstream parsing could change the authorization rule
selected from the raw request path. It compares rule identities, including the
default; it does not compare the caller's rule values.

Consider a table with an `/admin` subtree and a public default. The raw path
`/admin%2fusers` selects the default, while decoding the slash produces
`/admin/users`, which selects the admin rule. The guard rejects the request.
It does not choose which interpretation the backend will use.

Now consider a lone `/files` subtree. Both `/files/a%2fb` and `/files/a/b`
select its rule. An encoded slash does not by itself require rejection: what
matters is whether parsing could cross a rule boundary.

This explanation describes the default
[`RejectAmbiguous`](crate::config::GuardMode::RejectAmbiguous)
mode. It allows structural forms where the checks establish
that the rule cannot change. The
[security contract](crate::_docs::reference::contract) states the precise guarantee,
and the [coverage reference](crate::_docs::reference::coverage) lists supported
parsing behaviors and exclusions.

## Why there are two kinds of check

Some parsing behaviors change the content of a segment predictably. For example,
`/%61dmin` decodes to `/admin`, and ASCII case folding changes `/ADMIN` to
`/admin`. The guard can apply these operations to a copy of the path and compare
the selected rule with the raw path's rule.

Structural behavior is harder to simulate. Slash merging, path-parameter removal,
and dot-segment resolution can interact in different orders. Instead of choosing
one order, the guard calculates a region that contains the possible results.
If every path in that region selects the same rule for the request method, the structural
form cannot cross a rule boundary.

This distinction explains both the useful tolerance under a complete subtree
and the extra denials under partially covered prefixes.

## One pipeline for every percent interpretation

A single decoder supplies the original byte path, the result of one complete
percent-decode pass, and (under `UpToTwo`) the result of a second pass. Every
interpretation receives the same structural scan and rule comparison. Invalid
UTF-8 remains byte data and receives the same checks.

Structural detectors recognize bytes, not separate single- and double-encoded
spellings. For example, decoding `/admin%25EF%25BC%258Fusers` twice reveals
`/admin／users`. With fullwidth structure enabled, the shared scanner recognizes
that slash and rejects the possible change to the `/admin` rule.

Each decoded byte retains its original source offset. Structural analysis joins
classes and the earliest source position across interpretations, and takes the
maximum possible dot-segment climb count. The anchor is always computed in the
original request, never with offsets borrowed from a decoded buffer. Every rule
comparison also uses the original request's identity as its baseline.

## Structural ambiguity: find a stable prefix

For `/files/a%2fb`, the slash before `a` ends the prefix `/files/`.
Decoding the escape can change what comes after that prefix, but cannot change
the prefix itself. The algorithm calls this stable prefix the **anchor**.

The guard computes it conservatively:

1. Find the earliest recognized structural form. Also consider any earlier `%`,
   or uppercase ASCII when case folding is configured: these can change the
   path before the structural form.
2. Keep the path through the last slash before that position. If there is no
   earlier usable prefix, use the root `/`. For `//`, the second slash is the
   structural occurrence, because merging preserves the first.
3. Shorten the prefix by one segment for each dot-segment capable of traversal,
   stopping at the root. Counting more possible climbs can only add denials.

An escape in an earlier segment does **not** always force the anchor to the root.
For `/files/%61/a%2fb`, the earlier escape shortens it to `/files/`.
For `/%66iles/a%2fb`, it becomes `/`. The implementation keeps whatever earlier
prefix it can establish as stable.

Registered literal segments cannot contain enabled structural forms while the
guard is active. This build-time check prevents a literal route from depending
on the very spelling the guard treats as ambiguous.

## Structural ambiguity: check every reachable rule

The route tree summarizes whether a region contains one rule identity or several.
The structural check accepts only when the anchor's region contains one identity
and it agrees with the raw path's rule for the request method.

The region includes:

- literal and wildcard branches that path matching could reach;
- ancestor catch-alls used when a more-specific branch cannot finish matching;
- unmatched gaps that select the default, including missing trailing-slash coverage;
- method denials at paths with no applicable rule and inheritance disabled.

This is called **uniform coverage**: every path selects the same rule for the
request method. The modeled transformations change paths, not HTTP methods.
Coverage for unrelated methods therefore does not participate.
The [routing reference](crate::_docs::reference::routing) specifies matching
precedence and method behavior.

The region is deliberately broader than the actual parsing results. With only
`route("/users/{id}", rule)`, `/users/4;2` is denied because the analyzed
`/users/` region includes default-rule gaps. Stripping the path parameter would
actually produce `/users/4` and keep the rule. This is an intentional extra
denial, not evidence that a backend necessarily changes the rule.

By contrast, a complete `subtree("/files", rule)` covers
`/files/a%2fb` and every result in its analyzed region for each method it serves.
A GET-only subtree can therefore accept that request for GET. An `exclusive_subtree` has the
same request-time behavior; its extra protection is a build-time error if someone
adds more-specific paths beneath it. A more-specific terminal with no rule for
GET would create a method denial and prevent uniform GET coverage unless it
explicitly inherits. Inheritance retains the broader GET rule identity.

At build time the router compiles a view for each explicitly registered method
and a shared view for all other methods. Inheriting gaps are removed from each
view; blocking gaps become denial terminals. Matching and cached coverage use the
same view, preserving fallback semantics without copying rule values. This trades
additional tree storage for a simple request-time lookup; storage scales with the
number of nodes times the number of distinct registered methods.

## When uniform coverage subsumes precise comparisons

For a request with an enabled structural hit, passing the uniform-anchor check
also establishes agreement for whole-path percent decoding and configured ASCII
case folding. This narrower implication follows from how those two operations act:

1. The anchor ends before the first `%`, and before the first uppercase ASCII byte
   when case folding is enabled. Its bytes contain neither input that these
   operations can change. Raising the anchor for traversal only shortens it.
2. Each permitted decode pass therefore preserves the anchor byte-for-byte. A
   second pass cannot change that: the prefix has no escape from which the first
   pass could produce a new `%`. ASCII folding likewise preserves the prefix.
   This remains true when bytes after the prefix decode to invalid UTF-8.
3. Uniform coverage requires every byte path extending that anchor to select the
   original identity for the same method. Every precise interpretation is such an
   extension, so none can select a different identity.

This relies on the matcher's coverage contract and the content bound on the anchor.
It does not infer correctness from a silent mutation run, nor require that decoding
perform dot-segment resolution or other structural normalization. Those transforms
still require the separate anchor-invariance argument. The implication does **not**
apply to the structural check's early acceptance of a path with no enabled
structural hit: `/%61dmin`, for example, still needs precise rule comparison.

A September 2026 mutation experiment changed the **inner** length comparison in
`interpretations_deny` from `>` to `<`. This skips precise comparisons on short
paths once scanning has accumulated an enabled structural hit; it leaves scanning,
NUL denial, and the final uniform-anchor check intact. The flagship soundness
property found no relocation in 100,000 generated cases with seed `20260923`, nor
in another 100,000 with seed `20260924`. Each mutated run followed a passing
unmutated baseline at the same case count. These counts include generated cases
that skip invalid route tables or deny requests; they are not 200,000 accepted
structural paths. This is bounded experimental support for the argument above,
not a proof over all inputs or a reason to remove the production comparisons.

## Why exclusivity is checked across overlapping patterns

An ordinary subtree allows exceptions. Adding `/files/private` beneath a `/files`
subtree changes which rule applies there and can make structural paths elsewhere
under `/files/` ambiguous. An exclusive subtree declares that these nested path
exceptions are a configuration error. It is useful when an application intends a
tail to remain a single area, such as a file-key namespace.

The declaration is about paths, not just descendants of a node in the route tree.
For an exclusive `/{tenant}`, a separately registered `/files/private` occupies a
different branch of the tree. Nevertheless, a request for `/files/private` takes
the literal branch instead of the exclusive wildcard branch. Validation must
compare overlapping patterns using the same precedence as request matching.

Disjoint method sets do not repair that overlap: the path terminal is selected
before method lookup. A GET-only exclusive subtree and a POST-only nested exact
route can stop GET lookup with a method denial at the exact route. Conversely, a broader fallback that never takes precedence
inside the exclusive tail does not introduce a nested exception and remains valid.

This build-time restriction does not itself prove uniform rule coverage. Rules for
different methods at the same path patterns are still allowed. Gaps for the request
method can still introduce a denial into an analyzed region. The runtime guard therefore applies the same
checks to ordinary and exclusive subtrees. The
[routing reference](crate::_docs::reference::routing) lists forbidden combinations
and the permitted boundaries of exclusivity.

## Case folding and percent-decoding: compare the results

When case-insensitive parsing is configured, the guard lowercases ASCII letters
and compares the resulting rule with the raw path's rule. A change within one
rule, such as `/files/ReadMe.TXT` to `/files/readme.txt`, passes this comparison;
other checks can still deny the request.

The percent-decoding check compares the raw rule against the result after one
complete decode pass, and also after two passes under
[`DecodeDepth::UpToTwo`](crate::config::DecodeDepth::UpToTwo).
Each candidate receives structural analysis and is lowercased for rule comparison
when case folding is configured. This catches escapes that reveal uppercase letters,
such as `/%41dmin`, and structural forms that only become visible after decoding.

Each pass matters. A sequence of rule identities A → B → A is unsafe if a
downstream component might stop after one pass. The check uses a consistent
decode depth across the whole path; selective decoding is outside the model.

These comparisons and structural coverage all use the request's actual method.
Path precedence and method fallback are specified in the
[routing reference](crate::_docs::reference::routing).

## Unconditional checks and strict mode

NUL is unsupported path content and is always rejected when the guard is active.
Custom probes also reject on presence: they can add denials but cannot make a
request pass another check.

[`RequireCanonical`](crate::config::GuardMode::RequireCanonical)
rejects every enabled structural form and every complete percent escape, plus
uppercase ASCII when case folding is configured. It does not use the route table
to grant exceptions. A blob registration therefore provides no tolerance in this
mode. `Disabled` disables these checks; public `resolve` still validates its path input
and checks the returned rule ID and method availability.

## Why route-table changes matter

Adding a registration can introduce another identity into a previously uniform
region, causing encoded paths there to be rejected. Even an equal rule value gets
a new identity. Adding a registration can also restore uniformity by shadowing a
wildcard branch. With only `subtree("/{tenant}/private", private)`, the request
`/files/a%2fb` is denied: the analyzed region includes both the default and private
rules. Adding `subtree("/files", files)` makes that region uniformly select the files
rule, so the same request is accepted. Its decoded form selects the files rule too.

Route-table changes can therefore change both the selected rule and acceptance.
Every accepted request must still satisfy rule agreement under the configured
parsing model. Recheck representative requests when changing registrations.

The guard returns a result, not a forwarded request. The calling application
enforces the selected policy and forwards allowed paths unchanged. For the
reason behind that boundary, see
[Why the guard never rewrites paths](crate::_docs::explanation::no_rewrite).
