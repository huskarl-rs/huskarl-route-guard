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
[`RejectStructural`](crate::path_confusion::PathConfusion::RejectStructural)
mode. Despite its name, it allows structural forms where the checks establish
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
If every path and method in that region selects the same rule, the structural
form cannot cross a rule boundary.

This distinction explains both the useful tolerance under a complete subtree
and the extra denials under partially covered prefixes.

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
and it agrees with the raw path's rule.

The region includes:

- literal and wildcard branches that path matching could reach;
- ancestor catch-alls used when a more-specific branch cannot finish matching;
- gaps that select the default, including missing trailing-slash coverage; and
- all HTTP methods, including methods without a registration.

This is called **uniform coverage**: every path and method selects the same rule.
The [routing reference](crate::_docs::reference::routing) specifies matching
precedence and method behavior.

The region is deliberately broader than the actual parsing results. With only
`route("/users/{id}", rule)`, `/users/4;2` is denied because the analyzed
`/users/` region includes default-rule gaps. Stripping the path parameter would
actually produce `/users/4` and keep the rule. This is an intentional extra
denial, not evidence that a backend necessarily changes the rule.

By contrast, a complete all-method `subtree("/files", rule)` covers
`/files/a%2fb` and every result in its analyzed region. A `blob_subtree` has the
same request-time behavior; its extra protection is a build-time error if someone
adds more-specific paths beneath it. Method restrictions can still prevent
uniform coverage.

## Case folding and percent-decoding: compare the results

When case-insensitive parsing is configured, the guard lowercases ASCII letters
and compares the resulting rule with the raw path's rule. A change within one
rule, such as `/files/ReadMe.TXT` to `/files/readme.txt`, is accepted.

The percent-decoding check compares the raw rule against the result after one
complete decode pass, and also after two passes under
[`DecodeLayers::UpToTwo`](crate::path_confusion::DecodeLayers::UpToTwo).
Each candidate is lowercased too when case folding is configured. This catches
escapes that reveal uppercase letters, such as `/%41dmin`.

Each pass matters. A sequence of rule identities A → B → A is unsafe if a
downstream component might stop after one pass. The check uses a consistent
decode depth across the whole path; selective decoding is outside the model.

These comparisons use the request's actual method. Structural coverage spans all
methods instead, which can cause additional denials for method-qualified subtrees.
The distinction is specified in the
[routing reference](crate::_docs::reference::routing).

## Unconditional checks and strict mode

NUL is unsupported path content and is always rejected when the guard is active.
Custom probes also reject on presence: they can add denials but cannot make a
request pass another check.

[`RejectNonCanonical`](crate::path_confusion::PathConfusion::RejectNonCanonical)
rejects every enabled structural form and every complete percent escape, plus
uppercase ASCII when case folding is configured. It does not use the route table
to grant exceptions. A blob registration therefore provides no tolerance in this
mode. `Off` disables these checks; public `resolve` still validates its path input
and checks the returned rule ID.

## Why route-table changes matter

Adding a registration can introduce another identity into a previously uniform
region, causing encoded paths there to be rejected. Even an equal rule value gets
a new identity. Adding registrations can tighten the guard's decisions; it cannot
turn an existing denial into an allow within the supported model.

The guard returns a result, not a forwarded request. The calling application
enforces the selected policy and forwards allowed paths unchanged. For the
reason behind that boundary, see
[Why the guard never rewrites paths](crate::_docs::explanation::no_rewrite).
