# Registering routes

Use this guide when mapping your application's authorization policies to paths.
Start with the [tutorial](crate::_docs::tutorial) if you have not built a router yet.

## Choose the paths each rule covers

Use `route` for an exact path or pattern. Use `subtree` when the same policy applies
to a prefix and everything beneath it. For example, `subtree("/admin", rule)`
covers `/admin`, `/admin/`, and `/admin/users` under one identity.

Check trailing slashes deliberately. `subtree("/admin/", rule)` excludes the bare
`/admin`. If the backend treats those spellings as equivalent, give them the same
registration. The guard does not detect trailing-slash equivalence for you.

Keep patterns that should share an identity in one registration. Two calls with
equal rule values still create different identities. If the helper methods cannot
express your group of patterns, assemble a [`Registration`](crate::Registration)
and use [`build_with_config`](crate::RuleRouter::build_with_config).

## Set the default policy explicitly

The default rule handles unmatched paths and methods that have no rule at the
selected path. Choose a value your application can enforce safely in both cases.
Test unmatched requests as well as registered paths.

## Add method-specific rules

Use `route_for`, `subtree_for`, or `blob_subtree_for` to select methods. Check each
method you serve at an overlapping path: path matching happens before method lookup.

For example, with `/items/{id}` and a GET-only `/items/special`, POST to
`/items/special` selects the default. It does not use `/items/{id}`. If POST needs a
rule there, register it explicitly at `/items/special`, or add an all-method
`route` at that exact path. See [Routing behavior](crate::_docs::reference::routing)
for the executable example and precedence rules.

## Register areas that accept encoded keys

If one rule applies to an entire file-key prefix for all methods, use
`blob_subtree("/files", rule)`. Encoded slashes such as `/files/a%2fb` can then be
accepted when every supported interpretation stays in that rule. The blob
declaration prevents later registrations from adding more-specific paths beneath
it. Use `subtree` instead if nested routes are intentional.

Check method restrictions before relying on this tolerance. A GET-only subtree,
including a GET-only blob, denies structural keys even for GET: other methods fall
through to the default, so the region is not covered by one rule for every method.
Only register an all-method rule when its policy is appropriate for every method.

## Verify the table through `resolve`

Exercise ordinary paths, trailing slashes, overlapping patterns, unmatched paths,
and each relevant method. For encoded keys, include examples that should stay in
the rule and examples that could escape it. The
[denial guide](crate::_docs::guide::handling_denials) includes a regression-test
example and steps for investigating unexpected results.
