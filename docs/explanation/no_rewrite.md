# Why the guard forwards the raw path

The guard either denies a request or forwards its path unchanged. This is a boundary
choice, not a claim that normalization is always wrong.

Normalization can be sound when one trusted component uses the same normalized value
for authorization and dispatch, and downstream components cannot reinterpret it. In
that architecture the normalizer defines the path semantics.

This crate addresses a different architecture: one component authorizes a path and
another component later parses and serves it. The authorization layer cannot enforce
how many times the complete downstream chain decodes, whether a framework strips
parameters, or whether a filesystem folds case. Rewriting the path here would choose
one interpretation without preventing later components from choosing another.

## Preserve the evidence

Forwarding the original path has useful operational properties:

- a downstream WAF sees what the client sent;
- cache keys are not changed by this layer;
- origin defenses receive the original input; and
- logs retain the spelling that triggered the decision.

A normalizing gateway may intentionally choose different properties. The point is
that rewriting is an externally visible transformation which every downstream
component must account for; it is not a free substitute for modeling those
components.

## Keep the decision one-sided

Configuration changes in this guard are monotonic: stricter settings add denials.
They do not change the bytes received downstream. That makes the failure direction
simple—an overstatement of modeled behavior rejects additional requests.

A rewrite has a different shape. It can change the downstream route, cache key,
logging value, and security checks even when the request would otherwise have been
allowed. This crate therefore does not offer a “normalize and forward” mode.

When the downstream behavior is uncertain, declare the broader supported
interpretation set or use
[`reject_non_canonical`](crate::path_confusion::PathConfusion::reject_non_canonical)
if legitimate traffic permits it. That strict mode reduces exposure to recognized
non-canonical forms; it does not certify an otherwise unknown deployment. See
[Supported path interpretations](crate::_docs::reference::coverage) for the boundary
of the built-in model.
