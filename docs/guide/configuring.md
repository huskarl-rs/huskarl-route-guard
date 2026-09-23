# Choosing a configuration

Configure the parsing behaviors that may occur after your application forwards a
request. Include every downstream component, not just the final server. The library
cannot infer these behaviors from a framework name or inspect the deployment.

## Before you configure

Identify every component that can parse or rewrite the path between this guard and
the final route or protected resource: proxies, WAFs, framework middleware, routers,
and filesystem mappings. Determine whether they decode, fold case, treat alternate
characters as separators, remove parameters, or normalize Unicode.

Documentation and source review may be enough for a controlled stack. Empirical
validation requires observing the final route or authorization scope inside the
downstream system; equal HTTP responses alone are not reliable evidence. Treat bespoke
characterization as security-testing work.

## Choose the four settings

Make these four per-deployment choices in order. Two are **required
declarations** with no default — the builder will not compile without them —
because the library cannot determine them:

1. **Declare [`CaseSensitivity`](crate::path_confusion::CaseSensitivity)** —
   required, no default. Pick
   [`Insensitive`](crate::path_confusion::CaseSensitivity::Insensitive) if a
   downstream component folds ASCII case. Register literal routes in lowercase.
   Pick [`Sensitive`](crate::path_confusion::CaseSensitivity::Sensitive) only when
   downstream routing distinguishes ASCII case.
2. **Declare [`DecodeLayers`](crate::path_confusion::DecodeLayers)** — required, no
   default. Pick [`UpToTwo`](crate::path_confusion::DecodeLayers::UpToTwo) when the
   whole path may be decoded either once or twice before it is finally routed — a
   CDN or WAF in front of an origin, proxy-in-front-of-proxy (the CVE-2025-0108
   shape), or uncertainty between those two decode depths. Pick
   [`Single`](crate::path_confusion::DecodeLayers::Single) only when no more than one
   decode pass can happen.
3. **Enable the [`StructuralClasses`](crate::path_confusion::StructuralClasses)
   that match your stack.** Reach for
   [`with_backslash`](crate::path_confusion::StructuralClasses::with_backslash) on
   Windows/IIS,
   [`with_overlong`](crate::path_confusion::StructuralClasses::with_overlong) for a
   decoder that accepts non-shortest-form UTF-8, and
   [`with_unicode_normalization`](crate::path_confusion::StructuralClasses::with_unicode_normalization)
   for a backend you have **confirmed** Unicode-normalizes the path before routing.
   Leave a toggle off only when you are sure the backend does not do it. (NUL
   truncation needs no toggle — it is always-on because this library does not support
   NUL as path content.)
4. **Pick the [`PathConfusion`](crate::path_confusion::PathConfusion) mode.**
   [`reject_structural`](crate::path_confusion::PathConfusion::reject_structural)
   (the default) rejects possible rule changes. Despite its name, it accepts
   structural forms where the route table establishes that they cannot change the
   rule. Use [Registering routes](crate::_docs::guide::registering) when setting up
   areas for encoded keys;
   [`reject_non_canonical`](crate::path_confusion::PathConfusion::reject_non_canonical)
   is strict defense-in-depth that denies every form it recognizes as non-canonical —
   **including opaque blob keys and any percent-escape** — so opt in only where you
   serve no such content;
   [`off`](crate::path_confusion::PathConfusion::off) disables the guard. Use it only
   when route agreement is enforced elsewhere or this route result is not an
   authorization boundary.

## Reuse a deployment configuration

[`GuardConfig`](crate::path_confusion::GuardConfig) groups the four settings for
[`RuleRouter::build_with_config`](crate::RuleRouter::build_with_config). Its
constructor requires case sensitivity and decode depth; mode and structural classes
start at their defaults. Customize its fields and clone it when several route
tables share the same downstream assumptions. The existing router builder remains
available for declaring settings individually.

## When behavior remains uncertain

**The library cannot certify an uncharacterized deployment.** Within the built-in
model, every knob has a conservative direction: the stricter setting can only deny
*more*, never fewer. Over-declaring a supported
behavior therefore costs false-positive `400`s rather than creating a new allowed
request. If you cannot confirm the case behaviour, declare
[`Insensitive`](crate::path_confusion::CaseSensitivity::Insensitive) (it catches
more — the cost is that route patterns must then be lowercase). If there is *any*
chance a CDN, WAF, or second proxy fronts the origin — or you do not know whether
the backend decodes once or twice — declare
[`UpToTwo`](crate::path_confusion::DecodeLayers::UpToTwo). And if you can't
characterise the backend at all *and* serve no opaque or deliberately-encoded path
content,
[`reject_non_canonical`](crate::path_confusion::PathConfusion::reject_non_canonical)
is the strictest built-in fallback. It rejects every non-canonical form recognized by
the configured model, trading availability for a smaller attack surface. It does not
provide certainty about unknown downstream interpretations.

## Operate the result

After deployment, log the `Display` form of every [`DenyReason`](crate::DenyReason)
before changing configuration. For the reason-by-reason procedure, including when a
route redesign is appropriate, use
[Handling a denial](crate::_docs::guide::handling_denials).
