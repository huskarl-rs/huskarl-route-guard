# Choosing a configuration

Configure the parsing behaviors that may occur after your application forwards a
request. Include every downstream component, not just the final server. The library
cannot infer these behaviors from a framework name or inspect the deployment.

For a direct connection to a tested backend, start with
[Tested deployments](crate::_docs::reference::deployments). It lists exact
versions, server configurations, guard settings, and the evidence supporting each
recommendation, including a separately specified proxy-chain profile.
The [topology explanation](crate::_docs::explanation::topology) shows where the guard
sits in those tests and what changes when several downstream chains are reachable.

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
declarations** with no default — `GuardConfig::new` requires both —
because the library cannot determine them:

1. **Declare [`CaseSensitivity`](crate::config::CaseSensitivity)** —
   required, no default. Pick
   [`Insensitive`](crate::config::CaseSensitivity::Insensitive) if a
   downstream component folds ASCII case. Register literal routes in lowercase.
   Pick [`Sensitive`](crate::config::CaseSensitivity::Sensitive) only when
   downstream routing distinguishes ASCII case.
2. **Declare [`DecodeDepth`](crate::config::DecodeDepth)** — required, no
   default. Pick [`UpToTwo`](crate::config::DecodeDepth::UpToTwo) when the
   whole path may be decoded up to twice before it is finally routed, or the
   depth is uncertain between one and two. Count actual decode passes after
   this guard, not proxy processes. Pick
   [`UpToOne`](crate::config::DecodeDepth::UpToOne) only when no more than one
   decode pass can happen.
3. **Enable the [`StructuralClasses`](crate::config::StructuralClasses)
   that match your stack.** Reach for
   [`with_backslash`](crate::config::StructuralClasses::with_backslash) on
   Windows/IIS,
   [`with_overlong`](crate::config::StructuralClasses::with_overlong) for a
   decoder that accepts non-shortest-form UTF-8, and
   [`with_fullwidth_structure`](crate::config::StructuralClasses::with_fullwidth_structure)
   for a backend that folds the supported fullwidth structural characters.
   This does not cover general Unicode normalization or fullwidth letters; see
   [coverage limits](crate::_docs::reference::coverage).
   Leave a toggle off only when you are sure the backend does not do it. (NUL
   truncation needs no toggle — it is always-on because this library does not support
   NUL as path content.)
4. **Pick the [`GuardMode`](crate::config::GuardMode) mode.**
   [`RejectAmbiguous`](crate::config::GuardMode::RejectAmbiguous)
   (the default) rejects possible rule changes. It accepts
   structural forms where the route table establishes that they cannot change the
   rule. Use [Registering routes](crate::_docs::guide::registering) when setting up
   areas for encoded keys;
   [`RequireCanonical`](crate::config::GuardMode::RequireCanonical)
   is strict defense-in-depth that denies every form it recognizes as non-canonical —
   **including recognized forms inside opaque keys and every complete percent escape**
   — so opt in only where those restrictions are acceptable;
   [`Disabled`](crate::config::GuardMode::Disabled) disables the guard. Use it only
   when route agreement is enforced elsewhere or this route result is not an
   authorization boundary.

## Reuse a deployment configuration

[`GuardConfig`](crate::config::GuardConfig) groups the four settings for
[`RuleRouter::from_registrations`](crate::RuleRouter::from_registrations). Its
constructor requires case sensitivity and decode depth; mode and structural classes
start at their defaults. Customize it and clone it when several route tables share
the same downstream assumptions. Both construction paths take this same value:

```rust
use huskarl_route_guard::{CaseSensitivity, DecodeDepth, GuardConfig, GuardMode, RuleRouter, StructuralClasses};

let config = GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToTwo)
    .with_mode(GuardMode::RejectAmbiguous)
    .with_structural_classes(StructuralClasses::new().with_backslash());
let router = RuleRouter::builder("default", config)
    .subtree("/admin", "admin")
    .build()
    .expect("valid routes");
assert!(router.resolve("/admin%5cusers", &http::Method::GET).is_err());
```

## When behavior remains uncertain

**The library cannot certify an uncharacterized deployment.** Within the built-in
model, every knob has a conservative direction: the stricter setting can only deny
*more*, never fewer. Over-declaring a supported
behavior therefore costs false-positive `400`s rather than creating a new allowed
request. If you cannot confirm the case behaviour, declare
[`Insensitive`](crate::config::CaseSensitivity::Insensitive) (it catches
more — the cost is that route literals must then be lowercase). If the path may
receive two decode passes after this guard, or you cannot distinguish one pass
from two, declare
[`UpToTwo`](crate::config::DecodeDepth::UpToTwo). More than two passes are outside
the supported model. And if you can't
characterise the backend at all *and* serve no opaque or deliberately-encoded path
content,
[`RequireCanonical`](crate::config::GuardMode::RequireCanonical)
is the strictest built-in fallback. It rejects every non-canonical form recognized by
the configured model, trading availability for a smaller attack surface. It does not
provide certainty about unknown downstream interpretations.

## Operate the result

After deployment, log the `Display` form of every [`ResolveError`](crate::ResolveError)
before changing configuration. For the reason-by-reason procedure, including when a
route redesign is appropriate, use
[Handling a denial](crate::_docs::guide::handling_denials).
