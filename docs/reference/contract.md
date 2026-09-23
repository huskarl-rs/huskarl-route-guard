# Security contract

## Guarantee

For every request accepted by the active guard, every interpretation in the
configured downstream parsing model selects the **same rule identity** as the raw
path, using this route table.

The default rule has a distinct identity. A change from the default to a
registration, from a registration to the default, or between registrations is a
rule change. The guard rejects such requests rather than choosing an alternative
rule for authorization.

Acceptance does not authorize the request. The caller must enforce the returned
rule's policy. The crate does not forward requests.

## Scope and assumptions

- **Input:** pass the request path alone, normally `uri.path()`. `resolve` rejects
  inputs that do not start with `/` (except `*`) or contain `?` or `#`.
- **Forwarding:** the caller forwards accepted requests with their paths unchanged.
  The guard does not rewrite them.
- **Identity:** patterns in one registration share an identity. Separate
  registrations remain distinct even if their rule values are equal.
- **Parsing model:** the *declared interpretation set* consists of the built-in
  parsing behaviors, enabled options, and their supported combinations. See
  [Supported path interpretations](crate::_docs::reference::coverage) for the exact
  scope, including decode-depth limits and exclusions.
- **Deployment:** the guarantee depends on the downstream behavior being represented
  by that model and this authorization route table. The library does not inspect
  or certify a deployment.
- **Mode:** `Off` disables ambiguity checks. `resolve` still validates input and
  rejects invalid internal rule IDs. Custom probes can add denials but cannot
  establish agreement for behaviors outside the model.

See [Routing behavior](crate::_docs::reference::routing) for pattern precedence,
method fall-through, and registration identity.

## Decision precision

| Check | Acceptance condition |
|---|---|
| Structural ambiguity | Every path and method in the conservatively analyzed region selects the raw path's rule identity |
| ASCII case folding | Lowercasing selects the same rule for the request method |
| Whole-path percent-decoding | Each configured complete decode result selects the same rule for the request method; results are also lowercased when configured |
| NUL | Always rejected while the guard is active |
| Custom probe | Rejected if any probe matches |

The structural check can reject a request even when every actual interpretation
keeps its rule. For example, under a lone `/users/{id}` registration,
`/users/4;2` is denied: the analyzed region contains default-rule gaps even
though stripping `;2` keeps the rule. This is a conservative approximation:
imprecision must add denials, never permit a rule change within the model.

The case-folding and percent-decoding comparisons are exact for their respective
modeled results. Other checks can still reject the same request. The reasons for
this split and the structural region calculation belong to
[How the guard decides](crate::_docs::explanation::decision).

## Modes

| Mode | Behavior |
|---|---|
| `RejectStructural` (default) | Applies the checks above; structural forms can be accepted when the analyzed region has one rule |
| `RejectNonCanonical` | Rejects every enabled structural form, every complete percent escape, and uppercase ASCII when case folding is configured; also runs custom probes |
| `Off` | Does not run ambiguity checks or custom probes |

The strict mode does not grant exceptions for subtrees or blobs. Neither active
mode rejects every possible unusual spelling: recognition remains limited to the
configured model.

## Invariants

1. **Stricter settings only add denials.** Within the supported model, enabling more
   checks or increasing decode depth cannot turn a denial into acceptance.
2. **Adding registrations only adds denials.** A new registration has its own
   identity, even if its rule value equals an existing value.
3. **Canonical request paths pass built-in ambiguity checks.** Here, canonical means
   a slash-prefixed path with no recognized structural form, no percent escape,
   and no uppercase ASCII when case folding is configured. Custom probes may
   reject such paths. Input validation and internal invariant failures are
   separate from the ambiguity checks.
4. **Failure does not return a rule.** `resolve` returns `Err(DenyReason)` on a
   denial, including an invalid internal rule ID. That internal failure must not
   be treated as successful default matching.

The test suite exercises rule agreement, stricter configurations, added
registrations, and canonical paths. These are implementation checks against an
executable model, not proof about a deployed backend. See
[How the security claim is tested](crate::_docs::explanation::testing).

For operational responses to extra denials, use
[Handling a denial](crate::_docs::guide::handling_denials).
