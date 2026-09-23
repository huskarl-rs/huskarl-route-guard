# Supported path interpretations

This page is a reference for the built-in model. A row marked “default” means the
active guard considers that interpretation without an opt-in; it does **not** mean
that the library has detected the behavior in your deployment. `Disabled` disables these
checks. See the [security contract](crate::_docs::reference::contract) for how the
modes use this model.

| Path interpretation | Status | Enable with |
|---|---|---|
| encoded slash `%2F`, empty segment `//` | **default** | — |
| dot-segments `.`/`..`, encoded `%2E` | **default** | — |
| path parameters (matrix parameters), such as `;version=2`, or encoded `%3B` | **default** | — |
| `%00` / raw-NUL truncation (C-string backends) | **default** | — (always-on; NUL is unsupported path content) |
| percent-decoding to a different literal (`/%61dmin`) | **default** | — |
| double percent-decoding `%252F` (CDN/WAF → origin) | **required** declaration | [`DecodeDepth::UpToTwo`](crate::config::DecodeDepth::UpToTwo) |
| case folding `/ADMIN` ≡ `/admin` | **required** declaration | [`CaseSensitivity::Insensitive`](crate::config::CaseSensitivity::Insensitive) |
| `\` / `%5C` as a separator (Windows / IIS) | opt-in | [`with_backslash`](crate::config::StructuralClasses::with_backslash) |
| overlong UTF-8 `%C0%AF` / `%C0%AE` (legacy decoders) | opt-in | [`with_overlong`](crate::config::StructuralClasses::with_overlong) |
| fullwidth/NFKC structural confusables (`／`→`/`, …) | opt-in | [`with_fullwidth_structure`](crate::config::StructuralClasses::with_fullwidth_structure) |
| a novel structural form (fresh CVE, vendor quirk) | custom detector | [`with_probe`](crate::config::StructuralClasses::with_probe) |

“Default” interpretations are always considered. “Required” values must be supplied
to the builder. “Opt-in” interpretations are absent until enabled. A custom detector
can add a platform-specific denial, but cannot teach the guard how that platform
routes the resulting path.

## What is *not* covered

The guard models the downstream route decision as *this route table plus the
interpretations selected by configuration*. It is only as complete as that
declaration. Neither standards compliance nor a familiar platform name establishes
that the declaration matches a deployment. Behavior **outside the declared set** is
not seen at all:

- **Undeclared backend quirks.** If your backend treats `\` as a separator, folds
  case, or sits behind a second decoder and you have **not** made the matching
  declaration or enabled the matching toggle, that relocation is invisible to the
  guard. Each declaration is you asserting "my backend considers these paths
  equivalent"; the library cannot infer it and will not guess. (NUL truncation is
  the exception: always-on, because its legitimate-use rate is nil.)
- **Unicode *content* confusables and non-NFKC look-alikes.** The structural NFKC
  confusables (`／`→`/`, `．`→`.`, `；`→`;`, `＼`→`\`) *are* covered, opt-in, by
  [`with_fullwidth_structure`](crate::config::StructuralClasses::with_fullwidth_structure).
  What remains uncovered: fullwidth *letters* that NFKC-fold onto a different literal
  route (`/ＡＤＭＩＮ` → `/ADMIN` → `/admin` — a content relocation with no built-in
  class), and visual look-alikes NFKC does **not** decompose (U+2044 fraction slash,
  U+2215 division slash). For these, deny non-ASCII paths with a
  [`StructuralProbe`](crate::config::StructuralProbe) — blunt but monotonic,
  since a probe can only add denials:

  ```
  use huskarl_route_guard::config::{StructuralClasses, StructuralProbe};

  struct RejectNonAscii;
  impl StructuralProbe for RejectNonAscii {
      fn name(&self) -> &'static str {
          "reject-non-ascii"
      }
      // Whole-path presence check. Scope it tighter (the specific confusables your
      // backend folds) if you must serve legitimate non-ASCII paths.
      fn matches(&self, path: &str) -> bool {
          !path.is_ascii()
      }
  }

  let classes = StructuralClasses::new().with_probe(RejectNonAscii);
  ```
- **Trailing-slash / segment-presence equivalence.** A backend that treats
  `/admin/` ≡ `/admin` is not caught — `/admin/` carries no recognized structural form — so an
  exact `route("/admin", …)` lets `/admin/` fall through to the default rule while the
  backend still serves the admin resource. The defense here is rule *registration*,
  not detection: use `subtree` (one rule covering `/admin`, `/admin/`, and below)
  rather than `route` for anything you mean to protect.
- **Partial / selective decoding.** The content-decode check models the possibility
  that a backend decodes the whole path. A backend that decodes only *some*
  escapes, or in an order all its own, is not modelled.
- **Strip-style "sanitizers".** The built-in model includes decoding, slash merging,
  parameter stripping, and dot-segment resolution. Every supported member rewrites
  the path at or after the form that triggers it, which is what lets the scoped check
  bound its reach. A backend that instead **deletes patterns and rescans** (the
  `path.replace("../", "")` anti-pattern) is outside the family: it can *manufacture*
  a traversal from bytes the model considers inert — `....//` becomes `../` after one
  deletion pass — including inside a single-rule subtree the scoped check tolerates.
  If you must front such a backend, add a
  [`StructuralProbe`](crate::config::StructuralProbe) for the shapes its
  sanitizer reacts to (e.g. any `../` substring after one deletion pass), or run
  [`RequireCanonical`](crate::config::GuardMode::RequireCanonical).
- **Forms with no class and no probe.** A structural form outside the built-in
  alphabet — including a future CVE — is invisible until you add a
  [`with_probe`](crate::config::StructuralClasses::with_probe) for it or a
  release ships it.
- **Path only.** Pass `uri.path()`, never a full request-target.
  [`resolve`](crate::RuleRouter::resolve) validates this boundary: the input must begin
  with `/` (or be the special `*` request target) and contain no `?` or `#`. A full
  request-target such as `/admin?x=1`, or an absolute URI, is denied with
  [`InvalidPathInput`](crate::ResolveError::InvalidPathInput) rather than being routed.
- **Detection, not sanitisation.** The guard returns a rule or a denial. The caller
  forwards allowed requests with their paths unchanged. This is a condition of
  the contract — see
  [The guard never rewrites the path](crate::_docs::explanation::no_rewrite).
- **Not a WAF.** Within the declared interpretation set, the guard keeps the selected
  authorization rule stable. It does not inspect content for injection or repair a
  backend's own path-handling bugs. It may deny a request spelling used by a known
  vulnerability, but the underlying backend defect remains to be fixed.
