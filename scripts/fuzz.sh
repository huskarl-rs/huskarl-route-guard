#!/usr/bin/env bash
# Prime a bolero target's live corpus from the committed seeds, then fuzz it.
#
# The live corpus (src/__fuzz__/) is gitignored and may be cold (fresh checkout) or
# cache-evicted, so we always copy the committed seeds in first to start warm. Used by
# both `mise run fuzz` and the CI discovery job so local and CI prime identically.
#
# With no arguments, run all three targets with the CI discovery time budgets.
#   scripts/fuzz.sh [<full::target::name> [extra cargo-bolero args, e.g. -T 600s]]
set -euo pipefail

# Run from the repo root regardless of caller cwd.
cd "$(dirname "$0")/.."

if [ "$#" -eq 0 ]; then
  bash scripts/fuzz.sh structural::tests::scanner -T 300s
  bash scripts/fuzz.sh route_tree::tests::matcher_differential -T 300s
  bash scripts/fuzz.sh path_confusion_proptest::guard_relocation -T 600s
  exit 0
fi

target="$1"
shift

# bolero names its corpus dir after the target with `::` -> `__`.
dir=$(printf '%s' "$target" | sed 's/::/__/g')
mkdir -p "src/__fuzz__/$dir/corpus"
if [ -d "fuzz-corpus/$dir" ]; then
  cp -f "fuzz-corpus/$dir/"* "src/__fuzz__/$dir/corpus/" 2>/dev/null || true
fi

exec cargo +nightly bolero test "$target" "$@"
