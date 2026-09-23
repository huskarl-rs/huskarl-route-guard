#!/usr/bin/env bash
# Repeatable mutation audit; cargo-mutants works in temporary copies of this tree.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-full}"
if [[ $# -gt 0 ]]; then shift; fi
export PROPTEST_RNG_SEED="${PROPTEST_RNG_SEED:-20260923}"
# Shrinking is unnecessary for detection and can dominate a mutation run.
export PROPTEST_MAX_SHRINK_ITERS=0

case "$mode" in
  full)
    exec cargo mutants --file src/guard.rs --file src/structural.rs \
      --jobs 3 --timeout 45 --build-timeout 120 \
      --output "${MUTATION_OUTPUT:-target/mutation-audit/full}" "$@" -- --locked --lib --tests
    ;;
  property)
    # Four viable fail-open controls. Run only the flagship assertion, so a unit
    # test cannot mask its failure to detect a broken guard.
    exec cargo mutants --file src/guard.rs \
      --re '(positional_deny|interpretations_deny|interpretation_rule_deny).*with None$|replace == with != in PathConfusionGuard::positional_deny$' \
      --jobs 1 --timeout 45 --build-timeout 120 \
      --output "${MUTATION_OUTPUT:-target/mutation-audit/property}" "$@" -- --locked --lib \
      path_confusion_proptest::guard_denies_every_modeled_relocation -- --exact
    ;;
  *)
    echo "usage: $0 [full|property] [cargo-mutants options]" >&2
    exit 64
    ;;
esac
