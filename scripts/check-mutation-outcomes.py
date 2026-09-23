#!/usr/bin/env python3
"""Validate completed mutation runs; property controls must fail on a BYPASS witness."""
import json
from pathlib import Path
import sys

PROPERTY = "path_confusion_proptest::guard_denies_every_modeled_relocation"
CONTROLS = {
    f"replace PathConfusionGuard::{name} -> Option<ResolveError> with None"
    for name in ("positional_deny", "interpretations_deny", "interpretation_rule_deny")
} | {"replace == with != in PathConfusionGuard::positional_deny"}


def check(mode, directory):
    root = Path(directory) / "mutants.out"
    results = json.loads((root / "outcomes.json").read_text())
    inventory = json.loads((root / "mutants.json").read_text())
    outcomes = results["outcomes"]
    baseline = [o for o in outcomes if o["scenario"] == "Baseline"]
    mutants = [o for o in outcomes if isinstance(o["scenario"], dict)]
    if not results["end_time"] or len(baseline) != 1 or baseline[0]["summary"] != "Success":
        raise ValueError("mutation run did not complete with a passing baseline")
    baseline_tests = [p for p in baseline[0]["phase_results"] if p["phase"] == "Test"]
    if len(baseline_tests) != 1 or baseline_tests[0]["process_status"] != "Success":
        raise ValueError("baseline must run and pass tests, not merely compile")
    if any(o["summary"] not in {"CaughtMutant", "MissedMutant", "Unviable", "Timeout"} for o in mutants):
        raise ValueError("unexpected mutant outcome: require a test run, not check-only results")
    expected = {m["name"] for m in inventory}
    actual = {o["scenario"]["Mutant"]["name"] for o in mutants}
    if not expected or actual != expected or len(mutants) != len(inventory):
        raise ValueError("mutation results do not cover the complete nonempty inventory")
    if mode == "property":
        names = {name.split(": ", 1)[1] for name in actual}
        if len(mutants) != 4 or names != CONTROLS:
            raise ValueError("property run must exercise exactly the four fail-open controls")
        for outcome in [baseline[0], *mutants]:
            tests = [p for p in outcome["phase_results"] if p["phase"] == "Test"]
            if len(tests) != 1 or PROPERTY not in tests[0]["argv"] or "--exact" not in tests[0]["argv"]:
                raise ValueError("property controls must run only the exact flagship property")
        for outcome in mutants:
            if outcome["summary"] != "CaughtMutant":
                raise ValueError("every property control must be caught, not missed, unviable, or timed out")
            if "BYPASS: guard allowed" not in (root / outcome["log_path"]).read_text():
                raise ValueError("control failed without the soundness assertion's BYPASS witness")
    print(f"Mutation audit ({mode}): {len(mutants)} candidates; "
          f"{results['caught']} caught, {results['missed']} survivors, "
          f"{results['unviable']} unviable, {results['timeout']} timeouts.")
    for label, kind in [("Survivors", "MissedMutant"), ("Timeouts (separate from survivors)", "Timeout")]:
        matches = [o for o in mutants if o["summary"] == kind]
        if matches:
            print(f"\n{label}:\n")
            for outcome in matches:
                print(f"- `{outcome['scenario']['Mutant']['name']}`")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("full", "property"):
        sys.exit("usage: check-mutation-outcomes.py [full|property] OUTPUT_DIRECTORY")
    try:
        check(*sys.argv[1:])
    except (ValueError, KeyError, OSError) as error:
        sys.exit(f"Invalid mutation evidence: {error}")
