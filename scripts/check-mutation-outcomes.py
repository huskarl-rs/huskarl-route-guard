#!/usr/bin/env python3
"""Validate completed mutation runs; property controls must fail on a BYPASS witness."""
import json
from pathlib import Path
import re
import sys

REVIEWED = Path(__file__).with_name("mutation-baseline.json")
PROPERTY = "path_confusion_proptest::guard_denies_every_modeled_relocation"
CONTROLS = {
    f"replace PathConfusionGuard::{name} -> Option<ResolveError> with None"
    for name in ("positional_deny", "interpretations_deny", "interpretation_rule_deny")
} | {"replace == with != in PathConfusionGuard::positional_deny"}


def mutation_identity(mutant, diff):
    """Ignore coordinates, but retain the mutation site rather than just its operator."""
    description = re.sub(r"^.*?:\d+:\d+: ", "", mutant["name"], count=1)
    changes = tuple(
        line[0] + line[1:].strip()
        for line in diff.splitlines()
        if line.startswith(("-", "+")) and not line.startswith(("---", "+++"))
    )
    if not changes:
        raise ValueError(f"missing mutation diff for {mutant['name']}")
    return mutant["file"], description, changes


def check_reviewed(mutants, root):
    entries = json.loads(REVIEWED.read_text())
    reviewed = {}
    for entry in entries:
        key = (entry["file"], entry["mutation"], tuple(entry["changes"]))
        if key in reviewed or not entry["rationale"].strip() or entry["outcome"] not in {"MissedMutant", "Timeout"}:
            raise ValueError("invalid or duplicate reviewed mutation")
        reviewed[key] = entry

    observed = set()
    errors = []
    for outcome in mutants:
        mutant = outcome["scenario"]["Mutant"]
        key = mutation_identity(mutant, (root / outcome["diff_path"]).read_text())
        entry = reviewed.get(key)
        summary = outcome["summary"]
        if entry:
            if key in observed:
                errors.append(f"ambiguous reviewed mutation: {mutant['name']}")
            observed.add(key)
        if summary in {"MissedMutant", "Timeout"}:
            if not entry or summary != entry["outcome"]:
                errors.append(f"unreviewed {summary}: {mutant['name']}")
                continue
            builds = [p for p in outcome["phase_results"] if p["phase"] == "Build"]
            tests = [p for p in outcome["phase_results"] if p["phase"] == "Test"]
            expected_status = "Timeout" if summary == "Timeout" else "Success"
            if (len(builds) != 1 or builds[0]["process_status"] != "Success"
                    or len(tests) != 1 or tests[0]["process_status"] != expected_status):
                errors.append(f"reviewed outcome requires successful build and test {expected_status}: {mutant['name']}")
            else:
                print(f"- Reviewed {summary}: `{mutant['name']}` — {entry['rationale']}")
        elif entry:
            label = "Now caught" if summary == "CaughtMutant" else "Now unviable; review baseline"
            print(f"- {label}: `{mutant['name']}`")
    for key in reviewed.keys() - observed:
        print(f"- Not observed; review baseline: `{key[0]}: {key[1]}`")
    if errors:
        for error in errors:
            print(f"- ERROR: {error}")
        raise ValueError("unexplained mutation outcomes; review the audit summary and diffs")


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
    if mode == "full":
        print("\nReviewed mutation baseline:\n")
        check_reviewed(mutants, root)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("full", "property"):
        sys.exit("usage: check-mutation-outcomes.py [full|property] OUTPUT_DIRECTORY")
    try:
        check(*sys.argv[1:])
    except (ValueError, KeyError, OSError) as error:
        sys.exit(f"Invalid mutation evidence: {error}")
