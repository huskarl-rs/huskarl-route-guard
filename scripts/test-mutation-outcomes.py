"""Regression tests for the mutation CI gate; no Rust compilation required."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "checker", Path(__file__).with_name("check-mutation-outcomes.py")
)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class MutationGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.root = self.directory / "mutants.out"
        self.root.mkdir()
        self.outcomes = [{
            "scenario": "Baseline", "summary": "Success",
            "phase_results": [{"phase": "Test", "process_status": "Success"}],
        }]
        for index, entry in enumerate(json.loads(checker.REVIEWED.read_text())):
            diff_path = f"{index}.diff"
            (self.root / diff_path).write_text(
                "--- old\n+++ new\n@@ -1,2 +1,2 @@\n" + "\n".join(entry["changes"])
            )
            self.outcomes.append({
                "scenario": {"Mutant": {
                    "name": f"{entry['file']}:900:42: {entry['mutation']}",
                    "file": entry["file"],
                }},
                "summary": entry["outcome"], "diff_path": diff_path,
                "phase_results": [
                    {"phase": "Build", "process_status": "Success"},
                    {"phase": "Test", "process_status": "Timeout" if entry["outcome"] == "Timeout" else "Success"},
                ],
            })

    def run_gate(self, complete=True, inventory=None):
        mutants = self.outcomes[1:]
        results = {
            "end_time": "finished" if complete else None, "outcomes": self.outcomes,
            **{key: sum(o["summary"] == summary for o in mutants) for key, summary in [
                ("caught", "CaughtMutant"), ("missed", "MissedMutant"),
                ("unviable", "Unviable"), ("timeout", "Timeout"),
            ]},
        }
        (self.root / "outcomes.json").write_text(json.dumps(results))
        (self.root / "mutants.json").write_text(json.dumps(
            inventory if inventory is not None else [o["scenario"]["Mutant"] for o in mutants]
        ))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            checker.check("full", self.directory)
        return output.getvalue()

    def test_reviewed_results_pass_after_line_numbers_move(self):
        self.assertIn("Reviewed Timeout", self.run_gate())

    def test_new_survivor_fails_even_with_identical_totals(self):
        self.outcomes[1]["scenario"]["Mutant"]["name"] += "_different_function"
        with self.assertRaisesRegex(ValueError, "unexplained"):
            self.run_gate()

    def test_same_description_at_different_source_site_fails(self):
        diff = self.root / self.outcomes[2]["diff_path"]
        diff.write_text(diff.read_text().replace("path.len()", "other.len()"))
        with self.assertRaisesRegex(ValueError, "unexplained"):
            self.run_gate()

    def test_survivor_becoming_timeout_fails(self):
        self.outcomes[1]["summary"] = "Timeout"
        self.outcomes[1]["phase_results"][1]["process_status"] = "Timeout"
        with self.assertRaisesRegex(ValueError, "unexplained"):
            self.run_gate()

    def test_expected_hang_cannot_hide_a_build_timeout(self):
        self.outcomes[-1]["phase_results"] = [{"phase": "Build", "process_status": "Timeout"}]
        with self.assertRaisesRegex(ValueError, "unexplained"):
            self.run_gate()

    def test_expected_timeout_becoming_survivor_fails(self):
        self.outcomes[-1]["summary"] = "MissedMutant"
        self.outcomes[-1]["phase_results"][1]["process_status"] = "Success"
        with self.assertRaisesRegex(ValueError, "unexplained"):
            self.run_gate()

    def test_improvement_is_reported_and_passes(self):
        self.outcomes[1]["summary"] = "CaughtMutant"
        self.assertIn("Now caught", self.run_gate())

    def test_unviable_and_removed_entries_are_reported(self):
        self.outcomes[1]["summary"] = "Unviable"
        self.outcomes.pop()
        output = self.run_gate()
        self.assertIn("Now unviable", output)
        self.assertIn("Not observed", output)

    def test_ambiguous_identity_fails(self):
        duplicate = json.loads(json.dumps(self.outcomes[1]))
        duplicate["scenario"]["Mutant"]["name"] = duplicate["scenario"]["Mutant"]["name"].replace(":900:", ":901:")
        self.outcomes.append(duplicate)
        with self.assertRaisesRegex(ValueError, "unexplained"):
            self.run_gate()

    def test_incomplete_run_fails(self):
        with self.assertRaisesRegex(ValueError, "did not complete"):
            self.run_gate(complete=False)

    def test_missing_outcome_fails(self):
        inventory = [o["scenario"]["Mutant"] for o in self.outcomes[1:]]
        self.outcomes.pop()
        with self.assertRaisesRegex(ValueError, "complete nonempty inventory"):
            self.run_gate(inventory=inventory)


if __name__ == "__main__":
    unittest.main()
