#!/usr/bin/env python3
"""Check real runner wiring and cleanup without a Docker daemon."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

# Fake only the external commands. Execute the real Bash runner and registry.
COMMAND = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
log = pathlib.Path(os.environ["COMMAND_LOG"])
previous = log.read_text().splitlines() if log.exists() else []
with log.open("a") as f:
    f.write(json.dumps([pathlib.Path(sys.argv[0]).name, *args]) + "\n")
if pathlib.Path(sys.argv[0]).name == "cargo":
    sys.exit(int(os.environ.get("CARGO_RESULT", "0")))
if args[0] == "build":
    if args[-1].endswith("/" + os.environ.get("FAIL_BUILD", "-")):
        sys.exit(19)
    pathlib.Path(args[args.index("--iidfile") + 1]).write_text("image:" + args[-1].split("/")[-1])
elif args[:2] == ["network", "create"]:
    print("fixture-network")
elif args[0] == "run":
    print("container-" + str(sum(json.loads(line)[:2] == ["docker", "run"] for line in previous)))
elif args[0] == "port":
    print("127.0.0.1:12345")
elif args[0] == "logs":
    print("logs for " + args[1])
'''


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ["scripts", "tests/downstream", "bin"]:
            (self.root / name).mkdir(parents=True)
        for name in ["scripts/test-downstream.sh", "tests/downstream/topologies.tsv"]:
            shutil.copyfile(ROOT / name, self.root / name)
        for name in ["docker", "cargo"]:
            executable = self.root / "bin" / name
            executable.write_text(COMMAND)
            executable.chmod(0o755)
        self.log = self.root / "commands.jsonl"

    def run_fixture(self, *deployments, failure=0, build_failure="-"):
        env = {k: v for k, v in os.environ.items() if not k.startswith("ROUTE_GUARD_DOWNSTREAM_")}
        env.update(PATH=str(self.root / "bin") + os.pathsep + env["PATH"],
                   COMMAND_LOG=str(self.log), CARGO_RESULT=str(failure), FAIL_BUILD=build_failure)
        result = subprocess.run(["bash", str(self.root / "scripts/test-downstream.sh"), *deployments],
                                env=env, capture_output=True, text=True)
        self.commands = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        return result

    def test_order_ports_and_logs_for_mixed_chain(self):
        result = self.run_fixture("apache-proxy-nginx-express")
        self.assertEqual(result.returncode, 0, result.stderr)
        runs = [c for c in self.commands if c[:2] == ["docker", "run"]]
        self.assertEqual([c[-1] for c in runs], ["image:express", "image:nginx", "image:apache-proxy"])
        self.assertNotIn("--publish", runs[0])
        self.assertNotIn("--publish", runs[1])
        self.assertIn("127.0.0.1::8080", runs[2])
        self.assertIn("UPSTREAM=origin", runs[1])
        self.assertIn("UPSTREAM=hop-1", runs[2])
        self.assertIn("FORWARD_TARGET=$uri$is_args$args", runs[1])
        logs = list((self.root / "target/downstream").glob("apache-proxy-nginx-express-Mixed*.log"))
        self.assertEqual(len(logs), 3)
        removed = [c[-1] for c in self.commands if c[:3] == ["docker", "rm", "-f"]]
        self.assertEqual(removed, ["container-2", "container-1", "container-0"])
        self.assertEqual(self.commands[-1], ["docker", "network", "rm", "fixture-network"])

    def test_failure_keeps_status_and_cleans_every_hop(self):
        result = self.run_fixture("nginx-raw-nginx-apache", failure=17)
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertEqual(sum(c[:3] == ["docker", "rm", "-f"] for c in self.commands), 3)
        self.assertEqual(sum(c[:2] == ["docker", "logs"] for c in self.commands), 3)
        self.assertEqual(self.commands[-1], ["docker", "network", "rm", "fixture-network"])
        runs = [c for c in self.commands if c[:2] == ["docker", "run"]]
        self.assertIn("FORWARD_TARGET=$request_uri", runs[-1])

    def test_direct_profiles_and_build_reuse(self):
        result = self.run_fixture("apache")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sum(c[:2] == ["docker", "build"] for c in self.commands), 1)
        runs = [c for c in self.commands if c[:2] == ["docker", "run"]]
        self.assertEqual(len(runs), 3)
        for run, profile in zip(runs, ["Off", "On", "NoDecode"]):
            self.assertIn("APACHE_ENCODED_SLASHES=" + profile, run)
            self.assertIn("--publish", run)
            self.assertNotIn("--network", run)

    def test_partial_startup_failure_cleans_origin_and_network(self):
        result = self.run_fixture("nginx-nginx-express", build_failure="nginx")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(c[0] == "cargo" for c in self.commands))
        self.assertIn(["docker", "logs", "container-0"], self.commands)
        self.assertIn(["docker", "rm", "-f", "container-0"], self.commands)
        self.assertEqual(self.commands[-1], ["docker", "network", "rm", "fixture-network"])

    def test_default_runs_all_registered_profiles(self):
        result = self.run_fixture()
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = [line for line in (self.root / "tests/downstream/topologies.tsv").read_text().splitlines()
                if line and not line.startswith("#")]
        self.assertEqual(sum(c[0] == "cargo" for c in self.commands), len(rows))
        self.assertEqual(len(list((self.root / "target/downstream").glob("*-topology.txt"))), len(rows))

    def test_unknown_selection_fails_before_docker(self):
        result = self.run_fixture("express", "unknown")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.commands, [])


if __name__ == "__main__":
    unittest.main()
