import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest

from scripts.summarize import aggregate, discover, distribution, main, markdown


def sample(identity="one", concurrency=2):
    observations = {"backend_route_present": True, "bgp_backend_prefix_present": True,
                    "bgp_peers_established": True, "backend_listener_present": True,
                    "dns_ok": True, "primary_link_up": True, "netem_active": False,
                    "firewall_drop_active": False, "firewall_drop_packets": 0,
                    "backend_prefix_denied": False, "backend_prefix_policy_present": False,
                    "backend_route_nexthop": "10.77.12.2"}
    workload = {"duration_seconds": 2, "concurrency": concurrency,
                "payload_bytes": 256, "rate_per_second": 20}
    result = {"schema_version": 1, "experiment_id": identity, "scenario": "route-withdrawal",
              "cleanup": {"clean": True, "namespaces_remaining": []},
              "environment": {"kernel": "test-linux", "logical_cpus": 4},
              "source": {"files_sha256": {"netlab/linux.py": "abcdef"}},
              "topology": {"id": "six-node-bgp-diamond", "namespace_prefix": "pnid-test"},
              "workload": workload, "phases": {}, "result": {"passed": False}}
    for name in ("baseline", "fault", "recovery"):
        result["phases"][name] = {
            "probe": {"attempts": 100, "successes": 100, "errors": {}, "duration_seconds": 2,
                      "latency_ms": {"p50": 1, "p95": 2, "p99": 4}, "bytes": 25600},
            "effective_workload": copy.deepcopy(workload), "probe_artifact": name + "/probe.json",
            "snapshot": {"artifact_base": name + "/snapshot", "observations": copy.deepcopy(observations),
                         "evidence": {key: [key + ".json"] for key in observations}}}
    result["phases"]["fault"]["snapshot"]["observations"].update(
        backend_route_present=False, bgp_backend_prefix_present=False)
    result["phases"]["fault"]["probe"].update(successes=0, errors={"timeout": 100}, bytes=0)
    return result


class SummaryTests(unittest.TestCase):
    def write(self, root, name, value):
        folder = Path(root) / name
        folder.mkdir()
        path = folder / "experiment.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_statistics_do_not_pool_percentiles_or_nonfinite_values(self):
        self.assertEqual(distribution([1, 10, 100, None, float("nan"), True]),
                         {"count": 3, "median": 10, "min": 1, "max": 100})

    def test_discovers_recursively_and_deduplicates_paths(self):
        with tempfile.TemporaryDirectory() as root:
            path = self.write(root, "one", sample())
            self.assertEqual(discover([root, str(path), str(Path(root) / "**" / "experiment.json")]), [path.resolve()])

    def test_repeated_same_context_aggregates_each_phase(self):
        with tempfile.TemporaryDirectory() as root:
            first = self.write(root, "one", sample())
            second_record = sample("two")
            second_record["phases"]["baseline"]["probe"]["latency_ms"]["p99"] = 8
            second = self.write(root, "two", second_record)
            summary = aggregate([first, second])
            scenario = summary["scenarios"]["route-withdrawal"]
            self.assertEqual(scenario["trial_count"], 2)
            self.assertEqual(scenario["comparability"], "comparable")
            self.assertEqual(scenario["groups"][0]["phases"]["baseline"]["latency_ms"]["p99"]["median"], 6)
            self.assertEqual(scenario["groups"][0]["phases"]["fault"]["latency_ms"]["p99"]["count"], 0)
            self.assertEqual(scenario["passed"], 2)  # Stored false claims are recomputed.

    def test_different_workloads_are_not_pooled(self):
        with tempfile.TemporaryDirectory() as root:
            paths = [self.write(root, "one", sample()), self.write(root, "two", sample("two", concurrency=4))]
            scenario = aggregate(paths)["scenarios"]["route-withdrawal"]
            self.assertEqual(scenario["comparability"], "mixed")
            self.assertEqual(len(scenario["groups"]), 2)

    def test_missing_context_is_disclosed(self):
        with tempfile.TemporaryDirectory() as root:
            record = sample()
            del record["source"]
            scenario = aggregate([self.write(root, "one", record)])["scenarios"]["route-withdrawal"]
            self.assertEqual(scenario["comparability"], "incomplete")

    def test_duplicate_id_not_counted_as_independent_trial(self):
        with tempfile.TemporaryDirectory() as root:
            paths = [self.write(root, name, sample()) for name in ("one", "two")]
            summary = aggregate(paths)
            self.assertEqual(summary["trial_count"], 1)
            self.assertIn("Duplicate experiment_id", summary["invalid_trials"][0]["error"])

    def test_malformed_records_are_reported(self):
        with tempfile.TemporaryDirectory() as root:
            path = self.write(root, "bad", {})
            summary = aggregate([path])
            self.assertEqual(summary["trial_count"], 0)
            self.assertEqual(len(summary["invalid_trials"]), 1)

    def test_no_snapshot_derived_convergence_clock(self):
        with tempfile.TemporaryDirectory() as root:
            group = aggregate([self.write(root, "one", sample())])["scenarios"]["route-withdrawal"]["groups"][0]
            self.assertEqual(group["timings_seconds"]["route_convergence_seconds"]["count"], 0)

    def test_cli_stdout_does_not_create_files_and_output_is_explicit(self):
        with tempfile.TemporaryDirectory() as root:
            self.write(root, "one", sample())
            before = set(Path(root).rglob("*"))
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                self.assertEqual(main([root]), 0)
            self.assertEqual(before, set(Path(root).rglob("*")))
            self.assertIn("Valid trials: **1**", buffer.getvalue())
            output = Path(root) / "summary.json"
            self.assertEqual(main([root, "--format", "json", "--output", str(output)]), 0)
            self.assertEqual(json.loads(output.read_text())["trial_count"], 1)

    def test_markdown_documents_scope_and_workload_caveats(self):
        text = markdown({"trial_count": 0, "invalid_trials": [], "scenarios": {},
                         "method": {"aggregation": "median", "latency": "success-only",
                                    "comparability": "groups", "timing": "sampled bounds", "limitations": ["VM limitation"]}})
        self.assertIn("sampled bounds", text)
        self.assertIn("VM limitation", text)


if __name__ == "__main__":
    unittest.main()
