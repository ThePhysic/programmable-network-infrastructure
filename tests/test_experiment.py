import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from netlab.cli import operation_lock
from netlab.experiment import file_manifest, run_experiment, scenario_checks, validate_workload


class RecordingLab:
    """Orchestration test double; real datapath checks live in scripts/integration.py."""
    def __init__(self, root, fail_probe=False, cleanup_clean=True):
        self.root = root
        self.fail_probe = fail_probe
        self.cleanup_clean = cleanup_clean
        self.stopped = False
        self.faulted = False

    def status(self):
        return {"active": False}

    def doctor(self):
        return {"ready": True}

    def up(self):
        return {"nodes": ["test"]}

    def down(self):
        self.stopped = True
        return {"clean": self.cleanup_clean, "namespaces_remaining": [], "errors": [], "ownership_conflicts": []}

    def apply_fault(self, kind):
        self.faulted = True
        return {"kind": kind}

    def restore_fault(self):
        self.faulted = False
        return {"restored": True}

    def probe(self, output, **kwargs):
        if self.fail_probe:
            raise RuntimeError("deliberate probe failure")
        value = {"attempts": 2, "successes": 0 if self.faulted else 2,
                 "errors": {"timeout": 2} if self.faulted else {}, "bytes": 0 if self.faulted else 512,
                 "duration_seconds": 1.0, "latency_ms": {"p50": 1.0, "p95": 1.0, "p99": 1.0},
                 "samples": [{"elapsed_seconds": .1, "success": not self.faulted}]}
        output.write_text(json.dumps(value))
        return value

    def snapshot(self, destination):
        destination.mkdir()
        state = {"backend_route_present": not self.faulted, "bgp_backend_prefix_present": not self.faulted,
                 "bgp_peers_established": True, "backend_listener_present": True, "dns_ok": True,
                 "primary_link_up": True, "netem_active": False, "firewall_drop_active": False,
                 "firewall_drop_packets": 0, "backend_route_nexthop": "10.77.12.2"}
        value = {"observations": state, "evidence": {key: ["snapshot.json"] for key in state}, "artifacts": ["snapshot.json"]}
        (destination / "snapshot.json").write_text(json.dumps(value))
        return value


class ExperimentTests(unittest.TestCase):
    def test_invalid_workload_rejected(self):
        for duration, concurrency, payload, rate in [(float("nan"), 1, 1, 1), (1, 0, 1, 1), (1, 1, 0, 1), (1, 1, 1, float("inf"))]:
            with self.assertRaises(ValueError):
                validate_workload(duration, concurrency, payload, rate)

    def test_fault_label_alone_cannot_pass_acceptance(self):
        experiment = {"scenario": "route-withdrawal", "phases": {"fault": {"probe": {"attempts": 10, "successes": 0}}}}
        self.assertFalse(scenario_checks(experiment)["verified"])

    def test_cleanup_and_failure_evidence_retained_when_probe_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            lab = RecordingLab(base / "runtime", fail_probe=True)
            with self.assertRaises(RuntimeError):
                run_experiment(lab, "route-withdrawal", base / "experiment")
            self.assertTrue(lab.stopped)
            record = json.loads((base / "experiment" / "experiment.json").read_text())
            self.assertEqual(record["failure"]["message"], "deliberate probe failure")
            self.assertFalse(record["result"]["passed"])
            self.assertTrue((base / "experiment" / "manifest.json").is_file())

    def test_full_orchestration_tracks_observed_fault_and_recovery(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            lab = RecordingLab(base / "runtime")
            result = run_experiment(lab, "route-withdrawal", base / "experiment")
            self.assertTrue(result["result"]["passed"])
            self.assertTrue(lab.stopped)
            manifest = json.loads((base / "experiment" / "manifest.json").read_text())
            self.assertEqual(manifest["files"], file_manifest(base / "experiment"))
            for measurement in result["measurements"].values():
                for reference in measurement["evidence"]:
                    self.assertTrue((base / "experiment" / reference).is_file(), reference)

    def test_cleanup_failure_cannot_be_reported_as_success(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            result = run_experiment(RecordingLab(base / "runtime", cleanup_clean=False), "route-withdrawal", base / "experiment")
            self.assertFalse(result["result"]["passed"])

    def test_existing_evidence_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            with self.assertRaises(ValueError):
                run_experiment(RecordingLab(base / "runtime"), "route-withdrawal", base)

    @unittest.skipUnless(os.name == "posix", "Linux file lock semantics")
    def test_operation_lock_leaves_new_runtime_empty_for_ownership_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "runtime"
            with operation_lock(root):
                self.assertEqual(list(root.iterdir()), [])
                with self.assertRaises(RuntimeError):
                    with operation_lock(root):
                        self.fail("second lock acquired")

    def test_evidence_changes_are_detectable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "probe.json").write_text("baseline")
            before = file_manifest(root)
            (root / "probe.json").write_text("modified")
            self.assertNotEqual(before, file_manifest(root))
