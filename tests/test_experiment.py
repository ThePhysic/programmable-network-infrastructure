import copy
import errno
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from netlab.cli import operation_lock
from netlab.experiment import file_manifest, run_experiment, scenario_checks, validate_workload, write_json


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
                 "backend_prefix_denied": False, "backend_prefix_policy_present": False,
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

    def test_missing_fault_metrics_remain_unverified_without_crashing(self):
        for scenario in ("gateway-overload", "packet-loss", "dns-failure", "link-loss"):
            experiment = {"scenario": scenario, "phases": {"baseline": {"snapshot": {"observations": {"gateway_metrics": None}}},
                          "fault": {"probe": {"attempts": None, "successes": None}, "snapshot": {"observations": {"gateway_metrics": None}}}}}
            self.assertFalse(scenario_checks(experiment)["verified"])
        self.assertFalse(scenario_checks({"phases": None})["verified"])

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

    def test_persistent_event_write_failure_after_startup_cannot_skip_teardown(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            lab = RecordingLab(base / "runtime")
            def writer(path, value):
                if path.name == "events.json" and any(event["type"] == "baseline-started" for event in value):
                    raise OSError(errno.ENOSPC, "fixture storage exhausted")
                write_json(path, value)
            with patch("netlab.experiment.write_json", side_effect=writer), patch.object(lab, "down", wraps=lab.down) as down:
                with self.assertRaises(RuntimeError) as stopped:
                    run_experiment(lab, "route-withdrawal", base / "experiment")
            down.assert_called_once()
            self.assertIsInstance(stopped.exception.__cause__, OSError)
            record = json.loads((base / "experiment/experiment.json").read_text())
            self.assertTrue(record["cleanup"]["clean"])
            self.assertFalse(record["result"]["passed"])
            self.assertEqual(record["failure"]["type"], "OSError")
            self.assertIn("cleanup-started", {error["stage"] for error in record["evidence_errors"]})
            self.assertEqual(json.loads((base / "experiment/manifest.json").read_text())["files"],
                             file_manifest(base / "experiment"))

    def test_failed_cleanup_event_cannot_override_a_primary_probe_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            lab = RecordingLab(base / "runtime", fail_probe=True)
            def writer(path, value):
                if path.name == "events.json" and any(event["type"] == "experiment-failed" for event in value):
                    raise PermissionError("fixture output became read-only")
                write_json(path, value)
            with patch("netlab.experiment.write_json", side_effect=writer):
                with self.assertRaises(RuntimeError) as stopped:
                    run_experiment(lab, "route-withdrawal", base / "experiment")
            self.assertTrue(lab.stopped)
            self.assertEqual(str(stopped.exception.__cause__), "deliberate probe failure")
            record = json.loads((base / "experiment/experiment.json").read_text())
            self.assertEqual(record["failure"]["message"], "deliberate probe failure")
            self.assertFalse(record["result"]["passed"])

    def test_permanent_storage_failure_still_runs_teardown_once(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            lab = RecordingLab(base / "runtime")
            storage_failed = False
            def writer(path, value):
                nonlocal storage_failed
                if path.name == "events.json" and any(event["type"] == "startup-finished" for event in value):
                    storage_failed = True
                if storage_failed:
                    raise OSError(errno.ENOSPC, "fixture permanent storage failure")
                write_json(path, value)
            with patch("netlab.experiment.write_json", side_effect=writer), patch.object(lab, "down", wraps=lab.down) as down:
                with self.assertRaises(RuntimeError) as stopped:
                    run_experiment(lab, "route-withdrawal", base / "experiment")
            down.assert_called_once()
            self.assertTrue(lab.stopped)
            self.assertEqual(stopped.exception.__cause__.errno, errno.ENOSPC)

    def test_storage_failure_does_not_swallow_an_interruption(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            lab = RecordingLab(base / "runtime")
            def writer(path, value):
                if path.name == "events.json" and any(event["type"] == "experiment-failed" for event in value):
                    raise OSError(errno.ENOSPC, "fixture storage exhausted during interruption")
                write_json(path, value)
            with patch.object(lab, "probe", side_effect=KeyboardInterrupt), patch("netlab.experiment.write_json", side_effect=writer):
                with self.assertRaises(KeyboardInterrupt):
                    run_experiment(lab, "route-withdrawal", base / "experiment")
            self.assertTrue(lab.stopped)

    def test_transient_final_report_failure_cannot_leave_a_passing_record(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            lab = RecordingLab(base / "runtime")
            original_write = Path.write_text
            failed = False
            def writer(path, *args, **kwargs):
                nonlocal failed
                if path.name == "report.md" and not failed:
                    failed = True
                    raise OSError(errno.ENOSPC, "fixture transient final write failure")
                return original_write(path, *args, **kwargs)
            with patch.object(Path, "write_text", new=writer):
                with self.assertRaises(RuntimeError):
                    run_experiment(lab, "route-withdrawal", base / "experiment")
            self.assertTrue(lab.stopped)
            record = json.loads((base / "experiment/experiment.json").read_text())
            self.assertEqual(record["failure"]["type"], "OSError")
            self.assertFalse(record["result"]["passed"])
            self.assertIn("Experiment acceptance: **failed**", (base / "experiment/report.md").read_text())
            self.assertEqual(json.loads((base / "experiment/manifest.json").read_text())["files"],
                             file_manifest(base / "experiment"))

    def test_artifact_copy_failure_preserves_actual_teardown_result(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            lab = RecordingLab(base / "runtime")
            (lab.root / "logs").mkdir(parents=True)
            with patch("netlab.experiment.shutil.copytree", side_effect=OSError("fixture artifact copy failed")):
                with self.assertRaises(RuntimeError):
                    run_experiment(lab, "route-withdrawal", base / "experiment")
            self.assertTrue(lab.stopped)
            record = json.loads((base / "experiment/experiment.json").read_text())
            self.assertTrue(record["cleanup"]["clean"])
            self.assertFalse(record["result"]["passed"])
            self.assertEqual(record["evidence_errors"][0]["stage"], "final-artifacts")

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

    def test_contradictory_cleanup_record_cannot_override_analysis(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            lab = RecordingLab(base / "runtime")
            with patch.object(lab, "down", return_value={"clean": True, "namespaces_remaining": [], "processes_remaining": [123]}):
                result = run_experiment(lab, "route-withdrawal", base / "experiment")
            self.assertFalse(result["result"]["passed"])
            self.assertFalse(result["result"]["cleanup_verified"])

    def test_existing_evidence_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            with self.assertRaises(ValueError):
                run_experiment(RecordingLab(base / "runtime"), "route-withdrawal", base)

    def test_startup_refusal_does_not_stop_a_racing_existing_lab(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            lab = RecordingLab(base / "runtime")
            with patch.object(lab, "up", side_effect=RuntimeError("namespace collision")):
                with self.assertRaises(RuntimeError):
                    run_experiment(lab, "route-withdrawal", base / "experiment")
            self.assertFalse(lab.stopped)

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

    def test_added_nested_manifests_and_temporary_files_are_not_ignored(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            before = file_manifest(root)
            (root / "nested").mkdir()
            (root / "nested" / "manifest.json").write_text("additional file")
            (root / "unrelated.tmp").write_text("additional file")
            self.assertNotEqual(before, file_manifest(root))
            self.assertIn("nested/manifest.json", file_manifest(root))
            self.assertIn("unrelated.tmp", file_manifest(root))
