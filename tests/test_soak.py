import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.soak import assess_round, resource_checks, run_soak, validate_config


def metrics(**overrides):
    result = {"active_connections": 0, "max_connections": 16, "file_descriptors": 10,
              "goroutines": 5, "rss_bytes": 1000000, "cpu_user_seconds": 0.1,
              "cpu_system_seconds": 0.1, "cpu_total_seconds": 0.2, "accepted": 0, "rejected": 0}
    result.update(overrides)
    return result


class SoakTests(unittest.TestCase):
    def test_effective_soak_has_multiple_rounds_and_bounded_runtime(self):
        validate_config(10, 1)
        for rounds, duration in ((4, 1), (61, 1), (5, 0.1), (5, float("nan")), (True, 1)):
            with self.assertRaises(ValueError):
                validate_config(rounds, duration)

    def test_ordinary_round_requires_every_echo_and_real_samples(self):
        before, after = metrics(), metrics()
        samples = [{"metrics": metrics(active_connections=8)}]
        good = {"attempts": 10, "successes": 10, "errors": {}}
        self.assertTrue(all(assess_round(good, before, after, samples, False).values()))
        failed = {"attempts": 10, "successes": 9, "errors": {"timeout": 1}}
        self.assertFalse(all(assess_round(failed, before, after, samples, False).values()))
        self.assertFalse(all(assess_round(good, before, after, [], False).values()))

    def test_overload_requires_rejections_and_never_accepts_corruption(self):
        before, after = metrics(), metrics(rejected=20)
        samples = [{"metrics": metrics(active_connections=16)}]
        probe = {"attempts": 30, "successes": 10, "errors": {"eof": 20}}
        self.assertTrue(all(assess_round(probe, before, after, samples, True).values()))
        probe["errors"]["integrity"] = 1
        self.assertFalse(assess_round(probe, before, after, samples, True)["no_payload_corruption"])
        probe["errors"].pop("integrity")
        self.assertFalse(assess_round(probe, before, before, samples, True)["limit_rejections_observed"])
        samples[0]["metrics"]["active_connections"] = 17
        self.assertFalse(assess_round(probe, before, after, samples, True)["sampled_active_bounded"])

    def test_resource_growth_is_checked_without_constant_memory_claim(self):
        baseline = metrics()
        self.assertTrue(all(resource_checks(baseline, metrics(file_descriptors=14, goroutines=11, rss_bytes=9000000)).values()))
        self.assertFalse(resource_checks(baseline, metrics(file_descriptors=15))["descriptors_near_baseline"])
        self.assertFalse(resource_checks(baseline, metrics(goroutines=12))["goroutines_near_baseline"])
        self.assertFalse(resource_checks(baseline, metrics(active_connections=1))["active_connections_zero"])

    def test_failed_workload_still_cleans_and_preserves_failure_manifest(self):
        class BrokenLab:
            experiment_id = ""
            def __init__(self, root):
                self.root, self.cleaned = root, False
            def status(self):
                return {"active": False}
            def up(self):
                return {"nodes": 6}
            def doctor(self):
                return {"linux": True}
            def probe(self, *args, **kwargs):
                raise RuntimeError("intentional probe failure")
            def down(self):
                self.cleaned = True
                return {"clean": True}

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            lab = BrokenLab(base / "runtime")
            with patch("scripts.soak.source_metadata", return_value={"test": True}):
                report = run_soak(lab, base / "output", rounds=5)
            self.assertTrue(lab.cleaned)
            self.assertFalse(report["passed"])
            self.assertIn("intentional probe failure", report["errors"])
            manifest = json.loads((base / "output/manifest.json").read_text())
            self.assertIn("soak.json", manifest["files"])

    def test_active_lab_is_refused_without_teardown(self):
        class ActiveLab:
            def status(self):
                return {"active": True}
            def down(self):
                raise AssertionError("must preserve an already active lab")
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(RuntimeError, "inactive"):
            run_soak(ActiveLab(), Path(temporary) / "output", rounds=5)


if __name__ == "__main__":
    unittest.main()
