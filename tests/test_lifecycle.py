import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.lifecycle import Acceptance, delete_test_namespace


class LifecycleHarnessTests(unittest.TestCase):
    def test_collision_fixture_refuses_to_remove_replacement_namespace(self):
        with patch("scripts.lifecycle.namespace_inode", return_value=222), \
                patch("scripts.lifecycle.checked") as command:
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                delete_test_namespace("pnid-fixture-r1", 111)
        command.assert_not_called()

    def test_missing_collision_fixture_needs_no_deletion(self):
        with patch("scripts.lifecycle.namespace_inode", return_value=None), \
                patch("scripts.lifecycle.checked") as command:
            delete_test_namespace("pnid-fixture-r1", 111)
        command.assert_not_called()

    def test_a_failed_acceptance_case_is_retained_and_does_not_hide_later_results(self):
        with tempfile.TemporaryDirectory() as directory:
            location = Path(directory)
            acceptance = Acceptance(location / "runtime", location, location / "binary")

            def failure():
                raise AssertionError("actual residue found")

            acceptance.run_case("failure", failure)
            acceptance.run_case("success", lambda: {"clean": True})
            summary = json.loads((location / "summary.json").read_text())
            self.assertFalse(summary["passed"])
            self.assertEqual([row["passed"] for row in summary["cases"]], [False, True])
            self.assertIn("actual residue found", summary["cases"][0]["error"])


if __name__ == "__main__":
    unittest.main()
