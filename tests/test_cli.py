from contextlib import nullcontext
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from netlab.cli import main


class CLITests(unittest.TestCase):
    def run_down(self, result):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "runtime"
            with patch("netlab.linux.Lab") as factory, patch("netlab.cli.operation_lock", return_value=nullcontext()), patch("netlab.cli.sys.platform", "linux"), patch("sys.stdout", new_callable=io.StringIO):
                factory.return_value.root = root
                factory.return_value.down.return_value = result
                return main(["--root", str(root), "down"])

    def test_failed_cleanup_is_a_failed_cli_command(self):
        self.assertEqual(self.run_down({"clean": False, "ownership_conflicts": ["changed-namespace"]}), 1)

    def test_successful_cleanup_has_success_exit_code(self):
        self.assertEqual(self.run_down({"clean": True, "namespaces_remaining": []}), 0)

    def test_missing_cleanup_verdict_is_not_success(self):
        self.assertEqual(self.run_down({"namespaces_remaining": []}), 1)
