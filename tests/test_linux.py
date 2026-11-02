import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from netlab.linux import FAULTS, LINKS, Lab, NODES, _bgp_peers, _cmd, _read_json


class LabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "runtime"
        self.lab = Lab(self.root, Path(self.temp.name) / "agent")

    def marker(self, **extra):
        self.root.mkdir(mode=0o700, exist_ok=True)
        value = {"owner": "pnid-v1", "root": str(self.root), "prefix": self.lab.prefix,
                 "namespaces": {}, "processes": {}, "fault": None}
        value.update(extra)
        (self.root / "owner.json").write_text(json.dumps(value))
        return value

    def test_namespace_identity_is_stable_and_root_scoped(self):
        self.assertEqual(self.lab.prefix, Lab(self.root, Path("/other-binary")).prefix)
        self.assertNotEqual(self.lab.prefix, Lab(self.root.parent / "other", Path("/agent")).prefix)
        self.assertEqual(set(self.lab.namespaces), set(NODES))

    def test_topology_has_real_alternate_path(self):
        adjacency = {node: set() for node in NODES}
        for left, _, _, right, _, _ in LINKS:
            adjacency[left].add(right)
            adjacency[right].add(left)
        self.assertIn("r2", adjacency["r1"])
        self.assertIn("r3", adjacency["r1"])
        self.assertIn("r2", adjacency["r3"])
        self.assertEqual(len(LINKS), 6)

    def test_unowned_status_and_down_do_not_execute_commands(self):
        with patch("netlab.linux._cmd") as command:
            self.assertFalse(self.lab.status()["active"])
            self.assertTrue(self.lab.down()["clean"])
            command.assert_not_called()

    def test_marker_for_different_root_is_rejected(self):
        self.marker(root="/unrelated")
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            self.lab._state()

    def test_unknown_fault_does_not_touch_namespace(self):
        with patch("netlab.linux._cmd") as command, self.assertRaises(ValueError):
            self.lab.apply_fault("host-firewall")
        command.assert_not_called()

    def test_namespace_replacement_is_never_owned(self):
        state = self.marker(namespaces={"r1": 123})
        with patch.object(self.lab, "_inode", return_value=456):
            self.assertFalse(self.lab._owned("r1", state))
        with patch.object(self.lab, "_inode", return_value=123):
            self.assertTrue(self.lab._owned("r1", state))

    def test_ns_command_refuses_changed_ownership(self):
        self.marker(namespaces={"r1": 123})
        with patch.object(self.lab, "_inode", return_value=456), patch("netlab.linux._cmd") as command:
            with self.assertRaisesRegex(RuntimeError, "ownership changed"):
                self.lab._ns("r1", "ip", "route", "show")
            command.assert_not_called()

    @unittest.skipUnless(hasattr(os, "geteuid"), "Linux ownership semantics")
    def test_nonempty_unowned_root_is_refused(self):
        self.root.mkdir(mode=0o700)
        (self.root / "unrelated.txt").write_text("preserve")
        with self.assertRaisesRegex(RuntimeError, "nonempty"):
            self.lab._prepare_root()
        self.assertEqual((self.root / "unrelated.txt").read_text(), "preserve")

    @unittest.skipUnless(hasattr(os, "geteuid"), "Linux ownership semantics")
    def test_public_runtime_root_is_refused(self):
        self.root.mkdir(mode=0o755)
        self.root.chmod(0o755)
        with self.assertRaisesRegex(RuntimeError, "private"):
            self.lab._prepare_root()

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support")
    def test_symlink_root_is_rejected(self):
        target = Path(self.temp.name) / "target"
        target.mkdir()
        try:
            self.root.symlink_to(target, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaisesRegex(ValueError, "symlinks"):
            Lab(self.root, Path("/agent"))

    def test_probe_bounds_fail_before_spawning(self):
        for parameters in ({"duration": 0}, {"concurrency": 257}, {"payload": 1048577},
                           {"rate": -1}, {"target": "internet"}, {"hold": 6}):
            with self.subTest(parameters=parameters), patch("netlab.linux._cmd") as command:
                with self.assertRaises(ValueError):
                    self.lab.probe(self.root / "result.json", **parameters)
                command.assert_not_called()

    def test_command_error_preserves_diagnostic(self):
        result = subprocess.CompletedProcess(["ip"], 2, "", "permission denied")
        with patch("netlab.linux.subprocess.run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "permission denied"):
                _cmd(["ip", "netns", "list"])

    def test_json_parse_failure_remains_unknown(self):
        self.assertIsNone(_read_json("not json"))

    def test_bgp_peer_schema_supports_frr_address_family_and_summary_views(self):
        peers = {"10.77.12.2": {"state": "Established"}}
        self.assertEqual(_bgp_peers({"peers": peers}), peers)
        self.assertEqual(_bgp_peers({"ipv4Unicast": {"peers": peers}}), peers)
        self.assertIsNone(_bgp_peers({"warning": "daemon unavailable"}))


if __name__ == "__main__":
    unittest.main()
