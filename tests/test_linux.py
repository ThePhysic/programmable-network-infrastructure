import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from netlab.linux import FAULTS, LINKS, Lab, NODES, _bgp_peers, _cmd, _policy_observation, _read_json


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

    def test_cleanup_preserves_replaced_namespace_and_reports_conflict(self):
        self.marker(namespaces={"r1": 123})
        replacement = self.lab.namespaces["r1"]
        with patch.object(self.lab, "_inode", return_value=456), \
                patch.object(self.lab, "_existing", return_value={replacement}), \
                patch("netlab.linux._cmd") as command:
            result = self.lab._down_unlocked()
        self.assertFalse(result["clean"])
        self.assertEqual(result["ownership_conflicts"], [replacement])
        self.assertEqual(result["namespaces_remaining"], [replacement])
        command.assert_not_called()
        self.assertEqual(self.lab._state()["namespaces"], {"r1": 123})

    @unittest.skipUnless(hasattr(os, "geteuid"), "Linux locking semantics")
    def test_startup_collision_does_not_overwrite_existing_marker(self):
        marker = self.marker()
        with patch.object(self.lab, "doctor", return_value={"ready": True}), \
                patch.object(self.lab, "_existing", return_value={self.lab.namespaces["r1"]}), \
                patch("netlab.linux._cmd") as command:
            with self.assertRaisesRegex(RuntimeError, "collision"):
                self.lab.up()
        command.assert_not_called()
        self.assertEqual(self.lab._state(), marker)

    @unittest.skipUnless(hasattr(os, "geteuid"), "Linux locking semantics")
    def test_new_runtime_is_claimed_before_collision_and_remains_retryable(self):
        with patch.object(self.lab, "doctor", return_value={"ready": True}), \
                patch.object(self.lab, "_existing", return_value={self.lab.namespaces["r1"]}):
            with self.assertRaisesRegex(RuntimeError, "collision"):
                self.lab.up()
        self.assertEqual(self.lab._state()["namespaces"], {})
        self.lab._prepare_root()  # Previously failed as nonempty and unowned.
        self.assertTrue((self.root / "logs").is_dir())

    @unittest.skipUnless(hasattr(os, "geteuid"), "Linux locking semantics")
    def test_namespace_list_failure_leaves_claimed_retryable_runtime(self):
        with patch.object(self.lab, "doctor", return_value={"ready": True}), \
                patch.object(self.lab, "_existing", side_effect=RuntimeError("list failed")):
            with self.assertRaisesRegex(RuntimeError, "list failed"):
                self.lab.up()
        self.assertEqual(self.lab._state()["namespaces"], {})
        self.lab._prepare_root()

    @unittest.skipUnless(hasattr(os, "geteuid"), "Linux ownership semantics")
    def test_partial_helper_directory_failure_leaves_claimed_retryable_runtime(self):
        real_mkdir = Path.mkdir

        def fail_captures_once(path, *args, **kwargs):
            if path == self.root / "captures":
                raise OSError("injected helper directory failure")
            return real_mkdir(path, *args, **kwargs)

        with patch.object(Path, "mkdir", fail_captures_once):
            with self.assertRaisesRegex(OSError, "helper directory"):
                self.lab._prepare_root()
        self.assertEqual(self.lab._state()["namespaces"], {})
        self.lab._prepare_root()
        self.assertTrue((self.root / "captures").is_dir())

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

    def test_routing_ready_requires_the_intended_fib_path_and_established_peers(self):
        primary = {"dst": "10.77.3.0/24", "gateway": "10.77.12.2", "dev": "direct0"}
        alternatives = [None, [], [dict(primary, gateway="10.77.13.3", dev="backup0")],
                        [dict(primary, dst="10.77.4.0/24")], [dict(primary, type="blackhole")],
                        [dict(primary, dev="backup0")], [primary, dict(primary, gateway="10.77.13.3")]]
        for routes in alternatives:
            with self.subTest(routes=routes), patch.object(self.lab, "_route_data", return_value=routes), \
                    patch.object(self.lab, "_peers_established", return_value=True):
                self.assertFalse(self.lab._routing_ready())
        for peers in (False, True):
            with self.subTest(peers=peers), patch.object(self.lab, "_route_data", return_value=[primary]), \
                    patch.object(self.lab, "_peers_established", return_value=peers):
                self.assertIs(self.lab._routing_ready(), peers)

    @unittest.skipUnless(hasattr(os, "geteuid"), "Linux locking semantics")
    def test_restore_waits_for_primary_fib_even_when_all_peers_are_established(self):
        self.marker(fault={"kind": "link-loss"})
        backup = [{"dst": "10.77.3.0/24", "gateway": "10.77.13.3", "dev": "backup0"}]
        primary = [{"dst": "10.77.3.0/24", "gateway": "10.77.12.2", "dev": "direct0"}]
        choices = iter([backup, backup, primary])

        def observed_route():
            self.assertIsNotNone(self.lab._state()["fault"], "fault journal cleared before primary FIB restoration")
            return next(choices)

        with patch.object(self.lab, "_route_data", side_effect=observed_route) as route, \
                patch.object(self.lab, "_peers_established", return_value=True), \
                patch.object(self.lab, "_ns", return_value=subprocess.CompletedProcess([], 0, "", "")), \
                patch("netlab.linux.time.sleep") as sleep:
            result = self.lab.restore_fault()
        self.assertTrue(result["restored"])
        self.assertEqual(route.call_count, 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertIsNone(self.lab._state()["fault"])


class PrefixPolicyTests(unittest.TestCase):
    baseline = "hostname r1\nrouter bgp 65001\n address-family ipv4 unicast\n"
    rules = "ip prefix-list PNID-IN seq 5 deny 10.77.3.0/24\nip prefix-list PNID-IN seq 10 permit any\n"
    bindings = "  neighbor 10.77.12.2 prefix-list PNID-IN in\n  neighbor 10.77.13.3 prefix-list PNID-IN in\n"
    display = "ip prefix-list PNID-IN: 2 entries\n   seq 5 deny 10.77.3.0/24\n   seq 10 permit any\n"

    def test_healthy_and_restored_config_have_no_policy(self):
        result = _policy_observation(self.baseline, "")
        self.assertIs(result["backend_prefix_denied"], False)
        self.assertIs(result["backend_prefix_policy_present"], False)

    def test_deny_requires_actual_rules_and_both_inbound_bindings(self):
        result = _policy_observation(self.baseline + self.rules + self.bindings, self.display)
        self.assertIs(result["backend_prefix_denied"], True)
        partial = _policy_observation(self.baseline + self.rules + self.bindings.splitlines()[0], self.display)
        self.assertIs(partial["backend_prefix_denied"], False)
        self.assertIs(partial["backend_prefix_policy_present"], True)

    def test_earlier_permit_overrides_a_later_deny(self):
        earlier = "ip prefix-list PNID-IN seq 1 permit 10.77.3.0/24\n"
        display = self.display.replace("   seq 5", "   seq 1 permit 10.77.3.0/24\n   seq 5")
        result = _policy_observation(self.baseline + earlier + self.rules + self.bindings, display)
        self.assertIs(result["backend_prefix_denied"], False)

    def test_actual_multidaemon_vty_output_uses_bgp_policy(self):
        combined = ("ZEBRA: ip prefix-list PNID-IN: 1 entries\n seq 1 permit any\n"
                    + self.display.replace("ip prefix-list", "BGP: ip prefix-list", 1))
        result = _policy_observation(self.baseline + self.rules + self.bindings, combined)
        self.assertIs(result["backend_prefix_denied"], True)

    def test_unavailable_or_contradictory_sources_remain_unknown(self):
        for config, display in ((None, self.display), (self.baseline, None), ("", ""),
                                (self.baseline + self.rules + self.bindings, "")):
            with self.subTest(config=config, display=display):
                self.assertIsNone(_policy_observation(config, display)["backend_prefix_denied"])


if __name__ == "__main__":
    unittest.main()
