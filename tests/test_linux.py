import json
import os
from pathlib import Path
import subprocess
import signal
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from netlab.linux import FAULTS, LINKS, Lab, NODES, _bgp_peers, _cmd, _json, _policy_observation, _read_json


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


class ProcessCleanupTests(unittest.TestCase):
    """Model process identities, not real privileged namespace operations."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "runtime"
        self.root.mkdir(mode=0o700)
        self.lab = Lab(self.root, Path(self.temp.name) / "agent")
        self.record = {"pid": 424242, "node": "r1", "started": "11"}
        self.state = self.lab._new_state()
        self.state["namespaces"] = {"r1": 12345}
        self.state["processes"] = {"r1-bgpd": dict(self.record)}
        self.state["fault"] = {"kind": "backend-down"}
        self.lab._save(self.state)
        self.alive, self.started, self.inode = True, "11", 12345
        original_stat = Path.stat

        def process_stat(path, *args, **kwargs):
            if str(path) in ("/proc/424242", "/proc/424242/ns/net"):
                if not self.alive:
                    raise FileNotFoundError()
                return SimpleNamespace(st_ino=self.inode)
            return original_stat(path, *args, **kwargs)

        self.stat_patch = patch.object(Path, "stat", process_stat)
        self.stat_patch.start()
        self.addCleanup(self.stat_patch.stop)
        self.start_patch = patch.object(self.lab, "_proc_start", side_effect=lambda _pid: self.started if self.alive else None)
        self.start_patch.start()
        self.addCleanup(self.start_patch.stop)

    def sender(self, _fd, _sig, _info, _flags):
        self.alive = False

    def test_detached_owned_process_stops_and_repeated_cleanup_is_clean(self):
        with patch.object(self.lab, "_inode", return_value=None), \
                patch.object(self.lab, "_existing", return_value=set()), \
                patch("netlab.linux.os.pidfd_open", return_value=501, create=True) as opened, \
                patch("netlab.linux.signal.pidfd_send_signal", side_effect=self.sender, create=True) as sent, \
                patch("netlab.linux.os.close") as closed, patch("netlab.linux.os.kill") as unsafe:
            self.assertTrue(self.lab.status()["active"])
            first = self.lab._down_unlocked()
            second = self.lab._down_unlocked()
        self.assertTrue(first["clean"])
        self.assertTrue(second["clean"])
        self.assertFalse(self.alive)
        opened.assert_called_once_with(424242, 0)
        sent.assert_called_once_with(501, signal.SIGTERM, None, 0)
        closed.assert_called_once_with(501)
        unsafe.assert_not_called()
        self.assertEqual(self.lab._state()["processes"], {})
        self.assertEqual(self.lab._state()["namespaces"], {})

    def test_failed_detached_shutdown_retains_identity_and_can_retry(self):
        with patch.object(self.lab, "_inode", return_value=None), \
                patch.object(self.lab, "_existing", return_value=set()), \
                patch("netlab.linux.os.pidfd_open", return_value=501, create=True), \
                patch("netlab.linux.signal.pidfd_send_signal", side_effect=PermissionError(), create=True), \
                patch("netlab.linux.os.close"), patch("netlab.linux.os.kill") as unsafe:
            failed = self.lab._down_unlocked()
        self.assertFalse(failed["clean"])
        self.assertEqual(failed["processes_remaining"], [424242])
        self.assertEqual(self.lab._state()["processes"], {"r1-bgpd": self.record})
        self.assertEqual(self.lab._state()["namespaces"], {"r1": 12345})
        self.assertEqual(self.lab._state()["fault"], {"kind": "backend-down"})
        unsafe.assert_not_called()
        with patch.object(self.lab, "_inode", return_value=None), \
                patch.object(self.lab, "_existing", return_value=set()), \
                patch("netlab.linux.os.pidfd_open", return_value=501, create=True), \
                patch("netlab.linux.signal.pidfd_send_signal", side_effect=self.sender, create=True), \
                patch("netlab.linux.os.close"):
            retried = self.lab._down_unlocked()
        self.assertTrue(retried["clean"])
        self.assertIsNone(self.lab._state()["fault"])

    def test_reused_pid_is_never_signalled(self):
        self.started = "22"
        with patch.object(self.lab, "_inode", return_value=None), \
                patch.object(self.lab, "_existing", return_value=set()), \
                patch("netlab.linux.os.pidfd_open", create=True) as opened, \
                patch("netlab.linux.os.kill") as unsafe:
            result = self.lab._down_unlocked()
        self.assertTrue(result["clean"])
        self.assertTrue(self.alive)
        opened.assert_not_called()
        unsafe.assert_not_called()

    def test_same_pid_start_in_foreign_namespace_is_not_killed_or_forgotten(self):
        self.inode = 54321
        with patch.object(self.lab, "_inode", return_value=None), \
                patch.object(self.lab, "_existing", return_value=set()), \
                patch("netlab.linux.os.pidfd_open", create=True) as opened, \
                patch("netlab.linux.os.kill") as unsafe:
            result = self.lab._down_unlocked()
        self.assertFalse(result["clean"])
        self.assertEqual(result["process_identity_conflicts"], {"r1-bgpd": "scope_changed"})
        self.assertEqual(self.lab._state()["processes"], {"r1-bgpd": self.record})
        opened.assert_not_called()
        unsafe.assert_not_called()

    def test_unreadable_process_identity_is_retained_without_signalling(self):
        self.started = None
        with patch.object(self.lab, "_inode", return_value=None), \
                patch.object(self.lab, "_existing", return_value=set()), \
                patch("netlab.linux.os.pidfd_open", create=True) as opened:
            result = self.lab._down_unlocked()
        self.assertFalse(result["clean"])
        self.assertEqual(result["process_identity_conflicts"], {"r1-bgpd": "unverified"})
        self.assertEqual(self.lab._state()["processes"], {"r1-bgpd": self.record})
        opened.assert_not_called()

    def test_pid_reuse_between_identity_check_and_pidfd_open_is_rejected(self):
        def open_after_reuse(*_args):
            self.started = "22"
            return 501

        with patch("netlab.linux.os.pidfd_open", side_effect=open_after_reuse, create=True), \
                patch("netlab.linux.signal.pidfd_send_signal", create=True) as sent, \
                patch("netlab.linux.os.close") as closed:
            result = self.lab._signal_owned(self.record, signal.SIGTERM, self.state)
        self.assertFalse(result)
        sent.assert_not_called()
        closed.assert_called_once_with(501)

    def test_unavailable_pidfd_never_falls_back_to_pid_kill(self):
        with patch.object(self.lab, "_inode", return_value=None), \
                patch.object(self.lab, "_existing", return_value=set()), \
                patch("netlab.linux.os.pidfd_open", None, create=True), \
                patch("netlab.linux.os.kill") as unsafe:
            result = self.lab._down_unlocked()
        self.assertFalse(result["clean"])
        self.assertIn("pidfd signalling unavailable", " ".join(result["errors"]))
        self.assertEqual(self.lab._state()["processes"], {"r1-bgpd": self.record})
        unsafe.assert_not_called()

    def test_namespace_leftovers_use_same_pidfd_identity_checks(self):
        self.state["processes"] = {}
        self.lab._save(self.state)
        mounted = [True]

        def command(argv, **_kwargs):
            if argv[:3] == ["ip", "netns", "pids"]:
                return subprocess.CompletedProcess(argv, 0, "424242\n" if self.alive else "", "")
            if argv[:3] == ["ip", "netns", "delete"]:
                mounted[0] = False
                return subprocess.CompletedProcess(argv, 0, "", "")
            raise AssertionError("unexpected command")

        with patch.object(self.lab, "_inode", side_effect=lambda _node: 12345 if mounted[0] else None), \
                patch.object(self.lab, "_existing", side_effect=lambda: {self.lab.namespaces["r1"]} if mounted[0] else set()), \
                patch("netlab.linux._cmd", side_effect=command), \
                patch("netlab.linux.os.pidfd_open", return_value=501, create=True), \
                patch("netlab.linux.signal.pidfd_send_signal", side_effect=self.sender, create=True) as sent, \
                patch("netlab.linux.os.close"), patch("netlab.linux.os.kill") as unsafe:
            result = self.lab._down_unlocked()
        self.assertTrue(result["clean"])
        self.assertFalse(mounted[0])
        sent.assert_called_once_with(501, signal.SIGKILL, None, 0)
        unsafe.assert_not_called()

    def test_failed_process_enumeration_preserves_named_namespace_for_retry(self):
        self.state["processes"] = {}
        self.lab._save(self.state)
        with patch.object(self.lab, "_inode", return_value=12345), \
                patch.object(self.lab, "_existing", return_value={self.lab.namespaces["r1"]}), \
                patch("netlab.linux._cmd", return_value=subprocess.CompletedProcess([], 1, "", "fixture denial")) as command:
            result = self.lab._down_unlocked()
        self.assertFalse(result["clean"])
        self.assertEqual(self.lab._state()["namespaces"], {"r1": 12345})
        self.assertEqual(command.call_count, 1)
        self.assertEqual(command.call_args.args[0][:3], ["ip", "netns", "pids"])

    def test_all_enumerated_identities_survive_a_first_signal_failure(self):
        self.state["processes"] = {}
        self.lab._save(self.state)
        with patch.object(self.lab, "_inode", return_value=12345), \
                patch.object(self.lab, "_existing", return_value={self.lab.namespaces["r1"]}), \
                patch.object(self.lab, "_process_state", return_value="owned"), \
                patch.object(self.lab, "_signal_owned", side_effect=RuntimeError("fixture signalling failed")), \
                patch("netlab.linux._cmd", return_value=subprocess.CompletedProcess([], 0, "424242\n424243\n", "")):
            result = self.lab._down_unlocked()
        self.assertFalse(result["clean"])
        self.assertEqual(result["processes_remaining"], [424242, 424243])
        self.assertEqual(len(self.lab._state()["processes"]), 2)


class SnapshotSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "runtime"
        self.root.mkdir(mode=0o700)
        (self.root / "captures").mkdir()
        (self.root / "logs").mkdir()
        self.capture = self.root / "captures" / "gateway.pcap0"
        self.log = self.root / "logs" / "gateway.log"
        self.capture.write_bytes(b"fixture capture bytes")
        self.log.write_bytes(b"fixture log bytes")
        self.lab = Lab(self.root, self.base / "agent")

    def assert_sources_intact(self):
        self.assertEqual(self.capture.read_bytes(), b"fixture capture bytes")
        self.assertEqual(self.log.read_bytes(), b"fixture log bytes")

    def test_same_nested_ancestor_and_dotdot_destinations_refuse_before_any_write(self):
        destinations = [self.root, self.root / "new", self.root.parent,
                        self.root / "missing" / ".." / "nested",
                        self.root.parent / "missing" / ".." / "runtime"]
        for destination in destinations:
            with self.subTest(destination=destination), \
                    patch.object(Path, "mkdir", side_effect=AssertionError("mkdir must not run")), \
                    patch.object(self.lab, "_ns") as collect:
                with self.assertRaises(ValueError):
                    self.lab.snapshot(destination)
                collect.assert_not_called()
            self.assert_sources_intact()
        self.assertFalse((self.root / "missing").exists())

    def test_symlink_destination_and_existing_descendant_refuse_before_collection(self):
        alias = self.base / "alias"
        destination = self.base / "snapshot"
        destination.mkdir()
        try:
            alias.symlink_to(self.root, target_is_directory=True)
            (destination / "logs").symlink_to(self.root / "logs", target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation unavailable")
        for target in (alias, alias / "nested", destination):
            with self.subTest(target=target), patch.object(self.lab, "_ns") as collect:
                with self.assertRaisesRegex(ValueError, "symlink"):
                    self.lab.snapshot(target)
                collect.assert_not_called()
            self.assert_sources_intact()

    def test_hardlinked_output_file_cannot_clobber_runtime_source(self):
        destination = self.base / "snapshot"
        destination.mkdir()
        os.link(self.log, destination / "gateway-metrics.json")
        with patch.object(self.lab, "_ns") as collect, self.assertRaisesRegex(ValueError, "hard link"):
            self.lab.snapshot(destination)
        collect.assert_not_called()
        self.assert_sources_intact()

    def test_separate_snapshot_preserves_source_and_copies_bytes(self):
        destination = self.base / "snapshot"
        with patch.object(self.lab, "_ns", return_value=subprocess.CompletedProcess([], 0, "[]", "")), \
                patch.object(self.lab, "_vty", return_value=subprocess.CompletedProcess([], 0, "{}", "")), \
                patch.object(self.lab, "_metrics", return_value={}), \
                patch.object(self.lab, "_state", return_value={"processes": {}}):
            result = self.lab.snapshot(destination)
            self.lab.snapshot(destination)
        self.assert_sources_intact()
        self.assertEqual((destination / "captures/gateway.pcap0").read_bytes(), self.capture.read_bytes())
        self.assertEqual((destination / "logs/gateway.log").read_bytes(), self.log.read_bytes())
        self.assertIn("captures/gateway.pcap0", result["artifacts"])


class PidfdPrerequisiteTests(unittest.TestCase):
    def test_missing_pidfd_api_is_explicitly_unsupported(self):
        with patch("netlab.linux.os.pidfd_open", None, create=True):
            self.assertFalse(Lab._pidfd_supported())

    def test_supported_pidfd_probe_signals_only_zero_and_closes_descriptor(self):
        with patch("netlab.linux.os.pidfd_open", return_value=501, create=True), \
                patch("netlab.linux.signal.pidfd_send_signal", create=True) as sent, \
                patch("netlab.linux.os.close") as closed:
            self.assertTrue(Lab._pidfd_supported())
        sent.assert_called_once_with(501, 0, None, 0)
        closed.assert_called_once_with(501)

    @unittest.skipUnless(hasattr(os, "geteuid"), "Linux doctor prerequisites")
    def test_doctor_refuses_startup_when_only_pidfd_support_is_missing(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "fixture-agent"
            binary.write_bytes(b"fixture")
            lab = Lab(Path(temp) / "runtime", binary)
            with patch("netlab.linux.shutil.which", return_value="fixture-tool"), \
                    patch.object(lab, "_daemon", return_value="fixture-daemon"), \
                    patch.object(lab, "_pidfd_supported", return_value=False), \
                    patch("netlab.linux.os.geteuid", return_value=0), \
                    patch("pwd.getpwuid", return_value=SimpleNamespace(pw_gid=77, pw_name="fixture-user")), \
                    patch("grp.getgrnam", return_value=SimpleNamespace(gr_gid=77, gr_mem=[])):
                result = lab.doctor()
            self.assertFalse(result["ready"])
            self.assertFalse(result["pidfd_signalling_available"])
            self.assertTrue(result["root"])
            self.assertTrue(result["frr_vty_group_member"])


class StartupJournalRollbackTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "geteuid"), "Linux startup locking")
    def test_initial_generation_write_failure_without_resources_can_down_and_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "runtime"
            root.mkdir(mode=0o700)
            lab = Lab(root, Path(temp) / "agent")
            previous = dict(lab._new_state(), created_at="fixture-previous-generation")
            lab._save(previous)
            with patch.object(lab, "doctor", return_value={"ready": True}), \
                    patch.object(lab, "_existing", return_value=set()), \
                    patch("netlab.linux._json", side_effect=OSError("fixture initial save failure")), \
                    patch("netlab.linux._cmd") as command:
                with self.assertRaisesRegex(OSError, "initial save"):
                    lab.up()
                command.assert_not_called()
                self.assertFalse(lab.status()["active"])
            self.assertEqual(lab._pending_state["namespaces"], {})
            self.assertEqual(lab._pending_state["processes"], {})
            with patch.object(lab, "_existing", return_value=set()):
                self.assertTrue(lab.down()["clean"])
            self.assertIsNone(lab._pending_state)
            with patch.object(lab, "doctor", return_value={"ready": True}), \
                    patch.object(lab, "_existing", return_value=set()), \
                    patch("netlab.linux._cmd", side_effect=RuntimeError("fixture stop before namespace creation")) as command:
                with self.assertRaisesRegex(RuntimeError, "before namespace"):
                    lab.up()
            command.assert_called_once_with(["ip", "netns", "add", lab.namespaces["client"]])
            self.assertTrue(lab._last_cleanup["clean"])

    @unittest.skipUnless(hasattr(os, "geteuid"), "Linux startup locking")
    def test_new_namespace_is_rolled_back_when_its_journal_write_fails(self):
        self.exercise_failure(persistent=False)

    @unittest.skipUnless(hasattr(os, "geteuid"), "Linux startup locking")
    def test_unwritable_rollback_journal_reports_failure_then_retries(self):
        self.exercise_failure(persistent=True)

    def exercise_failure(self, *, persistent):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "runtime"
            lab = Lab(root, Path(temp) / "agent")
            mounted, deleted = {}, []
            failed = [False]

            def command(argv, **_kwargs):
                if argv[:3] == ["ip", "netns", "add"]:
                    mounted[argv[3]] = 12345
                elif argv[:3] == ["ip", "netns", "delete"]:
                    deleted.append(argv[3])
                    del mounted[argv[3]]
                elif argv[:3] != ["ip", "netns", "pids"]:
                    raise AssertionError("unexpected command")
                return subprocess.CompletedProcess(argv, 0, "", "")

            def journal(path, state):
                if path == lab.marker and (state.get("namespaces") or (persistent and failed[0])):
                    failed[0] = True
                    raise OSError("fixture journal unavailable")
                _json(path, state)

            with patch.object(lab, "doctor", return_value={"ready": True}), \
                    patch.object(lab, "_existing", side_effect=lambda: set(mounted)), \
                    patch.object(lab, "_inode", side_effect=lambda node: mounted.get(lab.namespaces[node])), \
                    patch("netlab.linux._cmd", side_effect=command), \
                    patch("netlab.linux._json", side_effect=journal), \
                    patch.object(lab, "_ns") as namespace_mutation:
                with self.assertRaisesRegex(OSError, "fixture journal"):
                    lab.up()
                namespace_mutation.assert_not_called()
            self.assertEqual(deleted, [lab.namespaces["client"]])
            self.assertEqual(mounted, {})
            self.assertIs(lab._last_cleanup["clean"], not persistent)
            if persistent:
                self.assertIn("could not be persisted", " ".join(lab._last_cleanup["errors"]))
                self.assertIsNotNone(lab._pending_state)
            with patch.object(lab, "_existing", return_value=set()):
                self.assertTrue(lab.down()["clean"])
                self.assertTrue(lab.down()["clean"])
            self.assertIsNone(lab._pending_state)
            self.assertEqual(lab._state()["namespaces"], {})

    def test_unpersisted_identity_never_overwrites_a_new_journal_generation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "runtime"
            root.mkdir(mode=0o700)
            lab = Lab(root, Path(temp) / "agent")
            original = lab._new_state()
            original["namespaces"] = {"r1": 12345}
            lab._save(original)
            with patch("netlab.linux._json", side_effect=OSError("fixture failure")):
                with self.assertRaises(OSError):
                    lab._save(original)
            replacement = dict(original, created_at="fixture-new-generation", namespaces={})
            _json(lab.marker, replacement)
            with patch.object(lab, "_down_unlocked") as cleanup, self.assertRaisesRegex(RuntimeError, "ownership conflicts"):
                lab.down()
            cleanup.assert_not_called()
            self.assertEqual(lab._state(), replacement)


if __name__ == "__main__":
    unittest.main()
