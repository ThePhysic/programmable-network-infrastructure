#!/usr/bin/env python3
"""Run privileged real-Linux lifecycle acceptance checks in private test roots."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import traceback

REPOSITORY = Path(__file__).resolve().parent.parent
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from netlab.linux import Lab, NODES


def checked(argv, *, timeout=10):
    return subprocess.run([str(part) for part in argv], capture_output=True, text=True,
                          timeout=timeout, check=True)


def namespace_inode(name):
    try:
        return (Path("/run/netns") / name).stat().st_ino
    except FileNotFoundError:
        return None


def namespace_processes(inodes):
    """Independent /proc scan also detects processes in detached namespaces."""
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            inode = (entry / "ns/net").stat().st_ino
            if inode in inodes:
                found.append({"pid": int(entry.name), "namespace_inode": inode,
                              "command": (entry / "comm").read_text().strip()})
        except (FileNotFoundError, ProcessLookupError):
            pass
    return found


def cleanup_evidence(lab, before):
    first = lab.down()
    second = lab.down()
    named_residue = [name for name in lab.namespaces.values() if namespace_inode(name) is not None]
    # Allow the kernel a short bounded interval to reap terminated children.
    deadline = time.monotonic() + 2
    residue = namespace_processes(set(before.values()))
    while residue and time.monotonic() < deadline:
        time.sleep(0.05)
        residue = namespace_processes(set(before.values()))
    result = {"first_down": first, "second_down": second,
              "namespaces_remaining": named_residue, "namespace_processes_remaining": residue,
              "namespaces_before_cleanup": before}
    if not first.get("clean") or not second.get("clean") or named_residue or residue:
        raise AssertionError("Cleanup was incomplete: " + json.dumps(result))
    return result


def delete_test_namespace(name, expected_inode):
    """The collision fixture may remove only its unchanged test namespace."""
    actual = namespace_inode(name)
    if actual is None:
        return
    if actual != expected_inode:
        raise RuntimeError("Collision fixture namespace identity changed; refusing deletion")
    checked(["ip", "netns", "delete", name])


class Acceptance:
    def __init__(self, root, output, binary):
        self.root, self.output, self.binary = Path(root), Path(output), Path(binary)
        self.results = []

    def lab(self, name):
        lab = Lab(self.root / name, self.binary)
        lab.experiment_id = "lifecycle-" + name
        return lab

    def run_case(self, name, function):
        started = time.monotonic()
        try:
            details = function()
            result = {"name": name, "passed": True, "details": details}
        except BaseException as exc:
            result = {"name": name, "passed": False,
                      "error": type(exc).__name__ + ": " + str(exc), "traceback": traceback.format_exc()}
        result["duration_seconds"] = time.monotonic() - started
        self.results.append(result)
        self.write_summary()
        print(json.dumps({"case": name, "passed": result["passed"]}), flush=True)
        return result

    def write_summary(self):
        summary = {"schema_version": 1, "observed_at": datetime.now(timezone.utc).isoformat(),
                   "passed": bool(self.results) and all(case["passed"] for case in self.results),
                   "cases": self.results}
        (self.output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")

    def permitted_and_forbidden_flows(self):
        lab = self.lab("segmentation")
        before = {}
        try:
            up = lab.up()
            before = lab._state()["namespaces"].copy()
            allowed = lab.probe(self.output / "allowed-proxy.json", duration=0.5, rate=20)
            forbidden_path = self.output / "forbidden-direct.json"
            lab._ns("client", self.binary, "probe", "--target", "10.77.3.2:19090", "--duration", "500ms",
                    "--timeout", "300ms", "--concurrency", "1", "--payload", "64", "--output", forbidden_path)
            forbidden = json.loads(forbidden_path.read_text())
            if not allowed["attempts"] or allowed["attempts"] != allowed["successes"]:
                raise AssertionError("The permitted proxy path did not carry correct payloads")
            if not forbidden["attempts"] or forbidden["successes"]:
                raise AssertionError("The forbidden direct client/backend flow was reachable")
            snapshot = lab.snapshot(self.output / "segmentation-snapshot")
            return {"permitted_attempts": allowed["attempts"], "permitted_successes": allowed["successes"],
                    "forbidden_attempts": forbidden["attempts"], "forbidden_successes": forbidden["successes"],
                    "policy": "Client traffic must use the gateway; the gateway namespace does not forward IP packets.",
                    "topology": up["topology"], "snapshot": snapshot,
                    "cleanup": cleanup_evidence(lab, before)}
        finally:
            lab.down()

    def interrupted_startup(self):
        lab = self.lab("startup-interrupt")
        before = {}
        real_start = lab._start_router

        def start_then_interrupt(router):
            real_start(router)
            before.update(lab._state()["namespaces"])
            raise KeyboardInterrupt("deterministic interruption after the first real FRR router starts")

        lab._start_router = start_then_interrupt
        raised = False
        try:
            try:
                lab.up()
            except KeyboardInterrupt:
                raised = True
            if not raised or len(before) != len(NODES):
                raise AssertionError("The startup interruption did not exercise the created topology")
            return {"interruption": "KeyboardInterrupt after actual zebra and bgpd startup",
                    "cleanup": cleanup_evidence(lab, before)}
        finally:
            lab.down()

    def collision_refusal(self):
        lab = self.lab("collision")
        name = lab.namespaces["r1"]
        if namespace_inode(name) is not None:
            raise RuntimeError("Collision fixture name already exists; refusing to touch it")
        checked(["ip", "netns", "add", name])
        inode = namespace_inode(name)
        child = None
        try:
            checked(["ip", "-n", name, "link", "set", "lo", "up"])
            child = subprocess.Popen(["ip", "netns", "exec", name, "sleep", "60"])
            time.sleep(0.05)
            addresses = checked(["ip", "-n", name, "-j", "address", "show"]).stdout
            refused = False
            try:
                lab.up()
            except RuntimeError as exc:
                if "collision" not in str(exc):
                    raise
                refused = True
            unchanged = (namespace_inode(name) == inode and child.poll() is None
                         and checked(["ip", "-n", name, "-j", "address", "show"]).stdout == addresses)
            if not refused or not unchanged:
                raise AssertionError("Startup did not preserve the existing namespace and process")
            # An unclaimed Lab.down also must not remove the collision fixture.
            lab.down()
            if namespace_inode(name) != inode or child.poll() is not None:
                raise AssertionError("Unclaimed cleanup touched the existing namespace")
            result = {"refused": refused, "fixture_namespace": name, "inode_before": inode,
                      "inode_after": namespace_inode(name), "configuration_unchanged": unchanged,
                      "fixture_process_preserved": child.poll() is None}
        finally:
            if child is not None:
                child.terminate()
                child.wait(timeout=3)
            delete_test_namespace(name, inode)
        # The exact runtime which refused the collision must work once the
        # external collision is gone; a fresh unrelated root would miss retries.
        before = {}
        try:
            lab.up()
            before = lab._state()["namespaces"].copy()
            probe = lab.probe(self.output / "collision-retry.json", duration=0.4, rate=10)
            if not probe["attempts"] or probe["attempts"] != probe["successes"]:
                raise AssertionError("The same runtime did not recover after collision removal")
            result["retry_same_runtime_successful"] = True
            result["retry_probe_successes"] = probe["successes"]
            result["retry_cleanup"] = cleanup_evidence(lab, before)
            return result
        finally:
            lab.down()

    def interrupted_cli_run(self):
        lab = self.lab("run-interrupt")
        evidence = self.output / "interrupted-experiment"
        command = [sys.executable, "-m", "netlab", "--root", str(lab.root), "--binary", str(self.binary),
                   "run", "--scenario", "packet-loss", "--duration", "30", "--rate", "20", "--output", str(evidence)]
        before = {}
        with (self.output / "interrupted-cli.stdout.txt").open("w") as stdout, \
                (self.output / "interrupted-cli.stderr.txt").open("w") as stderr:
            child = subprocess.Popen(command, cwd=REPOSITORY, stdout=stdout, stderr=stderr)
            try:
                deadline = time.monotonic() + 35
                while time.monotonic() < deadline:
                    if child.poll() is not None:
                        raise AssertionError("CLI exited before its baseline workload began")
                    try:
                        events = json.loads((evidence / "events.json").read_text())
                    except (FileNotFoundError, ValueError):
                        events = []
                    if any(event["type"] == "baseline-started" for event in events):
                        before = lab._state()["namespaces"].copy()
                        # Let the workload establish actual sessions before interrupting.
                        time.sleep(0.2)
                        child.send_signal(signal.SIGTERM)
                        break
                    time.sleep(0.05)
                else:
                    raise AssertionError("CLI never began its baseline workload")
                returncode = child.wait(timeout=20)
                if returncode == 0:
                    raise AssertionError("Interrupted experiment was falsely reported successful")
                experiment = json.loads((evidence / "experiment.json").read_text())
                if experiment["result"]["passed"] or not experiment["cleanup"].get("clean"):
                    raise AssertionError("Interrupted experiment result or cleanup is incorrect")
                cleanup = cleanup_evidence(lab, before)
                return {"returncode": returncode, "failure": experiment.get("failure"),
                        "evidence": "interrupted-experiment/experiment.json", "cleanup": cleanup}
            finally:
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)
                lab.down()

    def independent_roots(self):
        first, second = self.lab("parallel-a"), self.lab("parallel-b")
        before_first, before_second = {}, {}
        try:
            first.up()
            before_first = first._state()["namespaces"].copy()
            second.up()
            before_second = second._state()["namespaces"].copy()
            if set(first.namespaces.values()) & set(second.namespaces.values()):
                raise AssertionError("Independent roots used the same namespace names")
            first_probe = first.probe(self.output / "first-root.json", duration=0.4, rate=10)
            first_cleanup = cleanup_evidence(first, before_first)
            second_probe = second.probe(self.output / "second-after-first-down.json", duration=0.4, rate=10)
            for probe in (first_probe, second_probe):
                if not probe["attempts"] or probe["attempts"] != probe["successes"]:
                    raise AssertionError("An independent lab did not preserve connectivity")
            return {"first_prefix": first.prefix, "second_prefix": second.prefix,
                    "first_probe_successes": first_probe["successes"],
                    "second_successes_after_first_cleanup": second_probe["successes"],
                    "first_cleanup": first_cleanup, "second_cleanup": cleanup_evidence(second, before_second)}
        finally:
            first.down()
            second.down()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/var/tmp/pnid-lifecycle"))
    parser.add_argument("--output", type=Path, default=REPOSITORY / "results/lifecycle")
    parser.add_argument("--binary", type=Path, default=REPOSITORY / "bin/netlab-agent")
    args = parser.parse_args(argv)
    args.root, args.output, args.binary = args.root.absolute(), args.output.absolute(), args.binary.absolute()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("lifecycle acceptance requires Linux root")
    if any(path.is_symlink() for path in (args.root, *args.root.parents, args.output, *args.output.parents)):
        parser.error("test paths must not have symlink components")
    if args.root.exists() or args.output.exists():
        parser.error("use new runtime and output directories to preserve prior evidence")
    if args.root == args.output or args.root in args.output.parents or args.output in args.root.parents:
        parser.error("runtime and evidence directories must be separate")
    args.root.mkdir(parents=True, mode=0o700)
    args.output.mkdir(parents=True, mode=0o700)
    acceptance = Acceptance(args.root, args.output, args.binary)
    for name in ("permitted_and_forbidden_flows", "interrupted_startup", "collision_refusal",
                 "interrupted_cli_run", "independent_roots"):
        acceptance.run_case(name, getattr(acceptance, name))
    return 0 if all(case["passed"] for case in acceptance.results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
