"""Terminal interface for lifecycle, experiments and portable reports."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import sys
import uuid

from .experiment import SCENARIOS, file_manifest, run_experiment, validate_workload, write_json
from .report import analyze, render


def positive_float(value):
    import math
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite number")
    return result


@contextmanager
def operation_lock(root):
    import fcntl
    root = root.absolute()
    # Refuse symlink ancestors before root-level file creation.
    if any(path.is_symlink() for path in (root, *root.parents)):
        raise ValueError("Runtime path must not have symlink components")
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = root.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("Runtime directory must be owned by the current user with mode 0700")
    descriptor = os.open(root.parent / (root.name + ".operation.lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        lock_info = os.fstat(descriptor)
        if lock_info.st_uid != os.geteuid() or lock_info.st_mode & 0o077:
            raise ValueError("Operation lock must be private and owned by the current user")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("Another command is using this lab") from exc
        yield
    finally:
        os.close(descriptor)


def parser():
    result = argparse.ArgumentParser(prog="netlab", description="Isolated Linux network experiments with traceable evidence")
    result.add_argument("--root", type=Path, default=Path("/var/tmp/pnid-" + str(getattr(os, "geteuid", lambda: 0)())))
    result.add_argument("--binary", type=Path, default=Path(__file__).resolve().parent.parent / "bin" / "netlab-agent")
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("doctor", "up", "status", "down"):
        commands.add_parser(name)
    for name in ("run", "suite"):
        command = commands.add_parser(name)
        command.add_argument("--output", type=Path)
        command.add_argument("--duration", type=positive_float, default=2.0)
        command.add_argument("--concurrency", type=int, default=2)
        command.add_argument("--payload", type=int, default=256)
        command.add_argument("--rate", type=float, default=20.0)
        if name == "run":
            command.add_argument("--scenario", choices=SCENARIOS, required=True)
        else:
            command.add_argument("--scenarios", nargs="+", choices=SCENARIOS, default=list(SCENARIOS))
            command.add_argument("--trials", type=int, default=1)
    report = commands.add_parser("report", help="Regenerate a Markdown report without root or Linux")
    report.add_argument("experiment", type=Path)
    verify = commands.add_parser("verify", help="Verify hashes and sizes in an experiment manifest")
    verify.add_argument("directory", type=Path)
    return result


def main(argv=None):
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "report":
            data = json.loads(arguments.experiment.read_text(encoding="utf-8"))
            print(render(data))
            return 0
        if arguments.command == "verify":
            expected = json.loads((arguments.directory / "manifest.json").read_text(encoding="utf-8"))
            actual = file_manifest(arguments.directory)
            if expected.get("algorithm") != "sha256" or expected.get("files") != actual:
                raise ValueError("Evidence manifest mismatch (modified, added or missing files)")
            print(json.dumps({"verified": True, "files": len(actual)}))
            return 0
        from .linux import Lab
        lab = Lab(arguments.root.absolute(), arguments.binary.absolute())
        if arguments.command == "doctor":
            result = lab.doctor()
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result.get("ready", result.get("ok", False)) else 1
        if sys.platform != "linux":
            raise RuntimeError("Lab commands require Linux; use the dedicated WSL lab on Windows")
        def interrupted(_signal, _frame):
            raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM, interrupted)
        with operation_lock(lab.root):
            if arguments.command in ("up", "status", "down"):
                result = getattr(lab, arguments.command)()
                print(json.dumps(result, indent=2, sort_keys=True))
                return 0
            validate_workload(arguments.duration, arguments.concurrency, arguments.payload, arguments.rate)
            output = arguments.output or Path("results") / (arguments.command + "-" + uuid.uuid4().hex[:12])
            if output.absolute() == lab.root or lab.root in output.absolute().parents or output.absolute() in lab.root.parents:
                raise ValueError("Evidence output and runtime directory must be separate")
            workload = {"duration": arguments.duration, "concurrency": arguments.concurrency,
                        "payload": arguments.payload, "rate": arguments.rate}
            if arguments.command == "run":
                result = run_experiment(lab, arguments.scenario, output, **workload)
                print(json.dumps({"experiment": str(output / "experiment.json"), "passed": result["result"]["passed"]}))
                return 0 if result["result"]["passed"] else 1
            if not 1 <= arguments.trials <= 20:
                raise ValueError("trials must be between 1 and 20")
            output.mkdir(parents=True, exist_ok=False)
            runs = []
            for trial in range(1, arguments.trials + 1):
                for scenario in arguments.scenarios:
                    directory = output / (scenario + "-" + str(trial))
                    print("Running " + directory.name, file=sys.stderr, flush=True)
                    try:
                        result = run_experiment(lab, scenario, directory, **workload)
                        runs.append({"scenario": scenario, "trial": trial, "path": directory.name + "/experiment.json",
                                     "passed": result["result"]["passed"], "measurements": result["measurements"]})
                    except (RuntimeError, ValueError, OSError) as exc:
                        runs.append({"scenario": scenario, "trial": trial, "passed": False, "error": str(exc)})
                    write_json(output / "suite.json", {"runs": runs, "passed": all(run["passed"] for run in runs)})
            print(json.dumps({"output": str(output), "runs": len(runs), "passed": all(run["passed"] for run in runs)}))
            return 0 if all(run["passed"] for run in runs) else 1
    except KeyboardInterrupt:
        print("Interrupted; experiment cleanup was attempted. Inspect status and retained evidence.", file=sys.stderr)
        return 130
    except (ValueError, RuntimeError, OSError) as exc:
        print(type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
