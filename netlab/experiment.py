"""Coordinate real lab experiments; retain evidence even when a phase fails."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import shutil
import subprocess
import time
import uuid

from . import __version__
from .report import analyze, render

SCENARIOS = (
    "route-withdrawal", "route-policy", "firewall-drop", "dns-failure",
    "backend-down", "link-loss", "packet-loss", "gateway-overload",
)


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def file_manifest(directory: Path):
    result = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError("Evidence must not contain symlinks")
        if path.is_file() and path.name != "manifest.json" and not path.name.endswith(".tmp"):
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            result[path.relative_to(directory).as_posix()] = {"sha256": digest.hexdigest(), "bytes": path.stat().st_size}
    return result


def source_metadata():
    repository = Path(__file__).resolve().parent.parent
    files = {}
    for part in ("netlab", "cmd", "internal", "tests", "scripts", "docs", ".github"):
        base = repository / part
        if base.exists():
            for path in sorted(base.rglob("*")):
                if path.is_file() and not path.is_symlink() and "__pycache__" not in path.parts:
                    files[path.relative_to(repository).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    for name in ("go.mod", "README.md", "CONTRACT.md", "pyproject.toml", "Makefile"):
        path = repository / name
        if path.is_file():
            files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    result = {"files_sha256": files, "revision": None, "dirty": None}
    try:
        result["revision"] = subprocess.run(["git", "-C", str(repository), "rev-parse", "HEAD"],
                                            capture_output=True, text=True, timeout=5, check=True).stdout.strip()
        result["dirty"] = bool(subprocess.run(["git", "-C", str(repository), "status", "--porcelain"],
                                               capture_output=True, text=True, timeout=5, check=True).stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    return result


def validate_workload(duration, concurrency, payload, rate):
    if not math.isfinite(duration) or not 0.2 <= duration <= 120:
        raise ValueError("duration must be between 0.2 and 120 seconds")
    if not 1 <= concurrency <= 256:
        raise ValueError("concurrency must be between 1 and 256")
    if not 1 <= payload <= 1024 * 1024:
        raise ValueError("payload must be between 1 byte and 1 MiB")
    if not math.isfinite(rate) or not 0 <= rate <= 10000:
        raise ValueError("rate must be between 0 and 10000 attempts/second")


def scenario_checks(experiment):
    """Accept only independently observed effects, never fault injection success alone."""
    phases = experiment.get("phases", {})
    baseline = phases.get("baseline", {}).get("snapshot", {}).get("observations", {})
    fault = phases.get("fault", {}).get("snapshot", {}).get("observations", {})
    probe = phases.get("fault", {}).get("probe", {})
    attempts, successes = probe.get("attempts", 0), probe.get("successes", 0)
    disrupted = attempts > 0 and successes < attempts
    scenario = experiment["scenario"]
    checks = {}
    if scenario in ("route-withdrawal", "route-policy"):
        checks = {"baseline_route_present": baseline.get("backend_route_present") is True,
                  "fault_route_absent": fault.get("backend_route_present") is False,
                  "application_disrupted": disrupted}
    elif scenario == "firewall-drop":
        checks = {"route_still_present": fault.get("backend_route_present") is True,
                  "drop_counter_increased": isinstance(fault.get("firewall_drop_packets"), (int, float)) and fault["firewall_drop_packets"] > (baseline.get("firewall_drop_packets") or 0),
                  "application_disrupted": disrupted}
    elif scenario == "dns-failure":
        checks = {"resolution_failed": fault.get("dns_ok") is False, "application_disrupted": disrupted,
                  "route_still_present": fault.get("backend_route_present") is True}
    elif scenario == "backend-down":
        checks = {"listener_absent": fault.get("backend_listener_present") is False, "application_disrupted": disrupted,
                  "route_still_present": fault.get("backend_route_present") is True}
    elif scenario == "link-loss":
        first, second = baseline.get("backend_route_nexthop"), fault.get("backend_route_nexthop")
        checks = {"primary_link_down": fault.get("primary_link_up") is False,
                  "alternate_route_selected": bool(first and second and first != second),
                  "service_available_over_alternate": successes > 0}
    elif scenario == "packet-loss":
        base_p50 = phases.get("baseline", {}).get("probe", {}).get("latency_ms", {}).get("p50")
        fault_p50 = probe.get("latency_ms", {}).get("p50")
        checks = {"impairment_observed": fault.get("netem_active") is True,
                  "application_effect_observed": disrupted or (isinstance(base_p50, (int, float)) and isinstance(fault_p50, (int, float)) and fault_p50 > base_p50 + 10)}
    elif scenario == "gateway-overload":
        before = baseline.get("gateway_metrics", {}).get("rejected")
        after = fault.get("gateway_metrics", {}).get("rejected")
        checks = {"gateway_rejections_increased": isinstance(before, (int, float)) and isinstance(after, (int, float)) and after > before,
                  "application_disrupted": disrupted}
    return {"checks": checks, "verified": bool(checks) and all(checks.values())}


def run_experiment(lab, scenario: str, output: Path, *, duration=2.0, concurrency=2, payload=256, rate=20.0):
    if scenario not in SCENARIOS:
        raise ValueError("Unknown scenario: " + scenario)
    validate_workload(duration, concurrency, payload, rate)
    output = output.absolute()
    if output.is_symlink() or output.exists():
        raise ValueError("Experiment output must be a new directory: " + str(output))
    if lab.status().get("active"):
        raise RuntimeError("An existing lab is active; stop it before an experiment owns the lifecycle")
    output.mkdir(parents=True, mode=0o700)
    origin = time.monotonic()
    experiment = {
        "schema_version": 1, "experiment_id": uuid.uuid4().hex,
        "scenario": scenario, "started_at": timestamp(),
        "environment": {"platform": platform.platform(), "kernel": platform.release(),
                        "python": platform.python_version(), "netlab_version": __version__,
                        "logical_cpus": __import__("os").cpu_count(), "doctor": lab.doctor()},
        "source": source_metadata(), "topology": {},
        "workload": {"duration_seconds": duration, "concurrency": concurrency,
                     "payload_bytes": payload, "rate_per_second": rate, "connection_model": "one TCP connection per verified echo"},
        "phases": {}, "events": [], "fault": {}, "cleanup": {}, "artifacts": [], "measurements": {},
    }

    def event(kind, details=None):
        record = {"sequence": len(experiment["events"]) + 1, "type": kind,
                  "observed_at": timestamp(), "elapsed_seconds": time.monotonic() - origin, "details": details or {}}
        experiment["events"].append(record)
        write_json(output / "events.json", experiment["events"])
        return record

    def phase(name, *, phase_duration=duration, phase_concurrency=concurrency, phase_rate=rate):
        folder = output / name
        folder.mkdir()
        start = event(name + "-started")
        probe = lab.probe(folder / "probe.json", duration=phase_duration, concurrency=phase_concurrency,
                          payload=payload, rate=phase_rate)
        snapshot = lab.snapshot(folder / "snapshot")
        snapshot["artifact_base"] = name + "/snapshot"
        artifacts = [name + "/probe.json"] + [name + "/snapshot/" + p for p in snapshot.get("artifacts", [])]
        value = {"probe": probe, "snapshot": snapshot, "artifacts": artifacts,
                 "observed_at": start["observed_at"], "elapsed_seconds": start["elapsed_seconds"],
                 "completed_elapsed_seconds": time.monotonic() - origin,
                 "effective_workload": {"duration_seconds": phase_duration, "concurrency": phase_concurrency,
                                        "rate_per_second": phase_rate, "payload_bytes": payload}}
        experiment["phases"][name] = value
        experiment["artifacts"].extend(artifacts)
        event(name + "-finished", {"attempts": probe.get("attempts"), "successes": probe.get("successes")})
        return value

    failure = None
    try:
        event("startup-started")
        experiment["topology"] = lab.up()
        event("startup-finished")
        baseline = phase("baseline")
        if not baseline["probe"].get("successes") or baseline["probe"].get("successes") != baseline["probe"].get("attempts"):
            raise RuntimeError("Healthy baseline did not transfer every payload correctly")
        applied = event("fault-application-started", {"kind": scenario})
        experiment["fault"] = lab.apply_fault(scenario)
        event("fault-applied", experiment["fault"])
        faulted = phase("fault", phase_concurrency=max(48, concurrency) if scenario == "gateway-overload" else concurrency,
                        phase_rate=0 if scenario == "gateway-overload" else rate)
        failures = [s for s in faulted["probe"].get("samples", []) if s.get("success") is False]
        if failures:
            sample = min(failures, key=lambda s: s.get("elapsed_seconds", float("inf")))
            elapsed = sample.get("elapsed_seconds")
            if isinstance(elapsed, (int, float)) and elapsed >= 0:
                experiment["measurements"]["fault_to_detection_seconds"] = {
                    "value_seconds": faulted["elapsed_seconds"] + elapsed - applied["elapsed_seconds"],
                    "definition": "Time from beginning fault application to completion of first failed sampled echo; includes collection gap and probe timeout.",
                    "evidence": ["events.json", "fault/probe.json"]}
        restored = event("restoration-started")
        experiment["restoration"] = lab.restore_fault()
        event("restoration-finished", experiment["restoration"])
        recovery = phase("recovery", phase_duration=max(1.0, duration))
        successes = [s for s in recovery["probe"].get("samples", []) if s.get("success") is True]
        if successes:
            elapsed = min(s.get("elapsed_seconds", float("inf")) for s in successes)
            if math.isfinite(elapsed):
                experiment["measurements"]["first_success_after_restoration_seconds"] = {
                    "value_seconds": recovery["elapsed_seconds"] + elapsed - restored["elapsed_seconds"],
                    "definition": "Time from starting restoration to first successful sampled echo completion; restoration and sampling gaps included. Earlier success may be unobserved.",
                    "evidence": ["events.json", "recovery/probe.json"]}
        if recovery["probe"].get("attempts", 0) >= 2 and recovery["probe"].get("attempts") == recovery["probe"].get("successes"):
            experiment["measurements"]["stable_recovery_seconds"] = {
                "value_seconds": recovery["elapsed_seconds"] + recovery["probe"].get("duration_seconds", 0) - restored["elapsed_seconds"],
                "definition": "Completion of the error-free post-restoration probe window (at least one second); independent state recovery is evaluated separately. This is a sampled bound, not continuous health assurance.",
                    "evidence": ["events.json", "recovery/probe.json", "recovery/snapshot/snapshot.json"]}
    except BaseException as exc:
        failure = exc
        experiment["failure"] = {"type": type(exc).__name__, "message": str(exc)}
        event("experiment-failed", experiment["failure"])
    finally:
        event("cleanup-started")
        try:
            experiment["cleanup"] = lab.down()
            for name in ("captures", "logs"):
                folder = lab.root / name
                if folder.is_dir() and not folder.is_symlink():
                    shutil.copytree(folder, output / "final" / name, symlinks=False)
        except BaseException as exc:
            experiment["cleanup"] = {"clean": False, "error": str(exc)}
            if failure is None:
                failure = exc
        event("cleanup-finished", experiment["cleanup"])
        experiment["finished_at"] = timestamp()
        experiment["duration_seconds"] = time.monotonic() - origin
        experiment["result"] = analyze(experiment)
        experiment["result"]["scenario_validation"] = scenario_checks(experiment)
        experiment["result"]["cleanup_verified"] = experiment["cleanup"].get("clean") is True
        experiment["result"]["passed"] = not failure and experiment["result"].get("recovered") is True and experiment["cleanup"].get("clean") is True and experiment["result"]["scenario_validation"]["verified"]
        write_json(output / "experiment.json", experiment)
        (output / "report.md").write_text(render(experiment), encoding="utf-8")
        write_json(output / "manifest.json", {"algorithm": "sha256", "files": file_manifest(output)})
    if failure:
        raise RuntimeError("Experiment failed; preserved evidence in " + str(output)) from failure
    return experiment
