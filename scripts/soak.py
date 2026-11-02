#!/usr/bin/env python3
"""Run a bounded real-Linux load/soak check and preserve measurements and cleanup."""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import platform
import shutil
import sys
import threading
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from netlab.experiment import file_manifest, source_metadata, timestamp, write_json
from netlab.linux import Lab

FD_NOISE_ALLOWANCE = 4
GOROUTINE_NOISE_ALLOWANCE = 6
MAX_CAPTURE_BYTES = 2_100_000
MAX_ARTIFACT_BYTES = 40 * 1024 * 1024
LOG_TAIL_BYTES = 1024 * 1024


def validate_config(rounds, duration):
    if not isinstance(rounds, int) or isinstance(rounds, bool) or not 5 <= rounds <= 60:
        raise ValueError("rounds must be between 5 and 60")
    if not math.isfinite(duration) or not 0.5 <= duration <= 5:
        raise ValueError("duration must be between 0.5 and 5 seconds per round")


def read_metrics(lab):
    value = lab._metrics()
    required = ("active_connections", "max_connections", "file_descriptors", "goroutines",
                "rss_bytes", "cpu_user_seconds", "cpu_system_seconds", "cpu_total_seconds",
                "accepted", "rejected")
    if not isinstance(value, dict) or any(not isinstance(value.get(key), (int, float))
                                          or not math.isfinite(value[key]) for key in required):
        raise RuntimeError("Linux gateway metrics are missing required resource measurements")
    return value


def wait_idle(lab, *, timeout=5):
    """Require three consecutive idle observations, then return the last one."""
    deadline = time.monotonic() + timeout
    consecutive = 0
    while time.monotonic() < deadline:
        metrics = read_metrics(lab)
        consecutive = consecutive + 1 if metrics["active_connections"] == 0 else 0
        if consecutive >= 3:
            return metrics
        time.sleep(0.05)
    raise RuntimeError("gateway did not return to zero active sessions within five seconds")


def resource_checks(baseline, final):
    return {
        "active_connections_zero": final.get("active_connections") == 0,
        "descriptors_near_baseline": final.get("file_descriptors", math.inf)
        <= baseline["file_descriptors"] + FD_NOISE_ALLOWANCE,
        "goroutines_near_baseline": final.get("goroutines", math.inf)
        <= baseline["goroutines"] + GOROUTINE_NOISE_ALLOWANCE,
        "cpu_counters_monotonic": final.get("cpu_total_seconds", -1) >= baseline["cpu_total_seconds"],
    }


def assess_round(probe, before, after, samples, overload):
    attempts, successes = probe.get("attempts", 0), probe.get("successes", 0)
    errors = probe.get("errors", {})
    checks = {
        "traffic_attempted": attempts > 0,
        "some_verified_echoes": successes > 0,
        "no_payload_corruption": isinstance(errors, dict) and errors.get("integrity", 0) == 0,
        "connection_budget_16": before.get("max_connections") == 16 and after.get("max_connections") == 16,
        "metrics_sampled": bool(samples),
        "sampled_active_bounded": bool(samples) and all(0 <= s["metrics"]["active_connections"] <= 16 for s in samples),
        "idle_active_zero": after.get("active_connections") == 0,
    }
    if overload:
        checks["limit_rejections_observed"] = after.get("rejected", 0) > before.get("rejected", 0)
    else:
        checks["every_echo_verified"] = attempts > 0 and attempts == successes and not errors
    return checks


def environment():
    values = {"platform": platform.platform(), "kernel": platform.release(), "machine": platform.machine(),
              "python": platform.python_version(), "logical_cpus": os.cpu_count()}
    for name, path in (("cpuinfo", Path("/proc/cpuinfo")), ("meminfo", Path("/proc/meminfo"))):
        if path.is_file():
            text = path.read_text()
            if name == "cpuinfo":
                values["cpu_model"] = next((line.split(":", 1)[1].strip() for line in text.splitlines()
                                            if line.startswith("model name")), "unknown")
            else:
                values["memory_context"] = "\n".join(text.splitlines()[:3])
    return values


def final_artifacts(lab, output):
    """Copy flushed ring captures and bounded log tails after teardown."""
    records = []
    total = 0
    for folder in ("captures", "logs"):
        source_folder = lab.root / folder
        if not source_folder.exists():
            continue
        destination = output / "artifacts" / folder
        destination.mkdir(parents=True, exist_ok=True)
        for source in sorted(source_folder.iterdir()):
            if source.is_symlink() or not source.is_file():
                raise RuntimeError("unexpected non-file in owned runtime artifacts")
            size = source.stat().st_size
            if folder == "captures" and size > MAX_CAPTURE_BYTES:
                raise RuntimeError("capture exceeded its configured two MB ring-file bound")
            copied = size if folder == "captures" else min(size, LOG_TAIL_BYTES)
            total += copied
            if total > MAX_ARTIFACT_BYTES:
                raise RuntimeError("final artifact budget exceeded 40 MiB")
            target = destination / source.name
            if folder == "captures":
                shutil.copyfile(source, target)
            else:
                with source.open("rb") as incoming, target.open("wb") as outgoing:
                    incoming.seek(max(0, size - LOG_TAIL_BYTES))
                    shutil.copyfileobj(incoming, outgoing)
            records.append({"path": target.relative_to(output).as_posix(), "source_bytes": size,
                            "retained_bytes": copied, "tail_truncated": copied < size})
    return records


def run_soak(lab, output, *, rounds=10, duration=1.0):
    validate_config(rounds, duration)
    output = Path(output).resolve()
    if lab.status().get("active"):
        raise RuntimeError("soak requires an inactive owned lab")
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    report = {
        "schema_version": 1, "experiment_id": "soak-" + uuid.uuid4().hex,
        "started_at": timestamp(), "environment": environment(), "source": source_metadata(),
        "workload": {"rounds": rounds, "scheduling_seconds_per_round": duration,
                     "normal": {"concurrency": 8, "payload_bytes": 65536, "rate": 0, "hold_seconds": 0},
                     "every_fourth_round": {"concurrency": 48, "payload_bytes": 65536, "rate": 0,
                                            "hold_seconds": 0.25},
                     "operation_timeout_seconds": 1.5, "gateway_connection_budget": 16,
                     "metrics_sample_interval_seconds": 0.1},
        "resource_policy": {"descriptor_allowance_above_warmed_baseline": FD_NOISE_ALLOWANCE,
                            "goroutine_allowance_above_warmed_baseline": GOROUTINE_NOISE_ALLOWANCE,
                            "idle_observation": "three consecutive zero-active observations within five seconds",
                            "rss_policy": "recorded only; Go heap/RSS may retain allocations and no constant-memory claim is made",
                            "peak_policy": "sampled maxima, not exhaustive instantaneous peaks",
                            "cpu_policy": "whole gateway process including diagnostics; per-round deltas are CPU seconds"},
        "rounds": [], "errors": [], "cleanup": None, "passed": False,
    }
    lab.experiment_id = report["experiment_id"]
    baseline = None
    started_owned_runtime = False
    try:
        report["topology"] = lab.up()
        started_owned_runtime = True
        report["doctor"] = lab.doctor()
        warmup = lab.probe(output / "warmup.json", duration=0.3, concurrency=2, payload=1024, rate=20)
        if warmup.get("attempts", 0) == 0 or warmup.get("successes") != warmup.get("attempts") or warmup.get("errors"):
            raise RuntimeError("warmup failed exact echo verification")
        baseline = wait_idle(lab)
        report["warmed_baseline"] = baseline
        for index in range(1, rounds + 1):
            overload = index % 4 == 0
            before = read_metrics(lab)
            samples, sampling_errors = [], []
            stop = threading.Event()
            round_start = time.monotonic()

            def sample():
                while not stop.is_set():
                    try:
                        samples.append({"elapsed_seconds": time.monotonic() - round_start,
                                        "metrics": read_metrics(lab)})
                    except Exception as exc:
                        sampling_errors.append(str(exc))
                        return
                    if stop.wait(0.1):
                        return

            sampler = threading.Thread(target=sample, name="soak-metrics", daemon=True)
            sampler.start()
            try:
                probe = lab.probe(output / ("round-%02d.json" % index), duration=duration,
                                  concurrency=48 if overload else 8, payload=65536,
                                  rate=0, hold=0.25 if overload else 0)
            finally:
                stop.set()
                sampler.join(timeout=4)
                if sampler.is_alive():
                    raise RuntimeError("metrics sampler did not terminate")
            after = wait_idle(lab)
            checks = assess_round(probe, before, after, samples, overload)
            checks["metrics_without_errors"] = not sampling_errors
            checks.update(resource_checks(baseline, after))
            item = {"round": index, "overload": overload, "probe": "round-%02d.json" % index,
                    "metrics_before": before, "metrics_after_idle": after, "resource_samples": samples,
                    "sampling_errors": sampling_errors, "checks": checks, "passed": all(checks.values()),
                    "cpu_seconds": after["cpu_total_seconds"] - before["cpu_total_seconds"],
                    "sampled_peak_active": max((s["metrics"]["active_connections"] for s in samples), default=None),
                    "sampled_peak_rss_bytes": max((s["metrics"]["rss_bytes"] for s in samples), default=None),
                    "elapsed_seconds": time.monotonic() - round_start}
            report["rounds"].append(item)
            write_json(output / "soak.json", report)
            print(json.dumps({"round": index, "overload": overload, "passed": item["passed"],
                              "attempts": probe["attempts"], "successes": probe["successes"],
                              "sampled_peak_active": item["sampled_peak_active"]}), flush=True)
            if not item["passed"]:
                raise RuntimeError("round %d failed: %s" % (index, ", ".join(k for k, v in checks.items() if not v)))
    except Exception as exc:
        report["errors"].append(str(exc))
    finally:
        if baseline is not None:
            try:
                report["final_idle"] = wait_idle(lab)
                report["final_resource_checks"] = resource_checks(baseline, report["final_idle"])
            except Exception as exc:
                report["errors"].append("final resource check: " + str(exc))
        try:
            # A competing startup can win between status() and up(). Never
            # tear down that other experiment after our startup was refused.
            current = lab._state(required=False) if hasattr(lab, "_state") else None
            current_is_ours = current is not None and current.get("experiment_id") == report["experiment_id"]
            if current is not None and not current_is_ours:
                report["cleanup"] = {"clean": False, "skipped_foreign_experiment": True}
            elif started_owned_runtime or current_is_ours or current is None:
                report["cleanup"] = lab.down()
        except Exception as exc:
            report["cleanup"] = {"clean": False, "error": str(exc)}
        try:
            report["artifacts"] = final_artifacts(lab, output)
        except Exception as exc:
            report["errors"].append("artifact collection: " + str(exc))
        report["elapsed_seconds"] = time.monotonic() - started
        report["finished_at"] = timestamp()
        report["passed"] = (not report["errors"] and len(report["rounds"]) == rounds
                            and all(item["passed"] for item in report["rounds"])
                            and all(report.get("final_resource_checks", {"missing": False}).values())
                            and report["cleanup"].get("clean") is True)
        write_json(output / "soak.json", report)
        write_json(output / "manifest.json", {"schema_version": 1, "algorithm": "sha256", "files": file_manifest(output)})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/var/tmp/pnid-soak"))
    parser.add_argument("--output", type=Path, default=Path("results/soak"))
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--duration", type=float, default=1)
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("requires root in a dedicated Linux lab")
    try:
        lab = Lab(args.root, Path(__file__).resolve().parent.parent / "bin/netlab-agent")
        result = run_soak(lab, args.output, rounds=args.rounds, duration=args.duration)
    except (ValueError, RuntimeError, OSError) as exc:
        parser.exit(1, str(exc) + "\n")
    print(json.dumps({"passed": result["passed"], "rounds": len(result["rounds"]),
                      "cleanup": result["cleanup"], "errors": result["errors"]}))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
