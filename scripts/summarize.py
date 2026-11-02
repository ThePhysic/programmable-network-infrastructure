#!/usr/bin/env python3
"""Summarize real experiment records without pooling incompatible workloads."""
from __future__ import annotations

import argparse
from collections import defaultdict
from collections.abc import Mapping
import glob
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from netlab.report import analyze, PHASES  # noqa: E402
from netlab.experiment import scenario_checks  # noqa: E402


def distribution(values):
    finite = [float(value) for value in values
              if not isinstance(value, bool) and isinstance(value, (int, float))
              and math.isfinite(value) and value >= 0]
    return {"count": len(finite), "median": statistics.median(finite) if finite else None,
            "min": min(finite) if finite else None, "max": max(finite) if finite else None}


def discover(inputs):
    """Accept files, directories, or recursive glob patterns; deduplicate trials."""
    paths = set()
    for value in inputs:
        direct = Path(value)
        matches = [direct] if direct.exists() else [Path(item) for item in glob.glob(str(value), recursive=True)]
        for match in matches:
            if match.is_symlink():
                continue
            if match.is_dir():
                paths.update(path.resolve() for path in match.rglob("experiment.json")
                             if path.is_file() and not path.is_symlink())
            elif match.is_file() and match.name == "experiment.json":
                paths.add(match.resolve())
    return sorted(paths)


def _map(value):
    return value if isinstance(value, Mapping) else {}


def _fingerprint(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def comparison_context(experiment):
    environment = dict(_map(experiment.get("environment")))
    doctor = dict(_map(environment.get("doctor")))
    doctor.pop("binary", None)  # Local binary location does not alter the workload.
    if doctor:
        environment["doctor"] = doctor
    source_files = _map(_map(experiment.get("source")).get("files_sha256"))
    executable_sources = {name: digest for name, digest in source_files.items()
                          if name == "go.mod" or name.startswith(("netlab/", "cmd/", "internal/"))}
    workload = dict(_map(experiment.get("workload")))
    topology = dict(_map(experiment.get("topology")))
    topology.pop("namespace_prefix", None)
    effective = {name: dict(_map(_map(_map(experiment.get("phases")).get(name)).get("effective_workload")))
                 for name in PHASES}
    complete = (bool(environment.get("kernel")) and bool(environment.get("logical_cpus"))
                and all(key in workload for key in ("duration_seconds", "concurrency", "payload_bytes"))
                and all(effective.values()) and bool(executable_sources) and bool(topology.get("id")))
    return {"environment": environment, "topology": topology, "workload": workload, "effective_workloads": effective,
            "execution_source_sha256": _fingerprint(executable_sources) if executable_sources else None,
            "context_complete": complete}


def aggregate(paths):
    """Aggregate medians/ranges of per-trial metrics, recomputing analysis."""
    records = defaultdict(list)
    invalid = []
    seen_ids = {}
    for path in paths:
        path = Path(path)
        try:
            experiment = json.loads(path.read_text(encoding="utf-8"), parse_constant=_reject_constant)
            result = analyze(experiment)
            scenario = experiment.get("scenario")
            identity = experiment.get("experiment_id")
            if not isinstance(scenario, str) or not scenario:
                raise ValueError("Missing scenario identity")
            if not isinstance(identity, str) or not identity:
                raise ValueError("Missing experiment identity")
            if identity in seen_ids:
                raise ValueError("Duplicate experiment_id also present in " + seen_ids[identity])
            seen_ids[identity] = str(path)
            context = comparison_context(experiment)
            validation = scenario_checks(experiment)
            passed = (result["recovered"] and result["cleanup_verified"]
                      and validation["verified"] and not experiment.get("failure"))
            records[scenario].append({"path": str(path), "experiment_id": identity, "analysis": result,
                                      "gateway_snapshots": {phase: dict(_map(_map(_map(_map(experiment.get("phases")).get(phase)).get("snapshot")).get("observations")).get("gateway_metrics", {}))
                                                            for phase in PHASES},
                                      "context": context, "passed": passed})
        except (OSError, ValueError, TypeError, KeyError) as exc:
            invalid.append({"path": str(path), "error": str(exc)})
    scenarios = {}
    for scenario, trials in sorted(records.items()):
        groups = defaultdict(list)
        for trial in trials:
            groups[_fingerprint(trial["context"])].append(trial)
        comparable = len(groups) == 1 and all(item["context"]["context_complete"] for item in trials)
        grouped = []
        for identity, members in sorted(groups.items()):
            phases = {}
            for phase in PHASES:
                probes = [item["analysis"]["metrics"]["phases"][phase] for item in members]
                measurements = {key: distribution(probe.get(key) for probe in probes) for key in
                                ("attempts", "successes", "failures", "success_rate", "duration_seconds",
                                 "attempts_per_second", "successful_bytes")}
                measurements["latency_ms"] = {
                    key: distribution(probe["latency_ms"].get(key) for probe in probes)
                    for key in ("p50", "p95", "p99")}
                measurements["gateway_snapshot"] = {
                    key: distribution(_map(item["gateway_snapshots"][phase]).get(key) for item in members)
                    for key in ("goroutines", "rss_bytes", "heap_alloc_bytes", "file_descriptors", "cpu_total_seconds")}
                phases[phase] = measurements
            clocks = {}
            for clock in next(iter(members))["analysis"]["metrics"]["timings"]:
                items = [item["analysis"]["metrics"]["timings"][clock] for item in members]
                clocks[clock] = distribution(item["value_seconds"] for item in items)
                clocks[clock]["definitions"] = sorted(set(item["definition"] for item in items))
            grouped.append({"comparison_group": identity[:12], "trial_count": len(members),
                            "context": members[0]["context"], "phases": phases, "timings_seconds": clocks,
                            "trials": [{"experiment_id": item["experiment_id"],
                                        "source": item["path"], "passed": item["passed"],
                                        "recovered": item["analysis"]["recovered"],
                                        "cleanup_verified": item["analysis"]["cleanup_verified"],
                                        "diagnosis_confidence": item["analysis"]["diagnosis"]["confidence"]}
                                       for item in members]})
        scenarios[scenario] = {"trial_count": len(trials), "passed": sum(item["passed"] for item in trials),
                               "recovered": sum(item["analysis"]["recovered"] for item in trials),
                               "cleanup_verified": sum(item["analysis"]["cleanup_verified"] for item in trials),
                               "comparability": "comparable" if comparable else "mixed" if len(groups) > 1 else "incomplete",
                               "groups": grouped}
    return {"schema_version": 1, "trial_count": sum(len(items) for items in records.values()),
            "invalid_trials": invalid, "scenarios": scenarios,
            "method": {"aggregation": "Median and observed range of per-trial metrics; no pooled quantiles.",
                       "latency": "Percentiles include successful complete byte-verified operations only; failure rates are separate.",
                       "comparability": "Different environment, effective workload, or execution source hashes form separate groups. Missing context is disclosed.",
                       "timing": "Recovery clocks are sampled bounds with the recorded definitions; missing route convergence remains unmeasured.",
                       "resources": "Gateway resource values are post-phase snapshots, not peaks; CPU seconds are cumulative process lifetime, not phase utilization.",
                       "limitations": ["No confidence intervals or statistical significance are inferred from observed ranges.",
                                       "Fault-phase gateway overload intentionally changes concurrency and rate; do not attribute that comparison solely to a network change.",
                                       "A VM/namespace lab does not establish physical-network or production performance."]}}


def _reject_constant(value):
    raise ValueError("Non-finite JSON number: " + value)


def _cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _stat(item):
    if not item["count"]:
        return "unmeasured"
    return f"{item['median']:.3f} [{item['min']:.3f}, {item['max']:.3f}] (n={item['count']})"


def markdown(summary):
    lines = ["# Repeated network experiment measurements", "",
             f"Valid trials: **{summary['trial_count']}**. Invalid or duplicate records: **{len(summary['invalid_trials'])}**.", "",
             "Values are median [minimum, maximum] across trials. Each trial contributes its own metric; latency percentiles are never pooled.", ""]
    for scenario, result in summary["scenarios"].items():
        lines += ["## " + _cell(scenario), "",
                  f"Trials: {result['trial_count']}; accepted: {result['passed']}; restored: {result['recovered']}; clean teardown: {result['cleanup_verified']}.", "",
                  "Comparability: **" + result["comparability"] + "**. Different comparison groups are shown separately.", ""]
        for group in result["groups"]:
            lines += ["### Comparison group " + group["comparison_group"], "",
                      "```json", json.dumps(group["context"], indent=2, sort_keys=True), "```", "",
                      "| Phase | Attempts | Success fraction | Attempts/s | p50 ms | p95 ms | p99 ms |", "|---|---:|---:|---:|---:|---:|---:|"]
            for phase, metrics in group["phases"].items():
                cells = [phase, _stat(metrics["attempts"]), _stat(metrics["success_rate"]), _stat(metrics["attempts_per_second"]),
                         *(_stat(metrics["latency_ms"][key]) for key in ("p50", "p95", "p99"))]
                lines.append("| " + " | ".join(cells) + " |")
            lines += ["", "Gateway post-phase snapshots (CPU seconds are cumulative process lifetime; these are not peaks):", "",
                      "| Phase | Goroutines | RSS bytes | Heap bytes | File descriptors | Cumulative CPU seconds |", "|---|---:|---:|---:|---:|---:|"]
            for phase, measurements in group["phases"].items():
                resources = measurements["gateway_snapshot"]
                lines.append("| " + phase + " | " + " | ".join(_stat(resources[key]) for key in
                             ("goroutines", "rss_bytes", "heap_alloc_bytes", "file_descriptors", "cpu_total_seconds")) + " |")
            lines += ["", "| Recovery clock | Seconds | Recorded definition |", "|---|---:|---|"]
            for clock, stats in group["timings_seconds"].items():
                lines.append("| " + clock + " | " + _stat(stats) + " | " + _cell("; ".join(stats["definitions"])) + " |")
            lines += ["", "Trials: " + ", ".join("`" + _cell(item["experiment_id"]) + "`" for item in group["trials"]) + ".", ""]
    if summary["invalid_trials"]:
        lines += ["## Invalid records", ""]
        lines += ["- " + _cell(item["path"]) + ": " + _cell(item["error"]) for item in summary["invalid_trials"]]
        lines.append("")
    lines += ["## Method and limits", ""]
    lines += ["- " + summary["method"][key] for key in ("aggregation", "latency", "comparability", "timing", "resources") if key in summary["method"]]
    lines += ["- " + item for item in summary["method"]["limitations"]]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", help="Experiment directories, experiment.json files, or recursive globs")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", type=Path, help="Write this file; otherwise print to stdout")
    args = parser.parse_args(argv)
    paths = discover(args.inputs)
    if not paths:
        parser.error("No experiment.json files matched the inputs")
    summary = aggregate(paths)
    text = (json.dumps(summary, indent=2, sort_keys=True, allow_nan=False) + "\n"
            if args.format == "json" else markdown(summary))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 1 if summary["invalid_trials"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
