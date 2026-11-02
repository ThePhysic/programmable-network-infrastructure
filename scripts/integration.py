#!/usr/bin/env python3
"""Real Linux acceptance checks; no simulated routes or mocked packet paths."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from netlab.experiment import SCENARIOS, run_experiment, write_json
from netlab.linux import Lab


def host_state():
    result = {}
    for name, command in {
        "routes": ["ip", "-j", "route", "show", "table", "all"],
        "firewall": ["nft", "-j", "list", "ruleset"],
        "forwarding": ["sysctl", "-n", "net.ipv4.ip_forward"],
    }.items():
        result[name] = subprocess.run(command, text=True, capture_output=True, check=True, timeout=10).stdout
    return result


def host_configuration(state):
    """Compare configuration while preserving raw, naturally advancing counters."""
    def without_counter_values(value):
        if isinstance(value, list):
            return [without_counter_values(item) for item in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if key == "counter" and isinstance(item, dict):
                    item = {name: field for name, field in item.items() if name not in ("packets", "bytes")}
                result[key] = without_counter_values(item)
            return result
        return value

    routes = json.loads(state["routes"])
    firewall = json.loads(state["firewall"])
    if not isinstance(routes, list) or not isinstance(firewall, dict) or "nftables" not in firewall:
        raise ValueError("Invalid host route/firewall observation")
    return {"routes": sorted(json.dumps(route, sort_keys=True) for route in routes),
            "firewall": without_counter_values(firewall), "forwarding": state["forwarding"].strip()}


def compare_host_configuration(before, after):
    first, second = host_configuration(before), host_configuration(after)
    checks = {key: first[key] == second[key] for key in first}
    return {"unchanged": all(checks.values()), "checks": checks,
            "raw_state_equal": before == after,
            "comparison": "Configuration comparison excludes only nftables counter packets/bytes; raw before/after observations are retained."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("results") / ("acceptance-" + uuid.uuid4().hex[:12]))
    parser.add_argument("--root", type=Path, default=Path("/var/tmp/pnid-integration"))
    parser.add_argument("--trials", type=int, default=1)
    parser.add_argument("--duration", type=float, default=2)
    parser.add_argument("--scenarios", nargs="+", choices=SCENARIOS, default=list(SCENARIOS))
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("requires root in a dedicated Linux lab")
    if not 1 <= args.trials <= 20:
        parser.error("trials must be between 1 and 20")
    binary = Path(__file__).resolve().parent.parent / "bin" / "netlab-agent"
    lab = Lab(args.root, binary)
    args.output.mkdir(parents=True, exist_ok=False)
    before = host_state()
    runs = []
    for trial in range(1, args.trials + 1):
        for scenario in args.scenarios:
            destination = args.output / (scenario + "-" + str(trial))
            print("ACCEPTANCE " + destination.name, flush=True)
            try:
                experiment = run_experiment(lab, scenario, destination, duration=args.duration)
                result = experiment["result"]
                item = {"scenario": scenario, "trial": trial, "passed": result["passed"],
                        "scenario_validation": result["scenario_validation"], "recovered": result["recovered"],
                        "cleanup_verified": result["cleanup_verified"], "measurements": experiment["measurements"],
                        "experiment": destination.name + "/experiment.json"}
            except Exception as exc:
                item = {"scenario": scenario, "trial": trial, "passed": False, "error": str(exc)}
            runs.append(item)
            write_json(args.output / "summary.json", {"runs": runs})
            print(json.dumps(item), flush=True)
    after = host_state()
    comparison = compare_host_configuration(before, after)
    summary = {"runs": runs, "host_state_unchanged": comparison["unchanged"],
               "host_configuration_unchanged": comparison["unchanged"], "host_comparison": comparison,
               "host_state_before": before, "host_state_after": after,
               "passed": all(item["passed"] for item in runs) and comparison["unchanged"]}
    write_json(args.output / "summary.json", summary)
    print(json.dumps({"passed": summary["passed"], "runs": len(runs), "host_configuration_unchanged": comparison["unchanged"]}))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
