"""Evidence-linked experiment reports; injected labels never select a diagnosis."""
from __future__ import annotations

from collections.abc import Mapping
import json
import math
from pathlib import PurePosixPath
from typing import Any

PHASES = ("baseline", "fault", "recovery")
FIELDS = ("backend_route_present", "bgp_backend_prefix_present", "bgp_peers_established",
          "backend_prefix_denied", "backend_prefix_policy_present", "backend_prefix_policy",
          "backend_listener_present", "dns_ok", "primary_link_up", "netem_active",
          "firewall_drop_active", "firewall_drop_packets", "backend_route_nexthop",
          "dns_result", "gateway_metrics")
REQUIRED = {"backend_route_present": True, "backend_listener_present": True,
            "dns_ok": True, "primary_link_up": True, "netem_active": False,
            "bgp_peers_established": True, "bgp_backend_prefix_present": True,
            "firewall_drop_active": False, "backend_prefix_denied": False,
            "backend_prefix_policy_present": False}
TIMINGS = {
    "fault_to_detection_seconds": "Fault application to the first independently observed failed operation.",
    "route_convergence_seconds": "Routing change to a defined observed converged route state.",
    "first_success_after_restoration_seconds": "Restoration start to the first successful application operation.",
    "stable_recovery_seconds": "Restoration start to a stated sustained healthy observation window.",
}


def _map(value: Any) -> Mapping:
    return value if isinstance(value, Mapping) else {}


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) and value >= 0 else None


def _integer(value: Any) -> int | None:
    number = _number(value)
    return int(number) if number is not None and number.is_integer() else None


def _paths(value: Any, base: str = "") -> list[str]:
    """Keep evidence inside the report tree; do not link absolute/escaping paths."""
    values = value if isinstance(value, list) else [value]
    result = []
    prefix = PurePosixPath(base.replace("\\", "/"))
    if prefix.is_absolute() or ".." in prefix.parts or ":" in str(prefix):
        return result
    for item in values:
        if not isinstance(item, str) or not item:
            continue
        path = PurePosixPath(item.replace("\\", "/"))
        if path.is_absolute() or ".." in path.parts or ":" in item:
            continue
        joined = str(prefix / path)
        if joined not in result:
            result.append(joined)
    return result


def _probe(probe: Mapping) -> dict:
    attempts, successes = (_integer(probe.get(key)) for key in ("attempts", "successes"))
    errors = _map(probe.get("errors"))
    valid_errors = all(_integer(count) is not None for count in errors.values())
    error_count = sum(int(count) for count in errors.values()) if valid_errors else None
    valid = (attempts is not None and successes is not None and successes <= attempts
             and error_count is not None and successes + error_count == attempts)
    duration = _number(probe.get("duration_seconds"))
    latency = _map(probe.get("latency_ms"))
    return {"attempts": attempts, "successes": successes,
            "failures": attempts - successes if valid else None,
            "errors": dict(errors) if valid_errors else {}, "valid": valid,
            "all_successful": bool(valid and attempts > 0 and successes == attempts),
            "success_rate": successes / attempts if valid and attempts else None,
            "duration_seconds": duration,
            "attempts_per_second": attempts / duration if valid and duration else None,
            "successful_bytes": _integer(probe.get("bytes")),
            "latency_ms": {key: _number(latency.get(key)) if successes else None for key in ("p50", "p95", "p99")},
            "samples_truncated": bool(probe.get("samples_truncated", False))}


def analyze(experiment: dict) -> dict:
    """Analyze observed state conservatively, keeping missing evidence unknown."""
    if not isinstance(experiment, Mapping) or experiment.get("schema_version") != 1:
        raise ValueError("Expected an experiment object with schema_version 1")
    phases = _map(experiment.get("phases"))
    observations, by_id, states, limitations = [], {}, {}, []
    metrics = {"phases": {}, "timings": {}}

    def observe(phase, subject, value, evidence):
        identity = phase + "." + subject
        record = {"id": identity, "phase": phase, "subject": subject, "value": value,
                  "evidence": evidence,
                  "observed_at": _map(_map(phases.get(phase)).get("snapshot")).get("observed_at")
                  if subject not in ("probe", "direct_probe") else _map(phases.get(phase)).get("observed_at")}
        observations.append(record)
        by_id[identity] = record

    for name in PHASES:
        phase = _map(phases.get(name))
        snapshot = _map(phase.get("snapshot"))
        state = dict(_map(snapshot.get("observations")))
        states[name] = state
        evidence = _map(snapshot.get("evidence"))
        base = snapshot.get("artifact_base", "")
        base = base if isinstance(base, str) else ""
        for key in FIELDS:
            if key in state and state[key] is not None:
                observe(name, key, state[key], _paths(evidence.get(key), base))
        probe = _probe(_map(phase.get("probe")))
        metrics["phases"][name] = probe
        path = phase.get("probe_artifact")
        if not path:
            path = [item for item in phase.get("artifacts", [])
                    if isinstance(item, str) and item.endswith("probe.json")]
        observe(name, "probe", probe, _paths(path))
        if "direct_probe" in phase:
            direct = _probe(_map(phase.get("direct_probe")))
            metrics["phases"][name]["direct_probe"] = direct
            observe(name, "direct_probe", direct, _paths(phase.get("direct_probe_artifact")))
        if not probe["valid"]:
            limitations.append(name + ": missing or inconsistent probe operation counts.")
        if probe["attempts"] is not None and probe["attempts"] < 100:
            limitations.append(name + ": fewer than 100 operations; tail percentiles have limited resolution.")
        if probe["samples_truncated"]:
            limitations.append(name + ": per-operation samples were truncated; aggregate counts remain separate.")

    baseline, fault, recovery = (states[name] for name in PHASES)
    fault_probe = metrics["phases"]["fault"]
    failing = fault_probe["valid"] and fault_probe["failures"] > 0
    successful = fault_probe["all_successful"]
    candidates, conflicts = [], []

    def candidate(claim, support, confidence="supported"):
        support = [identity for identity in support if identity in by_id]
        sourced = bool(support and all(by_id[identity]["evidence"] for identity in support))
        candidates.append({"claim": claim, "support": support,
                           "confidence": confidence if sourced else "partial"})
        if not sourced:
            limitations.append("Some supporting observations lack linked primary artifacts; the interpretation is provisional.")

    route_lost = baseline.get("backend_route_present") is True and fault.get("backend_route_present") is False
    dns_lost = baseline.get("dns_ok") is True and fault.get("dns_ok") is False
    listener_lost = baseline.get("backend_listener_present") is True and fault.get("backend_listener_present") is False
    before, after = (_integer(state.get("firewall_drop_packets")) for state in (baseline, fault))
    drop_increase = before is not None and after is not None and after > before
    before, after = (_integer(_map(state.get("gateway_metrics")).get("rejected")) for state in (baseline, fault))
    rejection_increase = before is not None and after is not None and after > before
    if route_lost and failing:
        support = ["baseline.backend_route_present", "fault.backend_route_present", "fault.probe"]
        if baseline.get("bgp_backend_prefix_present") is True and fault.get("bgp_backend_prefix_present") is False:
            support += ["baseline.bgp_backend_prefix_present", "fault.bgp_backend_prefix_present"]
            claim = "The backend prefix disappeared from BGP and the forwarding table while application operations failed."
        else:
            claim = "The backend forwarding route disappeared while application operations failed; the routing mechanism is not fully established."
        if fault.get("backend_prefix_denied") is True:
            support.append("fault.backend_prefix_denied")
            if baseline.get("backend_prefix_denied") is False:
                support.append("baseline.backend_prefix_denied")
            claim = ("An inbound BGP policy attached to both r1 neighbors denied the backend prefix, as observed in routing policy state. " + claim)
        candidate(claim, support)
    if dns_lost and failing:
        claim = "Name resolution failed while application operations failed; a DNS failure is supported by resolver evidence."
        support = ["baseline.dns_ok", "fault.dns_ok", "fault.probe"]
        direct = _map(fault_probe.get("direct_probe"))
        if direct.get("all_successful") is True:
            claim += " A gateway-origin direct-IP control succeeded along the gateway-to-backend route, supporting a name-versus-transport distinction. This control bypasses DNS and proxy forwarding and does not verify the client-to-proxy hop."
            support.append("fault.direct_probe")
        elif direct.get("valid") is True and direct.get("failures", 0) > 0:
            limitations.append("The gateway-origin direct-IP control also failed; DNS evidence does not establish the sole failure mechanism.")
        candidate(claim, support)
    if listener_lost and failing:
        candidate("The backend listener became unavailable while application operations failed.",
                  ["baseline.backend_listener_present", "fault.backend_listener_present", "fault.probe"])
    if drop_increase and failing:
        candidate("The lab firewall drop counter increased while application operations failed, supporting packet filtering as a contributing mechanism.",
                  ["baseline.firewall_drop_packets", "fault.firewall_drop_packets", "fault.probe"])
    if rejection_increase and failing:
        candidate("The gateway rejected additional connections while application operations failed, supporting gateway resource pressure.",
                  ["baseline.gateway_metrics", "fault.gateway_metrics", "fault.probe"])
    link_failed = baseline.get("primary_link_up") is True and fault.get("primary_link_up") is False
    before_hop, after_hop = (state.get("backend_route_nexthop") for state in (baseline, fault))
    changed_hop = before_hop is not None and after_hop is not None and before_hop != after_hop
    if link_failed and changed_hop and fault_probe["successes"]:
        candidate("The primary link went down, the selected backend next hop changed, and the phase recorded byte-verified successful traffic. These observations support alternate-path reachability; they do not resolve every packet's path or interruption timing.",
                  ["baseline.primary_link_up", "fault.primary_link_up", "baseline.backend_route_nexthop", "fault.backend_route_nexthop", "fault.probe"])
    elif link_failed:
        candidate("The primary link was observed down. Available evidence does not independently establish use of an alternate path.",
                  ["baseline.primary_link_up", "fault.primary_link_up", "fault.probe"], "partial")
    if baseline.get("netem_active") is False and fault.get("netem_active") is True:
        before_p95 = metrics["phases"]["baseline"]["latency_ms"]["p95"]
        after_p95 = fault_probe["latency_ms"]["p95"]
        claim = "A link impairment was observed in traffic-control state."
        if before_p95 is not None and after_p95 is not None and after_p95 > before_p95:
            claim += " Measured p95 latency rose; this alone does not isolate loss from delay or establish statistical significance."
        elif failing:
            claim += " Application failures occurred in the impaired phase."
        candidate(claim, ["baseline.netem_active", "fault.netem_active", "baseline.probe", "fault.probe"], "partial")
    for changed, subject in ((route_lost, "backend route was observed absent"),
                             (dns_lost, "DNS control lookup failed"),
                             (listener_lost, "backend listener was observed absent")):
        if changed and successful:
            conflicts.append("The " + subject + " while all measured operations succeeded; timing, caching, or a different path needs investigation.")
    if len(candidates) > 1:
        limitations.append("Multiple mechanisms have supporting observations; the report does not establish a unique root cause.")
    if candidates:
        confidence = "supported" if all(item["confidence"] == "supported" for item in candidates) and not conflicts else "partial"
        diagnosis = {"claim": " ".join(item["claim"] for item in candidates),
                     "support": list(dict.fromkeys(identity for item in candidates for identity in item["support"])),
                     "conflicts": conflicts, "confidence": confidence, "mechanisms": candidates}
    else:
        claim = ("Application failures were observed, but the collected evidence does not isolate a network or service mechanism." if failing else
                 "No application disruption was established during the sampled fault workload." if successful else
                 "The available observations are insufficient to establish the application outcome.")
        diagnosis = {"claim": claim, "support": ["fault.probe"], "conflicts": conflicts,
                     "confidence": "insufficient", "mechanisms": []}

    checks = {"baseline_payload_transfer": metrics["phases"]["baseline"]["all_successful"] if metrics["phases"]["baseline"]["valid"] else None,
              "recovery_payload_transfer": metrics["phases"]["recovery"]["all_successful"] if metrics["phases"]["recovery"]["valid"] else None}
    for name in ("baseline", "recovery"):
        if checks[name + "_payload_transfer"] is True and not by_id[name + ".probe"]["evidence"]:
            checks[name + "_payload_transfer"] = None
    for key, expected in REQUIRED.items():
        before, after = baseline.get(key), recovery.get(key)
        checks[key] = (before is expected and after is expected) if before is not None and after is not None else None
        if checks[key] is True and (not by_id["baseline." + key]["evidence"] or not by_id["recovery." + key]["evidence"]):
            checks[key] = None
    for key in ("backend_route_nexthop",):
        before, after = baseline.get(key), recovery.get(key)
        if before is not None:
            checks[key] = before == after if after is not None else None
            if checks[key] is True and (not by_id["baseline." + key]["evidence"] or not by_id["recovery." + key]["evidence"]):
                checks[key] = None
    recovered = all(value is True for value in checks.values())
    status = "verified" if recovered else "failed" if any(value is False for value in checks.values()) else "unverified"
    limitations += ["Recovery is unverified for " + key + "." for key, value in checks.items() if value is None]
    for key, description in TIMINGS.items():
        item = _map(_map(experiment.get("measurements")).get(key))
        value, refs, definition = _number(item.get("value_seconds")), _paths(item.get("evidence")), item.get("definition")
        measured = value is not None and bool(refs) and isinstance(definition, str) and bool(definition.strip())
        metrics["timings"][key] = {"value_seconds": value if measured else None,
                                    "definition": definition if measured else description,
                                    "evidence": refs if measured else []}
        if not measured:
            limitations.append(key + " was not independently measured; phase snapshots do not establish this timing.")
    cleanup = _map(experiment.get("cleanup"))
    cleanup_verified = (cleanup.get("clean") is True
                        and isinstance(cleanup.get("namespaces_remaining"), list)
                        and not cleanup["namespaces_remaining"]
                        and not cleanup.get("ownership_conflicts")
                        and not cleanup.get("errors") and not cleanup.get("error")
                        and not cleanup.get("processes_remaining"))
    if not cleanup_verified:
        limitations.append("Lab teardown has not been verified by the supplied cleanup record.")
    limitations.append("Evidence is sampled within one host's local time context; cross-source timestamps do not imply perfect global synchronization.")
    return {"observations": observations, "diagnosis": diagnosis, "recovered": recovered,
            "recovery_status": status, "recovery_checks": checks, "cleanup_verified": cleanup_verified,
            "metrics": metrics, "limitations": list(dict.fromkeys(limitations))}


def _escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ").replace("<", "&lt;").replace(">", "&gt;")


def _display(value: Any) -> str:
    if value is None:
        return "unmeasured"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.3f}"
    return _escape(json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value)


def _links(paths):
    return ", ".join("[artifact](<" + path + ">)" for path in paths) or "not linked"


def render(experiment: dict) -> str:
    """Render standalone Markdown; evidence files accompany the report directory."""
    # Imported here because experiment orchestration imports the report module.
    # Acceptance is regenerated from current evidence, never persisted result flags.
    from .experiment import scenario_checks as evaluate_scenario

    result = analyze(experiment)
    diagnosis = result["diagnosis"]
    scenario = evaluate_scenario(experiment)
    scenario_checks = _map(scenario.get("checks"))
    scenario_verified = (scenario.get("verified") is True and bool(scenario_checks)
                         and all(value is True for value in scenario_checks.values()))
    passed = (result["recovered"]
              and result["cleanup_verified"] and scenario_verified and not experiment.get("failure"))
    acceptance = "passed" if passed else "failed" if scenario_checks else "unverified"
    lines = ["# Network experiment report", "", "Experiment: `" + _escape(experiment.get("experiment_id", "unknown")) + "`  ",
             "Scenario: `" + _escape(experiment.get("scenario", "unknown")) + "`  ",
             "Started: " + _escape(experiment.get("started_at", "unknown")), "", "## Observed outcome", "", diagnosis["claim"], "",
             "Evidence confidence: **" + diagnosis["confidence"] + "**. Restoration: **" + result["recovery_status"]
             + "**. Teardown verified: **" + _display(result["cleanup_verified"]) + "**.", "",
             "Experiment acceptance: **" + acceptance + "**. Scenario verification: **"
             + ("verified" if scenario_verified else "unverified") + "**.", "",
             "## Workload and environment", "", "```json",
             json.dumps({key: experiment.get(key, {}) for key in ("workload", "environment", "topology")}, indent=2, sort_keys=True),
             "```", "", "## Measurements", "",
             "Latency percentiles describe successful complete byte-verified operations. Failure counts have a separate denominator.", "",
             "| Phase | Attempts | Successes | Errors | Success fraction | Duration (s) | Attempts/s | p50 (ms) | p95 (ms) | p99 (ms) |",
             "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for name in PHASES:
        data = result["metrics"]["phases"][name]
        cells = [name, data["attempts"], data["successes"], data["failures"], data["success_rate"],
                 data["duration_seconds"], data["attempts_per_second"], *(data["latency_ms"][key] for key in ("p50", "p95", "p99"))]
        lines.append("| " + " | ".join(_display(value) for value in cells) + " |")
    lines += ["", "### Recovery clocks", "", "| Measurement | Seconds | Definition | Evidence |", "|---|---:|---|---|"]
    for key, item in result["metrics"]["timings"].items():
        lines.append("| " + _escape(key) + " | " + _display(item["value_seconds"]) + " | " + _escape(item["definition"]) + " | " + _links(item["evidence"]) + " |")
    lines += ["", "## Evidence and interpretation", "",
              "Injected-fault information is experiment ground truth. Interpretation is derived independently from these observations.", "",
              "| Observation | Value | Primary evidence |", "|---|---|---|"]
    for item in result["observations"]:
        lines.append("| " + item["id"] + " | " + _display(item["value"]) + " | " + _links(item["evidence"]) + " |")
    lines += ["", "Supporting observations: " + ", ".join("`" + identity + "`" for identity in diagnosis["support"]) + ".", ""]
    if diagnosis["conflicts"]:
        lines += ["Conflicting observations:", "", *("- " + item for item in diagnosis["conflicts"]), ""]
    lines += ["## Restoration checks", "", "| Check | Outcome |", "|---|---|"]
    for key, value in result["recovery_checks"].items():
        lines.append("| " + key + " | " + ("verified" if value is True else "failed" if value is False else "unverified") + " |")
    lines += ["", "## Scenario acceptance", "", "These checks are recomputed from the current observations and describe whether the intended experiment effect was observed; they are separate from the independently recomputed diagnosis.", "",
              "| Check | Outcome |", "|---|---|"]
    for key, value in scenario_checks.items():
        lines.append("| " + _escape(key) + " | " + ("verified" if value is True else "failed" if value is False else "unverified") + " |")
    if not scenario_checks:
        lines.append("| Scenario checks | not supplied |")
    if experiment.get("failure"):
        lines += ["", "Recorded execution failure:", "", "```json", json.dumps(experiment["failure"], indent=2, sort_keys=True), "```"]
    lines += ["", "## Event timeline", "", "| Sequence | Event | Local elapsed (s) | Wall time |", "|---:|---|---:|---|"]
    for event in experiment.get("events", []):
        if isinstance(event, Mapping):
            lines.append("| " + " | ".join(_display(event.get(key)) for key in ("sequence", "type", "elapsed_seconds", "observed_at")) + " |")
    lines += ["", "## Injected change", "", "```json", json.dumps(experiment.get("fault", {}), indent=2, sort_keys=True),
              "```", "", "## Limitations", "", *("- " + item for item in result["limitations"]), "",
              "Primary artifacts and checksums are listed in the experiment manifest. A configured route or disabled injector alone does not prove service recovery.", ""]
    return "\n".join(lines)
