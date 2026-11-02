"""Meaningful negative checks against unsupported causal/recovery claims."""
import copy
import unittest

from netlab.report import analyze, render


def experiment():
    healthy = {
        "backend_route_present": True, "bgp_backend_prefix_present": True,
        "backend_prefix_denied": False,
        "backend_prefix_policy_present": False,
        "bgp_peers_established": True, "backend_listener_present": True,
        "dns_ok": True, "primary_link_up": True, "netem_active": False,
        "firewall_drop_active": False, "firewall_drop_packets": 0,
        "backend_route_nexthop": "10.77.12.2",
        "gateway_metrics": {"rejected": 0, "active_connections": 0},
    }
    value = {"schema_version": 1, "experiment_id": "test-exp", "scenario": "route-withdrawal",
             "started_at": "2026-11-01T00:00:00Z", "fault": {"kind": "route-withdrawal"},
             "cleanup": {"clean": True, "namespaces_remaining": [], "errors": [], "ownership_conflicts": []},
             "phases": {}, "workload": {"payload": 256}}
    for name in ("baseline", "fault", "recovery"):
        value["phases"][name] = {
            "probe": {"attempts": 100, "successes": 100, "errors": {}, "duration_seconds": 2,
                      "bytes": 25600, "latency_ms": {"p50": 1, "p95": 2, "p99": 3}},
            "probe_artifact": name + "/probe.json",
            "snapshot": {"observations": copy.deepcopy(healthy),
                         "artifact_base": name + "/snapshot",
                         "evidence": {key: [key + ".json"] for key in healthy}},
        }
    return value


def fail(value, errors=None):
    value["phases"]["fault"]["probe"].update(
        {"attempts": 10, "successes": 0, "errors": errors or {"timeout": 10}, "bytes": 0})


class ReportTests(unittest.TestCase):
    def test_fault_truth_does_not_select_diagnosis(self):
        value = experiment()
        fail(value)
        result = analyze(value)
        self.assertEqual(result["diagnosis"]["confidence"], "insufficient")
        self.assertIn("does not isolate", result["diagnosis"]["claim"])
        value["scenario"] = "firewall-drop"
        value["fault"] = {"kind": "firewall-drop", "expected_root_cause": "firewall"}
        self.assertEqual(result["diagnosis"], analyze(value)["diagnosis"])

    def test_route_loss_uses_frr_and_kernel_observations(self):
        value = experiment()
        fail(value)
        value["phases"]["fault"]["snapshot"]["observations"].update(
            backend_route_present=False, bgp_backend_prefix_present=False)
        diagnosis = analyze(value)["diagnosis"]
        self.assertEqual(diagnosis["confidence"], "supported")
        self.assertIn("disappeared from BGP", diagnosis["claim"])
        self.assertIn("fault.backend_route_present", diagnosis["support"])

    def test_policy_diagnosis_uses_actual_attached_denial_evidence(self):
        value = experiment()
        value["scenario"] = "firewall-drop"  # The label cannot manufacture policy evidence.
        fail(value)
        value["phases"]["fault"]["snapshot"]["observations"].update(
            backend_route_present=False, bgp_backend_prefix_present=False, backend_prefix_denied=True)
        diagnosis = analyze(value)["diagnosis"]
        self.assertIn("policy attached to both r1 neighbors denied", diagnosis["claim"])
        self.assertIn("fault.backend_prefix_denied", diagnosis["support"])
        self.assertIn("baseline.backend_prefix_denied", diagnosis["support"])
        value["phases"]["fault"]["snapshot"]["observations"]["backend_prefix_denied"] = None
        self.assertNotIn("policy attached", analyze(value)["diagnosis"]["claim"])

    def test_residual_prefix_policy_does_not_verify_restoration(self):
        value = experiment()
        value["phases"]["recovery"]["snapshot"]["observations"]["backend_prefix_denied"] = True
        self.assertFalse(analyze(value)["recovered"])
        del value["phases"]["recovery"]["snapshot"]["observations"]["backend_prefix_denied"]
        self.assertEqual(analyze(value)["recovery_status"], "unverified")

    def test_partial_leftover_prefix_policy_cannot_pass_restoration(self):
        value = experiment()
        state = value["phases"]["recovery"]["snapshot"]["observations"]
        state.update(backend_prefix_denied=False, backend_prefix_policy_present=True)
        result = analyze(value)
        self.assertFalse(result["recovered"])
        self.assertFalse(result["recovery_checks"]["backend_prefix_policy_present"])
        self.assertEqual(result["recovery_status"], "failed")

    def test_missing_artifact_downgrades_interpretation(self):
        value = experiment()
        fail(value)
        value["phases"]["fault"]["snapshot"]["observations"]["dns_ok"] = False
        del value["phases"]["fault"]["snapshot"]["evidence"]["dns_ok"]
        self.assertEqual(analyze(value)["diagnosis"]["confidence"], "partial")

    def test_ambiguous_multiple_failures_not_unique_cause(self):
        value = experiment()
        fail(value)
        state = value["phases"]["fault"]["snapshot"]["observations"]
        state.update(dns_ok=False, backend_listener_present=False)
        result = analyze(value)
        self.assertEqual(len(result["diagnosis"]["mechanisms"]), 2)
        self.assertTrue(any("unique root cause" in item for item in result["limitations"]))

    def test_dns_control_distinguishes_gateway_backend_transport(self):
        value = experiment()
        direct = copy.deepcopy(value["phases"]["fault"]["probe"])
        fail(value)
        fault = value["phases"]["fault"]
        fault["snapshot"]["observations"]["dns_ok"] = False
        fault["direct_probe"] = direct
        fault["direct_probe_artifact"] = "fault/direct-probe.json"
        result = analyze(value)
        self.assertIn("fault.direct_probe", result["diagnosis"]["support"])
        self.assertIn("direct-IP control succeeded", result["diagnosis"]["claim"])
        self.assertIn("does not verify the client-to-proxy hop", result["diagnosis"]["claim"])
        fault["direct_probe"].update(successes=0, errors={"timeout": 100})
        result = analyze(value)
        self.assertTrue(any("direct-IP control also failed" in item for item in result["limitations"]))

    def test_successful_traffic_contradicts_route_loss_outage(self):
        value = experiment()
        value["phases"]["fault"]["snapshot"]["observations"]["backend_route_present"] = False
        result = analyze(value)
        self.assertTrue(result["diagnosis"]["conflicts"])
        self.assertNotIn("operations failed", result["diagnosis"]["claim"])

    def test_counter_reset_is_not_firewall_or_overload_evidence(self):
        value = experiment()
        fail(value)
        value["phases"]["baseline"]["snapshot"]["observations"].update(
            firewall_drop_packets=100, gateway_metrics={"rejected": 50})
        result = analyze(value)
        self.assertEqual(result["diagnosis"]["mechanisms"], [])

    def test_counter_increment_supports_filtering(self):
        value = experiment()
        fail(value)
        value["phases"]["fault"]["snapshot"]["observations"]["firewall_drop_packets"] = 50
        self.assertIn("packet filtering", analyze(value)["diagnosis"]["claim"])

    def test_link_success_needs_changed_next_hop_to_claim_failover(self):
        value = experiment()
        state = value["phases"]["fault"]["snapshot"]["observations"]
        state["primary_link_up"] = False
        result = analyze(value)
        self.assertIn("does not independently establish", result["diagnosis"]["claim"])
        state["backend_route_nexthop"] = "10.77.13.3"
        result = analyze(value)
        self.assertIn("support alternate-path reachability", result["diagnosis"]["claim"])
        self.assertEqual(result["diagnosis"]["confidence"], "supported")

    def test_probe_success_and_matching_state_verify_restoration(self):
        result = analyze(experiment())
        self.assertTrue(result["recovered"])
        self.assertEqual(result["recovery_status"], "verified")
        self.assertTrue(result["cleanup_verified"])

    def test_cleanup_needs_no_remaining_namespace_or_error(self):
        for change in ({"namespaces_remaining": ["pnid-r1"]}, {"errors": ["delete failed"]},
                       {"ownership_conflicts": ["pnid-r2"]}, {"error": "permission denied"}):
            value = experiment()
            value["cleanup"].update(change)
            self.assertFalse(analyze(value)["cleanup_verified"])

    def test_render_exposes_scenario_acceptance_and_recomputes_diagnosis(self):
        value = experiment()
        fail(value)
        value["phases"]["fault"]["snapshot"]["observations"].update(
            backend_route_present=False, bgp_backend_prefix_present=False)
        value["result"] = {"passed": True, "diagnosis": {"claim": "fabricated claim"},
                           "scenario_validation": {"verified": True, "checks": {"intended_effect": True}}}
        text = render(value)
        self.assertIn("Experiment acceptance: **passed**", text)
        self.assertIn("fault_route_absent", text)
        self.assertNotIn("intended_effect", text)
        self.assertNotIn("fabricated claim", text)
        value["phases"]["fault"]["snapshot"]["observations"]["backend_route_present"] = True
        self.assertIn("Experiment acceptance: **failed**", render(value))
        value["phases"]["fault"]["snapshot"]["observations"]["backend_route_present"] = False
        value["result"]["passed"] = False
        self.assertIn("Experiment acceptance: **passed**", render(value))
        value["cleanup"]["errors"] = ["failed cleanup"]
        self.assertIn("Experiment acceptance: **failed**", render(value))

    def test_fault_removal_alone_does_not_verify_recovery(self):
        value = experiment()
        value["fault"]["restored"] = True
        value["phases"]["recovery"]["probe"].update(successes=99, errors={"timeout": 1})
        result = analyze(value)
        self.assertFalse(result["recovered"])
        self.assertEqual(result["recovery_status"], "failed")

    def test_incomplete_recovery_evidence_is_unknown(self):
        value = experiment()
        del value["phases"]["recovery"]["snapshot"]["observations"]["dns_ok"]
        result = analyze(value)
        self.assertFalse(result["recovered"])
        self.assertEqual(result["recovery_status"], "unverified")
        self.assertIsNone(result["recovery_checks"]["dns_ok"])

    def test_missing_recovery_artifact_is_unknown(self):
        value = experiment()
        value["phases"]["recovery"]["snapshot"]["evidence"] = {}
        self.assertEqual(analyze(value)["recovery_status"], "unverified")

    def test_missing_primary_probe_artifact_does_not_verify_recovery(self):
        value = experiment()
        del value["phases"]["recovery"]["probe_artifact"]
        self.assertEqual(analyze(value)["recovery_status"], "unverified")

    def test_residual_fault_filter_does_not_verify_recovery(self):
        value = experiment()
        value["phases"]["recovery"]["snapshot"]["observations"]["firewall_drop_active"] = True
        self.assertFalse(analyze(value)["recovered"])

    def test_residual_impairment_fails_recovery(self):
        value = experiment()
        value["phases"]["recovery"]["snapshot"]["observations"]["netem_active"] = True
        self.assertFalse(analyze(value)["recovered"])

    def test_absent_bgp_baseline_cannot_verify_recovery(self):
        value = experiment()
        for phase in value["phases"].values():
            phase["snapshot"]["observations"]["bgp_peers_established"] = False
        self.assertFalse(analyze(value)["recovered"])

    def test_zero_attempts_cannot_establish_success(self):
        value = experiment()
        value["phases"]["recovery"]["probe"].update(attempts=0, successes=0)
        self.assertFalse(analyze(value)["recovered"])

    def test_invalid_counts_are_not_a_valid_failure_measurement(self):
        value = experiment()
        value["phases"]["fault"]["probe"].update(successes=99, errors={})
        result = analyze(value)
        self.assertFalse(result["metrics"]["phases"]["fault"]["valid"])
        self.assertIsNone(result["metrics"]["phases"]["fault"]["failures"])

    def test_all_failures_have_no_success_latency_percentile(self):
        value = experiment()
        fail(value)
        latency = analyze(value)["metrics"]["phases"]["fault"]["latency_ms"]
        self.assertTrue(all(item is None for item in latency.values()))

    def test_phase_snapshots_do_not_invent_convergence_clocks(self):
        value = experiment()
        for index, phase in enumerate(value["phases"].values()):
            phase["elapsed_seconds"] = index * 10
        timings = analyze(value)["metrics"]["timings"]
        self.assertTrue(all(item["value_seconds"] is None for item in timings.values()))

    def test_documented_sourced_clock_is_preserved(self):
        value = experiment()
        value["measurements"] = {"first_success_after_restoration_seconds": {
            "value_seconds": 1.25, "definition": "Restoration start to completed byte-verified probe.",
            "evidence": ["recovery/probe.json"]}}
        timing = analyze(value)["metrics"]["timings"]["first_success_after_restoration_seconds"]
        self.assertEqual(timing["value_seconds"], 1.25)
        value["measurements"]["first_success_after_restoration_seconds"]["value_seconds"] = float("nan")
        self.assertIsNone(analyze(value)["metrics"]["timings"]["first_success_after_restoration_seconds"]["value_seconds"])

    def test_absolute_and_escaping_artifacts_are_not_linked(self):
        value = experiment()
        snap = value["phases"]["fault"]["snapshot"]
        snap["evidence"]["dns_ok"] = ["../../private", "/etc/passwd", "C:\\secret", "dns.json"]
        observations = analyze(value)["observations"]
        dns = next(item for item in observations if item["id"] == "fault.dns_ok")
        self.assertEqual(dns["evidence"], ["fault/snapshot/dns.json"])

    def test_report_has_standalone_context_and_primary_links(self):
        text = render(experiment())
        for expected in ("Workload and environment", "Evidence and interpretation", "Restoration checks",
                         "fault/snapshot/backend_route_present.json", "unmeasured", "Injected change"):
            self.assertIn(expected, text)

    def test_unknown_or_malformed_version_is_rejected(self):
        for value in (None, [], {}, {"schema_version": 2}):
            with self.assertRaises(ValueError):
                analyze(value)


if __name__ == "__main__":
    unittest.main()
