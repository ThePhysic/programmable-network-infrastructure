# Network experiment report

Experiment: `f4a721be8baf4bf3bcc4a0d1dc96698d`  
Scenario: `route-withdrawal`  
Started: 2026-11-02T04:17:40.814956+00:00

## Observed outcome

The backend prefix disappeared from BGP and the forwarding table while application operations failed.

Evidence confidence: **supported**. Restoration: **verified**. Teardown verified: **yes**.

Experiment acceptance: **passed**. Scenario verification: **verified**.

## Workload and environment

```json
{
  "environment": {
    "cpu_model": "AMD Ryzen 9 7940HS w/ Radeon 780M Graphics",
    "doctor": {
      "binary": "/mnt/c/Users/ridle/programmable-network-infrastructure/bin/netlab-agent",
      "binary_exists": true,
      "environment": {
        "cpu_count": 16,
        "kernel": "6.18.54.1-microsoft-standard-WSL2",
        "platform": "Linux-6.18.54.1-microsoft-standard-WSL2-x86_64-with-glibc2.39",
        "python": "3.12.3"
      },
      "frr_vty_group_member": true,
      "linux": true,
      "ready": true,
      "root": true,
      "tools": {
        "bgpd": "/usr/lib/frr/bgpd",
        "ip": "/usr/sbin/ip",
        "nft": "/usr/sbin/nft",
        "python3": "/usr/bin/python3",
        "ss": "/usr/bin/ss",
        "tc": "/usr/sbin/tc",
        "tcpdump": "/usr/bin/tcpdump",
        "vtysh": "/usr/bin/vtysh",
        "zebra": "/usr/lib/frr/zebra"
      }
    },
    "frr_version": null,
    "go_binary_version": "/mnt/c/Users/ridle/programmable-network-infrastructure/bin/netlab-agent: go1.22.2",
    "iproute_version": "ip utility, iproute2-6.1.0, libbpf 1.3.0",
    "kernel": "6.18.54.1-microsoft-standard-WSL2",
    "logical_cpus": 16,
    "memory_total": "MemTotal:       15970204 kB",
    "netlab_version": "0.1.0",
    "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
    "platform": "Linux-6.18.54.1-microsoft-standard-WSL2-x86_64-with-glibc2.39",
    "python": "3.12.3"
  },
  "topology": {
    "alternate_path": [
      "gateway",
      "r1",
      "r3",
      "r2",
      "backend"
    ],
    "backend": "10.77.3.2:19090",
    "dns": "10.77.1.1:53",
    "gateway": "10.77.1.1:18080",
    "id": "six-node-bgp-diamond",
    "links": [
      {
        "left": "client",
        "left_address": "10.77.1.2/24",
        "left_interface": "eth0",
        "right": "gateway",
        "right_address": "10.77.1.1/24",
        "right_interface": "client0"
      },
      {
        "left": "gateway",
        "left_address": "10.77.2.2/24",
        "left_interface": "uplink0",
        "right": "r1",
        "right_address": "10.77.2.1/24",
        "right_interface": "gateway0"
      },
      {
        "left": "r1",
        "left_address": "10.77.12.1/24",
        "left_interface": "direct0",
        "right": "r2",
        "right_address": "10.77.12.2/24",
        "right_interface": "direct0"
      },
      {
        "left": "r1",
        "left_address": "10.77.13.1/24",
        "left_interface": "backup0",
        "right": "r3",
        "right_address": "10.77.13.3/24",
        "right_interface": "left0"
      },
      {
        "left": "r3",
        "left_address": "10.77.23.3/24",
        "left_interface": "right0",
        "right": "r2",
        "right_address": "10.77.23.2/24",
        "right_interface": "backup0"
      },
      {
        "left": "r2",
        "left_address": "10.77.3.1/24",
        "left_interface": "service0",
        "right": "backend",
        "right_address": "10.77.3.2/24",
        "right_interface": "eth0"
      }
    ],
    "namespace_prefix": "pnid-fa2106e5aa",
    "nodes": [
      "client",
      "gateway",
      "r1",
      "r2",
      "r3",
      "backend"
    ],
    "primary_path": [
      "gateway",
      "r1",
      "r2",
      "backend"
    ]
  },
  "workload": {
    "concurrency": 2,
    "connection_model": "one TCP connection per verified echo",
    "duration_seconds": 2.0,
    "payload_bytes": 256,
    "rate_per_second": 20.0
  }
}
```

## Measurements

Latency percentiles describe successful complete byte-verified operations. Failure counts have a separate denominator.

| Phase | Attempts | Successes | Errors | Success fraction | Duration (s) | Attempts/s | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline | 40 | 40 | 0 | 1.000 | 1.953 | 20.485 | 2.152 | 3.351 | 4.536 |
| fault | 8 | 0 | 8 | 0.000 | 2.561 | 3.123 | unmeasured | unmeasured | unmeasured |
| recovery | 40 | 40 | 0 | 1.000 | 1.954 | 20.470 | 2.307 | 2.813 | 3.446 |

### Recovery clocks

| Measurement | Seconds | Definition | Evidence |
|---|---:|---|---|
| fault_to_detection_seconds | 0.322 | Conservative upper bound from beginning fault application to first failed sampled echo completion; includes sampling gaps, timeout, and all parent/child launch/return overhead. | [artifact](<events.json>), [artifact](<fault/probe.json>), [artifact](<fault/probe-window.json>) |
| route_convergence_seconds | unmeasured | Routing change to a defined observed converged route state. | not linked |
| first_success_after_restoration_seconds | 0.455 | Conservative upper bound from restoration start to first successful sampled echo; includes restoration, sampling gaps, and all parent/child launch/return overhead. Earlier success may be unobserved. | [artifact](<events.json>), [artifact](<recovery/probe.json>), [artifact](<recovery/probe-window.json>) |
| stable_recovery_seconds | 2.407 | Completion of the error-free post-restoration probe window (at least one second); independent state recovery is evaluated separately. This is a sampled bound, not continuous health assurance. | [artifact](<events.json>), [artifact](<recovery/probe.json>), [artifact](<recovery/probe-window.json>), [artifact](<recovery/snapshot/snapshot.json>) |

## Evidence and interpretation

Injected-fault information is experiment ground truth. Interpretation is derived independently from these observations.

| Observation | Value | Primary evidence |
|---|---|---|
| baseline.backend_route_present | yes | [artifact](<baseline/snapshot/r1-routes.json>) |
| baseline.bgp_backend_prefix_present | yes | [artifact](<baseline/snapshot/r1-bgp-routes.json>) |
| baseline.bgp_peers_established | yes | [artifact](<baseline/snapshot/r1-bgp-summary.json>), [artifact](<baseline/snapshot/r2-bgp-summary.json>), [artifact](<baseline/snapshot/r3-bgp-summary.json>) |
| baseline.backend_prefix_denied | no | [artifact](<baseline/snapshot/r1-running-config.txt>), [artifact](<baseline/snapshot/r1-prefix-lists.txt>) |
| baseline.backend_prefix_policy_present | no | [artifact](<baseline/snapshot/r1-running-config.txt>), [artifact](<baseline/snapshot/r1-prefix-lists.txt>) |
| baseline.backend_prefix_policy | {"decision": null, "display_decision": null, "inbound_neighbors": [], "sources_consistent": true} | [artifact](<baseline/snapshot/r1-running-config.txt>), [artifact](<baseline/snapshot/r1-prefix-lists.txt>) |
| baseline.backend_listener_present | yes | [artifact](<baseline/snapshot/backend-sockets.txt>) |
| baseline.dns_ok | yes | [artifact](<baseline/snapshot/gateway-dns.json>) |
| baseline.primary_link_up | yes | [artifact](<baseline/snapshot/r1-links.json>) |
| baseline.netem_active | no | [artifact](<baseline/snapshot/gateway-netem.json>) |
| baseline.firewall_drop_active | no | [artifact](<baseline/snapshot/backend-firewall.json>) |
| baseline.firewall_drop_packets | 0 | [artifact](<baseline/snapshot/backend-firewall.json>) |
| baseline.backend_route_nexthop | 10.77.12.2 | [artifact](<baseline/snapshot/r1-routes.json>) |
| baseline.dns_result | {"address": "10.77.3.2", "name": "backend.lab", "ok": true, "rcode": 0} | not linked |
| baseline.gateway_metrics | {"accepted": 40, "accepted_definition": "all accepted TCP sockets including sockets immediately rejected at the connection limit", "active_connections": 0, "bytes_down": 10240, "bytes_up": 10240, "cpu_boundary": "cumulative CPU seconds for the entire process", "cpu_measurement_available": true, "cpu_system_seconds": 0.096438, "cpu_total_seconds": 0.113209, "cpu_user_seconds": 0.016771, "errors": {}, "errors_definition": "one terminal failure class per admitted session; connection-limit rejections are counted separately", "file_descriptors": 10, "gc_cycles": 1, "goroutines": 8, "heap_alloc_bytes": 790752, "heap_sys_bytes": 7634944, "log_dropped_total": 0, "log_policy": "64 queued records plus at most one sink write; overflow is dropped; one blocked sink goroutine may remain until release or process exit", "log_queue_capacity": 64, "log_queue_length": 0, "log_shutdown_timed_out": false, "log_sink_inflight": false, "log_write_errors_total": 0, "log_written_total": 40, "max_connections": 16, "rejected": 0, "rss_bytes": 9060352, "uptime_seconds": 3.819083822} | [artifact](<baseline/snapshot/gateway-metrics.json>) |
| baseline.probe | {"all_successful": true, "attempts": 40, "attempts_per_second": 20.48452192314503, "duration_seconds": 1.952693851, "errors": {}, "failures": 0, "latency_ms": {"p50": 2.152241, "p95": 3.351021, "p99": 4.536039}, "samples_truncated": false, "success_rate": 1.0, "successes": 40, "successful_bytes": 10240, "valid": true} | [artifact](<baseline/probe.json>) |
| fault.backend_route_present | no | [artifact](<fault/snapshot/r1-routes.json>) |
| fault.bgp_backend_prefix_present | no | [artifact](<fault/snapshot/r1-bgp-routes.json>) |
| fault.bgp_peers_established | yes | [artifact](<fault/snapshot/r1-bgp-summary.json>), [artifact](<fault/snapshot/r2-bgp-summary.json>), [artifact](<fault/snapshot/r3-bgp-summary.json>) |
| fault.backend_prefix_denied | no | [artifact](<fault/snapshot/r1-running-config.txt>), [artifact](<fault/snapshot/r1-prefix-lists.txt>) |
| fault.backend_prefix_policy_present | no | [artifact](<fault/snapshot/r1-running-config.txt>), [artifact](<fault/snapshot/r1-prefix-lists.txt>) |
| fault.backend_prefix_policy | {"decision": null, "display_decision": null, "inbound_neighbors": [], "sources_consistent": true} | [artifact](<fault/snapshot/r1-running-config.txt>), [artifact](<fault/snapshot/r1-prefix-lists.txt>) |
| fault.backend_listener_present | yes | [artifact](<fault/snapshot/backend-sockets.txt>) |
| fault.dns_ok | yes | [artifact](<fault/snapshot/gateway-dns.json>) |
| fault.primary_link_up | yes | [artifact](<fault/snapshot/r1-links.json>) |
| fault.netem_active | no | [artifact](<fault/snapshot/gateway-netem.json>) |
| fault.firewall_drop_active | no | [artifact](<fault/snapshot/backend-firewall.json>) |
| fault.firewall_drop_packets | 0 | [artifact](<fault/snapshot/backend-firewall.json>) |
| fault.dns_result | {"address": "10.77.3.2", "name": "backend.lab", "ok": true, "rcode": 0} | not linked |
| fault.gateway_metrics | {"accepted": 48, "accepted_definition": "all accepted TCP sockets including sockets immediately rejected at the connection limit", "active_connections": 0, "bytes_down": 10240, "bytes_up": 10240, "cpu_boundary": "cumulative CPU seconds for the entire process", "cpu_measurement_available": true, "cpu_system_seconds": 0.111754, "cpu_total_seconds": 0.129634, "cpu_user_seconds": 0.01788, "errors": {"upstream_network_unreachable": 2, "upstream_timeout": 6}, "errors_definition": "one terminal failure class per admitted session; connection-limit rejections are counted separately", "file_descriptors": 10, "gc_cycles": 1, "goroutines": 8, "heap_alloc_bytes": 920952, "heap_sys_bytes": 7634944, "log_dropped_total": 0, "log_policy": "64 queued records plus at most one sink write; overflow is dropped; one blocked sink goroutine may remain until release or process exit", "log_queue_capacity": 64, "log_queue_length": 0, "log_shutdown_timed_out": false, "log_sink_inflight": false, "log_write_errors_total": 0, "log_written_total": 48, "max_connections": 16, "rejected": 0, "rss_bytes": 9170944, "uptime_seconds": 8.397599903} | [artifact](<fault/snapshot/gateway-metrics.json>) |
| fault.probe | {"all_successful": false, "attempts": 8, "attempts_per_second": 3.123289554875972, "duration_seconds": 2.561401964, "errors": {"reset": 8}, "failures": 8, "latency_ms": {"p50": null, "p95": null, "p99": null}, "samples_truncated": false, "success_rate": 0.0, "successes": 0, "successful_bytes": 0, "valid": true} | [artifact](<fault/probe.json>) |
| recovery.backend_route_present | yes | [artifact](<recovery/snapshot/r1-routes.json>) |
| recovery.bgp_backend_prefix_present | yes | [artifact](<recovery/snapshot/r1-bgp-routes.json>) |
| recovery.bgp_peers_established | yes | [artifact](<recovery/snapshot/r1-bgp-summary.json>), [artifact](<recovery/snapshot/r2-bgp-summary.json>), [artifact](<recovery/snapshot/r3-bgp-summary.json>) |
| recovery.backend_prefix_denied | no | [artifact](<recovery/snapshot/r1-running-config.txt>), [artifact](<recovery/snapshot/r1-prefix-lists.txt>) |
| recovery.backend_prefix_policy_present | no | [artifact](<recovery/snapshot/r1-running-config.txt>), [artifact](<recovery/snapshot/r1-prefix-lists.txt>) |
| recovery.backend_prefix_policy | {"decision": null, "display_decision": null, "inbound_neighbors": [], "sources_consistent": true} | [artifact](<recovery/snapshot/r1-running-config.txt>), [artifact](<recovery/snapshot/r1-prefix-lists.txt>) |
| recovery.backend_listener_present | yes | [artifact](<recovery/snapshot/backend-sockets.txt>) |
| recovery.dns_ok | yes | [artifact](<recovery/snapshot/gateway-dns.json>) |
| recovery.primary_link_up | yes | [artifact](<recovery/snapshot/r1-links.json>) |
| recovery.netem_active | no | [artifact](<recovery/snapshot/gateway-netem.json>) |
| recovery.firewall_drop_active | no | [artifact](<recovery/snapshot/backend-firewall.json>) |
| recovery.firewall_drop_packets | 0 | [artifact](<recovery/snapshot/backend-firewall.json>) |
| recovery.backend_route_nexthop | 10.77.12.2 | [artifact](<recovery/snapshot/r1-routes.json>) |
| recovery.dns_result | {"address": "10.77.3.2", "name": "backend.lab", "ok": true, "rcode": 0} | not linked |
| recovery.gateway_metrics | {"accepted": 88, "accepted_definition": "all accepted TCP sockets including sockets immediately rejected at the connection limit", "active_connections": 0, "bytes_down": 20480, "bytes_up": 20480, "cpu_boundary": "cumulative CPU seconds for the entire process", "cpu_measurement_available": true, "cpu_system_seconds": 0.183264, "cpu_total_seconds": 0.225555, "cpu_user_seconds": 0.042291, "errors": {"upstream_network_unreachable": 2, "upstream_timeout": 6}, "errors_definition": "one terminal failure class per admitted session; connection-limit rejections are counted separately", "file_descriptors": 10, "gc_cycles": 2, "goroutines": 8, "heap_alloc_bytes": 798464, "heap_sys_bytes": 7634944, "log_dropped_total": 0, "log_policy": "64 queued records plus at most one sink write; overflow is dropped; one blocked sink goroutine may remain until release or process exit", "log_queue_capacity": 64, "log_queue_length": 0, "log_shutdown_timed_out": false, "log_sink_inflight": false, "log_write_errors_total": 0, "log_written_total": 88, "max_connections": 16, "rejected": 0, "rss_bytes": 10407936, "uptime_seconds": 12.662663951999999} | [artifact](<recovery/snapshot/gateway-metrics.json>) |
| recovery.probe | {"all_successful": true, "attempts": 40, "attempts_per_second": 20.470211609891358, "duration_seconds": 1.95405894, "errors": {}, "failures": 0, "latency_ms": {"p50": 2.307135, "p95": 2.812505, "p99": 3.445535}, "samples_truncated": false, "success_rate": 1.0, "successes": 40, "successful_bytes": 10240, "valid": true} | [artifact](<recovery/probe.json>) |

Supporting observations: `baseline.backend_route_present`, `fault.backend_route_present`, `fault.probe`, `baseline.bgp_backend_prefix_present`, `fault.bgp_backend_prefix_present`.

## Restoration checks

| Check | Outcome |
|---|---|
| baseline_payload_transfer | verified |
| recovery_payload_transfer | verified |
| backend_route_present | verified |
| backend_listener_present | verified |
| dns_ok | verified |
| primary_link_up | verified |
| netem_active | verified |
| bgp_peers_established | verified |
| bgp_backend_prefix_present | verified |
| firewall_drop_active | verified |
| backend_prefix_denied | verified |
| backend_prefix_policy_present | verified |
| backend_route_nexthop | verified |

## Scenario acceptance

These checks are recomputed from the current observations and describe whether the intended experiment effect was observed; they are separate from the independently recomputed diagnosis.

| Check | Outcome |
|---|---|
| baseline_route_present | verified |
| fault_route_absent | verified |
| application_disrupted | verified |

## Event timeline

| Sequence | Event | Local elapsed (s) | Wall time |
|---:|---|---:|---|
| 1 | startup-started | 1.139 | 2026-11-02T04:17:41.954108+00:00 |
| 2 | startup-finished | 4.904 | 2026-11-02T04:17:45.718649+00:00 |
| 3 | baseline-started | 4.922 | 2026-11-02T04:17:45.736823+00:00 |
| 4 | baseline-finished | 8.569 | 2026-11-02T04:17:49.383794+00:00 |
| 5 | fault-application-started | 8.580 | 2026-11-02T04:17:49.394747+00:00 |
| 6 | fault-applied | 8.796 | 2026-11-02T04:17:49.610736+00:00 |
| 7 | fault-started | 8.812 | 2026-11-02T04:17:49.626988+00:00 |
| 8 | fault-finished | 13.198 | 2026-11-02T04:17:54.012782+00:00 |
| 9 | restoration-started | 13.212 | 2026-11-02T04:17:54.026888+00:00 |
| 10 | restoration-finished | 13.571 | 2026-11-02T04:17:54.386041+00:00 |
| 11 | recovery-started | 13.590 | 2026-11-02T04:17:54.404463+00:00 |
| 12 | recovery-finished | 17.439 | 2026-11-02T04:17:58.253598+00:00 |
| 13 | cleanup-started | 17.451 | 2026-11-02T04:17:58.266108+00:00 |
| 14 | cleanup-finished | 18.739 | 2026-11-02T04:17:59.553827+00:00 |

## Injected change

```json
{
  "applied_at": "2026-11-02T04:17:49.405896+00:00",
  "apply_seconds": 0.20392147000006844,
  "kind": "route-withdrawal",
  "status": "applied"
}
```

## Limitations

- baseline: fewer than 100 operations; tail percentiles have limited resolution.
- fault: fewer than 100 operations; tail percentiles have limited resolution.
- recovery: fewer than 100 operations; tail percentiles have limited resolution.
- route_convergence_seconds was not independently measured; phase snapshots do not establish this timing.
- Evidence is sampled within one host's local time context; cross-source timestamps do not imply perfect global synchronization.

Primary artifacts and checksums are listed in the experiment manifest. A configured route or disabled injector alone does not prove service recovery.
