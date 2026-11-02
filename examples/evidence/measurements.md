# Repeated network experiment measurements

Valid trials: **24**. Invalid or duplicate records: **0**.

Values are median [minimum, maximum] across trials. Each trial contributes its own metric; latency percentiles are never pooled.

## backend-down

Trials: 3; accepted: 3; restored: 3; clean teardown: 3.

Comparability: **comparable**. Different comparison groups are shown separately.

### Comparison group 076497513e94

```json
{
  "context_complete": true,
  "effective_workloads": {
    "baseline": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    },
    "fault": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    },
    "recovery": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    }
  },
  "environment": {
    "cpu_model": "AMD Ryzen 9 7940HS w/ Radeon 780M Graphics",
    "doctor": {
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
    "go_binary_version": "/opt/netlab-public/programmable-network-infrastructure/bin/netlab-agent: go1.22.2",
    "iproute_version": "ip utility, iproute2-6.1.0, libbpf 1.3.0",
    "kernel": "6.18.54.1-microsoft-standard-WSL2",
    "logical_cpus": 16,
    "memory_total": "MemTotal:       15970204 kB",
    "netlab_version": "0.1.0",
    "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
    "platform": "Linux-6.18.54.1-microsoft-standard-WSL2-x86_64-with-glibc2.39",
    "python": "3.12.3"
  },
  "execution_source_sha256": "41ef07d4881cc82a6cd50a8970de4f511024c8cb6bfbd449eccd81a4e01fa0ac",
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

| Phase | Attempts | Success fraction | Attempts/s | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 40.000 [40.000, 40.000] (n=3) | 1.000 [1.000, 1.000] (n=3) | 20.469 [20.462, 20.477] (n=3) | 2.335 [1.806, 2.485] (n=3) | 3.195 [2.733, 3.806] (n=3) | 5.551 [4.945, 5.731] (n=3) |
| fault | 40.000 [40.000, 40.000] (n=3) | 0.000 [0.000, 0.000] (n=3) | 20.466 [20.465, 20.470] (n=3) | unmeasured | unmeasured | unmeasured |
| recovery | 40.000 [40.000, 40.000] (n=3) | 1.000 [1.000, 1.000] (n=3) | 20.477 [20.459, 20.479] (n=3) | 2.384 [2.318, 2.433] (n=3) | 3.356 [3.002, 3.383] (n=3) | 3.891 [3.276, 3.916] (n=3) |

Gateway post-phase snapshots (CPU seconds are cumulative process lifetime; these are not peaks):

| Phase | Goroutines | RSS bytes | Heap bytes | File descriptors | Cumulative CPU seconds |
|---|---:|---:|---:|---:|---:|
| baseline | 8.000 [8.000, 8.000] (n=3) | 8925184.000 [8843264.000, 9109504.000] (n=3) | 720240.000 [707984.000, 782944.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.119 [0.088, 0.120] (n=3) |
| fault | 8.000 [8.000, 8.000] (n=3) | 9371648.000 [9244672.000, 9510912.000] (n=3) | 1230216.000 [1221064.000, 1301008.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.190 [0.163, 0.195] (n=3) |
| recovery | 8.000 [8.000, 8.000] (n=3) | 10416128.000 [10174464.000, 10477568.000] (n=3) | 1198648.000 [1142432.000, 1201600.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.288 [0.266, 0.295] (n=3) |

| Recovery clock | Seconds | Recorded definition |
|---|---:|---|
| fault_to_detection_seconds | 0.165 [0.162, 0.186] (n=3) | Conservative upper bound from beginning fault application to first failed sampled echo completion; includes sampling gaps, timeout, and all parent/child launch/return overhead. |
| route_convergence_seconds | unmeasured | Routing change to a defined observed converged route state. |
| first_success_after_restoration_seconds | 0.299 [0.282, 0.304] (n=3) | Conservative upper bound from restoration start to first successful sampled echo; includes restoration, sampling gaps, and all parent/child launch/return overhead. Earlier success may be unobserved. |
| stable_recovery_seconds | 2.249 [2.233, 2.257] (n=3) | Completion of the error-free post-restoration probe window (at least one second); independent state recovery is evaluated separately. This is a sampled bound, not continuous health assurance. |

Trials: `b19eacb71c044029ba58fbf9e2a2a43b`, `e315b33f93f14bdb8979688451500899`, `c4f5a26cd7c947b486ed55100e8cf1ac`.

## dns-failure

Trials: 3; accepted: 3; restored: 3; clean teardown: 3.

Comparability: **comparable**. Different comparison groups are shown separately.

### Comparison group 076497513e94

```json
{
  "context_complete": true,
  "effective_workloads": {
    "baseline": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    },
    "fault": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    },
    "recovery": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    }
  },
  "environment": {
    "cpu_model": "AMD Ryzen 9 7940HS w/ Radeon 780M Graphics",
    "doctor": {
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
    "go_binary_version": "/opt/netlab-public/programmable-network-infrastructure/bin/netlab-agent: go1.22.2",
    "iproute_version": "ip utility, iproute2-6.1.0, libbpf 1.3.0",
    "kernel": "6.18.54.1-microsoft-standard-WSL2",
    "logical_cpus": 16,
    "memory_total": "MemTotal:       15970204 kB",
    "netlab_version": "0.1.0",
    "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
    "platform": "Linux-6.18.54.1-microsoft-standard-WSL2-x86_64-with-glibc2.39",
    "python": "3.12.3"
  },
  "execution_source_sha256": "41ef07d4881cc82a6cd50a8970de4f511024c8cb6bfbd449eccd81a4e01fa0ac",
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

| Phase | Attempts | Success fraction | Attempts/s | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 40.000 [40.000, 40.000] (n=3) | 1.000 [1.000, 1.000] (n=3) | 20.462 [20.453, 20.474] (n=3) | 2.381 [2.207, 2.430] (n=3) | 3.426 [3.321, 3.680] (n=3) | 5.241 [4.931, 6.112] (n=3) |
| fault | 40.000 [40.000, 40.000] (n=3) | 0.000 [0.000, 0.000] (n=3) | 20.483 [20.477, 20.496] (n=3) | unmeasured | unmeasured | unmeasured |
| recovery | 40.000 [40.000, 40.000] (n=3) | 1.000 [1.000, 1.000] (n=3) | 20.473 [20.469, 20.492] (n=3) | 2.486 [2.302, 2.562] (n=3) | 3.407 [3.040, 3.823] (n=3) | 5.236 [4.993, 5.747] (n=3) |

Gateway post-phase snapshots (CPU seconds are cumulative process lifetime; these are not peaks):

| Phase | Goroutines | RSS bytes | Heap bytes | File descriptors | Cumulative CPU seconds |
|---|---:|---:|---:|---:|---:|
| baseline | 8.000 [8.000, 8.000] (n=3) | 8835072.000 [8810496.000, 8908800.000] (n=3) | 717712.000 [633528.000, 786296.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.117 [0.116, 0.118] (n=3) |
| fault | 8.000 [8.000, 8.000] (n=3) | 9297920.000 [9039872.000, 9302016.000] (n=3) | 1182592.000 [1099856.000, 1269128.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.169 [0.167, 0.180] (n=3) |
| recovery | 8.000 [8.000, 8.000] (n=3) | 10125312.000 [10010624.000, 10182656.000] (n=3) | 1150784.000 [1031560.000, 1364840.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.269 [0.266, 0.281] (n=3) |

| Recovery clock | Seconds | Recorded definition |
|---|---:|---|
| fault_to_detection_seconds | 0.112 [0.105, 0.150] (n=3) | Conservative upper bound from beginning fault application to first failed sampled echo completion; includes sampling gaps, timeout, and all parent/child launch/return overhead. |
| route_convergence_seconds | unmeasured | Routing change to a defined observed converged route state. |
| first_success_after_restoration_seconds | 0.233 [0.201, 0.240] (n=3) | Conservative upper bound from restoration start to first successful sampled echo; includes restoration, sampling gaps, and all parent/child launch/return overhead. Earlier success may be unobserved. |
| stable_recovery_seconds | 2.185 [2.154, 2.190] (n=3) | Completion of the error-free post-restoration probe window (at least one second); independent state recovery is evaluated separately. This is a sampled bound, not continuous health assurance. |

Trials: `fba39d00ff844970826875dd55e02ff9`, `2a04f508b06d4977a7135c78f801f303`, `a7ed756652574ecbbea90679583192a2`.

## firewall-drop

Trials: 3; accepted: 3; restored: 3; clean teardown: 3.

Comparability: **comparable**. Different comparison groups are shown separately.

### Comparison group 076497513e94

```json
{
  "context_complete": true,
  "effective_workloads": {
    "baseline": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    },
    "fault": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    },
    "recovery": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    }
  },
  "environment": {
    "cpu_model": "AMD Ryzen 9 7940HS w/ Radeon 780M Graphics",
    "doctor": {
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
    "go_binary_version": "/opt/netlab-public/programmable-network-infrastructure/bin/netlab-agent: go1.22.2",
    "iproute_version": "ip utility, iproute2-6.1.0, libbpf 1.3.0",
    "kernel": "6.18.54.1-microsoft-standard-WSL2",
    "logical_cpus": 16,
    "memory_total": "MemTotal:       15970204 kB",
    "netlab_version": "0.1.0",
    "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
    "platform": "Linux-6.18.54.1-microsoft-standard-WSL2-x86_64-with-glibc2.39",
    "python": "3.12.3"
  },
  "execution_source_sha256": "41ef07d4881cc82a6cd50a8970de4f511024c8cb6bfbd449eccd81a4e01fa0ac",
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

| Phase | Attempts | Success fraction | Attempts/s | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 40.000 [40.000, 40.000] (n=3) | 1.000 [1.000, 1.000] (n=3) | 20.478 [20.477, 20.487] (n=3) | 2.244 [2.082, 2.518] (n=3) | 2.918 [2.686, 3.296] (n=3) | 5.195 [4.579, 6.330] (n=3) |
| fault | 6.000 [6.000, 6.000] (n=3) | 0.000 [0.000, 0.000] (n=3) | 2.443 [2.436, 2.445] (n=3) | unmeasured | unmeasured | unmeasured |
| recovery | 40.000 [40.000, 40.000] (n=3) | 1.000 [1.000, 1.000] (n=3) | 20.479 [20.474, 20.484] (n=3) | 2.292 [2.138, 2.556] (n=3) | 3.271 [2.886, 3.837] (n=3) | 3.358 [3.085, 4.400] (n=3) |

Gateway post-phase snapshots (CPU seconds are cumulative process lifetime; these are not peaks):

| Phase | Goroutines | RSS bytes | Heap bytes | File descriptors | Cumulative CPU seconds |
|---|---:|---:|---:|---:|---:|
| baseline | 8.000 [8.000, 8.000] (n=3) | 8769536.000 [8712192.000, 8843264.000] (n=3) | 749952.000 [704304.000, 779296.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.109 [0.107, 0.122] (n=3) |
| fault | 8.000 [8.000, 8.000] (n=3) | 8888320.000 [8867840.000, 9039872.000] (n=3) | 869144.000 [824104.000, 888744.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.121 [0.120, 0.138] (n=3) |
| recovery | 8.000 [8.000, 8.000] (n=3) | 10260480.000 [10162176.000, 10551296.000] (n=3) | 736352.000 [710224.000, 810576.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.214 [0.214, 0.244] (n=3) |

| Recovery clock | Seconds | Recorded definition |
|---|---:|---|
| fault_to_detection_seconds | 0.917 [0.916, 0.932] (n=3) | Conservative upper bound from beginning fault application to first failed sampled echo completion; includes sampling gaps, timeout, and all parent/child launch/return overhead. |
| route_convergence_seconds | unmeasured | Routing change to a defined observed converged route state. |
| first_success_after_restoration_seconds | 0.257 [0.245, 0.272] (n=3) | Conservative upper bound from restoration start to first successful sampled echo; includes restoration, sampling gaps, and all parent/child launch/return overhead. Earlier success may be unobserved. |
| stable_recovery_seconds | 2.210 [2.197, 2.223] (n=3) | Completion of the error-free post-restoration probe window (at least one second); independent state recovery is evaluated separately. This is a sampled bound, not continuous health assurance. |

Trials: `13222c20f87e4af19068815f4b43796a`, `cb777af2c5af404e9095e5023fe6ad44`, `1751e04fa4e64758ba343fa0340c6e3d`.

## gateway-overload

Trials: 3; accepted: 3; restored: 3; clean teardown: 3.

Comparability: **comparable**. Different comparison groups are shown separately.

### Comparison group 1618d0aac045

```json
{
  "context_complete": true,
  "effective_workloads": {
    "baseline": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    },
    "fault": {
      "concurrency": 48,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 0
    },
    "recovery": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    }
  },
  "environment": {
    "cpu_model": "AMD Ryzen 9 7940HS w/ Radeon 780M Graphics",
    "doctor": {
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
    "go_binary_version": "/opt/netlab-public/programmable-network-infrastructure/bin/netlab-agent: go1.22.2",
    "iproute_version": "ip utility, iproute2-6.1.0, libbpf 1.3.0",
    "kernel": "6.18.54.1-microsoft-standard-WSL2",
    "logical_cpus": 16,
    "memory_total": "MemTotal:       15970204 kB",
    "netlab_version": "0.1.0",
    "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
    "platform": "Linux-6.18.54.1-microsoft-standard-WSL2-x86_64-with-glibc2.39",
    "python": "3.12.3"
  },
  "execution_source_sha256": "41ef07d4881cc82a6cd50a8970de4f511024c8cb6bfbd449eccd81a4e01fa0ac",
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

| Phase | Attempts | Success fraction | Attempts/s | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 40.000 [40.000, 40.000] (n=3) | 1.000 [1.000, 1.000] (n=3) | 20.475 [20.471, 20.486] (n=3) | 2.542 [2.334, 2.595] (n=3) | 3.937 [3.452, 5.205] (n=3) | 6.247 [5.636, 6.813] (n=3) |
| fault | 384.000 [384.000, 384.000] (n=3) | 0.333 [0.333, 0.333] (n=3) | 183.141 [183.020, 184.136] (n=3) | 263.009 [257.419, 264.585] (n=3) | 270.570 [267.515, 291.479] (n=3) | 270.830 [269.099, 291.927] (n=3) |
| recovery | 40.000 [40.000, 40.000] (n=3) | 1.000 [1.000, 1.000] (n=3) | 20.465 [20.454, 20.465] (n=3) | 2.411 [2.084, 2.474] (n=3) | 3.081 [2.653, 3.161] (n=3) | 3.340 [2.867, 3.981] (n=3) |

Gateway post-phase snapshots (CPU seconds are cumulative process lifetime; these are not peaks):

| Phase | Goroutines | RSS bytes | Heap bytes | File descriptors | Cumulative CPU seconds |
|---|---:|---:|---:|---:|---:|
| baseline | 8.000 [8.000, 8.000] (n=3) | 8695808.000 [8630272.000, 8880128.000] (n=3) | 709608.000 [692776.000, 785368.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.114 [0.112, 0.121] (n=3) |
| fault | 8.000 [8.000, 8.000] (n=3) | 12791808.000 [11980800.000, 12873728.000] (n=3) | 1622856.000 [1600584.000, 1954512.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.284 [0.278, 0.323] (n=3) |
| recovery | 8.000 [8.000, 8.000] (n=3) | 12824576.000 [12378112.000, 13012992.000] (n=3) | 1973576.000 [1821696.000, 2384704.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.385 [0.368, 0.423] (n=3) |

| Recovery clock | Seconds | Recorded definition |
|---|---:|---|
| fault_to_detection_seconds | 0.364 [0.357, 0.377] (n=3) | Conservative upper bound from beginning fault application to first failed sampled echo completion; includes sampling gaps, timeout, and all parent/child launch/return overhead. |
| route_convergence_seconds | unmeasured | Routing change to a defined observed converged route state. |
| first_success_after_restoration_seconds | 0.235 [0.210, 0.244] (n=3) | Conservative upper bound from restoration start to first successful sampled echo; includes restoration, sampling gaps, and all parent/child launch/return overhead. Earlier success may be unobserved. |
| stable_recovery_seconds | 2.188 [2.162, 2.199] (n=3) | Completion of the error-free post-restoration probe window (at least one second); independent state recovery is evaluated separately. This is a sampled bound, not continuous health assurance. |

Trials: `04e2f02ac1c8487c838d3350f517643b`, `d5c76bc4a9e049e080b03ecca55be697`, `e0b74c4003c8488a9ff2d87787b6278e`.

## link-loss

Trials: 3; accepted: 3; restored: 3; clean teardown: 3.

Comparability: **comparable**. Different comparison groups are shown separately.

### Comparison group 076497513e94

```json
{
  "context_complete": true,
  "effective_workloads": {
    "baseline": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    },
    "fault": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    },
    "recovery": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    }
  },
  "environment": {
    "cpu_model": "AMD Ryzen 9 7940HS w/ Radeon 780M Graphics",
    "doctor": {
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
    "go_binary_version": "/opt/netlab-public/programmable-network-infrastructure/bin/netlab-agent: go1.22.2",
    "iproute_version": "ip utility, iproute2-6.1.0, libbpf 1.3.0",
    "kernel": "6.18.54.1-microsoft-standard-WSL2",
    "logical_cpus": 16,
    "memory_total": "MemTotal:       15970204 kB",
    "netlab_version": "0.1.0",
    "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
    "platform": "Linux-6.18.54.1-microsoft-standard-WSL2-x86_64-with-glibc2.39",
    "python": "3.12.3"
  },
  "execution_source_sha256": "41ef07d4881cc82a6cd50a8970de4f511024c8cb6bfbd449eccd81a4e01fa0ac",
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

| Phase | Attempts | Success fraction | Attempts/s | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 40.000 [40.000, 40.000] (n=3) | 1.000 [1.000, 1.000] (n=3) | 20.474 [20.471, 20.477] (n=3) | 2.328 [2.110, 2.502] (n=3) | 3.273 [2.968, 3.912] (n=3) | 5.227 [4.695, 5.563] (n=3) |
| fault | 40.000 [40.000, 40.000] (n=3) | 1.000 [1.000, 1.000] (n=3) | 20.478 [20.471, 20.484] (n=3) | 2.113 [2.103, 2.506] (n=3) | 2.746 [2.558, 3.486] (n=3) | 3.863 [3.350, 4.028] (n=3) |
| recovery | 40.000 [40.000, 40.000] (n=3) | 1.000 [1.000, 1.000] (n=3) | 20.474 [20.471, 20.484] (n=3) | 2.175 [2.028, 2.366] (n=3) | 3.325 [3.264, 3.789] (n=3) | 4.542 [4.070, 7.328] (n=3) |

Gateway post-phase snapshots (CPU seconds are cumulative process lifetime; these are not peaks):

| Phase | Goroutines | RSS bytes | Heap bytes | File descriptors | Cumulative CPU seconds |
|---|---:|---:|---:|---:|---:|
| baseline | 8.000 [8.000, 8.000] (n=3) | 8708096.000 [8687616.000, 9027584.000] (n=3) | 704392.000 [557976.000, 711896.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.114 [0.110, 0.122] (n=3) |
| fault | 8.000 [8.000, 8.000] (n=3) | 10186752.000 [10117120.000, 10207232.000] (n=3) | 644272.000 [545880.000, 781544.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.206 [0.202, 0.226] (n=3) |
| recovery | 8.000 [8.000, 8.000] (n=3) | 10416128.000 [10403840.000, 10481664.000] (n=3) | 649568.000 [496872.000, 725656.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.301 [0.296, 0.324] (n=3) |

| Recovery clock | Seconds | Recorded definition |
|---|---:|---|
| fault_to_detection_seconds | unmeasured | Fault application to the first independently observed failed operation. |
| route_convergence_seconds | unmeasured | Routing change to a defined observed converged route state. |
| first_success_after_restoration_seconds | 0.248 [0.226, 1.215] (n=3) | Conservative upper bound from restoration start to first successful sampled echo; includes restoration, sampling gaps, and all parent/child launch/return overhead. Earlier success may be unobserved. |
| stable_recovery_seconds | 2.199 [2.178, 3.166] (n=3) | Completion of the error-free post-restoration probe window (at least one second); independent state recovery is evaluated separately. This is a sampled bound, not continuous health assurance. |

Trials: `0eebf584280c4a2ba3def3624faa9451`, `9eb95746bf694f6ca800dd5c86504fb6`, `6f4146630b8f451bbf764d948b6d97cd`.

## packet-loss

Trials: 3; accepted: 3; restored: 3; clean teardown: 3.

Comparability: **comparable**. Different comparison groups are shown separately.

### Comparison group 076497513e94

```json
{
  "context_complete": true,
  "effective_workloads": {
    "baseline": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    },
    "fault": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    },
    "recovery": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    }
  },
  "environment": {
    "cpu_model": "AMD Ryzen 9 7940HS w/ Radeon 780M Graphics",
    "doctor": {
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
    "go_binary_version": "/opt/netlab-public/programmable-network-infrastructure/bin/netlab-agent: go1.22.2",
    "iproute_version": "ip utility, iproute2-6.1.0, libbpf 1.3.0",
    "kernel": "6.18.54.1-microsoft-standard-WSL2",
    "logical_cpus": 16,
    "memory_total": "MemTotal:       15970204 kB",
    "netlab_version": "0.1.0",
    "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
    "platform": "Linux-6.18.54.1-microsoft-standard-WSL2-x86_64-with-glibc2.39",
    "python": "3.12.3"
  },
  "execution_source_sha256": "41ef07d4881cc82a6cd50a8970de4f511024c8cb6bfbd449eccd81a4e01fa0ac",
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

| Phase | Attempts | Success fraction | Attempts/s | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 40.000 [40.000, 40.000] (n=3) | 1.000 [1.000, 1.000] (n=3) | 20.475 [20.451, 20.477] (n=3) | 2.372 [2.307, 2.715] (n=3) | 3.790 [3.261, 4.434] (n=3) | 6.072 [5.478, 7.105] (n=3) |
| fault | 14.000 [13.000, 17.000] (n=3) | 0.786 [0.692, 0.824] (n=3) | 6.935 [5.342, 7.475] (n=3) | 69.885 [69.151, 71.083] (n=3) | 341.775 [338.537, 353.638] (n=3) | 341.775 [338.537, 353.638] (n=3) |
| recovery | 40.000 [40.000, 40.000] (n=3) | 1.000 [1.000, 1.000] (n=3) | 20.474 [20.451, 20.478] (n=3) | 2.293 [2.055, 2.353] (n=3) | 3.059 [3.049, 3.392] (n=3) | 3.225 [3.179, 5.099] (n=3) |

Gateway post-phase snapshots (CPU seconds are cumulative process lifetime; these are not peaks):

| Phase | Goroutines | RSS bytes | Heap bytes | File descriptors | Cumulative CPU seconds |
|---|---:|---:|---:|---:|---:|
| baseline | 8.000 [8.000, 8.000] (n=3) | 8568832.000 [8507392.000, 8806400.000] (n=3) | 713952.000 [537976.000, 780912.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.116 [0.114, 0.120] (n=3) |
| fault | 8.000 [8.000, 8.000] (n=3) | 9326592.000 [8986624.000, 9408512.000] (n=3) | 1721800.000 [1337728.000, 1885624.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.159 [0.148, 0.161] (n=3) |
| recovery | 8.000 [8.000, 8.000] (n=3) | 10305536.000 [10182656.000, 10387456.000] (n=3) | 1600664.000 [1361456.000, 1890016.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.257 [0.238, 0.259] (n=3) |

| Recovery clock | Seconds | Recorded definition |
|---|---:|---|
| fault_to_detection_seconds | 0.968 [0.924, 0.987] (n=3) | Conservative upper bound from beginning fault application to first failed sampled echo completion; includes sampling gaps, timeout, and all parent/child launch/return overhead. |
| route_convergence_seconds | unmeasured | Routing change to a defined observed converged route state. |
| first_success_after_restoration_seconds | 0.268 [0.243, 0.269] (n=3) | Conservative upper bound from restoration start to first successful sampled echo; includes restoration, sampling gaps, and all parent/child launch/return overhead. Earlier success may be unobserved. |
| stable_recovery_seconds | 2.221 [2.193, 2.222] (n=3) | Completion of the error-free post-restoration probe window (at least one second); independent state recovery is evaluated separately. This is a sampled bound, not continuous health assurance. |

Trials: `acf2d639679d4c16ac389fc43fd48c21`, `e520b2d4211c4a60865b35fa2d8c5e64`, `b374ac2118b444d48dcd59567a79f99d`.

## route-policy

Trials: 3; accepted: 3; restored: 3; clean teardown: 3.

Comparability: **comparable**. Different comparison groups are shown separately.

### Comparison group 076497513e94

```json
{
  "context_complete": true,
  "effective_workloads": {
    "baseline": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    },
    "fault": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    },
    "recovery": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    }
  },
  "environment": {
    "cpu_model": "AMD Ryzen 9 7940HS w/ Radeon 780M Graphics",
    "doctor": {
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
    "go_binary_version": "/opt/netlab-public/programmable-network-infrastructure/bin/netlab-agent: go1.22.2",
    "iproute_version": "ip utility, iproute2-6.1.0, libbpf 1.3.0",
    "kernel": "6.18.54.1-microsoft-standard-WSL2",
    "logical_cpus": 16,
    "memory_total": "MemTotal:       15970204 kB",
    "netlab_version": "0.1.0",
    "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
    "platform": "Linux-6.18.54.1-microsoft-standard-WSL2-x86_64-with-glibc2.39",
    "python": "3.12.3"
  },
  "execution_source_sha256": "41ef07d4881cc82a6cd50a8970de4f511024c8cb6bfbd449eccd81a4e01fa0ac",
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

| Phase | Attempts | Success fraction | Attempts/s | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 40.000 [40.000, 40.000] (n=3) | 1.000 [1.000, 1.000] (n=3) | 20.474 [20.462, 20.486] (n=3) | 2.368 [2.159, 2.456] (n=3) | 3.554 [2.597, 3.554] (n=3) | 5.425 [4.758, 6.492] (n=3) |
| fault | 8.000 [8.000, 8.000] (n=3) | 0.000 [0.000, 0.000] (n=3) | 3.130 [3.129, 3.130] (n=3) | unmeasured | unmeasured | unmeasured |
| recovery | 40.000 [40.000, 40.000] (n=3) | 1.000 [1.000, 1.000] (n=3) | 20.482 [20.471, 20.489] (n=3) | 2.203 [2.160, 2.403] (n=3) | 3.385 [2.751, 3.423] (n=3) | 3.944 [3.531, 4.006] (n=3) |

Gateway post-phase snapshots (CPU seconds are cumulative process lifetime; these are not peaks):

| Phase | Goroutines | RSS bytes | Heap bytes | File descriptors | Cumulative CPU seconds |
|---|---:|---:|---:|---:|---:|
| baseline | 8.000 [8.000, 8.000] (n=3) | 9048064.000 [8994816.000, 9072640.000] (n=3) | 711064.000 [547128.000, 783504.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.110 [0.106, 0.123] (n=3) |
| fault | 8.000 [8.000, 8.000] (n=3) | 9199616.000 [9162752.000, 9207808.000] (n=3) | 856016.000 [691776.000, 923304.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.128 [0.122, 0.140] (n=3) |
| recovery | 8.000 [8.000, 8.000] (n=3) | 10379264.000 [10252288.000, 10416128.000] (n=3) | 810016.000 [737816.000, 899296.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.232 [0.216, 0.236] (n=3) |

| Recovery clock | Seconds | Recorded definition |
|---|---:|---|
| fault_to_detection_seconds | 0.358 [0.348, 0.364] (n=3) | Conservative upper bound from beginning fault application to first failed sampled echo completion; includes sampling gaps, timeout, and all parent/child launch/return overhead. |
| route_convergence_seconds | unmeasured | Routing change to a defined observed converged route state. |
| first_success_after_restoration_seconds | 0.474 [0.446, 0.498] (n=3) | Conservative upper bound from restoration start to first successful sampled echo; includes restoration, sampling gaps, and all parent/child launch/return overhead. Earlier success may be unobserved. |
| stable_recovery_seconds | 2.426 [2.397, 2.448] (n=3) | Completion of the error-free post-restoration probe window (at least one second); independent state recovery is evaluated separately. This is a sampled bound, not continuous health assurance. |

Trials: `721d917557854515b8258446e3637198`, `edeb6ed61c384d11aca34455d42d708b`, `0e7fda3e668649b7a4a9b9f5a1e0fba4`.

## route-withdrawal

Trials: 3; accepted: 3; restored: 3; clean teardown: 3.

Comparability: **comparable**. Different comparison groups are shown separately.

### Comparison group 076497513e94

```json
{
  "context_complete": true,
  "effective_workloads": {
    "baseline": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    },
    "fault": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    },
    "recovery": {
      "concurrency": 2,
      "duration_seconds": 2.0,
      "payload_bytes": 256,
      "rate_per_second": 20.0
    }
  },
  "environment": {
    "cpu_model": "AMD Ryzen 9 7940HS w/ Radeon 780M Graphics",
    "doctor": {
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
    "go_binary_version": "/opt/netlab-public/programmable-network-infrastructure/bin/netlab-agent: go1.22.2",
    "iproute_version": "ip utility, iproute2-6.1.0, libbpf 1.3.0",
    "kernel": "6.18.54.1-microsoft-standard-WSL2",
    "logical_cpus": 16,
    "memory_total": "MemTotal:       15970204 kB",
    "netlab_version": "0.1.0",
    "nft_version": "nftables v1.0.9 (Old Doc Yak #3)",
    "platform": "Linux-6.18.54.1-microsoft-standard-WSL2-x86_64-with-glibc2.39",
    "python": "3.12.3"
  },
  "execution_source_sha256": "41ef07d4881cc82a6cd50a8970de4f511024c8cb6bfbd449eccd81a4e01fa0ac",
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

| Phase | Attempts | Success fraction | Attempts/s | p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|---:|---:|---:|
| baseline | 40.000 [40.000, 40.000] (n=3) | 1.000 [1.000, 1.000] (n=3) | 20.463 [20.457, 20.485] (n=3) | 2.474 [2.152, 2.518] (n=3) | 3.801 [3.351, 4.287] (n=3) | 6.073 [4.536, 6.496] (n=3) |
| fault | 8.000 [8.000, 8.000] (n=3) | 0.000 [0.000, 0.000] (n=3) | 3.123 [3.061, 3.129] (n=3) | unmeasured | unmeasured | unmeasured |
| recovery | 40.000 [40.000, 40.000] (n=3) | 1.000 [1.000, 1.000] (n=3) | 20.481 [20.470, 20.486] (n=3) | 2.321 [2.307, 2.436] (n=3) | 3.246 [2.813, 3.486] (n=3) | 3.649 [3.446, 3.802] (n=3) |

Gateway post-phase snapshots (CPU seconds are cumulative process lifetime; these are not peaks):

| Phase | Goroutines | RSS bytes | Heap bytes | File descriptors | Cumulative CPU seconds |
|---|---:|---:|---:|---:|---:|
| baseline | 8.000 [8.000, 8.000] (n=3) | 8863744.000 [8744960.000, 9060352.000] (n=3) | 767232.000 [631280.000, 790752.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.121 [0.113, 0.126] (n=3) |
| fault | 8.000 [8.000, 8.000] (n=3) | 9170944.000 [8921088.000, 9203712.000] (n=3) | 901176.000 [773256.000, 920952.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.138 [0.130, 0.144] (n=3) |
| recovery | 8.000 [8.000, 8.000] (n=3) | 10407936.000 [10252288.000, 10416128.000] (n=3) | 798464.000 [743088.000, 893728.000] (n=3) | 10.000 [10.000, 10.000] (n=3) | 0.236 [0.226, 0.247] (n=3) |

| Recovery clock | Seconds | Recorded definition |
|---|---:|---|
| fault_to_detection_seconds | 0.476 [0.322, 0.490] (n=3) | Conservative upper bound from beginning fault application to first failed sampled echo completion; includes sampling gaps, timeout, and all parent/child launch/return overhead. |
| route_convergence_seconds | unmeasured | Routing change to a defined observed converged route state. |
| first_success_after_restoration_seconds | 0.455 [0.450, 0.480] (n=3) | Conservative upper bound from restoration start to first successful sampled echo; includes restoration, sampling gaps, and all parent/child launch/return overhead. Earlier success may be unobserved. |
| stable_recovery_seconds | 2.407 [2.400, 2.432] (n=3) | Completion of the error-free post-restoration probe window (at least one second); independent state recovery is evaluated separately. This is a sampled bound, not continuous health assurance. |

Trials: `f4a721be8baf4bf3bcc4a0d1dc96698d`, `afb4427282074664bac1c0c625fdd45f`, `ee26863a503c4b87962e17aa117739a2`.

## Method and limits

- Median and observed range of per-trial metrics; no pooled quantiles.
- Percentiles include successful complete byte-verified operations only; failure rates are separate.
- Different environment, effective workload, or execution source hashes form separate groups. Missing context is disclosed.
- Recovery clocks are sampled bounds with the recorded definitions; missing route convergence remains unmeasured.
- Gateway resource values are post-phase snapshots, not peaks; CPU seconds are cumulative process lifetime, not phase utilization.
- No confidence intervals or statistical significance are inferred from observed ranges.
- Fault-phase gateway overload intentionally changes concurrency and rate; do not attribute that comparison solely to a network change.
- A VM/namespace lab does not establish physical-network or production performance.
