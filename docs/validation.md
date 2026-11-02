# Validation evidence

The implementation was exercised in a dedicated Ubuntu 24.04 WSL2 distribution
using real Linux network namespaces, virtual Ethernet links, FRRouting, nftables,
traffic control, DNS packets, and the authored Go gateway. No route or packet
simulation substitutes for the integration checks.

## Recorded environment

- Kernel: `6.18.54.1-microsoft-standard-WSL2`.
- CPU: AMD Ryzen 9 7940HS w/ Radeon 780M Graphics; 16 logical CPUs.
- Linux memory context: `MemTotal:       15970204 kB`.
- Python: 3.12.3; Go binary: `/mnt/c/Users/ridle/programmable-network-infrastructure/bin/netlab-agent: go1.22.2`.
- FRRouting: `frr version 8.4.4`, independently recorded in the running configuration.
  The environment collector's `vtysh --version` field is unknown; the raw running
  configuration supplies this version evidence.
- Measured source revision: `a2ec006430e699513ae4b80ced5269f3a3396e5d`; per-file source hashes and binary SHA256 are retained in each experiment.

The load run separately records revision `78cb243316b633babff397f107edbfcf09841ccb` with
dirty state `True` and full source hashes. Its Go gateway
and Linux/DNS backend source hashes match the acceptance run. Reporting and
orchestration files changed afterward; the datasets retain their distinct source
contexts and are not pooled into a peak-performance claim.

## Outcomes

- **24/24 fault experiments passed**: three trials for each of eight scenarios.
- Every experiment independently verified its intended fault effect, restored
  service and network state, and checked teardown. The acceptance harness confirmed
  unchanged host routes, firewall rules, and IPv4 forwarding configuration.
- All five lifecycle acceptance cases passed: permitted versus forbidden flows,
  interrupted startup, preserved namespace collisions, SIGTERM during a run, and
  independent simultaneous lab roots. Independent `/proc` scans found no processes
  retaining cleaned namespace identities.
- The final ten-round load test passed. **15,155/15,155
  ordinary 64 KiB echo operations were byte-correct**, with 261
  controlled gateway rejections during the two overload rounds. No payload
  corruption was observed; sampled active sessions stayed within the 16-session
  budget. Descriptor and goroutine recovery checks passed. RSS and cumulative CPU
  are recorded without asserting constant memory or production performance.
- Go race tests and `go vet` passed. Python unit/negative-case checks passed;
  see the [retained check output](../examples/evidence/checks.txt) for the exact test count and invocation.
- A [representative artifact audit](../examples/evidence/artifact-audit.json) checked
  ten experiments, including policy and failover evidence, with full final-PCAP
  framing, trace parsing, identity checks, and historical source verification.
  Packaging separately revalidated the SHA256 manifests for all 24 experiments.

Other validation processes overlapped portions of the repeated functional suite
on the same VM. These are correctness and resilience demonstrations under documented
workloads, not isolated peak-performance measurements. Recovery clocks are sampled
bounds including restoration and collection gaps. Exact BGP convergence is
unmeasured. Fault-phase failover traffic begins after alternate-route readiness;
the project does not claim zero-loss transition behavior.

## Inspect or reproduce

The [representative route-withdrawal report](../examples/route-withdrawal/report.md)
is browsable with its linked raw evidence. The [repeated-trial measurements](../examples/evidence/measurements.md)
show per-scenario medians, ranges, sample counts and comparison groups.

Full evidence is packaged in [acceptance.tar.gz](../examples/evidence/acceptance.tar.gz),
[lifecycle.tar.gz](../examples/evidence/lifecycle.tar.gz), and
[soak.tar.gz](../examples/evidence/soak.tar.gz). They contain only synthetic lab
traffic and generated observations. [SHA256SUMS](../examples/evidence/SHA256SUMS)
records archive integrity. Extract an experiment and run `python3 -m netlab verify`
on its directory to check the original manifest. Raw JSON summaries are retained
alongside the archives for quick inspection.

```bash
make test
sudo python3 scripts/integration.py --trials 3 --output results/reproduction
sudo python3 scripts/lifecycle.py --output results/lifecycle-reproduction
sudo python3 scripts/soak.py --output results/soak-reproduction
python3 scripts/summarize.py results/reproduction
```

See [measurement methodology](measurement.md) for denominator definitions,
successful-operation percentile limits, and reasons not to pool different workloads.
The GitHub workflow is included; its result is reported separately from local checks.
