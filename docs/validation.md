# Validation evidence

The implementation was exercised in a dedicated Ubuntu 24.04 WSL2 distribution
using real Linux network namespaces, virtual Ethernet links, FRRouting, nftables,
traffic control, DNS packets, and the authored Go gateway. No route or packet
simulation substitutes for the integration checks.

The results below describe the original collection runs. Current public bundles
are sanitized derivative exports, with original source/binary hashes and
collection timestamps retained. Their regenerated artifact manifests verify the
published export's consistency, not byte equality with the original observations.
See [privacy scope and export provenance](privacy.md).

## Recorded environment

- Kernel: `6.18.54.1-microsoft-standard-WSL2`.
- CPU: AMD Ryzen 9 7940HS w/ Radeon 780M Graphics; 16 logical CPUs.
- Linux memory context: `MemTotal:       15970204 kB`.
- Python: 3.12.3; Go binary toolchain: `go1.22.2`.
- FRRouting: `frr version 8.4.4`, independently recorded in the running configuration.
  The environment collector's `vtysh --version` field is unknown; the raw running
  configuration supplies this version evidence.
- Acceptance source revisions: `a2ec006430e699513ae4b80ced5269f3a3396e5d`
  and `5391a698623b09b98340f5f89dbffdb6094b86b3`. The latter corrects only the
  Windows PowerShell helper; the executing Go and Linux/Python lab sources were
  identical across these trials. Per-file source hashes and binary SHA256 are
  retained in each experiment.

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
  Original packaging separately revalidated the SHA256 manifests for all 24
  experiments; that historical check is distinct from verification of the later
  sanitized exports.

Other validation processes overlapped portions of the repeated functional suite
on the same VM. These are correctness and resilience demonstrations under documented
workloads, not isolated peak-performance measurements. Recovery clocks are sampled
bounds including restoration and collection gaps. Exact BGP convergence is
unmeasured. Fault-phase failover traffic begins after alternate-route readiness;
the project does not claim zero-loss transition behavior.

## Inspect or reproduce

The [representative route-withdrawal report](../examples/route-withdrawal/report.md)
is browsable with its linked exported observations. The [repeated-trial measurements](../examples/evidence/measurements.md)
show per-scenario medians, ranges, sample counts and comparison groups.

Full evidence is packaged in [acceptance.tar.gz](../examples/evidence/acceptance.tar.gz),
[lifecycle.tar.gz](../examples/evidence/lifecycle.tar.gz), and
[soak.tar.gz](../examples/evidence/soak.tar.gz). They retain the experiment
structure and generated observations, with incidental host metadata transformed
as described in the [export provenance](../examples/evidence/sanitization-manifest.json).
[SHA256SUMS](../examples/evidence/SHA256SUMS) records exported archive integrity.
Extract an experiment and run `python3 -m netlab verify` on its directory to check
its regenerated export manifest. Derived JSON summaries are retained alongside
the archives for inspection; these are not newly rerun measurements.

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

## Hosted runner follow-up

The first hosted CI run passed seven scenarios and correctly rejected link-loss
restoration: application traffic succeeded, but the selected route still used the
alternate next hop. BGP peers being established did not establish preferred FIB
selection. Startup and restoration now wait for the intended primary unicast route
through `10.77.12.2` on `direct0`, with independent application checks retained.

That run also exposed a harness false positive: host routes, forwarding, and
firewall configuration were unchanged, while the hosted agent's live firewall
packet/byte counters advanced. The harness now retains raw JSON before/after state
and compares configuration excluding only nftables counter values. Tests still
reject changed routes, forwarding, verdicts, rule order, named counters, comments,
and malformed observations.

The corrections are committed in `b8b895aa25b944d4f2d8f95250974e8e0deed0b7`
and `c16a999ddb824fb57e3bd100b081c0f352819f96`. All **104 Python tests**, Go race
tests, and vet passed; [the follow-up log](../examples/evidence/hosted-followup-checks.txt)
is retained separately from the original 96-test log. Three real one-second
failover trials each restored the preferred next hop and transferred 20/20 recovery
echoes with clean teardown. The [summary](../examples/evidence/hosted-followup-link-summary.json)
and [full evidence](../examples/evidence/hosted-followup-link.tar.gz) retain their
own source records and manifests.

The 24-trial and load datasets retain their historical measurements and source
attribution. Current archives are sanitized derivatives; the original archive bytes
remain in earlier public Git history. The follow-up strengthens readiness and
host-check semantics without turning those datasets into measurements of a later
revision. Hosted CI status is available in the repository's Actions tab and is
distinct from the recorded local measurements.

## Public-export verification

The **2026-11-02** derivative export uses sanitizer 1.0.0 and ruleset
`pnid-public-v1`, with input source revision `d01941185dd1fa3523d9a6d06ab736a9660ac98a`.
It is a transformation of historical evidence, not a rerun of the 24-trial or load
datasets. [Export provenance](../examples/evidence/sanitization-manifest.json)
records input/output digests without an identifier mapping.

Verification established:

- Two staged exports matched across all **287 outer files**.
- All **183 provenance hash mappings**, **30 bundle manifests**, and **14 outer
  checksum entries** validated after transformation.
- All **348 PCAPs** were byte-identical, covering **565,622 records**. The packet
  scan included stored frame bytes and available payloads; it cannot inspect
  uncaptured bytes or every possible encoding.
- Numerical/boolean/null values, original collection timestamps, and retained
  source/binary hash strings matched the input evidence. Historical scenario and
  load totals above were not improved or newly measured by the export.
- The current-tree gate reported zero findings across **338 tracked files and
  7,806 tracked/archive-member entries**, including four archives.
- The current implementation passed **161 Python tests with zero skips**, Go race
  tests, `go vet`, and the Go build. The earlier 104-test log remains a separate
  historical record; these new checks include the exporter and packet inspector.
- A separate fresh privileged Linux/FRR integration run passed **8/8 scenarios**.
  It validates the updated implementation without replacing the historical
  three-trial tables or ten-round load observations.

[Privacy scope and counts](privacy.md#verified-export-scope) describe the exact
transformations, reserved-fixture allowances, unchanged packet bytes, and scan
limits. Prior public commits and three inspected earlier CI artifacts retain
original metadata. No historical erasure is claimed. Current hosted outcomes are
reported through Actions and must be distinguished from these local checks.
