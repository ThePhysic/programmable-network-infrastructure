# Measured results

**24/24 fault experiments passed: three trials for each of eight scenarios.**
Each trial checked the intended effect, restored application and network state,
and verified teardown. These are recorded results from an isolated Linux/WSL2
lab; the [validation record](validation.md) describes the environment and source
revisions.
Published records are sanitized derivative exports of those runs. Neutral host
metadata and regenerated export checksums do not change the numerical results
below or turn them into new experiments; see [privacy and provenance](privacy.md).

## Eight faults, distinct evidence

Values below are **per-trial median [minimum, maximum], n=3**. The last column
summarizes per-trial sampled upper bounds from starting restoration to a
successful echo, including restoration and collection overhead. It is not exact
routing convergence.

| Scenario | Intended change and independent observation | Fault-phase success (%) | Restored / clean trials | First restored success bound (s) |
|---|---|---:|---|---:|
| Route withdrawal | Withdraw the backend prefix; BGP and Linux forwarding entries disappear, and echoes fail | 0 [0, 0] | 3/3 each | 0.455 [0.450, 0.480] |
| Route policy | Deny the prefix inbound at r1; observed policy bindings and missing BGP/forwarding routes explain failed echoes | 0 [0, 0] | 3/3 each | 0.474 [0.446, 0.498] |
| Firewall drop | Drop backend TCP packets; rule counters advance while the route and listener remain available | 0 [0, 0] | 3/3 each | 0.257 [0.245, 0.272] |
| DNS failure | Fail name resolution; gateway-origin direct-IP controls still complete 10/10 echoes in each trial | 0 [0, 0] | 3/3 each | 0.233 [0.201, 0.240] |
| Backend down | Stop the listener; socket observations distinguish service absence from a missing route | 0 [0, 0] | 3/3 each | 0.299 [0.282, 0.304] |
| Link loss | Disable the primary link; the selected next hop changes to the alternate path and sampled traffic succeeds | 100 [100, 100] | 3/3 each | 0.248 [0.226, 1.215] |
| Packet loss | Apply delay/loss with `tc`; impairment state accompanies failed echoes and higher successful-operation latency | 78.6 [69.2, 82.4] | 3/3 each | 0.268 [0.243, 0.269] |
| Gateway overload | Increase offered load; gateway rejection counters rise while routing and the backend stay available | 33.3 [33.3, 33.3] | 3/3 each | 0.235 [0.210, 0.244] |

DNS direct-IP controls exercise gateway-to-backend transport while bypassing DNS
and proxy forwarding; they do not establish the client-to-proxy hop's health.
Link-loss probes begin after alternate-route readiness, so their success does not
establish zero-loss transition behavior or preservation of existing sessions.

## Baseline, disruption, restoration

These comparisons retain the same **n=3, median [minimum, maximum]** convention.
Success percentages count all attempted operations. **p99 describes successful,
complete byte-verified operations only**; a phase with no successes has no such
percentile. The median of three trial p99 values is not a pooled p99. Small sample
counts limit tail-percentile resolution.

| Scenario / metric | Baseline | Fault | Recovery |
|---|---:|---:|---:|
| Route withdrawal: success (%) | 100 [100, 100] | 0 [0, 0] | 100 [100, 100] |
| Route withdrawal: p99 (ms) | 6.073 [4.536, 6.496] | No successes | 3.649 [3.446, 3.802] |
| Link loss: success (%) | 100 [100, 100] | 100 [100, 100] | 100 [100, 100] |
| Link loss: p99 (ms) | 5.227 [4.695, 5.563] | 3.863 [3.350, 4.028] | 4.542 [4.070, 7.328] |
| Gateway overload: success (%) | 100 [100, 100] | 33.3 [33.3, 33.3] | 100 [100, 100] |
| Gateway overload: p99 (ms) | 6.247 [5.636, 6.813] | 270.830 [269.099, 291.927] | 3.340 [2.867, 3.981] |

Ordinary phases schedule 256-byte echoes for two seconds, with concurrency 2 and
a requested rate of 20 attempts/s. **The overload fault changes the workload**:
concurrency 48, no rate pacing (`rate=0`), and a 0.25-second connection hold,
against a 16-session gateway limit. Baseline and recovery have no hold. Its fault
phase completed 128/384 echoes in each trial; the p99 includes the intentional
hold and cannot be read as network-only latency or proxy overhead.

The [browsable route-withdrawal incident](../examples/route-withdrawal/report.md)
records **40/40 baseline, 0/8 fault, and 40/40 recovery** operations. Its linked
[BGP observation](../examples/route-withdrawal/fault/snapshot/r1-bgp-routes.json),
[Linux routes](../examples/route-withdrawal/fault/snapshot/r1-routes.json), and
[probe result](../examples/route-withdrawal/fault/probe.json) let a reader inspect
the explanation beyond the injected-fault label.

## Load, lifecycle, and provenance

Separate records contain **5/5 lifecycle cases** and a ten-round load test with
**15,155/15,155 byte-correct ordinary 64 KiB echoes**. Its two overload rounds
recorded **261 controlled rejections**; those are separate from the eight-scenario
acceptance dataset. Sampled active connections stayed within the 16-session
budget. [Validation details](validation.md) retain resource checks and the later
hosted-runner correction history.

The acceptance archive records revisions `a2ec006` and `5391a69`; these predate
the hosted-runner readiness fixes. The load record separately declares revision
`78cb243` with a dirty working tree. Source hashes are retained; its Go gateway
and Linux/DNS sources match the acceptance dataset, while reporting and
orchestration changed afterward. The [source context](validation.md#recorded-environment)
and separately retained [hosted follow-up](validation.md#hosted-runner-follow-up)
keep these measurements distinct. Other validation work overlapped portions of
the functional suite on the same VM.

These runs demonstrate observable correctness and recovery under their stated
conditions. They establish neither physical-network performance nor statistical
significance. Recovery times are sampled bounds; exact BGP convergence is
unmeasured. Public summaries and archives are derived exports with the same
measured counts, quantiles, workload, and collection timestamps. Their new
manifests validate export consistency; [sanitization provenance](../examples/evidence/sanitization-manifest.json)
links input and output artifact digests. Earlier public commits retain the
original records, so this export does not erase past exposure.

## Inspect the complete evidence

- [Measurement methodology](measurement.md) and [validation context](validation.md).
- [Full repeated-trial tables](../examples/evidence/measurements.md) and
  [machine-readable measurements](../examples/evidence/measurements.json).
- [Representative incident report](../examples/route-withdrawal/report.md) and
  [verification commands](../examples/README.md).
- Full archives: [acceptance](../examples/evidence/acceptance.tar.gz),
  [lifecycle](../examples/evidence/lifecycle.tar.gz),
  [load](../examples/evidence/soak.tar.gz), and
  [hosted follow-up](../examples/evidence/hosted-followup-link.tar.gz), with
  [checksums](../examples/evidence/SHA256SUMS).
