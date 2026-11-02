# Measuring and comparing experiments

Run repeated trials using the same Linux environment and a stated workload. The
experiment records workload duration, concurrency, payload, attempt rate, kernel,
software context, source hashes, and effective parameters for each phase. Keep raw
run records, captures, and manifests in ignored local storage; prepare an audited
sanitized export before public distribution. This document describes methodology;
it does not assert any achieved performance result or CI outcome.

To summarize existing records without writing files:

```sh
python3 scripts/summarize.py results/acceptance
python3 scripts/summarize.py 'results/**/experiment.json' --format json
```

Writing requires an explicit destination:

```sh
python3 scripts/summarize.py results/acceptance --output results/summary.md
python3 scripts/summarize.py results/acceptance --format json --output results/summary.json
```

The summarizer discovers `experiment.json` recursively, deduplicates paths,
rejects repeated experiment identities, and reports malformed records. It
recomputes diagnosis, restoration checks, teardown verification, and scenario
acceptance from the supplied observations. Saved `result` claims are not treated
as evidence. As with the report generator, edited JSON is not independently
authenticated. Verify the appropriate bundle manifest: original local manifests
describe collected files, while regenerated public manifests describe sanitized
export bytes. The [sanitization manifest](../examples/evidence/sanitization-manifest.json)
links input/output digests and transformation context without an identifier map.

## Public summaries are derivatives

Published JSON and Markdown summaries retain historical trial counts, quantiles,
sample windows, workload parameters, source/binary digests, and original collection
timestamps. Incidental execution paths, host labels, and host-side route values
may become explicitly synthetic metadata. Such transformations do not rerun an
experiment or improve a measured result. New archive hashes and nested manifests
establish consistency of the export; they do not assert original-byte equality.

Use [the export/audit workflow](privacy.md#future-runs-and-ci) for public evidence.
Its deterministic rules and public provenance support repeatable transformation.
Older Git commits and prior downloaded artifacts may retain the originals;
sanitization of the current tree does not remove those copies.

## Comparable conditions

Trials with different environment context, effective workloads, or execution
source hashes receive separate comparison groups. A group is labeled incomplete
if required environment, workload, per-phase parameters, or source hashes are
missing. Medians across incompatible groups are not pooled. Even within a group,
shared VM scheduling, host load, thermal behavior, and background traffic can
introduce variation. Record those factors when drawing an optimization conclusion.

The gateway-overload scenario intentionally raises concurrency and removes rate
pacing during the fault phase. Its baseline-versus-fault comparison demonstrates
bounded overload behavior under changed load; it does not isolate a network-only
effect. Effective phase workloads appear in every summary so this distinction
remains visible. Recovery may have a longer observation window than a short
baseline/fault phase. Different durations also affect sample counts and precision.

## Denominators and aggregation

- An attempt is one TCP operation with exact returned-byte verification. An echo
  mismatch is a failure even if the connection was accepted.
- Success fraction is successful operations divided by all attempted operations.
  Errors remain classified separately. Zero attempts cannot establish health.
- Latency percentiles describe successful complete operations only. A phase with
  no successes has no successful-operation percentile. Timeouts are not silently
  converted to zero latency or omitted from error rates.
- The summary gives the median and observed minimum/maximum of each per-trial
  metric, with its trial count. The median of trial p99 values is not a pooled
  workload p99. No confidence interval or significance claim follows from a range.
- Attempt rate is measured attempts divided by recorded probe duration. It is an
  achieved rate, distinct from the requested pacing limit.
- Per-operation sample retention is bounded. Aggregate counters remain the source
  for rates; a truncated sample list cannot prove the absence of a transient.
- Gateway resource values are snapshots collected after each phase, not peak RSS,
  peak descriptors, or peak goroutines. CPU seconds are cumulative process-lifetime
  values; they are not phase CPU utilization or CPU percentages.

Use enough successful operations to make the requested tail percentile meaningful.
For a small functional run, emphasize exact-byte correctness, classified failures,
and source evidence. Longer repeated workloads are necessary for stronger tail
latency, saturation, and resource conclusions.

## Recovery clocks are distinct

The recorded clocks may include fault application or restoration work, a sampling
gap, and probe timeouts. Their definitions and evidence travel with each value:
Parent invocation windows bracket the child's local scheduling clock. First-result
times add the full measured launch/return overhead to obtain a conservative upper
bound rather than assuming both processes started their clocks simultaneously.
An inconsistent child duration leaves alignment-dependent timings unmeasured.

| Clock | Interpretation |
|---|---|
| Fault to detection | Time to the first sampled failed operation; earlier failure may be unobserved |
| Route convergence | Requires a defined route-state observation; phase snapshots alone leave it unmeasured |
| First success after restoration | Time to the first completed successful sampled operation; earlier success may be unobserved |
| Stable recovery | Completion of a stated error-free probe window, with independent restored-state checks reported separately |

These are sampled bounds under the documented experiment. A route observed at one
instant does not establish its precise installation time. A healthy recovery
window does not establish uninterrupted service between samples. A successful
alternate-path probe does not imply zero-loss failover or preservation of existing
TCP sessions. Wall timestamps from different sources do not imply perfect clock
synchronization; local monotonic elapsed times support local durations.

## Limits of the environment

Linux namespaces and FRRouting produce real kernel forwarding and BGP behavior,
but share a kernel, CPU budget, and virtual host. They do not reproduce independent
physical routers, switch queues, NIC offloads, geographic latency, or production
failure rates. A Windows-hosted Linux VM adds virtualization and host scheduling
effects. Compare like environments, retain limitations, and derive portfolio
numbers only from actual reproducible records.
