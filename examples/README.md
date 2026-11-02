# Inspect the measured examples

Start with the [curated results](../docs/results.md): all eight scenarios, three
illustrative baseline/fault/recovery comparisons, and the measurement limits.
Then follow the [route-withdrawal report](route-withdrawal/report.md) for one
complete incident: 40/40 baseline echoes, 0/8 during the fault, and 40/40 after
restoration, with verified teardown. Its links lead to the original probes,
BGP/kernel observations, gateway metrics, and policy state. The
[flushed packet captures](route-withdrawal/final/captures/) sit alongside the report.

Check the browsable experiment's original manifest directly:

```bash
python3 -m netlab verify examples/route-withdrawal
```

[Full repeated-trial measurements](evidence/measurements.md) and
[their JSON](evidence/measurements.json) retain three trials per scenario. Each
value is a median and observed range across per-trial metrics; successful-operation
percentiles are not pooled. Read the [methodology](../docs/measurement.md) and
[validation context](../docs/validation.md) for workload differences, sampled
recovery bounds, and historical source states.

| Bundle | What it retains |
|---|---|
| [Acceptance](evidence/acceptance.tar.gz) | 24 experiments across eight scenarios |
| [Lifecycle](evidence/lifecycle.tar.gz) | Five cases covering isolation, interruptions, collisions, and independent lab roots |
| [Load](evidence/soak.tar.gz) | Ten rounds, including ordinary verified echoes and intentional overload |
| [Hosted follow-up](evidence/hosted-followup-link.tar.gz) | Three failover trials following the hosted-runner readiness corrections |

Full experiment directories are packaged in `evidence/acceptance.tar.gz`.
The lifecycle and soak archives retain their own records separately. Extract into
a new directory, preserving relative paths:

```bash
mkdir -p results/unpacked
tar -xzf examples/evidence/acceptance.tar.gz -C results/unpacked
python3 -m netlab verify results/unpacked/acceptance/route-policy-1
```

The [checksum list](evidence/SHA256SUMS) covers the archives and readable summaries.
From the repository root on Linux, check it with:

```bash
(cd examples/evidence && sha256sum -c SHA256SUMS)
```

[checks.txt](evidence/checks.txt) retains the race/vet/Python result;
[hosted-followup-checks.txt](evidence/hosted-followup-checks.txt) preserves the
later check output. [Engineering lessons](../docs/review.md) explain the defects
and their regression checks.
[artifact-audit.json](evidence/artifact-audit.json) records the scope and limits of
the representative packet/evidence audit. These are synthetic lab
captures, not production or other people's traffic.
