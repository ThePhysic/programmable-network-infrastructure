# Inspect the measured examples

Start with [the route-withdrawal report](route-withdrawal/report.md), which links
its original probes, BGP/kernel observations, gateway metrics, policy state, and
packet captures. Its original manifest can be checked directly:

```bash
python3 -m netlab verify examples/route-withdrawal
```

[Repeated-trial measurements](evidence/measurements.md) summarize three trials
per scenario. Each value is a median and observed range across trial metrics;
successful-operation percentiles are not pooled. See
[validation context](../docs/validation.md) for source states and limitations.

Full experiment directories are packaged in `evidence/acceptance.tar.gz`.
The lifecycle and soak archives retain their own records separately. Extract into
a new directory, preserving relative paths:

```bash
mkdir -p results/unpacked
tar -xzf examples/evidence/acceptance.tar.gz -C results/unpacked
python3 -m netlab verify results/unpacked/acceptance/route-policy-1
```

The [checksum list](evidence/SHA256SUMS) covers the archives and readable summaries.
[checks.txt](evidence/checks.txt) retains the race/vet/Python result;
[artifact-audit.json](evidence/artifact-audit.json) records the scope and limits of
the independent representative packet/evidence audit. These are synthetic lab
captures, not production or other people's traffic.
