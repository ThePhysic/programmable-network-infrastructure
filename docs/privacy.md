# Public evidence privacy and export provenance

**Cleaning the current tree does not erase earlier disclosure.** Original records
remain retrievable from older public Git commits. Forks, clones, caches, and
previous CI downloads can retain copies. Normal Git ancestry is preserved; this change does not
rewrite history, force-push, or delete prior remote artifacts. It minimizes
current and future publication without promising anonymity or complete removal.

## What the public exports represent

The examples and four evidence archives are derivative exports of the recorded
experiments. Exporting them does not rerun the lab or create new performance
results. The 24/24 fault trials, 5/5 lifecycle cases, 15,155/15,155 ordinary load
echoes, and 261 deliberate overload rejections remain historical observations.
The [validation record](validation.md) distinguishes the recorded source states
and check logs from later export work.

| Content | Public treatment | Interpretation |
|---|---|---|
| Incidental workstation execution paths | Replace with a neutral, explicitly synthetic absolute location label | Metadata only; not a path to copy into a command |
| Incidental FRR host label | Replace consistently with a neutral host label | Logical routers `r1`, `r2`, `r3` and their configuration remain meaningful |
| Host-side route addresses | Replace consistently with opaque address labels | Synthetic comparison identities, not the original host IPs; route count and before/after relationships remain useful |
| Lab addressing and protocols | Retain lab IPs/prefixes, BGP identities, DNS results, and fault semantics | These describe the actual isolated experiment |
| Measurements and collection provenance | Retain workload numbers, outcomes, quantiles, source/binary digests, and collection timestamps | They remain attributed to their original run and source revision |
| Archive metadata | Normalize member ordering and incidental owner metadata | Stable public packaging; required member paths remain intact |
| Packet captures | Retain all 348 reviewed files byte-for-byte | No packet payload was rewritten |

Kernel/runtime versions, software context, CPU and memory descriptors, logical
namespace identities, and synthetic interface information provide reproducibility
context. Intentional GitHub owner links and project attribution remain public.
They are distinct from an incidental local account or host address.

## Verified export scope

The original collection is dated **2026-11-02 UTC**; the representative incident
started at `2026-11-02T04:17:40.814956+00:00`. The later public export is dated
**2026-11-02**, uses sanitizer **1.0.0**, ruleset **`pnid-public-v1`**, and records
input source revision `d01941185dd1fa3523d9a6d06ab736a9660ac98a`.

| Finding category | Input occurrences | Export occurrences |
|---|---:|---:|
| Account-bearing execution paths | 158 | 0 |
| Incidental FRR host labels | 85 | 0 |
| Host-network address occurrences | 52 | 0 |
| Archive-metadata findings | 7,472 | 0 |

These are ruleset occurrence counts, including repeated copies and decoded
structured text. They are not directly comparable with the earlier audit's
location counts or unique-address counts. The 52 host-address occurrences
represent **seven identities: five IPv4 and two host-side link-local IPv6
addresses**. They are distinct from the unchanged synthetic lab/packet addresses.
No identifier lookup table is published.

The current-tree gate reported **zero findings across 338 tracked files and
7,806 tracked/archive-member entries, including four archives**. Its narrow
fixture allowances cover the invented sanitizer/packet-test identities only in
their designated test files and reserved example-domain email addresses. They are not
a blanket exemption for tests, arbitrary private networks, or account paths.

Two staged exports produced **287 byte-identical outer files**, with no
mismatches. Independent validation checked all **183** provenance input/output
hash mappings, including archive-member references, all **30** exported bundle
manifests, and all **14** outer checksum entries. It also confirmed preservation
of 189,385 numerical/boolean/null values, 2,827 collection timestamps, and 1,300
retained SHA256 strings. Original pre-export checks separately validated 13
checksum entries and 30 manifests covering 7,617 entries; those checks describe
the original bytes, not the derivative hashes.

## Provenance and verification

The [sanitization manifest](../examples/evidence/sanitization-manifest.json)
records artifact paths, input and output SHA256 digests, source revision,
ruleset/version, export context, and transformation categories/counts. It contains
no identifier-to-label lookup table. Original collection timestamps and hashes of
the executing source and binary remain separate from the export date and public
artifact hashes.

Affected nested manifests and
[SHA256SUMS](../examples/evidence/SHA256SUMS) describe the **sanitized exported
bytes**. Passing them establishes the export's internal consistency, not equality
with the original collected bytes or authenticity against replacement of an
entire bundle. Historical hashes and original records remain in earlier commits.
Stable export rules, ordering, and archive metadata permit byte-repeatable output
for the same inputs and export parameters.

```bash
python3 scripts/sanitize_public_evidence.py audit --repository .
python3 -m netlab verify examples/route-withdrawal
(cd examples/evidence && sha256sum -c SHA256SUMS)
```

For archived experiments, extract into a new local directory and run
`python3 -m netlab verify` on each experiment directory, as shown in
[evidence navigation](../examples/README.md). The verification schema applies to
the regenerated export manifests. A new hash does not imply a new experiment.

## Packet and scanning limits

The expanded packet assessment visited **all 348 PCAPs and 565,622 records**,
including complete stored frames, protocol metadata, and available application
payloads. It counted **48,580,487 stored frame bytes**, including **8,020,271
available application bytes**, with **115,474 snaplen-truncated records**. No new
credential or packet findings were reported by these bounded checks. Independent
comparison confirmed every PCAP file was byte-identical after export.

Uncaptured wire bytes in truncated records cannot be inspected. The scan does not
reassemble arbitrary application streams or decode every possible encoding.
Header-only inspection would have been narrower than this assessment; neither
scope establishes perfect privacy. Packet contents are not rewritten by generic
text substitution. A future finding requiring payload changes needs a separately
validated evidence treatment that preserves defensible lengths, checksums, and
causal interpretation.

The export/audit checks are bounded checks for known identifier patterns and
parsed evidence structures. They do not certify anonymous data, prove that every
possible credential is absent, or establish the origin of arbitrary external
input. Preserve the lab's isolation boundary and review newly generated evidence
before distribution. Measurement, timing, diagnosis, and virtual-lab limitations
in the [methodology](measurement.md) still apply after sanitization.

## Future runs and CI

Raw run output can be retained in ignored local storage. Prepare a separate public
export; never add an original backup or an identifier lookup table to the public
tree. Inputs are explicit and output must be a new directory:

```bash
python3 scripts/sanitize_public_evidence.py export \
  --input results/route-demo --output results/public-route-demo \
  --source-revision "$(git rev-parse HEAD)"
python3 scripts/sanitize_public_evidence.py audit --input results/public-route-demo
```

The optional `--export-date YYYY-MM-DD` fixes the export date when reproducing a
recorded transformation; `--provenance-path REL` selects its relative provenance
location. Export metadata must not be confused with the original collection time.

The [CI workflow](../.github/workflows/validate.yml) retains the existing tests
and real networking checks, then exports and audits `results/public-ci`. Only
that sanitized tree may be uploaded as `network-evidence`, with the existing
seven-day retention. Failure diagnostics use the same gate: unsuccessful export
or audit does not fall back to a raw upload. Checked-in evidence is audited too.

## Earlier downloadable copies

The pre-export inventory listed these unexpired `network-evidence` artifacts,
with scheduled expiry on **2026-11-09**. Private downloads confirmed that each
contains hosted-runner account paths, incidental FRR host labels, and host-side
network metadata:

| Run page | Artifact ID |
|---|---:|
| [Run 41393228046](https://github.com/ThePhysic/programmable-network-infrastructure/actions/runs/41393228046) | 13118167868 |
| [Run 41390078474](https://github.com/ThePhysic/programmable-network-infrastructure/actions/runs/41390078474) | 13116704580 |
| [Run 41389022632](https://github.com/ThePhysic/programmable-network-infrastructure/actions/runs/41389022632) | 13116384001 |

Each download contained **32 hosted-runner path findings, 24 incidental host-label
findings, and 56 host-address occurrences** across 2,172 files. The matched paths
were hosted-runner locations, not owner-workstation paths. Each artifact's eight
manifests validated; its 96 PCAPs were inspected. No additional stop-level
credential or payload findings were reported. Those scans do not make the
historical artifacts sanitized: their known incidental metadata remains.

None was deleted or sanitized in place by this change. Availability can change
with retention. No release assets were
listed in that inventory. Even eventual artifact expiry does not remove copies
from older Git commits, forks, clones, or caches. No history rewrite or remote
deletion was performed, and no license was added or changed.
