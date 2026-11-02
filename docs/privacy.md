# Public evidence privacy audit

The audit found no credential-pattern matches. Historical evidence retains local execution paths, host-derived configuration labels, and host-network metadata; those records and their checksums remain unchanged.

## Scope

The immutable baseline was [`d4da9b6`](https://github.com/ThePhysic/programmable-network-infrastructure/tree/d4da9b699c4854b85ba8ee6c33c6fade0f0e75a9). The read-only audit covered all 330 tracked files, including 314 text files, and all 7,132 text members in the four compressed evidence archives. Archive members were inspected without extraction. Counts include duplicate evidence preserved in multiple locations.

Checks searched for local account paths, hostname directives and fields, common machine-name formats, email addresses, credential formats, and network-address metadata. Logical lab node names were distinguished from additional host labels. This is a pattern-based audit of the baseline, not a guarantee that every possible secret or personal identifier is absent; Git history was not scanned or rewritten.

## Findings and retained context

| Category | Finding and locations |
| --- | --- |
| Incidental local paths | Account-bearing executable paths occurred in 63 baseline text locations, with 135 matches. Most are protected environment records: [measurements](../examples/evidence/measurements.json), its [generated report](../examples/evidence/measurements.md), the [load summary](../examples/evidence/soak-summary.json), the representative [experiment](../examples/route-withdrawal/experiment.json) and [report](../examples/route-withdrawal/report.md), and copies inside all four [evidence archives](../examples/README.md). These original records remain public and unchanged. |
| Ordinary documentation | The baseline validation page also contained one incidental executable path. That prose now uses a neutral description; the protected measured records retain their original paths. |
| Incidental host label | An additional host-derived hostname appears alongside the logical router name in 85 saved FRR/vtysh configuration files, including the representative [router snapshot](../examples/route-withdrawal/baseline/snapshot/r1-running-config.txt), its fault/recovery snapshots, and configuration copies in the acceptance, hosted-followup, and lifecycle archives. These labels remain in raw provenance; they are not synthetic router identities. |
| Incidental host-network metadata | The [acceptance summary](../examples/evidence/acceptance-summary.json) and `acceptance/summary.json` inside `acceptance.tar.gz` retain five private host-route IPv4 values. They support the before/after host-configuration check but also disclose part of the local virtual-network layout. They are separate from the synthetic experiment traffic. |
| Expected technical context | Synthetic lab addresses, virtual-interface identifiers, namespace/process IDs, kernel and WSL versions, software versions, CPU counts, and workload settings describe the experiment environment. Artificial route constants in test fixtures are expected test data. |
| Intentional public identity | The repository owner, GitHub links, and author attribution are intentional public project metadata. They are distinct from incidental local account paths. |
| Credentials and other identifiers | No matches were found for the scanned credential formats or email addresses. Residual host labels are disclosed above. This does not certify every packet payload's origin or comprehensively classify personal data. |

## Evidence integrity and packet scope

All 13 entries in [SHA256SUMS](../examples/evidence/SHA256SUMS) matched. The representative experiment's 270-file manifest and 29 manifests inside the archives also passed, covering 7,617 manifest entries in total. Protected evidence and implementation files were unchanged; the existing local executable's hash was unchanged during the audit.

All 348 retained PCAP files parsed through their record boundaries, covering 565,622 records. Captured IP and ARP header addresses stayed within the configured lab IPv4 ranges, loopback, or kernel-generated IPv6 link-local/multicast scope. No outside-lab header endpoint was observed. Header inspection is narrower than payload sanitization and does not establish a new timing or causality claim.

## Optional sanitized export

The residual identifiers above remain in provenance-protected historical records. A sanitized public export would need separate generated artifacts, new checksums, and an explicit mapping from original artifact hashes to exported hashes, with each transformation documented. Owner approval is required before replacing historical measured records or changing their publication. This presentation pass does not replace evidence, rewrite history, or force-push.
