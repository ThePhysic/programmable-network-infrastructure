# Independent adversarial review

The user requested Astra with medium reasoning effort. The review agent used
`gpt-6-astra` / `medium`, independently inspected the goal, implementation,
tests, and available runtime evidence, and reproduced important findings.

## First review

Verdict: changes required.

| Finding | Required correction |
|---|---|
| Failed teardown returned CLI success | Return nonzero for an incomplete `down`; add command regression checks |
| Soak manifest lacked its hash algorithm | Use the same SHA256 manifest contract as experiments; verify a real bundle |
| Route-policy evidence lacked observed configuration | Retain actual prefix-list and inbound-neighbor policy state and cite it |
| Initial collision prevented runtime reuse | Claim only a new/empty private runtime before helper artifacts; preserve foreign namespace and verify retry |
| Synchronous logging defeated concurrency and shutdown limits | Bound log queuing, account for dropped logs, and verify shutdown with a blocked sink |
| Final portable evidence was not packaged | Retain measured reports, traces, manifests, and environment/methodology documentation |

The logging defect was confirmed in a supplementary adversarial pass: releasing
session capacity before a blocking writer allowed worker accumulation, and the
shutdown wait could remain blocked after its timer. Merely moving capacity release
would not bound shutdown, so the correction needs independent logging ownership.

## Implementation re-review

Verdict: **no remaining code complaints**. Astra closed all five implementation
findings after reviewing the fixes, the blocked-writer regression, independent
policy evidence, the verified soak manifest, all five lifecycle cases, and the
96-test Python check log with Go race/vet results.

Final approval additionally requires the complete measured evidence package and
validation documentation. Publication privacy and commit identity are checked
separately after the reviewed source is pushed.

## Final project and package review

Verdict: **no remaining complaints**. The independent reviewer approves the
implementation and complete evidence package for publication. This verdict covers
commit `7a02b08a7a027234a7dc7468720b91edd821a611` plus the reviewed correction in
`docs/validation.md` listing both recorded acceptance source revisions.

The final read-only audit independently checked all ten packaged SHA256SUMS
entries, all 24 acceptance manifests inside the archive, the embedded lifecycle
and soak manifests, safe archive paths without symlinks, and the browsable
270-file experiment manifest. Recomputed analysis confirmed all 24 experiments
passed their scenario, restoration, and cleanup checks. Host-state records were
equal before and after acceptance; all eight measurement groups were comparable
with three trials each and no invalid records. The retained five lifecycle cases
and ten soak rounds passed, and local documentation/report links resolved.

All five implementation findings are closed. The final provenance wording now
accurately distinguishes both acceptance revisions and the separate dirty load-run
context. Measurement limitations remain explicit. GitHub publication, remote
privacy, remote commit identity, and any subsequent CI result remain separate
post-review checks; this verdict does not claim those actions have occurred.

## Hosted CI correction and renewed review

The first hosted run exposed two additional conditions after the initial approved
publication. The restoration report correctly rejected an alternate next hop that
remained selected after BGP peers returned; readiness now waits for the intended
primary FIB route. The host guard also treated naturally advancing nftables
packet/byte counters as a configuration change; it now compares structured
configuration while retaining raw observations and preserving policy changes.

The corrections passed 104 Python checks, Go race/vet checks, and three actual
one-second failover trials. Separate follow-up artifacts and source context are
recorded in the validation document without modifying the historical datasets.
These changes were submitted to the same independent Astra medium reviewer for a
renewed verdict before their publication.
