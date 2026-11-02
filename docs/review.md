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

The final review verdict and validation references are recorded after corrections
and re-review. Publication privacy and commit identity are checked separately once
the reviewed source is pushed.
