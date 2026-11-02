# Engineering lessons and regression evidence

Validation exposed defects in lifecycle handling, evidence contracts, and routing
readiness. Each correction below turns a failure into an explicit invariant with
a regression check. [Measured results](results.md) and the
[validation record](validation.md) describe the retained runtime evidence.

| Issue | Correction | Regression evidence and commit |
|---|---|---|
| An incomplete `down` returned CLI success | Return a nonzero status when cleanup fails or its success verdict is absent | [CLI tests](../tests/test_cli.py) cover failed, successful, and missing cleanup verdicts; [68fbcf6](https://github.com/ThePhysic/programmable-network-infrastructure/commit/68fbcf6407e3ab62d24059a4e1def33038369476) |
| The load-test manifest omitted its hash algorithm | Apply the same SHA256 manifest contract to load and experiment bundles, including failure artifacts | [Load tests](../tests/test_soak.py) check the algorithm and preserved failure record; [manifest tests](../tests/test_experiment.py) detect changed or added files; [a2ec006](https://github.com/ThePhysic/programmable-network-infrastructure/commit/a2ec006430e699513ae4b80ced5269f3a3396e5d) |
| A route-policy claim lacked observed configuration | Collect FRR running configuration and prefix-list output; require effective denial and inbound bindings on both r1 peers. Residual partial policy prevents verified restoration | [Policy parser tests](../tests/test_linux.py#L214) cover bindings, rule precedence, multi-daemon output, and unknown evidence; [report tests](../tests/test_report.py#L61) reject label-only attribution and residual policy; [cd9e4b0](https://github.com/ThePhysic/programmable-network-infrastructure/commit/cd9e4b0b5a8b24f02db20bed36c360e78186b0d1), [62e7241](https://github.com/ThePhysic/programmable-network-infrastructure/commit/62e724132a60457beb5aab6f9470fbfd0764dd57) |
| Refusing a namespace collision left the runtime unusable for retry | Claim only an empty private runtime before creating helper artifacts; preserve the foreign namespace and its process; permit retry after the collision is removed | [Startup tests](../tests/test_linux.py#L86) cover retryable collisions and partial helper failures; [lifecycle harness](../scripts/lifecycle.py) exercises the same runtime before and after collision removal; [cd9e4b0](https://github.com/ThePhysic/programmable-network-infrastructure/commit/cd9e4b0b5a8b24f02db20bed36c360e78186b0d1) |
| A blocked synchronous log sink defeated session and shutdown bounds | Give logging one sink worker and a bounded queue; count dropped records and bound the shutdown wait | [Blocked-writer and short-write tests](../internal/traffic/logging_test.go) exercise queue overflow, goroutine accounting, shutdown, and incomplete writes; [a2ec006](https://github.com/ThePhysic/programmable-network-infrastructure/commit/a2ec006430e699513ae4b80ced5269f3a3396e5d) |
| Reestablished BGP peers did not prove the preferred forwarding path had returned | Wait for the intended unicast backend prefix, next hop, and interface, as well as established peers; retain separate application verification | [Routing readiness tests](../tests/test_linux.py#L180) reject the alternate path and show restoration waiting for the primary FIB entry; [c16a999](https://github.com/ThePhysic/programmable-network-infrastructure/commit/c16a999ddb824fb57e3bd100b081c0f352819f96) |
| Advancing nftables counters looked like a host configuration change | Compare structured configuration after removing only counter packet/byte values; retain raw observations | [Host-state tests](../tests/test_integration.py) still reject changes to routes, forwarding, verdicts, rule order, named-counter identity, comments, and malformed observations; [b8b895a](https://github.com/ThePhysic/programmable-network-infrastructure/commit/b8b895aa25b944d4f2d8f95250974e8e0deed0b7) |

The logging correction has an explicit limit: an uninterruptible sink write may
retain its single logging goroutine until the writer is released or the process
exits. The queue and session work remain bounded; dropped logs and an incomplete
flush are reported rather than hidden.

## What the first hosted run caught

The first hosted CI run passed seven scenarios and **failed link-loss
restoration**. Echo traffic succeeded, but the selected route still used the
alternate next hop after the BGP peers returned. The restoration check correctly
rejected that state. The same run exposed the host-check false positive caused by
live firewall counters. These failures led to the final two corrections above;
the history is retained rather than relabeled as an all-green initial run.

The follow-up records **104 Python checks**, Go race tests, and `go vet`, plus
three real failover trials. Each trial restored the preferred next hop, completed
20/20 recovery echoes, and verified teardown. Inspect the
[check log](../examples/evidence/hosted-followup-checks.txt),
[trial summary](../examples/evidence/hosted-followup-link-summary.json), and
[full follow-up bundle](../examples/evidence/hosted-followup-link.tar.gz).
The evidence was retained in
[1cf1268](https://github.com/ThePhysic/programmable-network-infrastructure/commit/1cf1268ba54412d3b22c8e45fbfe073d0d3b6ee9).
Current hosted status belongs to [GitHub Actions](https://github.com/ThePhysic/programmable-network-infrastructure/actions);
it is separate from these historical local check results.

## Preserve the evidence behind the claim

Reports, raw observations, packet captures, source hashes, and artifact manifests
were packaged together in
[7a02b08](https://github.com/ThePhysic/programmable-network-infrastructure/commit/7a02b08a7a027234a7dc7468720b91edd821a611).
The original 24-trial dataset, the separately recorded load run, and the later
hosted follow-up retain their own source context. See
[provenance and limitations](validation.md#recorded-environment) and
[verification commands](../examples/README.md); the older measurements are not
presented as a fresh benchmark of every later revision.
