# Interfaces and evidence contract

Project executable: `python3 -m netlab`; original Go executable: `bin/netlab-agent`.
Python uses only the standard library. Go uses only the standard library.

This document describes the implemented CLI, Linux API, Go programs, experiment
records, and correctness invariants. See [architecture](docs/architecture.md) and
[measurement methodology](docs/measurement.md) for context and interpretation.

## CLI

```text
python3 -m netlab [--root PATH] [--binary PATH] COMMAND
COMMAND = doctor | up | status | down | run | suite | report | verify
```

Global options precede the subcommand. Defaults are `/var/tmp/pnid-<uid>` for the
mode-0700 runtime directory and `bin/netlab-agent` in the checkout for the binary.
Lab operations require Linux/root; portable `report` and `verify` also work on Windows.

| Command | Behavior |
|---|---|
| `doctor` | Report tool, binary, and runtime prerequisites |
| `up`, `status`, `down` | Manage one owned lab; incomplete `down` returns nonzero |
| `run --scenario NAME --output DIR` | Own baseline/fault/recovery and cleanup; require a new output directory |
| `suite --trials N [--scenarios ...] --output DIR` | Repeat selected scenarios and retain per-experiment results |
| `report EXPERIMENT_JSON` | Recompute interpretation/acceptance and render Markdown to stdout |
| `verify DIR` | Check exact SHA256/size manifest membership, including added or missing files |

`run`/`suite` workload flags are `--duration` (seconds), `--concurrency`,
`--payload` (bytes), and `--rate` (attempts/second; zero is unpaced). Defaults are
2 seconds, 2 workers, 256 bytes, and 20 attempts/second. Effective phase parameters
are recorded, including deliberately higher overload pressure. Active labs are not
taken over by experiments; CLI operations sharing a root are locked.

## Linux API

`Lab(root: pathlib.Path, binary: pathlib.Path)` uses root as an absolute private runtime directory. It owns a fixed six-node diamond topology with namespace prefix derived from root: client, gateway, r1, r2, r3, backend. Gateway connects through BGP routers to backend; direct r1-r2 path plus r1-r3-r2 alternate. DNS runs inside gateway.

Methods return dictionaries:

| Method | Contract |
|---|---|
| `doctor()`, `status()`, `topology()` | Describe prerequisites, ownership/state, and topology |
| `up()` | Create owned resources; wait for established peers and the intended primary FIB route |
| `down()` | Idempotent teardown; report `clean`, remaining namespaces/processes, errors, conflicts, artifacts |
| `snapshot(destination: Path)` | Preserve raw observations and normalized evidence with relative references |
| `apply_fault(kind: str)` | Journal and apply one supported fault in owned resources |
| `restore_fault()` | Restore fault effects and wait for intended routing readiness; application checks remain separate |
| `probe(output: Path, *, duration=2, concurrency=2, payload=256, target="gateway", rate=0, hold=0)` | Run real, byte-verified TCP traffic and return JSON measurements |

`target="gateway"` uses the client-to-proxy flow. `target="direct"` is a
gateway-origin direct-IP backend control that bypasses DNS, the proxy, and the
client hop. `hold` is seconds before the echo exchange. The overload fault forces
at least 48 workers and a 250 ms hold.

Faults: `route-withdrawal` (withdraw backend prefix from r2), `route-policy` (deny backend prefix at r1), `firewall-drop` (drop backend TCP on backend), `dns-failure`, `backend-down`, `link-loss` (primary r1-r2 down with alternate viable), `packet-loss` (netem delay/loss), `gateway-overload` (controlled workload above gateway limit). All reversible; faults scoped to owned namespaces only. API may raise meaningful RuntimeError/ValueError/OSError; CLI must unwind.

Snapshot persists raw outputs including routes, BGP JSON, nftables counters, sockets, tc, links, gateway metrics, DNS control lookup, and timestamp metadata. Packet capture lifecycle starts with lab startup and stops at teardown. Do not mutate host firewall/default routes/sysctls. Ownership markers and namespace collision checks are required. Processes are identified from owned namespaces, not arbitrary untrusted PIDs. `down` idempotent, including interrupted startup.

## Go executable contract

```bash
bin/netlab-agent gateway --listen 10.77.1.1:18080 \
  --upstream backend.lab:19090 --dns-server 10.77.1.1:53 \
  --metrics 127.0.0.1:19091 --max-connections 16 \
  --dial-timeout 800ms --idle-timeout 2s --shutdown-timeout 2s
bin/netlab-agent backend --listen 10.77.3.2:19090
bin/netlab-agent probe --target 10.77.1.1:18080 --duration 2s \
  --concurrency 2 --payload 256 --timeout 1500ms --rate 20 --output probe.json
```

The gateway preserves byte streams and half-closes, bounds active sessions and
buffers, applies dial/per-direction idle deadlines, and drains within a shutdown
budget. Streams are never replayed. Backend and probe resource use is also bounded.
The probe verifies complete returned bytes through EOF; optional `--hold` adds
controlled pressure. Scheduling duration and actual operation duration are separate.

Probe JSON includes attempts, successes, classified error counts, successful bytes,
actual/configured duration, achieved rate, effective workload, and successful-operation
`latency_ms` percentiles (`p50`, `p95`, `p99`). A bounded reservoir supplies quantiles;
sample counts and per-operation truncation are explicit. `PNID_EXPERIMENT_ID` and
`PNID_FLOW_ID` provide correlation in probe results and JSONL gateway session logs.

HTTP `/metrics` returns JSON connection, byte, error, memory, CPU, goroutine,
descriptor, and logging counters. `/health` checks upstream readiness; `/live`
checks liveness. Logging uses a bounded queue and reports drops/write errors. A
blocked writer can retain one sink worker until release or process exit, while
session capacity and shutdown waits remain bounded.

## Experiment/report contract

`python3 -m netlab doctor|up|status|down|run|suite|report` plus global `--root`, `--binary`. `run --scenario ... --output ...` owns startup/cleanup; refuses an already active lab. `suite` runs all representative scenarios. Baseline/fault/recovery phases each produce probe JSON and Linux snapshot. `report experiment.json` regenerates report.

Experiment JSON schema v1: `schema_version`, `experiment_id`, `scenario`, `started_at`, `environment` dict, `topology` dict, `workload` dict, `phases` map baseline/fault/recovery each with `probe` dict, `snapshot` dict, `artifacts` list, `observed_at`, `elapsed_seconds`; `events` list each with sequence, type, observed_at, elapsed_seconds, details; `fault` dict; `cleanup` dict; `artifacts` list; `result` dict. Artifacts use relative paths from experiment directory. Record monotonic local durations and wall timestamps. Snapshot return shape includes `artifacts` list and `observations` dict with normalized evidence where supported: `backend_route_present`, `bgp_peers_established`, `backend_listener_present`, `dns_ok`, `firewall_drop_packets`, `primary_link_up`, `netem_active`, `gateway_metrics`. Unknown must be `None`/absent, not guessed. Preserve raw evidence and hashes in manifest.

`report.analyze(experiment: dict) -> dict` returns `observations`, `diagnosis` (claim/support/conflicts/confidence), `recovered`, `metrics`, `limitations`. Do not infer cause from injected fault name alone. Recovery requires successful probes and independently restored network state relative to baseline. Report timings distinguish route convergence, first success and stable recovery, marking unmeasured values unknown.

## Correctness and isolation invariants

- Mutations target owned namespaces, virtual links, and processes. Faults do not
  change host routes, firewall policy, or forwarding configuration.
- New/empty private roots are claimed before helper files are created. Unmarked
  nonempty directories, symlinks, collisions, and changed identities are not taken
  over. Process ownership includes start and namespace identity.
- Routing readiness requires the intended unicast backend route through
  `10.77.12.2` on `direct0` plus established BGP peers. Recovery additionally requires
  independent byte-correct traffic and restored policy/link/impairment observations.
- Service restoration and teardown are separate checks. Cleanup is repeatable
  after partial startup; incomplete cleanup must be visible in `down` exit status.
- Host comparisons retain raw before/after state and exclude only live nftables
  counter packet/byte values from configuration equality.
- Saved result flags do not establish success; reports recompute acceptance from
  evidence. Missing/contradictory evidence and unmeasured clocks remain explicit.
- Historical measured artifacts retain their exact bytes and manifests. See the
  [public-data audit](docs/privacy.md) for residual identifiers and export boundaries.
