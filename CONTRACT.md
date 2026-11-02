# Network lab implementation contract

Project executable: `python3 -m netlab`; original Go executable: `bin/netlab-agent`.
Python uses only the standard library. Go uses only the standard library.

## Ownership during development

- Go agent: `go.mod`, `cmd/`, `internal/` (including Go tests).
- Linux agent: `netlab/linux.py`, `netlab/dns.py`, `tests/test_linux.py`, `tests/test_dns.py`.
- Reporting agent: `netlab/report.py`, `tests/test_report.py`, `docs/architecture.md`.
- Root agent: CLI, experiment orchestration, package scaffold, docs, CI, runtime scripts, integration tests.

Root integrates and commits each feature; agents do not run git mutations.

## Linux API

`Lab(root: pathlib.Path, binary: pathlib.Path)` uses root as an absolute private runtime directory. It owns a fixed six-node diamond topology with namespace prefix derived from root: client, gateway, r1, r2, r3, backend. Gateway connects through BGP routers to backend; direct r1-r2 path plus r1-r3-r2 alternate. DNS runs inside gateway.

Methods: `doctor() -> dict`, `up() -> dict`, `down() -> dict`, `status() -> dict`, `snapshot(destination: Path) -> dict`, `apply_fault(kind: str) -> dict`, `restore_fault() -> dict`, `probe(output: Path, *, duration: float=2, concurrency: int=2, payload: int=256, target: str="gateway", rate: float=0) -> dict`.

Faults: `route-withdrawal` (withdraw backend prefix from r2), `route-policy` (deny backend prefix at r1), `firewall-drop` (drop backend TCP on backend), `dns-failure`, `backend-down`, `link-loss` (primary r1-r2 down with alternate viable), `packet-loss` (netem delay/loss), `gateway-overload` (controlled workload above gateway limit). All reversible; faults scoped to owned namespaces only. API may raise meaningful RuntimeError/ValueError/OSError; CLI must unwind.

Snapshot persists raw outputs including routes, BGP JSON, nftables counters, sockets, tc, links, gateway metrics, DNS control lookup, and timestamp metadata. Packet capture lifecycle starts with lab startup and stops at teardown. Do not mutate host firewall/default routes/sysctls. Ownership markers and namespace collision checks are required. Processes are identified from owned namespaces, not arbitrary untrusted PIDs. `down` idempotent, including interrupted startup.

## Go executable contract

`netlab-agent gateway --listen 10.77.1.1:18080 --upstream backend.lab:19090 --dns-server 10.77.1.1:53 --metrics 127.0.0.1:19091 --max-connections 16 --dial-timeout 800ms --idle-timeout 2s --shutdown-timeout 2s`

`netlab-agent backend --listen 10.77.3.2:19090` is a concurrent stream echo backend.

`netlab-agent probe --target 10.77.1.1:18080 --duration 2s --concurrency 2 --payload 256 --timeout 1500ms --rate 0 --output /absolute/probe.json`; `rate=0` means unpaced. Probe JSON has `attempts`, `successes`, `errors` (map classes/counts), `bytes`, `duration_seconds`, `latency_ms` (`p50`, `p95`, `p99`), `samples` (bounded per attempt entries: monotonic `elapsed_seconds`, latency_ms, success, error). Include achieved rate and sample truncation if bounded. Check exact echo bytes. Metrics HTTP GET `/metrics` returns JSON with active_connections, accepted, rejected, bytes_up, bytes_down, errors, goroutines, uptime_seconds; `/health` readiness checks upstream separately from process liveness. Resource bounds must apply to backend and workload too. Logs JSONL on stderr.

## Experiment/report contract

`python3 -m netlab doctor|up|status|down|run|suite|report` plus global `--root`, `--binary`. `run --scenario ... --output ...` owns startup/cleanup; refuses an already active lab. `suite` runs all representative scenarios. Baseline/fault/recovery phases each produce probe JSON and Linux snapshot. `report experiment.json` regenerates report.

Experiment JSON schema v1: `schema_version`, `experiment_id`, `scenario`, `started_at`, `environment` dict, `topology` dict, `workload` dict, `phases` map baseline/fault/recovery each with `probe` dict, `snapshot` dict, `artifacts` list, `observed_at`, `elapsed_seconds`; `events` list each with sequence, type, observed_at, elapsed_seconds, details; `fault` dict; `cleanup` dict; `artifacts` list; `result` dict. Artifacts use relative paths from experiment directory. Record monotonic local durations and wall timestamps. Snapshot return shape includes `artifacts` list and `observations` dict with normalized evidence where supported: `backend_route_present`, `bgp_peers_established`, `backend_listener_present`, `dns_ok`, `firewall_drop_packets`, `primary_link_up`, `netem_active`, `gateway_metrics`. Unknown must be `None`/absent, not guessed. Preserve raw evidence and hashes in manifest.

`report.analyze(experiment: dict) -> dict` returns `observations`, `diagnosis` (claim/support/conflicts/confidence), `recovered`, `metrics`, `limitations`. Do not infer cause from injected fault name alone. Recovery requires successful probes and independently restored network state relative to baseline. Report timings distinguish route convergence, first success and stable recovery, marking unmeasured values unknown.

## Done

Full Go/Python checks, real Linux namespace/FRR scenario suite, documented benchmark conditions and repeated trials, clean cleanup verification, source and evidence manifests, usable docs, private GitHub publication, and independent Astra medium review with explicit no-complaints verdict. Do not invent results or silently replace real network testing with mocks.
