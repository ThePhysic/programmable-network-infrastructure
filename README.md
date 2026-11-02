# Programmable Network Infrastructure & Diagnostics

A CLI-driven Linux networking laboratory with a concurrent Go TCP gateway,
real FRRouting BGP, controlled failures, and evidence-linked incident reports.
The same traffic path connects the software, routing experiments, and measurements.

```text
client ── Go gateway + DNS ── r1 ───────── r2 ── echo backend
                             └─── r3 ────┘
                              alternate BGP path
```

Each node is a Linux network namespace. The gateway resolves `backend.lab`, accepts
concurrent client sessions, and forwards bytes through the routers. The CLI
establishes a healthy baseline, changes one condition, collects application and
network evidence, restores state, checks recovery, and tears down owned resources.

## Quick start in a dedicated Ubuntu Linux lab

Requires Linux with network namespaces, root privileges, Python 3.10+, and Go
1.22+. A dedicated Ubuntu 24.04 VM or WSL2 distribution is the reference runtime.
An ordinary container may lack the namespace/mount capabilities required by
`ip netns`; use a VM when those capabilities are unavailable.

```bash
sudo bash scripts/bootstrap-linux.sh
make build
sudo python3 -m netlab doctor
sudo python3 -m netlab run --scenario route-withdrawal --output results/route-demo
cat results/route-demo/report.md
python3 -m netlab verify results/route-demo
```

The output directory must be new. Dependencies use Ubuntu/Debian packages;
the Python CLI and Go programs have no third-party runtime libraries. The bootstrap
script installs compilers and network tools and adds root to FRRouting's `frrvty`
group. It is intended for the dedicated lab, not a production machine.

## Windows / WSL2

Create a dedicated distribution named `PNID-Lab` from an official Ubuntu rootfs.
Download the Ubuntu 24.04 amd64 WSL image and its checksum list from
[Ubuntu cloud images](https://cloud-images.ubuntu.com/wsl/releases/noble/current/),
verify the image SHA256, then import it into a new directory:

```powershell
wsl --import PNID-Lab "$env:USERPROFILE\pnid-lab-runtime\distro" <verified-rootfs.tar.gz> --version 2
.\scripts\wsl-lab.ps1 -Action Bootstrap
.\scripts\wsl-lab.ps1 -Action Build
.\scripts\wsl-lab.ps1 -Action Test
.\scripts\wsl-lab.ps1 -Action Doctor
.\scripts\wsl-lab.ps1 -Action Run -Scenario firewall-drop -Output results/firewall-demo
```

Run the helper from PowerShell in the checkout; it uses that checkout as the Linux
working directory. `-Distro` selects another explicitly designated lab distribution.
`Status` and `Down` inspect and stop the owned lab. The helper does not remove or
reconfigure existing WSL distributions. Root-owned generated files may require
Linux permissions when using a native Linux filesystem rather than a Windows mount.

## CLI

Global options precede the command. The default private runtime root is
`/var/tmp/pnid-<uid>`; the default binary is `bin/netlab-agent` in the checkout.

```bash
sudo python3 -m netlab --root /var/tmp/my-pnid up
sudo python3 -m netlab --root /var/tmp/my-pnid status
sudo python3 -m netlab --root /var/tmp/my-pnid down

sudo python3 -m netlab run --scenario dns-failure --duration 3 --rate 30 \
  --concurrency 4 --payload 4096 --output results/dns-demo

sudo python3 -m netlab suite --trials 3 --output results/repeated-suite
python3 scripts/summarize.py results/repeated-suite
python3 -m netlab report results/dns-demo/experiment.json
```

`run` and `suite` own startup and cleanup and refuse to take over an active lab.
Use `down` before running experiments if you previously used `up`. A command lock
prevents simultaneous CLI operations on the same runtime. Different private roots
produce different namespace names and can run independently.

| Scenario | Changed condition | Independent evidence |
|---|---|---|
| `route-withdrawal` | r2 withdraws the backend subnet | BGP prefix and forwarding route loss; failed echoes |
| `route-policy` | r1 rejects the backend prefix on both neighbors | Policy, BGP and route snapshots; failed echoes |
| `firewall-drop` | Backend firewall silently drops service TCP | Increased drop counter with route still present |
| `dns-failure` | Lab resolver returns NXDOMAIN | Actual DNS control query; gateway/client failure |
| `backend-down` | Echo listener stops | Absent listener with route still present |
| `link-loss` | Preferred r1–r2 link goes down | Changed next hop and successful alternate-path traffic |
| `packet-loss` | Gateway uplink gets delay, jitter, and loss | `tc` state/counters and measured application effects |
| `gateway-overload` | More held sessions than gateway capacity | Rejection counter increase and failed client operations |

The overload phase deliberately uses at least 48 clients, an unpaced workload, and
250 ms held connections against a 16-session gateway. Its effective workload is
recorded separately from baseline/recovery. Fault phase probes begin after fault
application and routing readiness checks; failover snapshots therefore establish
alternate-path operation, not zero-loss behavior during the transition.

## What an experiment retains

- `experiment.json`: topology, source hashes, environment, workload, phase results,
  injected change, interpreted evidence, recovery checks, and cleanup status.
- `report.md`: portable explanation with links to raw observations and limitations.
- `events.json`: ordered lifecycle events with wall timestamps and local monotonic durations.
- `baseline/`, `fault/`, `recovery/`: byte-verified probes; addresses, routes, BGP,
  sockets, DNS, firewall, link and traffic-control state; gateway metrics and logs.
- `final/captures/`: flushed packet traces from the gateway, r1, and backend.
- `manifest.json`: SHA256 and size for each retained artifact.

Open the report alongside its artifact directories. Verification detects changed,
missing, or additional files; hashes establish integrity relative to the retained
manifest, not authenticity against a malicious replacement of the entire bundle.
Reports can be regenerated on Windows without Linux privileges.

The report derives explanations from observations rather than the injected fault
label. A timeout remains ambiguous without discriminating evidence. Recovery
requires byte-correct traffic and independently restored state; teardown is checked
separately. Missing evidence is reported as unknown.

## Go software

`netlab-agent gateway` forwards streams with bounded concurrent sessions and fixed
buffers, per-direction idle deadlines, explicit upstream dial timeouts, correct
half-close behavior, and a bounded shutdown drain. Streams are never replayed.
The backend and probe also bound connections, memory, and retained samples.

The gateway exposes JSON metrics on `/metrics`, upstream-aware readiness on
`/health`, and process liveness on `/live`. The lab binds its metrics listener to
loopback inside the gateway namespace. Metrics include bytes, accepted/rejected
connections, active sessions, error classes, goroutines, memory, and descriptors.
Session logs preserve connection outcomes, upstream connection latency, and
experiment/flow identities. Linux CPU metrics report cumulative process user and
system seconds; compare snapshots to calculate CPU consumed over a window.
Logging uses a bounded queue and a separate sink worker. `log_dropped_total` and
write-error metrics disclose incomplete session logs when the sink cannot keep up.
Shutdown stops waiting at its deadline; an arbitrary blocked writer can retain one
sink goroutine until that writer returns or the process exits. Session workers and
their connection limits remain independent of the sink.

```bash
bin/netlab-agent gateway --help
bin/netlab-agent backend --help
bin/netlab-agent probe --help
```

## Validation and measurement

```bash
make test                     # Go race tests, vet, Python unit/negative tests
sudo make integration         # All eight real namespace/FRR fault scenarios
sudo python3 scripts/integration.py --trials 3 --output results/acceptance
sudo python3 scripts/lifecycle.py --output results/lifecycle
sudo python3 scripts/soak.py --output results/soak
```

Acceptance requires observed scenario effects, successful recovery, verified
cleanup, and unchanged host routes/firewall/forwarding settings. Host comparisons
distinguish firewall configuration from naturally advancing packet/byte counters;
the raw before/after observations remain available. Unit tests also
exercise stream isolation, half-closes, overload, timeouts, cancellation, payload
corruption, ownership conflicts, interrupted experiments, and unsupported diagnoses.
The CI workflow runs the checks on an Ubuntu runner and retains generated evidence.

Measurements describe successful complete echo operations separately from failures.
Each operation opens a new TCP connection; this is not a persistent-stream bandwidth
benchmark. Percentiles use a bounded successful-operation reservoir; full aggregate
counts and sample truncation are disclosed. Recovery timings are sampled bounds
that include restoration and collection gaps. Routing convergence remains unmeasured
unless a dedicated, sourced measurement is added.

See [architecture](docs/architecture.md), [measurement methodology](docs/measurement.md),
and [validation evidence](docs/validation.md) for details and measured results.

## Isolation and limitations

Mutations target owned namespaces, virtual links, and processes. Ownership uses a
private mode-0700 runtime directory, recorded namespace identities, and process
identity checks. Network faults do not modify host routes, firewall rules, or
forwarding settings. Captures contain only the isolated synthetic workload and are
bounded by a ring. After an interruption, rerun `down` with the same `--root`.

This is an inspectable engineering lab with a fixed topology, not a production
network controller. It does not claim comprehensive automated root-cause analysis,
production service discovery, or a secure Internet-facing proxy. A web dashboard,
Kubernetes, IPv6, WireGuard, and eBPF remain optional extensions. Virtual-lab timing
depends on the stated VM/kernel/hardware and should not be generalized to physical
production networks.
