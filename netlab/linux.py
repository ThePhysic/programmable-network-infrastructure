"""Real Linux namespace/FRRouting lab with ownership-scoped lifecycle operations."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time


NODES = ("client", "gateway", "r1", "r2", "r3", "backend")
ROUTERS = ("r1", "r2", "r3")
FAULTS = ("route-withdrawal", "route-policy", "firewall-drop", "dns-failure",
          "backend-down", "link-loss", "packet-loss", "gateway-overload")
LINKS = (
    ("client", "eth0", "10.77.1.2/24", "gateway", "client0", "10.77.1.1/24"),
    ("gateway", "uplink0", "10.77.2.2/24", "r1", "gateway0", "10.77.2.1/24"),
    ("r1", "direct0", "10.77.12.1/24", "r2", "direct0", "10.77.12.2/24"),
    ("r1", "backup0", "10.77.13.1/24", "r3", "left0", "10.77.13.3/24"),
    ("r3", "right0", "10.77.23.3/24", "r2", "backup0", "10.77.23.2/24"),
    ("r2", "service0", "10.77.3.1/24", "backend", "eth0", "10.77.3.2/24"),
)
ASN = {"r1": 65001, "r2": 65002, "r3": 65003}
NEIGHBORS = {"r1": (("10.77.12.2", 65002), ("10.77.13.3", 65003)),
             "r2": (("10.77.12.1", 65001), ("10.77.23.3", 65003)),
             "r3": (("10.77.13.1", 65001), ("10.77.23.2", 65002))}


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def _cmd(argv, *, timeout=10, check=True, input=None, env=None):
    result = subprocess.run([str(a) for a in argv], input=input, text=True,
                            capture_output=True, timeout=timeout, check=False, env=env)
    if check and result.returncode:
        raise RuntimeError(f"{argv[0]} exited {result.returncode}: {result.stderr.strip() or result.stdout.strip()}")
    return result


def _read_json(text, fallback=None):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return fallback


def _bgp_peers(value):
    if not isinstance(value, dict):
        return None
    if isinstance(value.get("peers"), dict):
        return value["peers"]
    family = value.get("ipv4Unicast")
    return family.get("peers") if isinstance(family, dict) and isinstance(family.get("peers"), dict) else None


def _prefix_decision(lines):
    """Evaluate ordered FRR prefix-list entries for the backend /24."""
    target = ipaddress.IPv4Network("10.77.3.0/24")
    entries = []
    for line in lines:
        match = re.fullmatch(r"seq (\d+) (permit|deny) (\S+)(?: ge (\d+))?(?: le (\d+))?", line)
        if match:
            sequence, action, prefix, minimum, maximum = match.groups()
            if prefix == "any":
                prefix, minimum, maximum = "0.0.0.0/0", "0", "32"
            try:
                network = ipaddress.IPv4Network(prefix)
            except ValueError:
                return None
            lower = int(minimum) if minimum else network.prefixlen
            upper = int(maximum) if maximum else (32 if minimum else network.prefixlen)
            entries.append((int(sequence), action, network, lower, upper))
    for _, action, network, lower, upper in sorted(entries):
        if target.subnet_of(network) and lower <= target.prefixlen <= upper:
            return action
    return "implicit-deny" if entries else None


def _policy_observation(running_config, prefix_display):
    if running_config is None or prefix_display is None:
        return {"backend_prefix_denied": None, "backend_prefix_policy_present": None,
                "backend_prefix_policy": None}
    config_lines = [" ".join(line.split()) for line in running_config.splitlines()]
    if "router bgp 65001" not in config_lines:
        return {"backend_prefix_denied": None, "backend_prefix_policy_present": None,
                "backend_prefix_policy": None}
    config_entries = [line.removeprefix("ip prefix-list PNID-IN ") for line in config_lines
                      if line.startswith("ip prefix-list PNID-IN ")]
    attached = sorted(neighbor for neighbor, _ in NEIGHBORS["r1"]
                      if f"neighbor {neighbor} prefix-list PNID-IN in" in config_lines)
    displayed, in_list = [], False
    has_bgp_section = any(line.strip().startswith("BGP: ip prefix-list ") for line in prefix_display.splitlines())
    for original in prefix_display.splitlines():
        line = " ".join(original.split())
        header = re.fullmatch(r"(?:(\S+): )?ip prefix-list ([^:]+):.*", line)
        if header:
            daemon, name = header.groups()
            in_list = name == "PNID-IN" and (daemon == "BGP" if has_bgp_section else daemon is None)
        elif in_list and line.startswith("seq "):
            displayed.append(line)
    decision, display_decision = _prefix_decision(config_entries), _prefix_decision(displayed)
    consistent = (decision == display_decision
                  and (not config_entries or decision is not None)
                  and (not attached or bool(config_entries)))
    denied = (decision in ("deny", "implicit-deny") and len(attached) == len(NEIGHBORS["r1"])) if consistent else None
    return {"backend_prefix_denied": denied,
            "backend_prefix_policy_present": bool(config_entries or attached),
            "backend_prefix_policy": {"decision": decision, "display_decision": display_decision,
                                      "inbound_neighbors": attached, "sources_consistent": consistent}}


class Lab:
    """A private runtime root owns exactly the namespaces recorded in its marker."""

    def __init__(self, root: Path, binary: Path):
        supplied = Path(root).expanduser()
        if not supplied.is_absolute():
            raise ValueError("lab root must be absolute")
        # Reject symlinks in existing ancestry before resolve erases that fact.
        if any(p.is_symlink() for p in (supplied, *supplied.parents)):
            raise ValueError("lab root and ancestors must not be symlinks")
        self.root = supplied.resolve()
        if self.root in (Path("/"), Path("/tmp"), Path("/run"), Path("/root"), Path.home()):
            raise ValueError("lab root must be a dedicated private subdirectory")
        self.binary = Path(binary).expanduser().resolve()
        digest = hashlib.sha256(str(self.root).encode()).hexdigest()[:10]
        self.prefix = "pnid-" + digest
        self.namespaces = {node: self.prefix + "-" + node for node in NODES}
        self.marker = self.root / "owner.json"
        self._children = {}
        self.experiment_id = ""

    def _state(self, *, required=True):
        if not self.marker.exists():
            if required:
                raise RuntimeError("lab ownership marker is absent")
            return None
        if self.marker.is_symlink():
            raise RuntimeError("ownership marker cannot be a symlink")
        data = _read_json(self.marker.read_text())
        if not isinstance(data, dict) or data.get("owner") != "pnid-v1" or data.get("root") != str(self.root) or data.get("prefix") != self.prefix:
            raise RuntimeError("lab ownership marker does not match this runtime root")
        return data

    def _save(self, state):
        _json(self.marker, state)

    def _prepare_root(self):
        if self.root.exists():
            info = self.root.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                raise RuntimeError("lab root must be a directory owned by the current user")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise RuntimeError("lab root must be private (chmod 700)")
            if not self.marker.exists() and any(self.root.iterdir()):
                raise RuntimeError("refusing nonempty runtime directory without ownership marker")
            if any(path.is_symlink() for path in self.root.rglob("*")):
                raise RuntimeError("runtime descendants cannot be symlinks")
        else:
            self.root.mkdir(parents=True, mode=0o700)
        # Claim only a newly accepted empty/private directory before creating any
        # helper files. Early collision/lock/tool failures then remain retryable.
        if self._state(required=False) is None:
            self._save(self._new_state())
        for child in ("logs", "captures", "frr"):
            path = self.root / child
            if path.is_symlink():
                raise RuntimeError("runtime paths cannot be symlinks")
            path.mkdir(exist_ok=True, mode=0o700)

    def _new_state(self):
        return {"owner": "pnid-v1", "root": str(self.root), "prefix": self.prefix,
                "created_at": utc(), "namespaces": {}, "processes": {}, "fault": None,
                "experiment_id": self.experiment_id, "flow_id": "client-gateway-backend-tcp"}

    @contextmanager
    def _lock(self):
        import fcntl
        # The root was validated before creating lock files.
        path = self.root / ".lock"
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        except BlockingIOError:
            raise RuntimeError("another operation owns this lab runtime lock") from None
        finally:
            os.close(descriptor)

    def _existing(self):
        result = _cmd(["ip", "netns", "list"], check=False)
        if result.returncode:
            raise RuntimeError("cannot list Linux network namespaces: " + result.stderr.strip())
        return {line.split()[0] for line in result.stdout.splitlines() if line.strip()}

    def _inode(self, node):
        try:
            return (Path("/run/netns") / self.namespaces[node]).stat().st_ino
        except FileNotFoundError:
            return None

    def _owned(self, node, state=None):
        state = self._state() if state is None else state
        expected = state.get("namespaces", {}).get(node)
        actual = self._inode(node)
        return expected is not None and actual is not None and expected == actual

    def _ns(self, node, *argv, timeout=10, check=True, input=None, env=None):
        if node not in self.namespaces or not self._owned(node):
            raise RuntimeError("namespace is absent or ownership changed: " + node)
        return _cmd(["ip", "netns", "exec", self.namespaces[node], *argv],
                    timeout=timeout, check=check, input=input, env=env)

    def _launch(self, node, role, argv):
        self._ns(node, "true")
        environment = self._identity_environment()
        log = self.root / "logs" / (role + ".log")
        if log.is_symlink():
            raise RuntimeError("process log cannot be a symlink")
        with log.open("ab") as handle:
            process = subprocess.Popen(["ip", "netns", "exec", self.namespaces[node], *map(str, argv)],
                                       stdin=subprocess.DEVNULL, stdout=handle, stderr=handle,
                                       start_new_session=True, env=environment)
        self._children[role] = process
        state = self._state()
        state.setdefault("processes", {})[role] = {"pid": process.pid, "node": node,
                                                     "started": self._proc_start(process.pid)}
        self._save(state)
        time.sleep(0.05)
        if process.poll() is not None:
            raise RuntimeError(f"{role} exited during startup; see {log}")

    @staticmethod
    def _proc_start(pid):
        try:
            return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
        except (OSError, IndexError):
            return None

    def _process_matches(self, record):
        pid, node = record.get("pid"), record.get("node")
        if not isinstance(pid, int) or pid <= 1 or node not in self.namespaces or not self._owned(node):
            return False
        try:
            return (record.get("started") is not None and self._proc_start(pid) == record["started"]
                    and Path(f"/proc/{pid}/ns/net").stat().st_ino == self._inode(node))
        except OSError:
            return False

    @staticmethod
    def _still_in_namespace(pid, started, inode):
        try:
            return (Lab._proc_start(pid) == started
                    and Path(f"/proc/{pid}/ns/net").stat().st_ino == inode)
        except OSError:
            return False

    def _stop_role(self, role):
        state = self._state()
        record = state.get("processes", {}).get(role)
        if record and self._process_matches(record):
            os.kill(record["pid"], signal.SIGTERM)
            end = time.monotonic() + 3
            while self._process_matches(record) and time.monotonic() < end:
                child = self._children.get(role)
                if child:
                    child.poll()
                time.sleep(0.05)
            if self._process_matches(record):
                os.kill(record["pid"], signal.SIGKILL)
            child = self._children.pop(role, None)
            if child:
                child.wait(timeout=2)

    def _vty(self, router, *commands, check=True):
        argv = ["vtysh", "--vty_socket", str(self.root / "frr" / router)]
        for command in commands:
            argv += ["-c", command]
        return self._ns(router, *argv, check=check)

    def _identity_environment(self):
        state = self._state()
        environment = os.environ.copy()
        environment["PNID_EXPERIMENT_ID"] = state.get("experiment_id", "")
        environment["PNID_FLOW_ID"] = state.get("flow_id", "client-gateway-backend-tcp")
        return environment

    def doctor(self):
        tools = {name: shutil.which(name) for name in ("ip", "nft", "tc", "ss", "tcpdump", "vtysh", "python3")}
        tools.update({name: self._daemon(name) for name in ("zebra", "bgpd")})
        group_ready = False
        if sys.platform == "linux":
            import grp
            import pwd
            try:
                user = pwd.getpwuid(os.geteuid())
                group = grp.getgrnam("frrvty")
                group_ready = user.pw_gid == group.gr_gid or user.pw_name in group.gr_mem
            except KeyError:
                pass
        return {"linux": sys.platform == "linux", "root": hasattr(os, "geteuid") and os.geteuid() == 0,
                "tools": tools, "binary": str(self.binary), "binary_exists": self.binary.is_file(),
                "frr_vty_group_member": group_ready,
                "ready": sys.platform == "linux" and hasattr(os, "geteuid") and os.geteuid() == 0
                and all(tools.values()) and self.binary.is_file() and group_ready,
                "environment": {"kernel": platform.release(), "platform": platform.platform(),
                                "python": platform.python_version(), "cpu_count": os.cpu_count()}}

    @staticmethod
    def _daemon(name):
        found = shutil.which(name)
        if found:
            return found
        path = Path("/usr/lib/frr") / name
        return str(path) if path.is_file() else None

    def status(self):
        state = self._state(required=False)
        if state is None:
            return {"active": False, "owned": False, "prefix": self.prefix, "namespaces": {}}
        existing = self._existing()
        namespaces = {node: {"name": name, "present": name in existing, "owned": self._owned(node, state)}
                      for node, name in self.namespaces.items()}
        return {"active": any(row["present"] for row in namespaces.values()), "owned": True,
                "prefix": self.prefix, "namespaces": namespaces, "fault": state.get("fault"),
                "experiment_id": state.get("experiment_id"), "flow_id": state.get("flow_id"),
                "topology": self.topology()}

    def topology(self):
        return {"id": "six-node-bgp-diamond", "namespace_prefix": self.prefix,
                "nodes": list(NODES), "links": [{"left": a, "left_interface": ai, "left_address": aa,
                                                  "right": b, "right_interface": bi, "right_address": ba}
                                                 for a, ai, aa, b, bi, ba in LINKS],
                "gateway": "10.77.1.1:18080", "backend": "10.77.3.2:19090",
                "dns": "10.77.1.1:53", "primary_path": ["gateway", "r1", "r2", "backend"],
                "alternate_path": ["gateway", "r1", "r3", "r2", "backend"]}

    def up(self):
        requirements = self.doctor()
        if not requirements["ready"]:
            raise RuntimeError("Linux root, required tools, and built Go binary are required: " + json.dumps(requirements))
        self._prepare_root()
        with self._lock():
            # Refuse collisions before claiming or changing any namespace.
            existing = self._existing()
            collisions = existing.intersection(self.namespaces.values())
            if collisions:
                raise RuntimeError("namespace collision; refusing startup: " + ", ".join(sorted(collisions)))
            prior = self._state(required=False)
            if prior and prior.get("namespaces"):
                raise RuntimeError("stale runtime state; run down before restarting")
            state = self._new_state()
            self._save(state)
            # Each startup gets fresh logs/captures; do not mix earlier experiments.
            for folder in ("captures", "logs"):
                for old in (self.root / folder).iterdir():
                    if not old.is_file() or old.is_symlink():
                        raise RuntimeError("unexpected runtime artifact: " + str(old))
                    old.unlink()
            try:
                for node in NODES:
                    _cmd(["ip", "netns", "add", self.namespaces[node]])
                    state["namespaces"][node] = self._inode(node)
                    self._save(state)
                    self._ns(node, "ip", "link", "set", "lo", "up")
                    # These sysctls affect only the owned network namespace.
                    self._ns(node, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0")
                    self._ns(node, "sysctl", "-qw", "net.ipv4.conf.default.rp_filter=0")
                    self._ns(node, "sysctl", "-qw", "net.ipv4.ip_forward=0")
                for left, li, la, right, ri, ra in LINKS:
                    _cmd(["ip", "link", "add", li, "netns", self.namespaces[left], "type", "veth",
                          "peer", "name", ri, "netns", self.namespaces[right]])
                    for node, interface, address in ((left, li, la), (right, ri, ra)):
                        self._ns(node, "ip", "address", "add", address, "dev", interface)
                        self._ns(node, "ip", "link", "set", interface, "up")
                for node, gateway in (("client", "10.77.1.1"), ("gateway", "10.77.2.1"), ("backend", "10.77.3.1")):
                    self._ns(node, "ip", "route", "add", "default", "via", gateway)
                for router in ROUTERS:
                    self._ns(router, "sysctl", "-qw", "net.ipv4.ip_forward=1")
                    self._start_router(router)
                self._wait(self._routing_ready, 25,
                           "BGP peers and the primary backend forwarding route did not converge")
                _json(self.root / "dns-state.json", {"mode": "healthy"})
                self._launch("gateway", "dns", [sys.executable, str(Path(__file__).with_name("dns.py")),
                                                   "--bind", "10.77.1.1", "--state", self.root / "dns-state.json"])
                self._start_backend()
                self._launch("gateway", "gateway", [self.binary, "gateway", "--listen", "10.77.1.1:18080",
                             "--upstream", "backend.lab:19090", "--dns-server", "10.77.1.1:53",
                             "--metrics", "127.0.0.1:19091", "--max-connections", "16",
                             "--dial-timeout", "800ms", "--idle-timeout", "2s", "--shutdown-timeout", "2s"])
                self._wait(lambda: self._metrics() is not None, 5, "gateway metrics did not start")
                for node in ("gateway", "r1", "backend"):
                    self._launch(node, "capture-" + node, ["tcpdump", "-U", "-i", "any", "-n", "-s", "128",
                                 "-C", "2", "-W", "2", "-Z", "root", "-w", self.root / "captures" / (node + ".pcap")])
                return {"active": True, "topology": self.topology(), "environment": requirements["environment"]}
            except BaseException:
                self._down_unlocked()
                raise

    def _start_router(self, router):
        directory = self.root / "frr" / router
        directory.mkdir(exist_ok=True, mode=0o700)
        for socket_name in ("zebra.vty", "bgpd.vty", "zserv.api"):
            socket_path = directory / socket_name
            if socket_path.exists():
                socket_path.unlink()
        config = ["frr defaults traditional", "hostname " + router, "log stdout", "!"]
        (directory / "zebra.conf").write_text("\n".join(config) + "\n")
        config += ["router bgp " + str(ASN[router]), " bgp router-id 10.255.0." + router[-1],
                   " no bgp ebgp-requires-policy", " no bgp network import-check", " timers bgp 1 3"]
        for neighbor, asn in NEIGHBORS[router]:
            config += [f" neighbor {neighbor} remote-as {asn}", f" neighbor {neighbor} timers connect 1",
                       f" neighbor {neighbor} soft-reconfiguration inbound"]
        config += [" address-family ipv4 unicast"]
        if router == "r1":
            config += ["  network 10.77.2.0/24"]
        elif router == "r2":
            config += ["  network 10.77.3.0/24"]
        config += [" exit-address-family", "!", "line vty", "!"]
        (directory / "bgpd.conf").write_text("\n".join(config) + "\n")
        for daemon in ("zebra", "bgpd"):
            argv = [self._daemon(daemon), "-f", directory / (daemon + ".conf"),
                    "-i", directory / (daemon + ".pid"), "-z", directory / "zserv.api",
                    "--vty_socket", directory, "-u", "root", "-g", "root", "-P", "0"]
            self._launch(router, router + "-" + daemon, argv)
            self._wait(lambda: (directory / (daemon + ".vty")).exists(), 4,
                       daemon + " VTY socket did not start")

    def _start_backend(self):
        self._launch("backend", "backend", [self.binary, "backend", "--listen", "10.77.3.2:19090"])

    @staticmethod
    def _wait(predicate, timeout, message):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate():
                return
            time.sleep(0.15)
        raise RuntimeError(message)

    def _route_data(self):
        result = self._ns("r1", "ip", "-j", "route", "show", "10.77.3.0/24", check=False)
        return _read_json(result.stdout) if result.returncode == 0 else None

    def _route_present(self):
        routes = self._route_data()
        return isinstance(routes, list) and any(row.get("dst") == "10.77.3.0/24" and row.get("type", "unicast") == "unicast" for row in routes)

    def _routing_ready(self):
        # Session establishment and reachability can precede best-path/FIB
        # restoration. Healthy baseline/recovery requires the intended primary.
        routes = self._route_data()
        if not isinstance(routes, list):
            return False
        selected = [row for row in routes if row.get("dst") == "10.77.3.0/24"
                    and row.get("type", "unicast") == "unicast"]
        return (len(selected) == 1 and selected[0].get("gateway") == "10.77.12.2"
                and selected[0].get("dev") == "direct0" and self._peers_established())

    def _peers_established(self):
        for router in ROUTERS:
            value = _read_json(self._vty(router, "show bgp ipv4 unicast summary json", check=False).stdout)
            peers = _bgp_peers(value)
            if not isinstance(peers, dict) or len(peers) != 2 or not all(peer.get("state") == "Established" for peer in peers.values()):
                return False
        return True

    def _metrics(self):
        script = "import json,urllib.request; print(urllib.request.urlopen('http://127.0.0.1:19091/metrics', timeout=1).read().decode())"
        result = self._ns("gateway", sys.executable, "-c", script, timeout=3, check=False)
        return _read_json(result.stdout) if result.returncode == 0 else None

    def apply_fault(self, kind):
        if kind not in FAULTS:
            raise ValueError("unknown fault: " + kind)
        with self._lock():
            state = self._state()
            if state.get("fault"):
                raise RuntimeError("restore the current fault before applying another")
            # Journal before mutation so interrupted applications remain restorable.
            state["fault"] = {"kind": kind, "applied_at": utc(), "status": "applying"}
            self._save(state)
            started = time.monotonic()
            if kind == "route-withdrawal":
                self._vty("r2", "configure terminal", "router bgp 65002", "address-family ipv4 unicast", "no network 10.77.3.0/24")
                self._wait(lambda: not self._route_present(), 12, "withdrawal did not remove backend route")
            elif kind == "route-policy":
                commands = ["configure terminal", "ip prefix-list PNID-IN seq 5 deny 10.77.3.0/24",
                            "ip prefix-list PNID-IN seq 10 permit 0.0.0.0/0 le 32", "router bgp 65001", "address-family ipv4 unicast"]
                commands += [f"neighbor {neighbor} prefix-list PNID-IN in" for neighbor, _ in NEIGHBORS["r1"]]
                self._vty("r1", *commands)
                self._vty("r1", "clear bgp * soft in")
                self._wait(lambda: not self._route_present(), 12, "policy did not remove backend route")
            elif kind == "firewall-drop":
                rules = "table inet pnid {\n chain input {\n  type filter hook input priority 0; policy accept;\n  tcp dport 19090 counter drop\n }\n}\n"
                self._ns("backend", "nft", "-f", "-", input=rules)
            elif kind == "dns-failure":
                _json(self.root / "dns-state.json", {"mode": "nxdomain"})
            elif kind == "backend-down":
                self._stop_role("backend")
            elif kind == "link-loss":
                self._ns("r1", "ip", "link", "set", "direct0", "down")
                self._ns("r2", "ip", "link", "set", "direct0", "down")
                self._wait(lambda: any(row.get("gateway") == "10.77.13.3" for row in self._route_data() or []),
                           12, "alternate route did not become active")
            elif kind == "packet-loss":
                self._ns("gateway", "tc", "qdisc", "add", "dev", "uplink0", "root", "netem", "delay", "30ms", "5ms", "loss", "15%")
            state = self._state()
            state["fault"]["status"] = "applied"
            state["fault"]["apply_seconds"] = time.monotonic() - started
            self._save(state)
            return dict(state["fault"])

    def restore_fault(self):
        with self._lock():
            state = self._state()
            fault = state.get("fault")
            if not fault:
                return {"restored": True, "kind": None, "wait_seconds": 0}
            kind = fault["kind"]
            started = time.monotonic()
            if kind == "route-withdrawal":
                self._vty("r2", "configure terminal", "router bgp 65002", "address-family ipv4 unicast", "network 10.77.3.0/24")
            elif kind == "route-policy":
                commands = ["configure terminal", "router bgp 65001", "address-family ipv4 unicast"]
                commands += [f"no neighbor {neighbor} prefix-list PNID-IN in" for neighbor, _ in NEIGHBORS["r1"]]
                commands += ["exit-address-family", "exit", "no ip prefix-list PNID-IN"]
                self._vty("r1", *commands)
                self._vty("r1", "clear bgp * soft in")
            elif kind == "firewall-drop":
                self._ns("backend", "nft", "delete", "table", "inet", "pnid", check=False)
            elif kind == "dns-failure":
                _json(self.root / "dns-state.json", {"mode": "healthy"})
            elif kind == "backend-down":
                self._start_backend()
            elif kind == "link-loss":
                self._ns("r1", "ip", "link", "set", "direct0", "up")
                self._ns("r2", "ip", "link", "set", "direct0", "up")
            elif kind == "packet-loss":
                self._ns("gateway", "tc", "qdisc", "del", "dev", "uplink0", "root", check=False)
            self._wait(self._routing_ready, 15,
                       "routing did not restore the primary backend forwarding route and BGP peers")
            state = self._state()
            state["fault"] = None
            self._save(state)
            return {"restored": True, "kind": kind, "restored_at": utc(), "wait_seconds": time.monotonic() - started}

    def probe(self, output: Path, *, duration=2, concurrency=2, payload=256, target="gateway", rate=0, hold=0):
        if target not in ("gateway", "direct"):
            raise ValueError("probe target must be gateway or direct")
        if not 0.1 <= duration <= 300 or not 1 <= concurrency <= 256 or not 1 <= payload <= 1048576 or not 0 <= rate <= 100000 or not 0 <= hold <= 5:
            raise ValueError("probe parameters exceed supported bounds")
        fault = self._state().get("fault")
        if fault and fault["kind"] == "gateway-overload" and target == "gateway":
            concurrency, hold = max(concurrency, 48), max(hold, 0.25)
        output = Path(output).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        node, endpoint = ("client", "10.77.1.1:18080") if target == "gateway" else ("gateway", "10.77.3.2:19090")
        args = [self.binary, "probe", "--target", endpoint, "--duration", f"{duration}s", "--concurrency", str(concurrency),
                "--payload", str(payload), "--timeout", "1500ms", "--rate", str(rate), "--output", output]
        if hold:
            args += ["--hold", f"{hold}s"]
        result = self._ns(node, *args, timeout=duration + 10, check=False, env=self._identity_environment())
        if result.returncode or not output.is_file():
            raise RuntimeError("probe execution failed: " + result.stderr.strip())
        value = _read_json(output.read_text())
        if not isinstance(value, dict):
            raise RuntimeError("probe did not emit a JSON object")
        value["effective_workload"] = {"duration": duration, "concurrency": concurrency, "payload": payload,
                                       "target": target, "rate": rate, "hold_seconds": hold}
        _json(output, value)
        return value

    def snapshot(self, destination: Path):
        destination = Path(destination).resolve()
        destination.mkdir(parents=True, exist_ok=True)
        artifacts, evidence, observations = [], {}, {}

        def collect(node, name, *argv, is_json=False):
            result = self._ns(node, *argv, check=False)
            relative = node + "-" + name + (".json" if is_json else ".txt")
            (destination / relative).write_text(result.stdout)
            artifacts.append(relative)
            if result.stderr or result.returncode:
                error = relative + ".stderr.txt"
                (destination / error).write_text(f"exit_code={result.returncode}\n" + result.stderr)
                artifacts.append(error)
            return (_read_json(result.stdout) if is_json else result.stdout) if result.returncode == 0 else None, relative

        for node in NODES:
            collect(node, "addresses", "ip", "-j", "address", "show", is_json=True)
            routes, route_ref = collect(node, "routes", "ip", "-j", "route", "show", is_json=True)
            collect(node, "neighbors", "ip", "-j", "neighbor", "show", is_json=True)
            links, link_ref = collect(node, "links", "ip", "-j", "-s", "link", "show", is_json=True)
            sockets, socket_ref = collect(node, "sockets", "ss", "-lntp")
            collect(node, "established", "ss", "-ntip")
            collect(node, "tc", "tc", "-j", "-s", "qdisc", "show", is_json=True)
            collect(node, "forwarding", "sysctl", "net.ipv4.ip_forward")
            rules, rule_ref = collect(node, "firewall", "nft", "-j", "list", "ruleset", is_json=True)
            if node == "r1":
                if isinstance(routes, list):
                    selected = [row for row in routes if row.get("dst") == "10.77.3.0/24"]
                    observations["backend_route_present"] = bool(selected)
                    observations["backend_route_nexthop"] = selected[0].get("gateway") if selected else None
                else:
                    observations["backend_route_present"] = None
                    observations["backend_route_nexthop"] = None
                evidence["backend_route_present"] = [route_ref]
                evidence["backend_route_nexthop"] = [route_ref]
                observations["primary_link_up"] = next(("UP" in row.get("flags", []) for row in links if row.get("ifname") == "direct0"), None) if isinstance(links, list) else None
                evidence["primary_link_up"] = [link_ref]
            if node == "backend":
                observations["backend_listener_present"] = ":19090" in sockets if isinstance(sockets, str) else None
                evidence["backend_listener_present"] = [socket_ref]
                if isinstance(rules, dict):
                    counters = []
                    observations["firewall_drop_active"] = False
                    for row in rules.get("nftables", []):
                        rule = row.get("rule", {})
                        if rule.get("table") == "pnid":
                            observations["firewall_drop_active"] = True
                            counters += [item["counter"].get("packets", 0) for item in rule.get("expr", []) if "counter" in item]
                    observations["firewall_drop_packets"] = sum(counters)
                else:
                    observations["firewall_drop_packets"] = None
                    observations["firewall_drop_active"] = None
                evidence["firewall_drop_packets"] = [rule_ref]
                evidence["firewall_drop_active"] = [rule_ref]

        bgp_states, bgp_refs = [], []
        for router in ROUTERS:
            for command, name in (("show bgp ipv4 unicast summary json", "bgp-summary"),
                                  ("show bgp ipv4 unicast json", "bgp-routes")):
                result = self._vty(router, command, check=False)
                name = router + "-" + name + ".json"
                (destination / name).write_text(result.stdout)
                artifacts.append(name)
                value = _read_json(result.stdout) if result.returncode == 0 else None
                if command.endswith("summary json"):
                    bgp_refs.append(name)
                    peers = _bgp_peers(value)
                    bgp_states.append(all(p.get("state") == "Established" for p in peers.values()) and len(peers) == 2 if isinstance(peers, dict) else None)
                elif router == "r1":
                    observations["bgp_backend_prefix_present"] = "10.77.3.0/24" in value.get("routes", {}) if isinstance(value, dict) else None
                    evidence["bgp_backend_prefix_present"] = [name]
        observations["bgp_peers_established"] = all(bgp_states) if all(value is not None for value in bgp_states) else None
        evidence["bgp_peers_established"] = bgp_refs
        policy_outputs, policy_refs = {}, []
        for command, label in (("show running-config", "running-config"), ("show ip prefix-list", "prefix-lists")):
            result = self._vty("r1", command, check=False)
            relative = "r1-" + label + ".txt"
            (destination / relative).write_text(result.stdout)
            artifacts.append(relative)
            policy_refs.append(relative)
            policy_outputs[label] = result.stdout if result.returncode == 0 else None
            if result.returncode or result.stderr:
                error = relative + ".stderr.txt"
                (destination / error).write_text(f"exit_code={result.returncode}\n" + result.stderr)
                artifacts.append(error)
        observations.update(_policy_observation(policy_outputs["running-config"], policy_outputs["prefix-lists"]))
        for field in ("backend_prefix_denied", "backend_prefix_policy_present", "backend_prefix_policy"):
            evidence[field] = policy_refs.copy()
        dns_script = str(Path(__file__).with_name("dns.py"))
        result, dns_ref = collect("gateway", "dns", sys.executable, dns_script, "--query", "--state", self.root / "dns-state.json", is_json=True)
        observations["dns_ok"] = result.get("ok") if isinstance(result, dict) else None
        observations["dns_result"] = result
        evidence["dns_ok"] = [dns_ref]
        observations["gateway_metrics"] = self._metrics()
        (destination / "gateway-metrics.json").write_text(json.dumps(observations["gateway_metrics"], indent=2) + "\n")
        artifacts.append("gateway-metrics.json")
        evidence["gateway_metrics"] = ["gateway-metrics.json"]
        netem, netem_ref = collect("gateway", "netem", "tc", "-j", "-s", "qdisc", "show", "dev", "uplink0", is_json=True)
        observations["netem_active"] = any(row.get("kind") == "netem" for row in netem) if isinstance(netem, list) else None
        evidence["netem_active"] = [netem_ref]
        resources = {}
        for role, record in self._state().get("processes", {}).items():
            if self._process_matches(record):
                pid = record["pid"]
                try:
                    process_status = Path(f"/proc/{pid}/status").read_text()
                    stats = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
                    rss_line = next((line for line in process_status.splitlines() if line.startswith("VmRSS:")), None)
                    resources[role] = {"pid": pid, "cpu_ticks": int(stats[11]) + int(stats[12]),
                                       "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
                                       "rss_kib": int(rss_line.split()[1]) if rss_line else None,
                                       "open_fds": len(list(Path(f"/proc/{pid}/fd").iterdir()))}
                except (OSError, ValueError, IndexError):
                    resources[role] = None
        _json(destination / "process-resources.json", resources)
        artifacts.append("process-resources.json")
        observations["process_resources"] = resources
        evidence["process_resources"] = ["process-resources.json"]
        for folder in ("captures", "logs"):
            (destination / folder).mkdir(exist_ok=True)
            for source in sorted((self.root / folder).iterdir()):
                if source.is_file() and not source.is_symlink():
                    relative = folder + "/" + source.name
                    # Bound snapshots of log files; captures already have a ring size limit.
                    with source.open("rb") as incoming, (destination / relative).open("wb") as output:
                        if folder == "logs" and source.stat().st_size > 1048576:
                            incoming.seek(-1048576, 2)
                        shutil.copyfileobj(incoming, output, 65536)
                    artifacts.append(relative)
        meta = {"observed_at": utc(), "observations": observations, "evidence": evidence,
                "artifacts": artifacts, "capture_note": "Active capture copies may end with an incomplete final packet; final post-down captures are flushed."}
        _json(destination / "snapshot.json", meta)
        artifacts.append("snapshot.json")
        return meta

    def down(self):
        state = self._state(required=False)
        if state is None:
            return {"clean": True, "namespaces_remaining": [], "artifacts": []}
        with self._lock():
            return self._down_unlocked()

    def _down_unlocked(self):
        state = self._state()
        conflicts, errors, process_residue = [], [], []
        # Gracefully flush tcpdump first and stop network-facing software.
        for role in list(state.get("processes", {})):
            try:
                self._stop_role(role)
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                errors.append(str(exc))
        state = self._state()
        for node, expected_inode in state.get("namespaces", {}).items():
            actual = self._inode(node)
            if actual is None:
                continue
            if expected_inode != actual:
                conflicts.append(self.namespaces[node])
                continue
            pids = self._ns(node, "ip", "netns", "pids", self.namespaces[node], check=False).stdout.split()
            signaled = []
            for pid_string in pids:
                if pid_string.isdigit():
                    record = {"pid": int(pid_string), "node": node, "started": self._proc_start(int(pid_string))}
                    if self._process_matches(record):
                        try:
                            os.kill(record["pid"], signal.SIGKILL)
                            signaled.append((record["pid"], record["started"], actual))
                        except ProcessLookupError:
                            pass
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and any(self._still_in_namespace(*item) for item in signaled):
                time.sleep(0.02)
            process_residue += [pid for pid, started, inode in signaled if self._still_in_namespace(pid, started, inode)]
            result = _cmd(["ip", "netns", "delete", self.namespaces[node]], check=False)
            if result.returncode:
                errors.append(result.stderr.strip())
        existing = self._existing()
        remaining = sorted(set(self.namespaces.values()).intersection(existing))
        state["namespaces"] = {node: inode for node, inode in state.get("namespaces", {}).items()
                               if self.namespaces[node] in remaining}
        state["processes"] = {}
        state["fault"] = None
        state["cleaned_at"] = utc()
        self._save(state)
        artifacts = [str(path.relative_to(self.root)) for folder in ("captures", "logs")
                     for path in sorted((self.root / folder).glob("*")) if path.is_file() and not path.is_symlink()]
        return {"clean": not remaining and not errors and not conflicts and not process_residue, "namespaces_remaining": remaining,
                "ownership_conflicts": conflicts, "processes_remaining": process_residue,
                "errors": errors, "artifacts": artifacts}
