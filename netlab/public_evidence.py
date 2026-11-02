"""Deterministic privacy exports of lab artifacts, with verifiable derivatives.

Original observations are read-only. Export metadata describes redaction, not a
new experiment. Public reports intentionally contain categories and paths only.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import gzip
import heapq
import hashlib
import io
import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import zlib

from .public_packets import inspect_pcap

RULESET = "pnid-public-v1"
VERSION = "1.0.1"
PUBLIC_HOME = "/opt/netlab-public"
PUBLIC_HOST = "public-lab-host"
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_ENTRIES = 20000
MAX_DEPTH = 4
LOGICAL_HOSTS = {"client", "gateway", "r1", "r2", "r3", "backend", "backend.lab", "localhost", PUBLIC_HOST}
LAB4 = (ipaddress.ip_network("10.77.0.0/16"), ipaddress.ip_network("10.255.0.0/24"))
EXAMPLE4 = tuple(ipaddress.ip_network(value) for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
HOST_KEYS = {"host_state_before", "host_state_after", "host_routes", "host_network", "host_configuration"}
UNIQUE_KEYS = {"machine_id", "boot_id", "hardware_serial", "device_serial", "product_uuid", "computer_name", "host_name", "hostname"}
ROOT_HOME = "/" + "root"
HOME = re.compile(r"(?:[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s\"'<>]+|/mnt/[a-z]/[U]sers/[^/\s\"'<>]+|/(?:home|Users)/[^/\s\"'<>]+|" + re.escape(ROOT_HOME) + r"(?=/))(?:(?:[\\/]+)[^\s\"'<>]*)?", re.I | re.ASCII)
HOST_LINE = re.compile(r"^(\s*hostname\s+)([A-Za-z0-9_.-]+)(\s*)$", re.M)
COMMON_HOST = re.compile(r"\b(?:DESKTOP|LAPTOP|WIN)-[A-Z0-9-]{3,}\b", re.I | re.ASCII)
ADDRESS = re.compile(r"(?<![\w.:])(?:[0-9A-Fa-f]*:[0-9A-Fa-f:.]+|(?:\d{1,3}\.){3}\d{1,3})(?:/\d{1,3})?(?![\w.])")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", re.ASCII)
SECRETS = {
    "github_token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "api_key": re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}\b"),
    "bearer_token": re.compile(r"\bBearer\s+[A-Za-z0-9_.=-]{24,}", re.I),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b"),
    "credential_url": re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@", re.I),
}
# Credential formats use ASCII tokens. Unicode word characters adjacent to
# decoded binary must not conceal an otherwise recognizable token boundary.
SECRETS = {category: re.compile(pattern.pattern, (pattern.flags & ~re.UNICODE) | re.ASCII)
           for category, pattern in SECRETS.items()}
SECRET_HINTS = {
    "github_token": ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
    "aws_access_key": ("AKIA", "ASIA"), "private_key": ("-----BEGIN ",),
    "api_key": ("sk-",), "bearer_token": ("bearer",), "jwt": ("eyJ",),
    "credential_url": ("://",),
}


class PublicEvidenceError(ValueError):
    """A deliberately value-free publication failure."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def _json(data):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                # A duplicate can conceal an earlier escaped identifier. Never
                # include either the key or its values in a publication error.
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    try:
        return json.loads(data.decode("utf-8-sig"), object_pairs_hook=unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise PublicEvidenceError("malformed JSON evidence") from None


def _relative(name):
    # "!" separates archive boundaries in public provenance references. A real
    # filename containing it could make an otherwise correct hash ambiguous.
    if not isinstance(name, str) or not name or "\\" in name or "\x00" in name or "!" in name:
        raise PublicEvidenceError("unsafe artifact path")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or ":" in name or any(ord(c) < 32 for c in name):
        raise PublicEvidenceError("unsafe artifact path")
    value = path.as_posix()
    if value == ".":
        raise PublicEvidenceError("empty artifact path")
    return value


def _text(data):
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8-sig")
    except UnicodeError:
        return None


def _email_count(value):
    if "@" not in value:
        return 0
    reserved = ("example.test", "example.invalid", "example.com", "example.net", "example.org")
    return sum(not any(m.group(1).lower() == domain or m.group(1).lower().endswith("." + domain)
                       for domain in reserved) for m in EMAIL.finditer(value))


def _address(value):
    try:
        return ipaddress.ip_interface(value)
    except ValueError:
        return None


def _lab_address(value):
    address = value.ip
    return (address.is_loopback or address.is_unspecified or address.is_multicast
            or (address.version == 4 and any(address in network for network in LAB4)))


@dataclass
class Entry:
    data: bytes
    children: dict | None = None
    metadata_findings: int = 0
    original: bytes = b""
    metadata_sensitive: dict = field(default_factory=dict)
    metadata_values: list = field(default_factory=list, repr=False)
    is_dir: bool = False


@dataclass
class Budget:
    size: int = 0
    entries: int = 0

    def add(self, size):
        self.size += size
        self.entries += 1
        if size > MAX_FILE or self.size > MAX_TOTAL or self.entries > MAX_ENTRIES:
            raise PublicEvidenceError("evidence exceeds publication scan bounds")


def _metadata_findings(values):
    counts = Counter()
    for value in values:
        views = _byte_views(value) if isinstance(value, bytes) else [str(value)]
        for text in views:
            for category, pattern in SECRETS.items():
                counts[category] += len(pattern.findall(text))
            counts["personal_email"] += _email_count(text)
    return {key: value for key, value in counts.items() if value}


def _byte_views(data):
    """Bounded ASCII-compatible and common UTF-16 views; no arbitrary decoding."""
    yield data.decode("latin-1")
    if b"\0" in data:
        for offset in (0, 1):
            for encoding in ("utf-16-le", "utf-16-be"):
                yield data[offset:].decode(encoding, errors="ignore")


def _gzip_metadata(data):
    if len(data) < 18 or data[2] != 8 or data[3] & 0xe0:
        raise PublicEvidenceError("malformed gzip header")
    position, values, flags = 10, [], data[3]
    if flags & 4:
        if position + 2 > len(data):
            raise PublicEvidenceError("malformed gzip extra header")
        size = int.from_bytes(data[position:position + 2], "little")
        position += 2
        values.append(data[position:position + size])
        position += size
    for flag in (8, 16):
        if flags & flag:
            end = data.find(b"\0", position, min(len(data), position + 65536))
            if end < 0:
                raise PublicEvidenceError("malformed gzip text metadata")
            values.append(data[position:end])
            position = end + 1
    if position + (2 if flags & 2 else 0) >= len(data) - 8:
        raise PublicEvidenceError("malformed gzip header length")
    return (_metadata_findings(values), int(bool(flags or int.from_bytes(data[4:8], "little"))),
            [text for value in values for text in _byte_views(value)])


def _pax_values(payload):
    """Consume every PAX byte instead of accepting ignored or repeated fields."""
    result, position = {}, 0
    while position < len(payload):
        end = payload.find(b" ", position, min(len(payload), position + 24))
        size_text = payload[position:end] if end >= 0 else b""
        if not size_text or not size_text.isdigit():
            raise PublicEvidenceError("malformed archive extension metadata")
        size = int(size_text)
        if size <= end - position + 2 or position + size > len(payload):
            raise PublicEvidenceError("malformed archive extension metadata")
        record = payload[end + 1:position + size]
        if not record.endswith(b"\n") or b"=" not in record or b"\0" in record:
            raise PublicEvidenceError("malformed archive extension metadata")
        key, value = record[:-1].split(b"=", 1)
        if not key or any(byte in key for byte in b" \n\r") or key in result:
            raise PublicEvidenceError("ambiguous archive extension metadata")
        result[key] = value
        position += size
    return result


def _tar_header(header):
    """Reject ignored header bytes while retaining supported USTAR/GNU forms."""
    member = tarfile.TarInfo.frombuf(header, encoding="utf-8", errors="surrogateescape")
    magic = header[257:265]
    if magic not in (tarfile.POSIX_MAGIC, tarfile.GNU_MAGIC, bytes(8)):
        raise PublicEvidenceError("unsupported archive header format")
    text_fields = [(0, 100), (157, 257), (265, 297), (297, 329)]
    if magic == tarfile.POSIX_MAGIC:
        text_fields.append((345, 500))
        unused = header[500:]
    else:
        # GNU sparse/extended-layout records are unsupported. Ordinary GNU
        # headers and GNU long-name/link records leave this area empty.
        unused = header[345:]
    if any(unused):
        raise PublicEvidenceError("nonzero unused archive header bytes")
    for start, end in text_fields:
        value = header[start:end]
        terminator = value.find(b"\0")
        if terminator >= 0 and any(byte not in (0, 32) for byte in value[terminator:]):
            raise PublicEvidenceError("nonzero unused archive header bytes")
    for start, end in ((100, 108), (108, 116), (116, 124), (124, 136),
                       (136, 148), (148, 156), (329, 337), (337, 345)):
        value = header[start:end]
        if value[0] in (128, 255):
            continue  # All bytes of GNU base-256 numeric fields are consumed.
        terminator = value.find(b"\0")
        if terminator >= 0 and any(byte not in (0, 32) for byte in value[terminator:]):
            raise PublicEvidenceError("nonzero unused archive header bytes")
    return member


def _tar_layout(decoded):
    """Validate physical blocks that tarfile skips, including extension padding.

    Return all header/extension bytes for metadata scanning. File payload bytes
    are inspected recursively through their logical entries after this pass.
    """
    if len(decoded) % tarfile.BLOCKSIZE:
        raise PublicEvidenceError("incomplete archive block framing")
    offset, headers = 0, 0
    metadata, global_pax, pending_pax = [], {}, {}
    extensions = {tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE,
                  tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK}
    while offset < len(decoded):
        header = decoded[offset:offset + tarfile.BLOCKSIZE]
        if not any(header):
            if len(decoded) - offset < 2 * tarfile.BLOCKSIZE or any(decoded[offset:]):
                raise PublicEvidenceError("malformed archive end marker")
            if pending_pax:
                raise PublicEvidenceError("orphaned archive extension metadata")
            return metadata
        headers += 1
        if headers > MAX_ENTRIES:
            raise PublicEvidenceError("archive header count exceeds publication scan bounds")
        member = _tar_header(header)
        if member.type not in extensions | {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}:
            raise PublicEvidenceError("unsupported archive member type")
        size = member.size
        if member.type not in extensions:
            size_value = pending_pax.get(b"size", global_pax.get(b"size"))
            if size_value is not None:
                if not size_value.isdigit() or len(size_value) > 20:
                    raise PublicEvidenceError("malformed archive extension size")
                size = int(size_value)
        if size < 0 or size > MAX_FILE or (member.isdir() and size):
            raise PublicEvidenceError("unsupported archive member size")
        body = offset + tarfile.BLOCKSIZE
        end = body + size
        padded_end = body + ((size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE) * tarfile.BLOCKSIZE
        if padded_end > len(decoded) or any(decoded[end:padded_end]):
            raise PublicEvidenceError("nonzero or incomplete archive member padding")
        metadata.append(header)
        if member.type in extensions:
            payload = decoded[body:end]
            metadata.append(payload)
            if member.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE):
                values = _pax_values(payload)
                if member.type == tarfile.XGLTYPE:
                    global_pax.update(values)
                elif pending_pax:
                    raise PublicEvidenceError("unsupported overlapping archive metadata")
                else:
                    pending_pax = values
            else:
                terminator = payload.find(b"\0")
                if terminator < 0 or any(payload[terminator:]):
                    raise PublicEvidenceError("malformed archive long-name metadata")
        else:
            pending_pax = {}
        offset = padded_end
    raise PublicEvidenceError("missing archive end marker")


def _entry(data, budget, depth=0):
    budget.add(len(data))
    result = Entry(data=data, original=data)
    if data.startswith(b"\x1f\x8b"):
        if depth >= MAX_DEPTH:
            raise PublicEvidenceError("archive nesting exceeds publication scan bounds")
        children = {}
        try:
            result.metadata_sensitive, result.metadata_findings, result.metadata_values = _gzip_metadata(data)
            decompressor = zlib.decompressobj(31)
            decoded = decompressor.decompress(data, MAX_TOTAL + 1)
            if len(decoded) > MAX_TOTAL or decompressor.unconsumed_tail:
                raise PublicEvidenceError("archive exceeds decompression bounds")
            if not decompressor.eof or decompressor.unused_data:
                raise PublicEvidenceError("incomplete, concatenated, or trailing gzip data")
            metadata = _tar_layout(decoded)
            merged_metadata = Counter(result.metadata_sensitive)
            merged_metadata.update(_metadata_findings(metadata))
            result.metadata_sensitive = dict(merged_metadata)
            result.metadata_values.extend(value.decode("latin-1") for value in metadata)
            if any(HOME.search(value.decode("latin-1")) or COMMON_HOST.search(value.decode("latin-1"))
                   for value in metadata):
                result.metadata_findings += 1
            with tarfile.open(fileobj=io.BytesIO(decoded), mode="r:") as archive:
                for member in archive:
                    name = _relative(member.name.rstrip("/"))
                    if name in children or member.linkname or member.issparse() or not (member.isfile() or member.isdir()):
                        raise PublicEvidenceError("duplicate or unsafe archive member")
                    metadata_values = [member.name, member.uname, member.gname,
                                       *member.pax_headers.keys(), *member.pax_headers.values()]
                    metadata_sensitive = _metadata_findings(metadata_values)
                    if member.isdir():
                        budget.add(0)
                        children[name] = Entry(b"", is_dir=True, metadata_sensitive=metadata_sensitive,
                                               metadata_values=metadata_values,
                                               metadata_findings=int(bool(member.uid or member.gid or member.uname or member.gname or member.mtime or member.pax_headers or member.mode != 0o755)))
                        continue
                    if member.size > MAX_FILE or member.size < 0:
                        raise PublicEvidenceError("archive member exceeds publication scan bounds")
                    incoming = archive.extractfile(member)
                    if incoming is None:
                        raise PublicEvidenceError("unreadable archive member")
                    payload = incoming.read(MAX_FILE + 1)
                    if len(payload) != member.size:
                        raise PublicEvidenceError("archive member length mismatch")
                    child = _named_entry(name, payload, budget, depth + 1)
                    merged = Counter(child.metadata_sensitive)
                    merged.update(metadata_sensitive)
                    child.metadata_sensitive = dict(merged)
                    child.metadata_values.extend(metadata_values)
                    child.metadata_findings += int(bool(member.uid or member.gid or member.uname or member.gname
                                                      or member.mtime or (set(member.pax_headers) - {"path", "size"}) or member.mode != 0o644))
                    children[name] = child
                if any(decoded[archive.offset:]):
                    raise PublicEvidenceError("nonzero data after tar end marker")
        except (tarfile.TarError, EOFError, OSError, zlib.error):
            raise PublicEvidenceError("malformed or unsupported gzip/tar evidence") from None
        result.children = children
        for name in children:
            if any(parent.as_posix() in children and not children[parent.as_posix()].is_dir
                   for parent in PurePosixPath(name).parents if parent.as_posix() != "."):
                raise PublicEvidenceError("archive file/directory path conflict")
    return result


def _named_entry(name, data, budget, depth=0):
    if name.lower().endswith((".tar.gz", ".tgz")) and not data.startswith(b"\x1f\x8b"):
        raise PublicEvidenceError("malformed declared archive")
    if name.lower().endswith((".tar", ".zip", ".pcapng")):
        raise PublicEvidenceError("unsupported archive or packet format")
    if re.search(r"\.pcap\d*$", name.lower()) and not _is_pcap(data):
        raise PublicEvidenceError("malformed declared packet capture")
    return _entry(data, budget, depth)


def _load(input_path):
    source = Path(input_path).absolute()
    if any(path.is_symlink() for path in (source, *source.parents)):
        raise PublicEvidenceError("input path cannot contain symlinks")
    if not source.exists():
        raise PublicEvidenceError("missing input")
    if source.is_dir() and (source / ".git").exists():
        raise PublicEvidenceError("export input must be an artifact subtree, not a repository root")
    budget = Budget()
    files = {}
    paths = sorted(source.rglob("*")) if source.is_dir() else [source]
    for path in paths:
        if path.is_symlink():
            raise PublicEvidenceError("input contains a symlink")
        if path.is_dir():
            continue
        if not path.is_file():
            raise PublicEvidenceError("input contains an unsupported file")
        if path.stat().st_size > MAX_FILE:
            raise PublicEvidenceError("input file exceeds publication scan bounds")
        name = path.relative_to(source).as_posix() if source.is_dir() else path.name
        files[_relative(name)] = _named_entry(name, path.read_bytes(), budget)
    if not files:
        raise PublicEvidenceError("input contains no evidence files")
    return files


def _containers(files, prefix=""):
    yield files, prefix
    for name, entry in files.items():
        if entry.children is not None:
            yield from _containers(entry.children, prefix + name + "!")


def _verify(files):
    count = 0
    for entries, prefix in _containers(files):
        for name, entry in entries.items():
            if name.endswith("/manifest.json") or name == "manifest.json":
                value = _json(entry.data)
                if not isinstance(value, dict) or value.get("algorithm") != "sha256" or not isinstance(value.get("files"), dict):
                    raise PublicEvidenceError("unsupported evidence manifest")
                base = name.rpartition("/")[0]
                base = base + "/" if base else ""
                actual = {p[len(base):]: {"sha256": digest(item.data), "bytes": len(item.data)}
                          for p, item in entries.items() if p.startswith(base) and p != name and not item.is_dir}
                expected = value["files"]
                for relative in expected:
                    _relative(relative)
                if actual != expected:
                    raise PublicEvidenceError("input manifest membership or digest mismatch")
                count += 1
            elif name.endswith("SHA256SUMS"):
                base = name.rpartition("/")[0]
                base = base + "/" if base else ""
                for relative, expected in _checksum_records(entry.data).items():
                    if base + relative not in entries or entries[base + relative].is_dir or digest(entries[base + relative].data) != expected:
                        raise PublicEvidenceError("input checksum index mismatch")
    return count


def _strings(value, host=False, key=""):
    if isinstance(value, dict):
        for name, item in value.items():
            yield name, False, ""
            yield from _strings(item, host or name in HOST_KEYS, name)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item, host, key)
    elif isinstance(value, str):
        yield value, host, key


def _string_contexts(name, data):
    text = _text(data)
    if text is None:
        return []
    if name.endswith(".json"):
        return list(_strings(_json(data)))
    # Generated reports carry JSON context blocks, as well as ordinary prose.
    contexts = []
    for match in re.finditer(r"```json\s*\n([\s\S]*?)```", text):
        contexts.extend(_strings(_json(match.group(1).encode())))
    contexts.append((re.sub(r"```json\s*\n[\s\S]*?```", "", text), False, ""))
    return contexts


def _context_values(files):
    hosts = set()
    addresses = set()
    for entries, _ in _containers(files):
        for name, entry in entries.items():
            if entry.is_dir or entry.children is not None or _is_pcap(entry.data):
                continue
            for value, host, key in _string_contexts(name, entry.data):
                for match in HOST_LINE.finditer(value):
                    if match.group(2) not in LOGICAL_HOSTS:
                        hosts.add(match.group(2))
                if key in {"hostname", "host_name", "computer_name"} and value not in LOGICAL_HOSTS:
                    hosts.add(value)
                if host:
                    for match in ADDRESS.finditer(value):
                        address = _address(match.group())
                        if address is not None and not _lab_address(address):
                            addresses.add(str(address.ip))
    return hosts, {value: f"host-address-{index:04d}" for index, value in enumerate(sorted(addresses), 1)}


def _is_pcap(data):
    return data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")


def _host_mentions(text, hosts):
    return sum(len(re.findall(r"(?<![A-Za-z0-9])" + re.escape(host) + r"(?![A-Za-z0-9])", text, re.I | re.ASCII)) for host in hosts)


def _report_path(path, hosts=()):
    if HOME.search(path) or COMMON_HOST.search(path) or _host_mentions(path, hosts) or any(pattern.search(path) for pattern in SECRETS.values()) or _email_count(path):
        return "[redacted-artifact-path]"
    return path


def _audit(files, *, fixture_sources=False, known_hosts=None):
    hosts, addresses = _context_values(files)
    hosts |= known_hosts or set()
    findings = []
    counts = Counter()
    packets = Counter()
    total_files = 0
    archives = 0

    def add(category, path, count=1, severity="incidental"):
        if count:
            counts[category] += count
            findings.append({"category": category, "path": _report_path(path, hosts), "count": count, "severity": severity})

    def byte_categories(data):
        result = set()
        for text in _byte_views(data):
            lower = text.lower()
            result.update(category for category, pattern in SECRETS.items()
                          if any(hint in (lower if category == "bearer_token" else text) for hint in SECRET_HINTS[category])
                          and pattern.search(text))
            if _email_count(text):
                result.add("personal_email")
            if any(hint in lower for hint in ("/home/", "/users/", ROOT_HOME + "/", "users\\")) and HOME.search(text):
                result.add("packet_account_path")
            if ((any(hint in lower for hint in ("desktop-", "laptop-", "win-")) and COMMON_HOST.search(text))
                    or any(host.lower() in lower for host in hosts)):
                result.add("packet_host_label")
        return result

    for entries, prefix in _containers(files):
        for name, entry in entries.items():
            total_files += 1
            location = prefix + name
            if HOME.search(name) or COMMON_HOST.search(name) or _host_mentions(name, hosts):
                add("identifier_in_filename", location, severity="stop")
            for category, amount in _metadata_findings([name]).items():
                add(category, location, amount, "stop")
            for category, amount in entry.metadata_sensitive.items():
                add(category, location, amount, "stop")
            if entry.metadata_findings:
                add("archive_metadata", location, entry.metadata_findings)
            if any(_host_mentions(str(value), hosts) for value in entry.metadata_values):
                add("archive_host_label", location)
            if entry.children is not None:
                archives += 1
                continue
            if entry.is_dir:
                continue
            if _is_pcap(entry.data):
                try:
                    packet_result = inspect_pcap(entry.data)
                except ValueError:
                    raise PublicEvidenceError("malformed or unsupported packet evidence") from None
                for key in ("files", "records", "stored_bytes", "payload_bytes", "truncated_records"):
                    packets[key] += packet_result.get(key, 0)
                for finding in packet_result.get("findings", []):
                    category = finding["category"]
                    add(category, location, finding.get("count", 1), "stop")
                # Scan the complete stored capture, including padding and packet
                # metadata, once. Framing/protocol checks above still visit every
                # packet; contiguous identifiers across records also fail closed.
                for category in sorted(byte_categories(entry.data)):
                    add(category, location, severity="stop")
                continue
            text = _text(entry.data)
            if text is None:
                if any(byte_categories(entry.data)):
                    add("sensitive_binary", location, severity="stop")
                else:
                    add("unsupported_binary", location, severity="stop")
                continue
            scan = text
            def fixture_scan(value):
                if fixture_sources and name in {"tests/test_public_evidence.py", "tests/test_public_packets.py"}:
                    return re.sub(r"(?:[A-Za-z]:[\\/]+Users[\\/]+|/[h]ome/|/[U]sers/)fixture-user(?=[/\\\"'])", PUBLIC_HOME, value)
                return value
            scan = fixture_scan(scan)
            contexts = _string_contexts(name, entry.data)
            decoded = [fixture_scan(value) for value, _, _ in contexts]
            for category, pattern in SECRETS.items():
                add(category, location, max(len(pattern.findall(scan)), sum(len(pattern.findall(value)) for value in decoded)), "stop")
            add("personal_email", location, max(_email_count(scan), sum(_email_count(value) for value in decoded)), "stop")
            add("account_path", location, max(len(HOME.findall(scan)), sum(len(HOME.findall(value)) for value in decoded)))
            add("machine_hostname", location, max(len(COMMON_HOST.findall(scan)), sum(len(COMMON_HOST.findall(value)) for value in decoded)))
            # Directives are handled below; references elsewhere must not silently
            # survive merely because a label was discovered in another artifact.
            add("host_label_reference", location, max(_host_mentions(HOST_LINE.sub("", scan), hosts),
                sum(_host_mentions(HOST_LINE.sub("", value), hosts) for value in decoded)))
            for value, host, key in contexts:
                for match in HOST_LINE.finditer(value):
                    if match.group(2) not in LOGICAL_HOSTS and not (fixture_sources and name.startswith("tests/test_public_") and match.group(2) == "fixture-host"):
                        add("host_label", location)
                if key in UNIQUE_KEYS and value and value not in LOGICAL_HOSTS and value not in {"redacted-machine-identifier"}:
                    add("machine_identifier", location)
                if host:
                    add("host_network_address", location, sum(_address(m.group()) is not None and not _lab_address(_address(m.group())) for m in ADDRESS.finditer(value)))
    return {"schema_version": 1, "ruleset": RULESET, "safe": not findings,
            "files": total_files, "archives": archives, "pcaps": dict(packets),
            "counts": dict(sorted(counts.items())), "findings": findings,
            "integrity_errors": [], "limits": ["Stored packet bytes only; truncated wire bytes were not captured.",
                                                  "Pattern and schema checks do not certify anonymity or scan Git history."]}


def audit_tree(input_path):
    files = _load(input_path)
    manifests = _verify(files)
    report = _audit(files)
    report["manifests_verified"] = manifests
    return report


def audit_repository(repository):
    root = Path(repository).absolute()
    try:
        result = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        raise PublicEvidenceError("cannot enumerate tracked public files") from None
    budget = Budget()
    files = {}
    for encoded in result.stdout.split(b"\0"):
        if not encoded:
            continue
        name = _relative(encoded.decode())
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise PublicEvidenceError("tracked public path is missing or unsafe")
        files[name] = _named_entry(name, path.read_bytes(), budget)
    _verify(files)
    return _audit(files, fixture_sources=True)


def _neutral_path(match):
    original = match.group()
    # Preserve the artifact/source filename while replacing account location.
    prefix = re.match(r"(?:[A-Za-z]:[\\/]+Users[\\/]+[^\\/]+|/mnt/[a-z]/[U]sers/[^/]+|/(?:home|Users)/[^/]+|" + re.escape(ROOT_HOME) + r")", original, re.I)
    suffix = original[prefix.end():] if prefix else ""
    suffix = re.sub(r"[\\/]+", "/", suffix)
    return PUBLIC_HOME + suffix


def _transform_string(value, host, key, addresses, changes):
    if key in UNIQUE_KEYS and value and value not in LOGICAL_HOSTS and value != "redacted-machine-identifier":
        changes["machine_identifier"] += 1
        value = PUBLIC_HOST if key in {"hostname", "computer_name", "host_name"} else "redacted-machine-identifier"
    def home(match):
        changes["account_path"] += 1
        return _neutral_path(match)
    value = HOME.sub(home, value)
    def hostname(match):
        if match.group(2) in LOGICAL_HOSTS:
            return match.group()
        changes["host_label"] += 1
        return match.group(1) + PUBLIC_HOST + match.group(3)
    value = HOST_LINE.sub(hostname, value)
    value, amount = COMMON_HOST.subn(PUBLIC_HOST, value)
    changes["machine_hostname"] += amount
    if host:
        def address(match):
            parsed = _address(match.group())
            if parsed is None or _lab_address(parsed):
                return match.group()
            changes["host_network_address"] += 1
            base = addresses[str(parsed.ip)]
            return base + ("/" + str(parsed.network.prefixlen) if "/" in match.group() else "")
        value = ADDRESS.sub(address, value)
    return value


def _transform_value(value, addresses, changes, host=False, key=""):
    if isinstance(value, dict):
        return {name: _transform_value(item, addresses, changes, host or name in HOST_KEYS, name) for name, item in value.items()}
    if isinstance(value, list):
        return [_transform_value(item, addresses, changes, host, key) for item in value]
    if isinstance(value, str):
        return _transform_string(value, host, key, addresses, changes)
    return value


def _transform_text(name, data, addresses, changes):
    text = _text(data)
    if text is None:
        return data
    if name.endswith(".json"):
        original = _json(data)
        transformed = _transform_value(original, addresses, changes)
        return json_bytes(transformed) if transformed != original else data
    def block(match):
        original = _json(match.group(1).encode())
        transformed = _transform_value(original, addresses, changes)
        return "```json\n" + json_bytes(transformed).decode() + "```" if transformed != original else match.group()
    text = re.sub(r"```json\s*\n([\s\S]*?)```", block, text)
    text = _transform_string(text, False, "", addresses, changes)
    return text.encode() if text != data.decode("utf-8-sig") else data


def _archive_bytes(files):
    stream = io.BytesIO()
    with gzip.GzipFile(fileobj=stream, mode="wb", filename="", compresslevel=9, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            for name, entry in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.size = len(entry.data)
                info.mode = 0o755 if entry.is_dir else 0o644
                if entry.is_dir:
                    info.type = tarfile.DIRTYPE
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                archive.addfile(info, None if entry.is_dir else io.BytesIO(entry.data))
    return stream.getvalue()


def _checksum_records(data):
    result = {}
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeError:
        raise PublicEvidenceError("malformed checksum index") from None
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise PublicEvidenceError("malformed checksum index")
        expected, relative = match.groups()
        relative = _relative(relative)
        if relative in result:
            raise PublicEvidenceError("ambiguous checksum index")
        result[relative] = expected
    return result


def _integrity_kind(name):
    if PurePosixPath(name).name == "manifest.json":
        return "manifest"
    if name.endswith("SHA256SUMS"):
        return "checksum"
    return None


def _integrity_plan(entries, provenance_path=None):
    """Order all integrity nodes by their actual file dependencies, or refuse."""
    kinds = {name: _integrity_kind(name) for name, entry in entries.items()
             if not entry.is_dir and _integrity_kind(name)}
    targets, dependencies, dependents = {}, {}, {name: [] for name in kinds}
    edges = 0
    for name, kind in kinds.items():
        base = name.rpartition("/")[0]
        base = base + "/" if base else ""
        if kind == "manifest":
            members = sorted(path for path, item in entries.items()
                             if path.startswith(base) and path != name and not item.is_dir)
        else:
            members = [base + relative for relative in _checksum_records(entries[name].original)]
            if provenance_path is not None and provenance_path.startswith(base):
                members.append(provenance_path)
            members = sorted(set(members))
            if any(path not in entries or entries[path].is_dir for path in members):
                raise PublicEvidenceError("missing checksum dependency")
        edges += len(members)
        if edges > MAX_ENTRIES * MAX_DEPTH * 2:
            raise PublicEvidenceError("integrity graph exceeds publication scan bounds")
        targets[name] = members
        dependencies[name] = set(members).intersection(kinds)
        for dependency in dependencies[name]:
            dependents[dependency].append(name)
    ready = [name for name in kinds if not dependencies[name]]
    heapq.heapify(ready)
    order = []
    while ready:
        name = heapq.heappop(ready)
        order.append(name)
        for parent in dependents[name]:
            dependencies[parent].remove(name)
            if not dependencies[parent]:
                heapq.heappush(ready, parent)
    if len(order) != len(kinds):
        raise PublicEvidenceError("cyclic integrity dependencies cannot be exported")
    # These outer integrity files change when the provenance bytes are inserted.
    # Their output hashes cannot themselves appear inside that provenance.
    sensitive = set()
    if provenance_path is not None:
        for name in order:
            if provenance_path in targets[name] or sensitive.intersection(targets[name]):
                sensitive.add(name)
    return order, kinds, targets, sensitive


def _rebuild_integrity(entries, provenance_path=None):
    order, kinds, targets, sensitive = _integrity_plan(entries, provenance_path)
    for name in order:
        base = name.rpartition("/")[0]
        base = base + "/" if base else ""
        if kinds[name] == "manifest":
            value = _json(entries[name].data)
            if not isinstance(value, dict) or value.get("algorithm") != "sha256":
                raise PublicEvidenceError("unsupported evidence manifest")
            value["files"] = {path[len(base):]: {"sha256": digest(entries[path].data),
                                                "bytes": len(entries[path].data)}
                              for path in targets[name]}
            entries[name].data = json_bytes(value)
        else:
            entries[name].data = "".join(digest(entries[path].data) + "  " + path[len(base):] + "\n"
                                        for path in targets[name]).encode()
    return sensitive


def export_tree(input_path, output_path, *, source_revision, export_date="", provenance_path="sanitization-manifest.json"):
    if not isinstance(source_revision, str) or not re.fullmatch(r"[0-9a-fA-F]{7,40}", source_revision):
        raise PublicEvidenceError("source revision must be a Git commit identifier")
    if export_date and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", export_date):
        raise PublicEvidenceError("export date must use YYYY-MM-DD")
    source, output = Path(input_path).absolute(), Path(output_path).absolute()
    if output.exists() or any(p.is_symlink() for p in (output, *output.parents)):
        raise PublicEvidenceError("output must be a new directory without symlink components")
    if any(p.is_symlink() for p in (source, *source.parents)):
        raise PublicEvidenceError("input path cannot contain symlinks")
    source, output = source.resolve(), output.resolve()
    if source == output or source in output.parents or output in source.parents:
        raise PublicEvidenceError("input and output must be separate nonoverlapping paths")
    provenance_path = _relative(provenance_path)
    if _integrity_kind(provenance_path):
        raise PublicEvidenceError("provenance cannot replace an integrity record")
    files = _load(source)
    if provenance_path in files:
        raise PublicEvidenceError("input already contains export provenance; audit it instead")
    if (any(parent.as_posix() in files and not files[parent.as_posix()].is_dir
            for parent in PurePosixPath(provenance_path).parents if parent.as_posix() != ".")
            or any(name.startswith(provenance_path + "/") for name in files)):
        raise PublicEvidenceError("provenance conflicts with an existing artifact path")
    manifests = _verify(files)
    before = _audit(files)
    if any(item["severity"] == "stop" for item in before["findings"]):
        raise PublicEvidenceError("input requires review before public export; run audit for categories and paths")
    hosts, addresses = _context_values(files)
    records = []
    totals = Counter()
    changes_by_path = {}
    def transform(entries, prefix=""):
        for name, entry in sorted(entries.items()):
            changes = Counter()
            totals["archive_metadata"] += entry.metadata_findings
            if entry.children is not None:
                transform(entry.children, prefix + name + "!")
                entry.data = _archive_bytes(entry.children)
                changes["archive_metadata"] += entry.metadata_findings + sum(child.metadata_findings for child in entry.children.values())
            elif entry.is_dir or _is_pcap(entry.data):
                # Packet bytes are observations, never subject to byte substitution.
                pass
            elif not _integrity_kind(name):
                entry.data = _transform_text(name, entry.data, addresses, changes)
            changes_by_path[(prefix, name)] = changes
        _rebuild_integrity(entries)
    transform(files)
    # Plan with a placeholder to settle all provenance-independent output hashes
    # and account for newly enclosing integrity records before serializing it.
    files[provenance_path] = Entry(b"")
    provenance_dependents = _rebuild_integrity(files, provenance_path)
    recorded_entries = []
    seen_paths = set()
    for entries, prefix in _containers(files):
        for name, entry in sorted(entries.items()):
            if not prefix and name == provenance_path:
                continue
            changes = changes_by_path[(prefix, name)]
            if entry.data != entry.original:
                kind = _integrity_kind(name)
                if kind == "manifest":
                    changes["export_manifest"] += 1
                elif kind == "checksum":
                    changes["checksum_index"] += 1
                totals.update({key: amount for key, amount in changes.items() if key != "archive_metadata"})
                if not (not prefix and name in provenance_dependents):
                    path = prefix + name
                    if path in seen_paths:
                        raise PublicEvidenceError("ambiguous archive provenance path")
                    seen_paths.add(path)
                    record = {"path": path, "input_sha256": digest(entry.original),
                              "output_sha256": digest(entry.data),
                              "categories": {k: v for k, v in sorted(changes.items()) if v}}
                    records.append(record)
                    recorded_entries.append((record, entry))
    provenance = {"schema_version": 1, "ruleset": RULESET, "sanitizer_version": VERSION,
                  "source_revision": source_revision, "export_date": export_date or None,
                  "new_experiment": False, "transformed_artifacts": sorted(records, key=lambda item: item["path"]),
                  "transformation_counts": dict(sorted(totals.items())),
                  "archive_convention": "Sorted PAX tar members; uid/gid/mtime zero; empty owner names; file mode0644; gzip level9, mtime0, no filename. Observation timestamps remain unchanged.",
                  "path_convention": "Synthetic absolute display paths under /opt/netlab-public are not executable instructions.",
                  "host_address_convention": "Opaque host-address labels preserve equalities; they are not original addresses. Lab addresses stay unchanged.",
                  "checksum_convention": "Integrity records are rebuilt in dependency order. Only outer-container integrity records transitively depending on this provenance are excluded from output mapping to avoid digest cycles; other checksum and manifest hashes are retained.",
                  "packet_policy": "Stored packet bytes audited and retained byte-for-byte; uncaptured bytes and arbitrary encodings are outside scan scope.",
                  "original_findings": before["counts"], "input_manifests_verified": manifests}
    files[provenance_path].data = json_bytes(provenance)
    _rebuild_integrity(files, provenance_path)
    if any(record["output_sha256"] != digest(entry.data) for record, entry in recorded_entries):
        raise PublicEvidenceError("unstable provenance output digest")
    _verify(files)
    # Header findings were normalized when serializing; reload to assess final bytes.
    final_files = {name: _entry(entry.data, Budget()) for name, entry in files.items()}
    report = _audit(final_files, known_hosts=hosts)
    if not report["safe"]:
        raise PublicEvidenceError("export did not satisfy the public privacy gate")
    output.mkdir(parents=True, mode=0o700)
    for name, entry in files.items():
        target = output.joinpath(*PurePosixPath(name).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(entry.data)
    report["provenance"] = provenance_path
    report["transformation_counts"] = dict(sorted(totals.items()))
    report["input_counts"] = before["counts"]
    return report
