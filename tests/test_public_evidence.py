"""Privacy export checks use invented identifiers and synthetic packet fixtures."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from netlab.public_evidence import (
    Entry, PublicEvidenceError, RULESET, _rebuild_integrity, audit_repository, audit_tree, export_tree,
)


SOURCE_REVISION = "a" * 40
EXPORT_DATE = "2026-11-02"
BINARY_DIGEST = "b" * 64
REPOSITORY = Path(__file__).resolve().parent.parent


def put_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def manifest(directory):
    values = {}
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path != directory / "manifest.json":
            raw = path.read_bytes()
            values[path.relative_to(directory).as_posix()] = {"sha256": digest(raw), "bytes": len(raw)}
    put_json(directory / "manifest.json", {"algorithm": "sha256", "schema_version": 1, "files": values})


def make_tar(members, *, username="fixture-user", mtime=123456789, uid=1234,
             filename="fixture-host-private-name.tar"):
    archive_bytes = io.BytesIO()
    with gzip.GzipFile(fileobj=archive_bytes, mode="wb", filename=filename, mtime=mtime) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for name, data in reversed(list(members.items())):
                entry = tarfile.TarInfo(name)
                entry.size, entry.uid, entry.gid = len(data), uid, uid
                entry.uname = entry.gname = username
                entry.mtime = mtime
                archive.addfile(entry, io.BytesIO(data))
    return archive_bytes.getvalue()


def members(raw):
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        return {entry.name: archive.extractfile(entry).read() for entry in archive if entry.isfile()}


def synthetic_pcap(payload=b"synthetic echo"):
    """Classic Ethernet/IPv4/UDP capture with valid IP checksum and lab endpoints."""
    source, target = socket.inet_aton("10.77.1.2"), socket.inet_aton("10.77.1.1")
    udp = struct.pack("!HHHH", 40000, 19090, 8 + len(payload), 0) + payload
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, source, target)
    checksum = sum(struct.unpack("!10H", header))
    while checksum >> 16:
        checksum = (checksum & 65535) + (checksum >> 16)
    header = header[:10] + struct.pack("!H", (~checksum) & 65535) + header[12:]
    frame = bytes.fromhex("0200000000010200000000020800") + header + udp
    global_header = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    return global_header + struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame


class PublicEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.input = self.base / "input"
        self.input.mkdir()
        self.output = self.base / "public"

    def export(self, output=None, **kwargs):
        return export_tree(self.input, output or self.output, source_revision=SOURCE_REVISION,
                           export_date=EXPORT_DATE, **kwargs)

    def assert_manifest(self, directory):
        value = json.loads((directory / "manifest.json").read_text())
        self.assertEqual(value["algorithm"], "sha256")
        for name, record in value["files"].items():
            path = directory / name
            self.assertTrue(path.is_file(), name)
            self.assertEqual(record["sha256"], digest(path.read_bytes()), name)
            self.assertEqual(record["bytes"], path.stat().st_size, name)

    def test_mixed_absolute_paths_normalized_without_altering_measurements(self):
        original = {
            "environment": {
                "binary": str(PureWindowsPath("C:/Users/fixture-user/work/bin/netlab-agent")),
                "linux_binary": str(PurePosixPath("/home/fixture-user/work/bin/netlab-agent")),
                "mounted_binary": "/mnt/c/Users/fixture-user/work/bin/netlab-agent",
                "binary_sha256": BINARY_DIGEST, "kernel": "6.6.0-fixture", "logical_cpus": 4,
            },
            "workload": {"concurrency": 2, "payload": 256},
            "measurements": {"attempts": 40, "successes": 40, "latency_ms": {"p99": 1.234}},
        }
        put_json(self.input / "experiment.json", original)
        manifest(self.input)
        before = {p.name: p.read_bytes() for p in self.input.iterdir()}
        result = self.export()
        self.assertTrue(result["safe"])
        exported = json.loads((self.output / "experiment.json").read_text())
        text = json.dumps(exported)
        self.assertNotIn("fixture-user", text)
        for key in ("binary", "linux_binary", "mounted_binary"):
            value = exported["environment"][key]
            self.assertTrue(PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute())
        self.assertEqual(exported["environment"]["binary_sha256"], BINARY_DIGEST)
        self.assertEqual(exported["measurements"], original["measurements"])
        self.assertEqual(exported["workload"], original["workload"])
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.input.iterdir()})
        self.assert_manifest(self.output)
        self.assertTrue(audit_tree(self.output)["safe"])

    def test_incidental_frr_label_changes_but_logical_protocol_state_does_not(self):
        text = "hostname r1\nhostname fixture-host\nrouter bgp 65001\n bgp router-id 10.77.12.1\n neighbor 10.77.12.2 remote-as 65002\n"
        (self.input / "r1-running-config.txt").write_text(text)
        self.export()
        exported = (self.output / "r1-running-config.txt").read_text()
        self.assertNotIn("fixture-host", exported)
        self.assertIn("hostname r1\n", exported)
        for line in text.splitlines()[2:]:
            self.assertIn(line, exported)

    def test_host_route_pseudonyms_preserve_counts_and_before_after_relationships(self):
        routes = [{"dst": "default", "gateway": "192.168.88.1", "dev": "eth0"},
                  {"dst": "192.168.88.0/24", "prefsrc": "192.168.88.20", "dev": "eth0"},
                  {"dst": "127.0.0.0/8", "prefsrc": "127.0.0.1", "dev": "lo"}]
        original = {"host_state_before": {"routes": json.dumps(routes)},
                    "host_state_after": {"routes": json.dumps(routes)}, "host_state_unchanged": True,
                    "lab_destination": "10.77.3.2", "lab_prefix": "10.77.3.0/24"}
        put_json(self.input / "summary.json", original)
        self.export()
        result = json.loads((self.output / "summary.json").read_text())
        self.assertEqual(result["host_state_before"], result["host_state_after"])
        self.assertTrue(result["host_state_unchanged"])
        self.assertEqual(len(json.loads(result["host_state_before"]["routes"])), len(routes))
        self.assertNotIn("192.168.88.", json.dumps(result))
        self.assertEqual(result["lab_destination"], original["lab_destination"])
        self.assertEqual(result["lab_prefix"], original["lab_prefix"])

    def test_changed_host_route_is_not_made_falsely_equal(self):
        original = {"host_state_before": {"routes": '[{"dst":"default","gateway":"192.168.88.1"}]'},
                    "host_state_after": {"routes": '[{"dst":"default","gateway":"192.168.88.2"}]'},
                    "host_state_unchanged": False}
        put_json(self.input / "summary.json", original)
        self.export()
        result = json.loads((self.output / "summary.json").read_text())
        self.assertNotEqual(result["host_state_before"], result["host_state_after"])
        self.assertFalse(result["host_state_unchanged"])

    def test_synthetic_lab_private_fixtures_and_reserved_contact_are_unchanged(self):
        original = {"destination": "10.77.3.2", "neighbor": "10.77.12.2", "prefix": "10.77.3.0/24",
                    "private_fixture": "10.123.0.0/24", "dns_failure": "missing.lab",
                    "contact": "fixture-user@example.test", "router": "r3"}
        put_json(self.input / "fixture.json", original)
        self.export()
        self.assertEqual(json.loads((self.output / "fixture.json").read_text()), original)

    def test_nested_archives_are_deterministic_and_rebuild_inner_integrity(self):
        raw = json.dumps({"environment": {"binary": "/home/fixture-user/bin/netlab-agent", "binary_sha256": BINARY_DIGEST}}).encode()
        inner_manifest = json.dumps({"schema_version": 1, "algorithm": "sha256", "files": {
            "record.json": {"sha256": digest(raw), "bytes": len(raw)}}}).encode()
        inner = make_tar({"bundle/record.json": raw, "bundle/manifest.json": inner_manifest})
        (self.input / "outer.tar.gz").write_bytes(make_tar({"nested.tar.gz": inner, "note.txt": b"synthetic lab evidence\n"}))
        manifest(self.input)
        first = self.export()
        second_output = self.base / "second"
        second = self.export(second_output)
        self.assertTrue(first["safe"] and second["safe"])
        first_files = {p.relative_to(self.output).as_posix(): p.read_bytes() for p in self.output.rglob("*") if p.is_file()}
        second_files = {p.relative_to(second_output).as_posix(): p.read_bytes() for p in second_output.rglob("*") if p.is_file()}
        self.assertEqual(first_files, second_files)
        outer_bytes = (self.output / "outer.tar.gz").read_bytes()
        self.assertEqual(outer_bytes[3] & 8, 0, "gzip filename metadata must be absent")
        self.assertEqual(outer_bytes[4:8], bytes(4), "gzip timestamp must be normalized")
        outer = members(outer_bytes)
        exported_inner = members(outer["nested.tar.gz"])
        self.assertNotIn(b"fixture-user", exported_inner["bundle/record.json"])
        rebuilt = json.loads(exported_inner["bundle/manifest.json"])
        self.assertEqual(rebuilt["files"]["record.json"]["sha256"], digest(exported_inner["bundle/record.json"]))
        self.assertEqual(rebuilt["files"]["record.json"]["bytes"], len(exported_inner["bundle/record.json"]))
        self.assert_manifest(self.output)
        with tarfile.open(fileobj=io.BytesIO((self.output / "outer.tar.gz").read_bytes()), mode="r:gz") as archive:
            headers = archive.getmembers()
            self.assertEqual([h.name for h in headers], sorted(h.name for h in headers))
            self.assertTrue(all(h.uid == 0 and h.gid == 0 and not h.uname and not h.gname for h in headers))
            self.assertTrue(all(h.mtime == 0 for h in headers))

    def test_provenance_preserves_original_digests_without_identifier_map(self):
        raw = b'{"binary":"/home/fixture-user/bin/netlab-agent","successes":40}\n'
        (self.input / "record.json").write_bytes(raw)
        self.export(provenance_path="provenance/export.json")
        provenance = json.loads((self.output / "provenance/export.json").read_text())
        text = json.dumps(provenance)
        self.assertIn(digest(raw), text)
        self.assertIn(digest((self.output / "record.json").read_bytes()), text)
        self.assertIn(SOURCE_REVISION, text)
        self.assertIn(RULESET, text)
        self.assertNotIn("fixture-user", text)

    def test_audit_reports_categories_and_paths_without_raw_values(self):
        raw = "/home/fixture-user/bin/netlab-agent"
        put_json(self.input / "record.json", {"binary": raw})
        result = audit_tree(self.input)
        self.assertFalse(result["safe"])
        self.assertTrue(result["counts"])
        self.assertTrue(result["findings"])
        report = json.dumps(result)
        self.assertIn("record.json", report)
        self.assertNotIn(raw, report)

    def test_high_risk_token_blocks_export_and_never_appears_in_report(self):
        token = "ghp_" + "x" * 36
        put_json(self.input / "record.json", {"token": token})
        audit = audit_tree(self.input)
        self.assertFalse(audit["safe"])
        self.assertNotIn(token, json.dumps(audit))
        with self.assertRaises(PublicEvidenceError) as caught:
            self.export()
        self.assertNotIn(token, str(caught.exception))
        self.assertFalse(self.output.exists())

    def test_escaped_json_tokens_in_keys_or_values_block_without_double_counts(self):
        token = "ghp_" + "x" * 36
        escaped = "".join("\\u%04x" % ord(character) for character in token)
        cases = ('{"token":"' + escaped + '"}', '{"' + escaped + '":"synthetic"}',
                 json.dumps({"token": token}))
        for index, raw in enumerate(cases):
            (self.input / "record.json").write_text(raw)
            with self.subTest(index=index):
                report = audit_tree(self.input)
                self.assertFalse(report["safe"])
                self.assertEqual(report["counts"].get("github_token"), 1)
                self.assertNotIn(token, json.dumps(report))
                with self.assertRaises(PublicEvidenceError):
                    self.export(self.base / ("escaped-token-%d" % index))

    def test_duplicate_json_members_are_rejected_at_every_nesting_level(self):
        token = "ghp_" + "x" * 36
        escaped = "".join("\\u%04x" % ord(character) for character in token)
        hidden = '"token":"' + escaped + '","token":"synthetic"'
        cases = ['{' + hidden + '}', '{"outer":{' + hidden + '}}',
                 '[{"outer":[{' + hidden + '}]}]',
                 '{"token":"' + escaped + '","\\u0074oken":"synthetic"}',
                 '{"' + escaped + '":0,"' + escaped + '":1}',
                 '{"successes":40,"successes":0}']
        for index, raw in enumerate(cases):
            path = self.input / "record.json"
            path.write_text(raw)
            original = path.read_bytes()
            with self.subTest(index=index):
                for action in (lambda: audit_tree(self.input),
                               lambda: self.export(self.base / ("duplicate-%d" % index))):
                    with self.assertRaises(PublicEvidenceError) as caught:
                        action()
                    self.assertEqual(str(caught.exception), "malformed JSON evidence")
                    self.assertNotIn(token, str(caught.exception))
                    self.assertNotIn(escaped, str(caught.exception))
                self.assertEqual(path.read_bytes(), original)
                self.assertFalse((self.base / ("duplicate-%d" % index)).exists())

    def test_duplicate_json_in_fenced_reports_and_nested_archives_is_refused(self):
        token = "ghp_" + "x" * 36
        escaped = "".join("\\u%04x" % ord(character) for character in token)
        raw = '{"outer":{"token":"' + escaped + '","token":"synthetic"}}'
        path = self.input / "report.md"
        path.write_text("Synthetic report\n\n```json\n" + raw + "\n```\n")
        with self.assertRaises(PublicEvidenceError):
            audit_tree(self.input)
        with self.assertRaises(PublicEvidenceError):
            self.export()
        path.unlink()
        nested = make_tar({"bundle/record.json": raw.encode()})
        archive = make_tar({"inner.tar.gz": nested})
        (self.input / "outer.tar.gz").write_bytes(archive)
        with self.assertRaises(PublicEvidenceError):
            audit_tree(self.input)
        with self.assertRaises(PublicEvidenceError):
            self.export()
        self.assertEqual((self.input / "outer.tar.gz").read_bytes(), archive)

    def test_duplicate_json_cli_failure_does_not_log_hidden_values(self):
        token = "ghp_" + "x" * 36
        escaped = "".join("\\u%04x" % ord(character) for character in token)
        (self.input / "record.json").write_text('{"token":"' + escaped + '","token":"synthetic"}')
        for command in ("audit", "export"):
            arguments = [sys.executable, str(REPOSITORY / "scripts/sanitize_public_evidence.py"),
                         command, "--input", str(self.input)]
            if command == "export":
                arguments += ["--output", str(self.output), "--source-revision", SOURCE_REVISION]
            result = subprocess.run(arguments, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(token, result.stdout + result.stderr)
            self.assertNotIn(escaped, result.stdout + result.stderr)
            self.assertNotIn("Traceback", result.stdout + result.stderr)
        self.assertFalse(self.output.exists())

    def test_escaped_json_account_values_normalize_but_sensitive_keys_are_refused(self):
        account = "/home/fixture-user/private-runtime/netlab-agent"
        escaped = "".join("\\u%04x" % ord(character) for character in account)
        (self.input / "record.json").write_text('{"binary":"' + escaped + '","successes":40}')
        report = audit_tree(self.input)
        self.assertFalse(report["safe"])
        self.assertEqual(report["counts"].get("account_path"), 1)
        self.assertTrue(self.export()["safe"])
        exported = json.loads((self.output / "record.json").read_text())
        self.assertNotIn("fixture-user", exported["binary"])
        self.assertEqual(exported["successes"], 40)
        (self.input / "record.json").write_text('{"' + escaped + '":"synthetic"}')
        report = audit_tree(self.input)
        self.assertFalse(report["safe"])
        self.assertEqual(report["counts"].get("account_path"), 1)
        # Changing dictionary keys can change schema meaning; fail closed.
        with self.assertRaises(PublicEvidenceError):
            self.export(self.base / "escaped-key")

    def test_escaped_json_email_is_checked_and_reserved_contacts_stay_allowed(self):
        # This invented non-reserved domain is assembled only at fixture time.
        personal_shape = "fixture-user@" + "mailbox.fixture"
        escaped = "".join("\\u%04x" % ord(character) for character in personal_shape)
        (self.input / "record.json").write_text('{"contact":"' + escaped + '"}')
        report = audit_tree(self.input)
        self.assertFalse(report["safe"])
        self.assertEqual(report["counts"].get("personal_email"), 1)
        self.assertNotIn(personal_shape, json.dumps(report))
        with self.assertRaises(PublicEvidenceError):
            self.export()
        reserved = "fixture-user@example.test"
        escaped_reserved = "".join("\\u%04x" % ord(character) for character in reserved)
        (self.input / "record.json").write_text('{"contact":"' + escaped_reserved + '"}')
        self.assertTrue(audit_tree(self.input)["safe"])
        self.assertTrue(self.export()["safe"])
        self.assertEqual(json.loads((self.output / "record.json").read_text())["contact"], reserved)

    def test_markdown_json_blocks_decode_before_privacy_checks_and_transform(self):
        token = "ghp_" + "x" * 36
        escaped_token = "".join("\\u%04x" % ord(character) for character in token)
        note = self.input / "report.md"
        note.write_text("Synthetic report\n\n```json\n{\"token\":\"" + escaped_token + "\"}\n```\n")
        report = audit_tree(self.input)
        self.assertFalse(report["safe"])
        self.assertEqual(report["counts"].get("github_token"), 1)
        with self.assertRaises(PublicEvidenceError):
            self.export()
        account = "/home/fixture-user/private-runtime/netlab-agent"
        escaped_account = "".join("\\u%04x" % ord(character) for character in account)
        note.write_text("Synthetic report\n\n```json\n{\"binary\":\"" + escaped_account + "\",\"successes\":40}\n```\n")
        self.assertFalse(audit_tree(self.input)["safe"])
        self.assertTrue(self.export()["safe"])
        text = (self.output / "report.md").read_text()
        value = json.loads(text.split("```json\n", 1)[1].split("```", 1)[0])
        self.assertEqual(value["successes"], 40)
        self.assertNotIn("fixture-user", value["binary"])
        self.assertTrue(text.startswith("Synthetic report\n"))

    def test_secret_shaped_archive_owner_metadata_stops_export(self):
        token = "ghp_" + "x" * 36
        (self.input / "metadata.tar.gz").write_bytes(make_tar({"record.txt": b"synthetic result\n"}, username=token))
        report = audit_tree(self.input)
        self.assertFalse(report["safe"])
        self.assertNotIn(token, json.dumps(report))
        with self.assertRaises(PublicEvidenceError):
            self.export()

    def test_directory_header_and_pax_metadata_are_scanned_before_normalization(self):
        token = "ghp_" + "x" * 36
        for index, location in enumerate(("directory-owner", "pax-comment")):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
                directory = tarfile.TarInfo("bundle")
                directory.type = tarfile.DIRTYPE
                if location == "directory-owner":
                    directory.uname = token
                else:
                    directory.pax_headers = {"comment": token}
                archive.addfile(directory)
                record = tarfile.TarInfo("bundle/record.txt")
                record.size = 4
                archive.addfile(record, io.BytesIO(b"data"))
            (self.input / "metadata.tar.gz").write_bytes(stream.getvalue())
            with self.subTest(location=location), self.assertRaises(PublicEvidenceError):
                self.export(self.base / ("metadata-%d" % index))

    def test_gzip_filename_and_comment_are_scanned_before_normalization(self):
        token = "ghp_" + "x" * 36
        filename = make_tar({"record.txt": b"synthetic result\n"}, filename=token)
        plain = make_tar({"record.txt": b"synthetic result\n"}, filename="")
        comment = plain[:3] + bytes([plain[3] | 0x10]) + plain[4:10] + token.encode() + b"\x00" + plain[10:]
        for index, raw in enumerate((filename, comment)):
            (self.input / "metadata.tar.gz").write_bytes(raw)
            with self.subTest(index=index), self.assertRaises(PublicEvidenceError):
                self.export(self.base / ("gzip-metadata-%d" % index))

    def test_nested_gzip_header_findings_survive_outer_tar_metadata(self):
        token = "ghp_" + "x" * 36
        filename = make_tar({"record.txt": b"synthetic result\n"}, filename=token,
                            username="", uid=0, mtime=0)
        plain = make_tar({"record.txt": b"synthetic result\n"}, filename="",
                         username="", uid=0, mtime=0)
        comment = plain[:3] + bytes([plain[3] | 0x10]) + plain[4:10] + token.encode() + b"\x00" + plain[10:]
        for index, nested in enumerate((filename, comment)):
            # Ordinary, clean outer member metadata must not replace findings
            # already discovered in the nested gzip header.
            outer = make_tar({"nested.tar.gz": nested}, username="", uid=0, mtime=0, filename="")
            (self.input / "outer.tar.gz").write_bytes(outer)
            with self.subTest(index=index):
                report = audit_tree(self.input)
                self.assertFalse(report["safe"])
                self.assertGreater(report["counts"].get("github_token", 0), 0)
                self.assertNotIn(token, json.dumps(report))
                with self.assertRaises(PublicEvidenceError):
                    self.export(self.base / ("nested-header-%d" % index))

    def test_discovered_host_label_in_ordinary_text_prevents_publication(self):
        (self.input / "config.txt").write_text("hostname r1\nhostname fixture-host\n")
        (self.input / "notes.txt").write_text("Observed service on fixture-host during the synthetic run.\n")
        report = audit_tree(self.input)
        self.assertFalse(report["safe"])
        self.assertGreater(report["counts"].get("host_label_reference", 0), 0)
        with self.assertRaises(PublicEvidenceError):
            self.export()
        self.assertFalse(self.output.exists())

    def test_discovered_host_label_in_filename_is_redacted_in_reports(self):
        (self.input / "config.txt").write_text("hostname fixture-host\n")
        for index, filename in enumerate(("fixture-host.txt", "fixture-host-diagnostic.txt", "fixture-host_diagnostic.txt")):
            path = self.input / filename
            path.write_text("synthetic result\n")
            try:
                with self.subTest(filename=filename):
                    report = audit_tree(self.input)
                    self.assertFalse(report["safe"])
                    self.assertGreater(report["counts"].get("identifier_in_filename", 0), 0)
                    self.assertNotIn("fixture-host", json.dumps(report))
                    output = self.base / ("host-filename-%d" % index)
                    with self.assertRaises(PublicEvidenceError):
                        self.export(output)
                    self.assertFalse(output.exists())
            finally:
                path.unlink()

    def test_concatenated_gzip_and_nonzero_trailing_tar_data_are_rejected(self):
        first = make_tar({"first.txt": b"synthetic first\n"}, filename="", username="", uid=0, mtime=0)
        second = make_tar({"second.txt": b"synthetic second\n"}, filename="", username="", uid=0, mtime=0)
        tar_with_tail = gzip.compress(gzip.decompress(first) + b"unindexed trailing data", mtime=0)
        for index, raw in enumerate((first + second, first + b"unindexed gzip tail", tar_with_tail)):
            (self.input / "ambiguous.tar.gz").write_bytes(raw)
            with self.subTest(index=index), self.assertRaises(PublicEvidenceError):
                self.export(self.base / ("ambiguous-%d" % index))

    def test_nonzero_file_padding_is_refused_before_publication(self):
        token = ("ghp_" + "x" * 36).encode()
        clean = make_tar({"record.txt": b"short"}, filename="", username="", uid=0, mtime=0)
        self.assertEqual(members(clean), {"record.txt": b"short"})
        for index, hidden in enumerate((token, b"unindexed ordinary bytes")):
            raw = bytearray(gzip.decompress(clean))
            raw[512 + 5:512 + 5 + len(hidden)] = hidden
            archive = gzip.compress(bytes(raw), mtime=0)
            path = self.input / "padding.tar.gz"
            path.write_bytes(archive)
            with self.subTest(index=index):
                for action in (lambda: audit_tree(self.input),
                               lambda: self.export(self.base / ("padding-%d" % index))):
                    with self.assertRaisesRegex(PublicEvidenceError, "archive member padding") as caught:
                        action()
                    self.assertNotIn(hidden.decode(), str(caught.exception))
                self.assertEqual(path.read_bytes(), archive)
                self.assertFalse((self.base / ("padding-%d" % index)).exists())

    def test_unused_header_bytes_are_refused_after_a_valid_checksum(self):
        clean = make_tar({"record.txt": b"synthetic"}, filename="", username="", uid=0, mtime=0)
        self.assertEqual(members(clean), {"record.txt": b"synthetic"})
        cases = ((20, ("ghp_" + "x" * 36).encode()), (500, b"unused-data"))
        for index, (offset, hidden) in enumerate(cases):
            raw = bytearray(gzip.decompress(clean))
            raw[offset:offset + len(hidden)] = hidden
            raw[148:156] = b" " * 8
            raw[148:156] = ("%06o\0 " % sum(raw[:512])).encode("ascii")
            archive = gzip.compress(bytes(raw), mtime=0)
            (self.input / "header.tar.gz").write_bytes(archive)
            with self.subTest(index=index), self.assertRaises(PublicEvidenceError) as caught:
                self.export(self.base / ("header-%d" % index))
            self.assertNotIn(hidden.decode(), str(caught.exception))

    def test_pax_extension_padding_is_not_ignored(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
            entry = tarfile.TarInfo("record.txt")
            entry.pax_headers = {"comment": "synthetic metadata"}
            entry.size = 4
            archive.addfile(entry, io.BytesIO(b"data"))
        pristine = stream.getvalue()
        self.assertEqual(members(gzip.compress(pristine, mtime=0)), {"record.txt": b"data"})
        raw = bytearray(pristine)
        header = tarfile.TarInfo.frombuf(bytes(raw[:512]), "utf-8", "strict")
        self.assertEqual(header.type, tarfile.XHDTYPE)
        size = header.size
        token = ("ghp_" + "x" * 36).encode()
        self.assertGreater(size, 0)
        self.assertLessEqual(size + len(token), tarfile.BLOCKSIZE)
        self.assertEqual(raw[512 + size:1024], bytes(512 - size))
        raw[512 + size:512 + size + len(token)] = token
        payload = gzip.compress(bytes(raw), mtime=0)
        # Some Python patch releases reject this malformed padding themselves.
        # Our publication boundary must reject it on every supported release.
        (self.input / "pax-padding.tar.gz").write_bytes(payload)
        with self.assertRaisesRegex(PublicEvidenceError, "archive member padding"):
            audit_tree(self.input)
        with self.assertRaisesRegex(PublicEvidenceError, "archive member padding"):
            self.export()

    def test_ambiguous_or_unconsumed_pax_records_are_refused(self):
        def pax_record(key, value):
            body = key + b"=" + value + b"\n"
            size = len(body) + 2
            while True:
                result = str(size).encode() + b" " + body
                if len(result) == size:
                    return result
                size = len(result)

        cases = (pax_record(b"comment", b"first") + pax_record(b"comment", b"second"),
                 pax_record(b"comment", b"synthetic") + b"unconsumed metadata")
        for index, payload in enumerate(cases):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as archive:
                info = tarfile.TarInfo("pax")
                info.type, info.size = tarfile.XHDTYPE, len(payload)
                archive.addfile(info, io.BytesIO(payload))
                info = tarfile.TarInfo("record.txt")
                info.size = 4
                archive.addfile(info, io.BytesIO(b"data"))
            (self.input / "pax.tar.gz").write_bytes(gzip.compress(stream.getvalue(), mtime=0))
            with self.subTest(index=index), self.assertRaises(PublicEvidenceError):
                self.export(self.base / ("pax-%d" % index))

    def test_supported_pax_and_gnu_long_names_keep_members_and_empty_directories(self):
        name = "bundle/" + "nested-" * 20 + "/record.txt"
        for index, archive_format in enumerate((tarfile.PAX_FORMAT, tarfile.GNU_FORMAT)):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w", format=archive_format) as archive:
                directory = tarfile.TarInfo("empty")
                directory.type = tarfile.DIRTYPE
                archive.addfile(directory)
                info = tarfile.TarInfo(name)
                info.size = 4
                archive.addfile(info, io.BytesIO(b"data"))
            original = gzip.compress(stream.getvalue(), mtime=0)
            (self.input / "long.tar.gz").write_bytes(original)
            output = self.base / ("long-%d" % index)
            with self.subTest(format_index=index):
                self.assertTrue(self.export(output)["safe"])
                self.assertEqual(members((output / "long.tar.gz").read_bytes()), {name: b"data"})
                with tarfile.open(output / "long.tar.gz", mode="r:gz") as archive:
                    self.assertTrue(archive.getmember("empty").isdir())
                self.assertEqual((self.input / "long.tar.gz").read_bytes(), original)

    def test_pax_size_override_controls_physical_payload_boundaries(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
            info = tarfile.TarInfo("record.txt")
            info.pax_headers = {"size": "4"}
            info.size = 4
            archive.addfile(info, io.BytesIO(b"data"))
        raw = bytearray(stream.getvalue())
        extension_size = tarfile.TarInfo.frombuf(bytes(raw[:512]), "utf-8", "strict").size
        record_offset = 512 + ((extension_size + 511) // 512) * 512
        # POSIX PAX may override the following header's size. The payload still
        # occupies four bytes even when that legacy numeric field says zero.
        raw[record_offset + 124:record_offset + 136] = b"00000000000\0"
        raw[record_offset + 148:record_offset + 156] = b" " * 8
        checksum = sum(raw[record_offset:record_offset + 512])
        raw[record_offset + 148:record_offset + 156] = ("%06o\0 " % checksum).encode("ascii")
        original = gzip.compress(bytes(raw), mtime=0)
        self.assertEqual(members(original), {"record.txt": b"data"})
        (self.input / "pax-size.tar.gz").write_bytes(original)
        self.assertTrue(self.export()["safe"])
        self.assertEqual(members((self.output / "pax-size.tar.gz").read_bytes()), {"record.txt": b"data"})
        self.assertEqual((self.input / "pax-size.tar.gz").read_bytes(), original)

    def test_empty_tar_directories_are_preserved_with_normalized_metadata(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            for name in ("empty/", "empty/nested/"):
                entry = tarfile.TarInfo(name)
                entry.type, entry.mode = tarfile.DIRTYPE, 0o750
                entry.uid = entry.gid = 1234
                entry.uname = entry.gname = "fixture-user"
                entry.mtime = 123456789
                archive.addfile(entry)
        (self.input / "empty.tar.gz").write_bytes(stream.getvalue())
        self.assertTrue(self.export()["safe"])
        with tarfile.open(self.output / "empty.tar.gz", mode="r:gz") as archive:
            exported = archive.getmembers()
            self.assertEqual({entry.name.rstrip("/") for entry in exported}, {"empty", "empty/nested"})
            self.assertTrue(all(entry.isdir() for entry in exported))
            self.assertTrue(all(entry.mode == 0o755 and entry.uid == 0 and entry.gid == 0
                                and not entry.uname and not entry.gname and entry.mtime == 0
                                for entry in exported))
        self.assertTrue(audit_tree(self.output)["safe"])

    def test_tar_file_directory_path_conflicts_are_rejected(self):
        conflict = make_tar({"branch": b"file", "branch/child.txt": b"child"})
        (self.input / "conflict.tar.gz").write_bytes(conflict)
        with self.assertRaises(PublicEvidenceError):
            self.export()
        self.assertFalse(self.output.exists())
        # Explicitly reusing one path for a file and a directory is also unsafe.
        for index, directory_first in enumerate((False, True)):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w:gz") as archive:
                for is_directory in (directory_first, not directory_first):
                    entry = tarfile.TarInfo("branch")
                    if is_directory:
                        entry.type = tarfile.DIRTYPE
                        archive.addfile(entry)
                    else:
                        entry.size = 4
                        archive.addfile(entry, io.BytesIO(b"file"))
            (self.input / "conflict.tar.gz").write_bytes(stream.getvalue())
            with self.subTest(directory_first=directory_first), self.assertRaises(PublicEvidenceError):
                self.export(self.base / ("duplicate-path-%d" % index))

    def test_unused_linkname_on_regular_or_directory_tar_members_is_rejected(self):
        for index, kind in enumerate((tarfile.REGTYPE, tarfile.DIRTYPE)):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w:gz") as archive:
                entry = tarfile.TarInfo("record.txt" if kind == tarfile.REGTYPE else "empty")
                entry.type = kind
                entry.linkname = "/home/fixture-user/private-runtime"
                if kind == tarfile.REGTYPE:
                    entry.size = 4
                    archive.addfile(entry, io.BytesIO(b"data"))
                else:
                    archive.addfile(entry)
            (self.input / "unused-link.tar.gz").write_bytes(stream.getvalue())
            with self.subTest(kind_index=index), self.assertRaises(PublicEvidenceError):
                self.export(self.base / ("unused-link-%d" % index))

    def test_sparse_tar_members_are_not_silently_converted_to_ordinary_files(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.GNU_FORMAT) as archive:
            entry = tarfile.TarInfo("sparse.bin")
            entry.type = tarfile.GNUTYPE_SPARSE
            entry.size = 4
            archive.addfile(entry, io.BytesIO(b"data"))
        (self.input / "sparse.tar.gz").write_bytes(stream.getvalue())
        with self.assertRaises(PublicEvidenceError):
            self.export()

    def test_clean_pcap_is_byte_identical_and_sensitive_payload_aborts(self):
        clean = synthetic_pcap()
        (self.input / "gateway.pcap0").write_bytes(clean)
        self.export()
        self.assertEqual((self.output / "gateway.pcap0").read_bytes(), clean)
        token = ("ghp_" + "x" * 36).encode()
        (self.input / "gateway.pcap0").write_bytes(synthetic_pcap(token))
        audit = audit_tree(self.input)
        self.assertFalse(audit["safe"])
        self.assertNotIn(token.decode(), json.dumps(audit))
        with self.assertRaises(PublicEvidenceError):
            self.export(self.base / "unsafe")
        self.assertFalse((self.base / "unsafe").exists())

    def test_packet_account_path_and_binary_secret_are_not_blindly_rewritten(self):
        path_payload = b"/home/fixture-user/private-runtime/netlab-agent"
        (self.input / "gateway.pcap0").write_bytes(synthetic_pcap(path_payload))
        with self.assertRaises(PublicEvidenceError):
            self.export()
        (self.input / "gateway.pcap0").unlink()
        token = ("ghp_" + "x" * 36).encode()
        (self.input / "unknown.bin").write_bytes(b"\x00\xff" + token + b"\x00\xfe")
        self.assertFalse(audit_tree(self.input)["safe"])
        with self.assertRaises(PublicEvidenceError):
            self.export()

    def test_utf16_packet_tokens_and_account_paths_block_at_both_byte_alignments(self):
        token = "ghp_" + "x" * 36
        account = "/home/fixture-user/private-runtime/netlab-agent"
        index = 0
        for encoding in ("utf-16-le", "utf-16-be"):
            for alignment in (0, 1):
                for value in (token, account):
                    raw = synthetic_pcap(bytes([255]) * alignment + value.encode(encoding))
                    packet = self.input / "gateway.pcap0"
                    packet.write_bytes(raw)
                    with self.subTest(encoding=encoding, alignment=alignment, value_kind="token" if value == token else "path"):
                        report = audit_tree(self.input)
                        self.assertFalse(report["safe"])
                        self.assertNotIn(value, json.dumps(report))
                        with self.assertRaises(PublicEvidenceError):
                            self.export(self.base / ("utf16-packet-%d" % index))
                        self.assertEqual(packet.read_bytes(), raw)
                    index += 1

    def test_non_ascii_packet_byte_delimiters_do_not_hide_ascii_tokens(self):
        token = ("ghp_" + "x" * 36).encode()
        for index, prefix in enumerate((b"\xff", b"\x80", b"\xfe")):
            (self.input / "gateway.pcap0").write_bytes(synthetic_pcap(prefix + token + b"\xff"))
            with self.subTest(prefix_index=index):
                self.assertFalse(audit_tree(self.input)["safe"])
                with self.assertRaises(PublicEvidenceError):
                    self.export(self.base / ("binary-delimiter-%d" % index))

    def test_non_ascii_delimiters_do_not_hide_packet_email_shapes(self):
        personal_shape = "fixture-user".replace("-", "") + "@" + "mailbox.fixture"
        payloads = (b"\xff" + personal_shape.encode(), b"\xff" + personal_shape.encode("utf-16-be"))
        for index, payload in enumerate(payloads):
            (self.input / "gateway.pcap0").write_bytes(synthetic_pcap(payload))
            with self.subTest(index=index):
                report = audit_tree(self.input)
                self.assertFalse(report["safe"])
                self.assertNotIn(personal_shape, json.dumps(report))
                with self.assertRaises(PublicEvidenceError):
                    self.export(self.base / ("email-delimiter-%d" % index))

    def test_corrupt_json_or_archive_is_not_silently_published(self):
        for name, raw in (("record.json", b"{broken"), ("broken.tar.gz", b"not an archive")):
            with self.subTest(name=name):
                target = self.input / name
                target.write_bytes(raw)
                with self.assertRaises(PublicEvidenceError):
                    self.export(self.base / ("out-" + name))
                target.unlink()

    def test_invalid_manifest_hash_bytes_or_membership_stops_export(self):
        (self.input / "record.txt").write_text("synthetic result\n")
        manifest(self.input)
        original = json.loads((self.input / "manifest.json").read_text())
        invalid = []
        changed = json.loads(json.dumps(original)); changed["files"]["record.txt"]["sha256"] = "0" * 64; invalid.append(changed)
        changed = json.loads(json.dumps(original)); changed["files"]["record.txt"]["bytes"] += 1; invalid.append(changed)
        changed = json.loads(json.dumps(original)); changed["files"]["missing.txt"] = dict(changed["files"]["record.txt"]); invalid.append(changed)
        changed = json.loads(json.dumps(original)); changed["files"] = {}; invalid.append(changed)
        for index, changed in enumerate(invalid):
            with self.subTest(index=index):
                put_json(self.input / "manifest.json", changed)
                with self.assertRaises(PublicEvidenceError):
                    self.export(self.base / ("invalid-%d" % index))

    def test_original_checksum_list_is_verified_and_export_list_rebuilt(self):
        raw = b'{"binary":"/home/fixture-user/bin/netlab-agent"}\n'
        (self.input / "record.json").write_bytes(raw)
        (self.input / "SHA256SUMS").write_text(digest(raw) + "  record.json\n")
        self.export()
        new = (self.output / "record.json").read_bytes()
        self.assertIn(digest(new), (self.output / "SHA256SUMS").read_text())
        self.assertNotEqual(digest(raw), digest(new))
        (self.input / "SHA256SUMS").write_text("0" * 64 + "  record.json\n")
        with self.assertRaises(PublicEvidenceError):
            self.export(self.base / "bad-sums")

    def test_manifest_and_checksum_dependencies_are_rebuilt_before_their_owners(self):
        bundle = self.input / "bundle"
        nested = bundle / "nested"
        put_json(nested / "record.json", {"binary": "/home/fixture-user/bin/netlab-agent", "successes": 40})
        record = (nested / "record.json").read_bytes()
        (nested / "SHA256SUMS").write_text(digest(record) + "  record.json\n")
        manifest(nested)
        (bundle / "SHA256SUMS").write_text(digest((nested / "manifest.json").read_bytes()) + "  nested/manifest.json\n")
        manifest(bundle)
        (self.input / "SHA256SUMS").write_text(digest((bundle / "manifest.json").read_bytes()) + "  bundle/manifest.json\n")
        manifest(self.input)
        originals = {p.relative_to(self.input).as_posix(): p.read_bytes() for p in self.input.rglob("*") if p.is_file()}
        self.assertTrue(audit_tree(self.input)["manifests_verified"] == 3)
        self.assertTrue(self.export(provenance_path="bundle/export.json")["safe"])
        for directory in (self.output, self.output / "bundle", self.output / "bundle/nested"):
            self.assert_manifest(directory)
        self.assertEqual(audit_tree(self.output)["manifests_verified"], 3)
        provenance = json.loads((self.output / "bundle/export.json").read_text())
        paths = {item["path"] for item in provenance["transformed_artifacts"]}
        self.assertNotIn("manifest.json", paths)
        self.assertNotIn("bundle/manifest.json", paths)
        self.assertIn("bundle/nested/manifest.json", paths)
        self.assertIn("bundle/nested/SHA256SUMS", paths)
        for item in provenance["transformed_artifacts"]:
            self.assertEqual(item["input_sha256"], digest(originals[item["path"]]))
            self.assertEqual(item["output_sha256"], digest((self.output / item["path"]).read_bytes()))
        self.assertEqual(originals, {p.relative_to(self.input).as_posix(): p.read_bytes() for p in self.input.rglob("*") if p.is_file()})

    def test_nested_archive_integrity_indexes_are_deterministic_and_provenance_is_final(self):
        source = self.base / "bundle-source"
        put_json(source / "nested/record.json", {"binary": "/home/fixture-user/bin/netlab-agent", "successes": 40})
        record = (source / "nested/record.json").read_bytes()
        (source / "nested/SHA256SUMS").write_text(digest(record) + "  record.json\n")
        manifest(source / "nested")
        (source / "SHA256SUMS").write_text(digest((source / "nested/manifest.json").read_bytes()) + "  nested/manifest.json\n")
        manifest(source)
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            empty = tarfile.TarInfo("bundle/empty")
            empty.type = tarfile.DIRTYPE
            archive.addfile(empty)
            for path in sorted(source.rglob("*")):
                if path.is_file():
                    payload = path.read_bytes()
                    info = tarfile.TarInfo("bundle/" + path.relative_to(source).as_posix())
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
        inner = gzip.compress(stream.getvalue(), mtime=0)
        outer = make_tar({"nested.tar.gz": inner}, filename="", username="", uid=0, mtime=0)
        (self.input / "outer.tar.gz").write_bytes(outer)
        (self.input / "SHA256SUMS").write_text(digest(outer) + "  outer.tar.gz\n")
        manifest(self.input)
        original = {p.name: p.read_bytes() for p in self.input.iterdir()}
        first = self.export()
        second_output = self.base / "second-export"
        self.assertTrue(first["safe"] and self.export(second_output)["safe"])
        self.assertEqual({p.name: p.read_bytes() for p in self.output.iterdir()},
                         {p.name: p.read_bytes() for p in second_output.iterdir()})
        self.assertEqual(audit_tree(self.output)["manifests_verified"], 3)
        self.assert_manifest(self.output)
        provenance = json.loads((self.output / "sanitization-manifest.json").read_text())
        self.assertIn("outer.tar.gz!nested.tar.gz!bundle/nested/SHA256SUMS",
                      {item["path"] for item in provenance["transformed_artifacts"]})
        for item in provenance["transformed_artifacts"]:
            parts = item["path"].split("!")
            before, after = original[parts[0]], (self.output / parts[0]).read_bytes()
            for part in parts[1:]:
                before, after = members(before)[part], members(after)[part]
            self.assertEqual(item["input_sha256"], digest(before))
            self.assertEqual(item["output_sha256"], digest(after))
        nested_bytes = members((self.output / "outer.tar.gz").read_bytes())["nested.tar.gz"]
        with tarfile.open(fileobj=io.BytesIO(nested_bytes), mode="r:gz") as archive:
            self.assertTrue(archive.getmember("bundle/empty").isdir())
        self.assertEqual(original, {p.name: p.read_bytes() for p in self.input.iterdir()})

    def test_impossible_integrity_cycles_are_refused_before_mutation(self):
        first = ("0" * 64 + "  second-SHA256SUMS\n").encode()
        second = ("0" * 64 + "  first-SHA256SUMS\n").encode()
        entries = {"first-SHA256SUMS": Entry(first, original=first),
                   "second-SHA256SUMS": Entry(second, original=second)}
        with self.assertRaisesRegex(PublicEvidenceError, "cyclic integrity"):
            _rebuild_integrity(entries)
        self.assertEqual(entries["first-SHA256SUMS"].data, first)
        self.assertEqual(entries["second-SHA256SUMS"].data, second)
        (self.input / "record.txt").write_text("synthetic evidence\n")
        for index, path in enumerate(("manifest.json", "SHA256SUMS", "nested/SHA256SUMS")):
            output = self.base / ("cycle-%d" % index)
            with self.subTest(path=path), self.assertRaises(PublicEvidenceError):
                self.export(output, provenance_path=path)
            self.assertFalse(output.exists())

    def test_archive_provenance_separator_cannot_be_an_artifact_filename(self):
        raw = b'{"binary":"/home/fixture-user/bin/netlab-agent"}\n'
        path = self.input / "ambiguous!record.json"
        path.write_bytes(raw)
        with self.assertRaises(PublicEvidenceError):
            self.export()
        self.assertEqual(path.read_bytes(), raw)
        self.assertFalse(self.output.exists())

    def test_missing_inputs_and_existing_or_overlapping_outputs_are_refused(self):
        with self.assertRaises(PublicEvidenceError):
            export_tree(self.base / "absent", self.output, source_revision=SOURCE_REVISION)
        (self.input / "record.txt").write_text("synthetic evidence")
        self.output.mkdir()
        (self.output / "sentinel").write_text("preserve")
        for output in (self.input, self.output, self.input / "nested", self.base):
            with self.subTest(output=output.name), self.assertRaises(PublicEvidenceError):
                self.export(output)
        self.assertEqual((self.output / "sentinel").read_text(), "preserve")

    def test_normalized_dotdot_paths_cannot_export_into_the_input(self):
        original = b"synthetic original evidence\n"
        (self.input / "record.txt").write_bytes(original)
        outside = self.base / "outside"
        outside.mkdir()
        disguised_output = outside / ".." / "input" / "public-copy"
        with self.assertRaises(PublicEvidenceError):
            self.export(disguised_output)
        with self.assertRaises(PublicEvidenceError):
            export_tree(outside / ".." / "input", self.input / "another-copy",
                        source_revision=SOURCE_REVISION)
        self.assertEqual((self.input / "record.txt").read_bytes(), original)
        self.assertEqual({path.name for path in self.input.iterdir()}, {"record.txt"})

    def test_provenance_paths_cannot_escape_or_replace_input_members(self):
        (self.input / "record.txt").write_text("synthetic evidence\n")
        for index, path in enumerate(("../escape.json", "/absolute.json", "record.txt")):
            with self.subTest(path=path), self.assertRaises(PublicEvidenceError):
                self.export(self.base / ("bad-provenance-%d" % index), provenance_path=path)
        self.assertFalse((self.base / "escape.json").exists())

    def test_symlinks_and_tar_traversal_or_links_are_refused(self):
        outside = self.base / "outside.txt"; outside.write_text("preserve")
        link = self.input / "link.txt"
        try:
            link.symlink_to(outside)
        except OSError:
            pass
        else:
            with self.assertRaises(PublicEvidenceError):
                self.export()
            link.unlink()
        for index, kind in enumerate(("../escape.txt", "/absolute.txt", "symlink")):
            archive_bytes = io.BytesIO()
            with tarfile.open(fileobj=archive_bytes, mode="w:gz") as archive:
                entry = tarfile.TarInfo(kind)
                if kind == "symlink":
                    entry.type, entry.linkname = tarfile.SYMTYPE, "../outside.txt"
                    archive.addfile(entry)
                else:
                    entry.size = 4
                    archive.addfile(entry, io.BytesIO(b"data"))
            path = self.input / "unsafe.tar.gz"; path.write_bytes(archive_bytes.getvalue())
            with self.subTest(kind=kind), self.assertRaises(PublicEvidenceError):
                self.export(self.base / ("unsafe-%d" % index))
            path.unlink()
        self.assertEqual(outside.read_text(), "preserve")

    def test_input_and_output_symlink_ancestry_is_not_followed(self):
        (self.input / "record.txt").write_text("synthetic evidence\n")
        other = self.base / "other"; other.mkdir()
        alias = self.base / "alias"
        input_alias = self.base / "input-alias"
        try:
            alias.symlink_to(other, target_is_directory=True)
            input_alias.symlink_to(self.input, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaises(PublicEvidenceError):
            self.export(alias / "public")
        with self.assertRaises(PublicEvidenceError):
            export_tree(input_alias, self.output, source_revision=SOURCE_REVISION)
        self.assertFalse((other / "public").exists())

    @unittest.skipUnless(shutil.which("git"), "Git required for tracked-file audit")
    def test_repository_gate_checks_tracked_files_without_private_untracked_outputs(self):
        subprocess.run(["git", "init", "--quiet", str(self.input)], check=True, capture_output=True)
        (self.input / "README.md").write_text("Synthetic network lab evidence.\n")
        subprocess.run(["git", "-C", str(self.input), "add", "README.md"], check=True, capture_output=True)
        (self.input / "private.txt").write_text("ghp_" + "x" * 36)
        self.assertTrue(audit_repository(self.input)["safe"])
        subprocess.run(["git", "-C", str(self.input), "add", "private.txt"], check=True, capture_output=True)
        self.assertFalse(audit_repository(self.input)["safe"])

    @unittest.skipUnless(shutil.which("git"), "Git required for tracked-file audit")
    def test_test_fixture_allowance_does_not_exempt_secrets_or_other_accounts(self):
        subprocess.run(["git", "init", "--quiet", str(self.input)], check=True, capture_output=True)
        source = self.input / "tests/test_public_evidence.py"
        source.parent.mkdir()
        for value in ("ghp_" + "x" * 36, "/home/" + "unexpected-account/private-runtime"):
            source.write_text("fixture = " + repr(value) + "\n")
            subprocess.run(["git", "-C", str(self.input), "add", "tests/test_public_evidence.py"], check=True, capture_output=True)
            self.assertFalse(audit_repository(self.input)["safe"])

    def test_cli_failure_does_not_echo_input_values_or_traceback(self):
        missing = self.base / "fixture-user-absent"
        result = subprocess.run([sys.executable, str(REPOSITORY / "scripts/sanitize_public_evidence.py"),
                                 "export", "--input", str(missing), "--output", str(self.output),
                                 "--source-revision", SOURCE_REVISION], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(str(missing), result.stdout + result.stderr)
        self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_cli_unexpected_errors_and_invalid_argv_do_not_disclose_values(self):
        from scripts import sanitize_public_evidence as cli
        sensitive = "/home/fixture-user/private-input"
        output = io.StringIO()
        with patch.object(cli, "audit_tree", side_effect=RuntimeError(sensitive)), redirect_stderr(output):
            result = cli.main(["audit", "--input", sensitive])
        self.assertEqual(result, 1)
        self.assertNotIn(sensitive, output.getvalue())
        output = io.StringIO()
        with redirect_stderr(output), self.assertRaises(SystemExit) as stopped:
            cli.main(["audit", "--input", "safe-input", sensitive])
        self.assertEqual(stopped.exception.code, 2)
        self.assertNotIn(sensitive, output.getvalue())

    def test_cli_audit_report_is_structured_and_export_does_not_overwrite(self):
        put_json(self.input / "record.json", {"binary": "/home/fixture-user/bin/netlab-agent"})
        report = self.base / "audit.json"
        result = subprocess.run([sys.executable, str(REPOSITORY / "scripts/sanitize_public_evidence.py"),
                                 "audit", "--input", str(self.input), "--report", str(report)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout), json.loads(report.read_text()))
        self.assertNotIn("fixture-user", result.stdout)
        self.output.mkdir(); (self.output / "sentinel").write_text("preserve")
        refused = subprocess.run([sys.executable, str(REPOSITORY / "scripts/sanitize_public_evidence.py"),
                                  "export", "--input", str(self.input), "--output", str(self.output),
                                  "--source-revision", SOURCE_REVISION], text=True, capture_output=True)
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual((self.output / "sentinel").read_text(), "preserve")

    def test_workflow_uploads_only_after_public_export_and_audit(self):
        workflow = (REPOSITORY / ".github/workflows/validate.yml").read_text()
        self.assertIn("make test", workflow)
        self.assertIn("scripts/bootstrap-linux.sh", workflow)
        self.assertIn("make build", workflow)
        self.assertIn("scripts/integration.py --output results/private-ci", workflow)
        self.assertIn("audit --repository .", workflow)
        self.assertIn("audit --input results/public-ci", workflow)
        uploader = workflow.split("uses: actions/upload-artifact@v7", 1)[1]
        self.assertIn("path: results/public-ci/", uploader)
        self.assertIn("steps.public-export.outcome == 'success'", uploader)
        self.assertIn("steps.public-audit.outcome == 'success'", uploader)
        self.assertNotIn("path: results/private-ci", uploader)
        self.assertNotIn("path: results/\n", uploader)


if __name__ == "__main__":
    unittest.main()
