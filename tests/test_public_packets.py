import ipaddress
import struct
import unittest
from unittest.mock import patch

from netlab.public_packets import inspect_pcap, iter_pcap_payloads


def ipv4(payload=b"hello", *, protocol=17, source="10.77.1.2", destination="10.77.1.1", padding=b""):
    if protocol == 17:
        transport = struct.pack("!HHHH", 20000, 18080, 8 + len(payload), 0) + payload
    else:
        transport = struct.pack("!HHIIBBHHH", 20000, 18080, 0, 0, 0x50, 0x18, 4096, 0, 0) + payload
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 0, 0, 64, protocol, 0,
                         ipaddress.IPv4Address(source).packed, ipaddress.IPv4Address(destination).packed)
    return header + transport + padding


def frame(network, *, linktype=1, protocol=0x0800):
    address = bytes.fromhex("020000000001")
    if linktype == 1:
        return address + address + struct.pack("!H", protocol) + network
    if linktype == 113:
        return struct.pack("!HHH8sH", 0, 1, 6, address + b"\0\0", protocol) + network
    if linktype == 276:
        return struct.pack("!HHIHBB8s", protocol, 0, 2, 1, 0, 6, address + b"\0\0") + network
    raise ValueError("test linktype")


def capture(*frames, linktype=1, endian="<", original_lengths=None, nanosecond=False):
    magic = 0xA1B23C4D if nanosecond else 0xA1B2C3D4
    result = struct.pack(endian + "IHHiiII", magic, 2, 4, 0, 0, 65535, linktype)
    originals = original_lengths or [len(item) for item in frames]
    for packet, original in zip(frames, originals):
        result += struct.pack(endian + "4I", 0, 0, len(packet), original) + packet
    return result


class PublicPacketTests(unittest.TestCase):
    def test_classic_endianness_linktypes_and_timestamp_resolutions(self):
        for linktype in (1, 113, 276):
            for endian in ("<", ">"):
                for nano in (False, True):
                    with self.subTest(linktype=linktype, endian=endian, nano=nano):
                        packet = frame(ipv4(), linktype=linktype)
                        result = inspect_pcap(capture(packet, linktype=linktype, endian=endian, nanosecond=nano))
                        self.assertEqual(result["records"], 1)
                        self.assertEqual(result["payload_bytes"], 5)
                        self.assertEqual(result["addresses_checked"], 2)
                        self.assertEqual(result["findings"], [])

    def test_detector_sees_application_bytes_padding_and_complete_stored_frames(self):
        payload = b"/home/fixture-user/private.txt secret-fixture-value"
        padding = b"C:\\Users\\fixture-user\\tail.txt"
        packet = frame(ipv4(payload, protocol=6, padding=padding))
        seen = []

        def detector(value):
            seen.append(value)
            return ["fixture_path"] if b"fixture-user" in value else []

        data = capture(packet)
        result = inspect_pcap(data, detector)
        self.assertEqual(seen, [packet])
        self.assertEqual(list(iter_pcap_payloads(data)), [packet])
        self.assertEqual(result["payload_bytes"], len(payload))
        self.assertEqual(result["findings"], [{"category": "fixture_path", "count": 1, "severity": "high"}])
        self.assertNotIn("fixture-user", str(result))

    def test_non_lab_endpoints_are_high_severity_without_echoing_addresses(self):
        result = inspect_pcap(capture(frame(ipv4(source="192.0.2.10", destination="198.51.100.5"))))
        self.assertIn({"category": "non_lab_packet_endpoint", "count": 2, "severity": "high"}, result["findings"])
        self.assertNotIn("192.0.2.10", str(result))

    def test_lab_router_and_loopback_addresses_are_expected(self):
        for source in ("10.77.3.2", "10.255.0.1", "127.0.0.1", "0.0.0.0"):
            self.assertEqual(inspect_pcap(capture(frame(ipv4(source=source))))["findings"], [])

    def test_ipv6_udp_and_kernel_scope(self):
        payload = b"synthetic"
        udp = struct.pack("!HHHH", 10, 20, 8 + len(payload), 0) + payload
        header = struct.pack("!IHBB16s16s", 6 << 28, len(udp), 17, 64,
                             ipaddress.IPv6Address("fe80::1").packed, ipaddress.IPv6Address("ff02::1").packed)
        result = inspect_pcap(capture(frame(header + udp, protocol=0x86DD)))
        self.assertEqual(result["payload_bytes"], len(payload))
        self.assertEqual(result["findings"], [])

    def test_ipv6_extensions_are_bounded_and_fragments_are_not_reassembled(self):
        udp = struct.pack("!HHHH", 10, 20, 12, 0) + b"data"

        def v6(body, next_protocol):
            return struct.pack("!IHBB16s16s", 6 << 28, len(body), next_protocol, 64,
                               ipaddress.IPv6Address("fe80::1").packed,
                               ipaddress.IPv6Address("ff02::1").packed) + body

        extension = bytes([17, 0]) + b"\0" * 6
        result = inspect_pcap(capture(frame(v6(extension + udp, 0), protocol=0x86DD)))
        self.assertEqual(result["payload_bytes"], 4)
        fragment = struct.pack("!BBHI", 17, 0, 8, 1)
        result = inspect_pcap(capture(frame(v6(fragment + udp, 44), protocol=0x86DD)))
        self.assertEqual(result["payload_bytes"], 0)
        self.assertEqual(result["opaque_payload_bytes"], len(udp))
        chain = (bytes([0, 0]) + b"\0" * 6) * 9 + udp
        with self.assertRaisesRegex(ValueError, "extension chain"):
            inspect_pcap(capture(frame(v6(chain, 0), protocol=0x86DD)))

    def test_arp_lab_addresses_and_virtual_macs(self):
        address = bytes.fromhex("020000000001")
        arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + address + ipaddress.IPv4Address("10.77.1.2").packed
        arp += b"\0" * 6 + ipaddress.IPv4Address("10.77.1.1").packed
        result = inspect_pcap(capture(frame(arp, protocol=0x0806)))
        self.assertEqual(result["arp_records"], 1)
        self.assertEqual(result["addresses_checked"], 2)
        self.assertEqual(result["findings"], [])

    def test_snaplen_truncation_scans_stored_bytes_without_claiming_missing_bytes(self):
        complete = frame(ipv4(b"x" * 100))
        stored = complete[:-50]
        seen = []
        result = inspect_pcap(capture(stored, original_lengths=[len(complete)]), lambda value: seen.append(value) or [])
        self.assertEqual(result["truncated_records"], 1)
        self.assertEqual(result["payload_bytes"], 50)
        self.assertEqual(seen, [stored])

    def test_unknown_ethertype_is_still_scanned(self):
        data = capture(frame(b"fixture-host", protocol=0x88B5))
        result = inspect_pcap(data, lambda value: ["fixture_host"] if b"fixture-host" in value else [])
        self.assertEqual(result["unknown_ethertypes"], 1)
        self.assertTrue(any(row["category"] == "fixture_host" for row in result["findings"]))

    def test_bad_framing_versions_lengths_and_formats_fail_safely(self):
        valid = capture(frame(ipv4()))
        malformed = [b"", valid[:23], valid[:-1], valid + b"x", b"\x0a\x0d\x0d\x0a" + valid[4:]]
        unknown_link = bytearray(valid)
        unknown_link[20:24] = struct.pack("<I", 101)
        malformed.append(bytes(unknown_link))
        invalid_length = bytearray(valid)
        invalid_length[32:36] = struct.pack("<I", 65536)
        malformed.append(bytes(invalid_length))
        for data in malformed:
            with self.subTest(length=len(data)), self.assertRaises(ValueError) as error:
                inspect_pcap(data)
            self.assertNotIn("/", str(error.exception))

    def test_malformed_network_and_transport_headers_fail_closed(self):
        invalid_ip = bytearray(ipv4())
        invalid_ip[0] = 0x41
        invalid_udp = bytearray(ipv4())
        invalid_udp[24:26] = struct.pack("!H", 4)
        invalid_tcp = bytearray(ipv4(protocol=6))
        invalid_tcp[32] = 0x10
        for packet in (invalid_ip, invalid_udp, invalid_tcp):
            with self.subTest(packet=bytes(packet[:4])), self.assertRaises(ValueError):
                inspect_pcap(capture(frame(bytes(packet))))

    def test_short_capture_of_protocol_header_is_explicitly_flagged(self):
        complete = frame(ipv4())
        short = complete[:20]
        result = inspect_pcap(capture(short, original_lengths=[len(complete)]))
        self.assertEqual(result["truncated_records"], 1)
        self.assertIn({"category": "truncated_protocol_header", "count": 1, "severity": "high"}, result["findings"])

    def test_capture_and_record_bounds(self):
        valid = capture(frame(ipv4()), frame(ipv4()))
        with patch("netlab.public_packets.MAX_CAPTURE_BYTES", 10), self.assertRaisesRegex(ValueError, "size bound"):
            inspect_pcap(valid)
        with patch("netlab.public_packets.MAX_RECORDS", 1), self.assertRaisesRegex(ValueError, "record bound"):
            inspect_pcap(valid)

    def test_detector_output_and_exceptions_cannot_leak_private_values(self):
        valid = capture(frame(ipv4()))
        for detector in (lambda _value: ["C:/Users/fixture-user"], lambda _value: "fixture_path"):
            with self.assertRaisesRegex(ValueError, "packet detector failed") as error:
                inspect_pcap(valid, detector)
            self.assertNotIn("fixture-user", str(error.exception))


if __name__ == "__main__":
    unittest.main()
