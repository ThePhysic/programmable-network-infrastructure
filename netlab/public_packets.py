"""Bounded inspection of stored classic-PCAP bytes for public-evidence audits.

This module never rewrites captures, reconstructs traffic, or returns endpoints.
The optional detector sees complete stored frames, including protocol headers,
padding, and undecoded bytes, rather than only the application slice.
"""
from __future__ import annotations

from collections import Counter
import ipaddress
import re
import struct
from typing import Callable, Iterable, Iterator

MAX_CAPTURE_BYTES = 16 * 1024 * 1024
MAX_PACKET_BYTES = 1024 * 1024
MAX_RECORDS = 250_000
MAX_EXTENSION_HEADERS = 8
LINKTYPES = {1, 113, 276}  # Ethernet, Linux cooked v1, Linux cooked v2.
LAB_NETWORK = ipaddress.IPv4Network("10.77.0.0/16")
ROUTER_NETWORK = ipaddress.IPv4Network("10.255.0.0/24")
Detector = Callable[[bytes], Iterable[str]]


def _records(data: bytes):
    if not isinstance(data, bytes):
        raise ValueError("capture must be bytes")
    if len(data) > MAX_CAPTURE_BYTES:
        raise ValueError("capture exceeds size bound")
    if len(data) < 24:
        raise ValueError("truncated PCAP global header")
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
               b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
               b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
               b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000)}
    if data[:4] not in formats:
        raise ValueError("unsupported capture format")
    endian, resolution = formats[data[:4]]
    major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHiiII", data[4:24])
    if (major, minor) != (2, 4):
        raise ValueError("unsupported PCAP version")
    if not 0 < snaplen <= MAX_PACKET_BYTES:
        raise ValueError("PCAP snapshot length exceeds supported bound")
    if linktype not in LINKTYPES:
        raise ValueError("unsupported capture linktype")
    offset, records = 24, 0
    while offset < len(data):
        records += 1
        if records > MAX_RECORDS:
            raise ValueError("capture exceeds record bound")
        if len(data) - offset < 16:
            raise ValueError("truncated PCAP record header")
        _, fraction, captured, original = struct.unpack(endian + "4I", data[offset:offset + 16])
        offset += 16
        if fraction >= resolution:
            raise ValueError("invalid PCAP timestamp fraction")
        if captured > snaplen or captured > original or original > MAX_PACKET_BYTES:
            raise ValueError("invalid PCAP record length")
        if offset + captured > len(data):
            raise ValueError("truncated PCAP record body")
        yield data[offset:offset + captured], original, linktype
        offset += captured


def iter_pcap_payloads(data: bytes) -> Iterator[bytes]:
    """Yield full stored record bodies, not reconstructed application streams.

    Each yielded frame includes link/network headers, application bytes, padding,
    and unparsed record bytes. Consuming the iterator validates all file framing.
    ``inspect_pcap`` separately counts available TCP/UDP application bytes.
    """
    for frame, _, _ in _records(data):
        yield frame


def _allowed_address(address):
    if address.version == 4:
        return (address in LAB_NETWORK or address in ROUTER_NETWORK
                or address.is_loopback or address.is_unspecified)
    return (address.is_link_local or address.is_multicast
            or address.is_loopback or address.is_unspecified)


def inspect_pcap(data: bytes, detector: Detector | None = None) -> dict:
    """Inspect classic PCAP safely; report counts/categories without raw values.

    Detector callbacks receive complete stored frames and return category names
    matching ``[a-z][a-z0-9_]{0,63}``. Every detector finding has high severity.
    Intentionally snaplen-truncated records are accepted and counted; incomplete
    file framing, malformed headers, unsupported formats and bounds fail closed.
    """
    counts = Counter(files=1, records=0, stored_bytes=0, payload_bytes=0,
                     opaque_payload_bytes=0, truncated_records=0,
                     addresses_checked=0, mac_addresses_checked=0,
                     tcp_records=0, udp_records=0, arp_records=0,
                     ipv4_records=0, ipv6_records=0, unknown_ethertypes=0)
    findings = Counter()

    def finding(category, severity="high", amount=1):
        findings[(category, severity)] += amount

    def addresses(*values):
        for address in values:
            counts["addresses_checked"] += 1
            if not _allowed_address(address):
                finding("non_lab_packet_endpoint")

    def mac(value):
        if len(value) != 6:
            return
        counts["mac_addresses_checked"] += 1
        # Virtual Ethernet addresses have the local bit set; zero and multicast
        # addresses are normal loopback/broadcast/kernel protocol metadata.
        if value != b"\0" * 6 and not value[0] & 0x03:
            finding("globally_administered_packet_mac", "review")

    def shortage(message, truncated):
        if not truncated:
            raise ValueError(message)
        finding("truncated_protocol_header")
        return None

    def transport(body, protocol, expected_length, truncated, fragmented=False):
        if fragmented:
            counts["opaque_payload_bytes"] += len(body)
            return
        if protocol == 6:
            counts["tcp_records"] += 1
            if len(body) < 20:
                shortage("truncated TCP header", truncated)
                counts["opaque_payload_bytes"] += len(body)
                return
            header = (body[12] >> 4) * 4
            if header < 20 or header > expected_length:
                raise ValueError("invalid TCP header length")
            if len(body) < header:
                shortage("truncated TCP options", truncated)
                counts["opaque_payload_bytes"] += len(body)
                return
            counts["payload_bytes"] += len(body) - header
        elif protocol == 17:
            counts["udp_records"] += 1
            if len(body) < 8:
                shortage("truncated UDP header", truncated)
                counts["opaque_payload_bytes"] += len(body)
                return
            length = struct.unpack("!H", body[4:6])[0]
            if length < 8 or length > expected_length:
                raise ValueError("invalid UDP length")
            counts["payload_bytes"] += max(0, min(length, len(body)) - 8)
        else:
            counts["opaque_payload_bytes"] += len(body)

    for frame, original, linktype in _records(data):
        counts["records"] += 1
        counts["stored_bytes"] += len(frame)
        truncated = len(frame) < original
        counts["truncated_records"] += truncated
        if detector is not None:
            try:
                categories = detector(frame)
                if isinstance(categories, (str, bytes)):
                    raise ValueError("invalid detector result")
                for category in categories:
                    if not isinstance(category, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", category):
                        raise ValueError("invalid detector category")
                    finding(category)
            except Exception:
                raise ValueError("packet detector failed") from None
        minimum = {1: 14, 113: 16, 276: 20}[linktype]
        if len(frame) < minimum:
            shortage("truncated link header", truncated)
            counts["opaque_payload_bytes"] += len(frame)
            continue
        if linktype == 1:
            mac(frame[:6])
            mac(frame[6:12])
            protocol = struct.unpack("!H", frame[12:14])[0]
        elif linktype == 113:
            address_length = struct.unpack("!H", frame[4:6])[0]
            if address_length > 8:
                raise ValueError("invalid Linux cooked address length")
            if address_length == 6:
                mac(frame[6:12])
            protocol = struct.unpack("!H", frame[14:16])[0]
        else:
            if frame[11] > 8:
                raise ValueError("invalid Linux cooked address length")
            if frame[11] == 6:
                mac(frame[12:18])
            protocol = struct.unpack("!H", frame[:2])[0]
        offset, vlan_tags = minimum, 0
        while protocol in (0x8100, 0x88A8):
            vlan_tags += 1
            if vlan_tags > 4:
                raise ValueError("VLAN chain exceeds supported bound")
            if len(frame) < offset + 4:
                shortage("truncated VLAN header", truncated)
                break
            protocol = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
            offset += 4
        body = frame[offset:]
        if protocol == 0x0800:
            counts["ipv4_records"] += 1
            if len(body) < 20:
                shortage("truncated IPv4 header", truncated)
                counts["opaque_payload_bytes"] += len(body)
                continue
            header, length = (body[0] & 15) * 4, struct.unpack("!H", body[2:4])[0]
            if body[0] >> 4 != 4 or header < 20 or length < header:
                raise ValueError("invalid IPv4 header")
            addresses(ipaddress.IPv4Address(body[12:16]), ipaddress.IPv4Address(body[16:20]))
            if len(body) < header:
                shortage("truncated IPv4 options", truncated)
                counts["opaque_payload_bytes"] += len(body)
                continue
            if len(body) < length and not truncated:
                raise ValueError("truncated IPv4 packet")
            fragment = struct.unpack("!H", body[6:8])[0] & 0x3FFF
            transport(body[header:min(length, len(body))], body[9], length - header, truncated, bool(fragment))
        elif protocol == 0x86DD:
            counts["ipv6_records"] += 1
            if len(body) < 40:
                shortage("truncated IPv6 header", truncated)
                counts["opaque_payload_bytes"] += len(body)
                continue
            if body[0] >> 4 != 6:
                raise ValueError("invalid IPv6 header")
            addresses(ipaddress.IPv6Address(body[8:24]), ipaddress.IPv6Address(body[24:40]))
            length = struct.unpack("!H", body[4:6])[0] + 40
            if length == 40 and len(body) > 40:
                raise ValueError("IPv6 jumbograms are unsupported")
            if len(body) < length and not truncated:
                raise ValueError("truncated IPv6 packet")
            available = body[:min(length, len(body))]
            protocol, position, fragmented, extensions = body[6], 40, False, 0
            while protocol in (0, 43, 44, 51, 60):
                extensions += 1
                if extensions > MAX_EXTENSION_HEADERS:
                    raise ValueError("IPv6 extension chain exceeds supported bound")
                if len(available) < position + 2:
                    shortage("truncated IPv6 extension header", truncated)
                    position = len(available)
                    break
                next_protocol = available[position]
                size = 8 if protocol == 44 else (available[position + 1] + (2 if protocol == 51 else 1)) * (4 if protocol == 51 else 8)
                if position + size > length:
                    raise ValueError("invalid IPv6 extension length")
                if position + size > len(available):
                    shortage("truncated IPv6 extension body", truncated)
                    position = len(available)
                    break
                if protocol == 44:
                    fragment_field = struct.unpack("!H", available[position + 2:position + 4])[0]
                    fragmented |= bool(fragment_field & 0xFFF9)
                protocol, position = next_protocol, position + size
            transport(available[position:], protocol, max(0, length - position), truncated, fragmented)
        elif protocol == 0x0806:
            counts["arp_records"] += 1
            if len(body) < 8:
                shortage("truncated ARP header", truncated)
                counts["opaque_payload_bytes"] += len(body)
                continue
            _, address_type, hardware_size, address_size, _ = struct.unpack("!HHBBH", body[:8])
            if hardware_size > 32 or address_size > 16:
                raise ValueError("ARP address length exceeds supported bound")
            size = 8 + hardware_size * 2 + address_size * 2
            if len(body) < size:
                shortage("truncated ARP addresses", truncated)
                counts["opaque_payload_bytes"] += len(body)
                continue
            if hardware_size == 6:
                mac(body[8:14])
                mac(body[8 + hardware_size + address_size:8 + hardware_size * 2 + address_size])
            if address_type != 0x0800 or address_size != 4:
                finding("unsupported_arp_addresses", "review")
            else:
                sender = 8 + hardware_size
                target = 8 + hardware_size * 2 + address_size
                addresses(ipaddress.IPv4Address(body[sender:sender + 4]), ipaddress.IPv4Address(body[target:target + 4]))
        else:
            counts["unknown_ethertypes"] += 1
            counts["opaque_payload_bytes"] += len(body)
            finding("undecoded_link_payload", "info")
    result = dict(counts)
    result["findings"] = [{"category": category, "count": count, "severity": severity}
                          for (category, severity), count in sorted(findings.items())]
    result["limits"] = [
        "Only stored capture bytes are inspected; snaplen-truncated bytes are unavailable.",
        "Detector callbacks scan full stored frames, including headers, padding, and undecoded bytes.",
        "No TCP stream or IP fragment reassembly is performed; split identifiers may require separate review.",
        "Payload byte counts cover decoded, unfragmented TCP/UDP application bytes; other bytes are opaque.",
        "Packet checksums, payload provenance, and absence of every possible secret are not certified.",
    ]
    return result
