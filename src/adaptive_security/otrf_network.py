"""Pinned OTRF Ethernet/IPv4 TCP/UDP capture metadata and conservative host links."""

import ipaddress
import struct
import zipfile
from collections import Counter
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any

from adaptive_security.domain.events import EntityRef, EventCategory, SecurityEvent
from adaptive_security.domain.incidents import EventReference, Incident

NETWORK_URL = ("https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
               "datasets/atomic/windows/lateral_movement/network/purplesharp_ad_playbook_I.zip")
NETWORK_SHA256 = "c7dd67e1f2b914d4f553b3ef98d29b8858ed86b03ffa7dd7c0a55af30eacf03b"
NETWORK_MEMBER = "purplesharp_ad_playbook_I_2020-10-22042947.cap"


def packet_metadata(data: bytes) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Read classic microsecond PCAP. Unsupported packets remain in the source capture."""
    if len(data) < 24 or data[:4] not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        raise ValueError("expected classic microsecond PCAP")
    endian = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    major, minor, _, _, snaplen, link = struct.unpack(endian + "HHIIII", data[4:24])
    if (major, minor) != (2, 4) or link != 1:
        raise ValueError("expected PCAP 2.4 Ethernet link type")
    packets: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    position = 24
    while position < len(data):
        if position + 16 > len(data):
            raise ValueError("truncated PCAP packet header")
        seconds, micros, captured, original = struct.unpack(
            endian + "IIII", data[position:position + 16]
        )
        position += 16
        if (captured > snaplen or captured > original or micros >= 1_000_000
                or position + captured > len(data)):
            raise ValueError("invalid PCAP packet length or timestamp")
        frame = data[position:position + captured]
        position += captured
        counts["total_packets"] += 1
        if len(frame) < 14:
            counts["short_ethernet"] += 1
            continue
        ethertype = int.from_bytes(frame[12:14], "big")
        offset = 14
        if ethertype == 0x8100 and len(frame) >= 18:
            ethertype, offset = int.from_bytes(frame[16:18], "big"), 18
        if ethertype != 0x0800:
            counts["non_ipv4"] += 1
            continue
        ip = frame[offset:]
        if len(ip) < 20 or ip[0] >> 4 != 4:
            counts["invalid_ipv4"] += 1
            continue
        header_length = (ip[0] & 15) * 4
        total_length = int.from_bytes(ip[2:4], "big")
        if header_length < 20 or total_length < header_length or len(ip) < total_length:
            counts["truncated_ipv4"] += 1
            continue
        if int.from_bytes(ip[6:8], "big") & 0x3FFF:
            counts["fragmented_ipv4"] += 1
            continue
        protocol = {6: "tcp", 17: "udp"}.get(ip[9])
        if protocol is None:
            counts["other_ip_protocol"] += 1
            continue
        transport = ip[header_length:total_length]
        minimum = 20 if protocol == "tcp" else 8
        if len(transport) < minimum:
            counts["short_transport"] += 1
            continue
        if protocol == "tcp" and not 20 <= (transport[12] >> 4) * 4 <= len(transport):
            counts["invalid_tcp"] += 1
            continue
        if protocol == "udp" and not 8 <= int.from_bytes(transport[4:6], "big") <= len(transport):
            counts["invalid_udp"] += 1
            continue
        source_port, destination_port = struct.unpack("!HH", transport[:4])
        packets.append({
            "packet_number": counts["total_packets"],
            "time": datetime.fromtimestamp(seconds, UTC) + timedelta(microseconds=micros),
            "source_ip": str(ipaddress.IPv4Address(ip[12:16])),
            "destination_ip": str(ipaddress.IPv4Address(ip[16:20])),
            "source_port": source_port, "destination_port": destination_port,
            "protocol": protocol, "captured_bytes": captured,
        })
        counts["parsed_packets"] += 1
    return packets, dict(counts)


def load_network(path: Path) -> tuple[list[SecurityEvent], dict[str, int]]:
    if sha256(path.read_bytes()).hexdigest() != NETWORK_SHA256:
        raise ValueError("network capture checksum mismatch")
    with zipfile.ZipFile(path) as archive:
        if archive.namelist() != [NETWORK_MEMBER]:
            raise ValueError("unexpected network ZIP members")
        if archive.getinfo(NETWORK_MEMBER).file_size > 10_000_000:
            raise ValueError("network capture too large")
        packets, inventory = packet_metadata(archive.read(NETWORK_MEMBER))
    # Directed tuple + UTC second bucket avoids joining long unrelated sessions.
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for packet in packets:
        key = (*(packet[name] for name in (
            "source_ip", "destination_ip", "source_port", "destination_port", "protocol"
        )), int(packet["time"].timestamp()))
        groups.setdefault(key, []).append(packet)
    events = []
    for key, members in sorted(groups.items()):
        first, last = min(p["time"] for p in members), max(p["time"] for p in members)
        event_id = sha256(repr((NETWORK_SHA256, key)).encode()).hexdigest()
        events.append(SecurityEvent(
            source="otrf-network", event_id=event_id, category=EventCategory.NETWORK,
            event_time=first, observed_time=first, action="captured_connection",
            source_ip=key[0], entities=(EntityRef(type="ip", value=key[0]),
                                       EntityRef(type="destination_ip", value=key[1])),
            attributes={
                "capture_sha256": NETWORK_SHA256, "raw_member": NETWORK_MEMBER,
                "packet_numbers": [p["packet_number"] for p in members],
                "destination_ip": key[1], "source_port": key[2], "destination_port": key[3],
                "protocol": key[4], "last_packet_time": last.isoformat(),
                "packet_count": len(members),
                "captured_bytes": sum(p["captured_bytes"] for p in members),
                "time_basis": "PCAP UTC epoch; observation time unavailable",
            },
        ))
    inventory["connection_buckets"] = len(events)
    return events, inventory


def link_network(incident: Incident, hosts: list[SecurityEvent],
                 network: list[SecurityEvent]) -> tuple[Incident, list[SecurityEvent]]:
    """Match exact directed five-tuples within two seconds to nearby endpoint Sysmon events."""
    endpoints = {e.value for e in incident.entities if e.type == "host"}
    anchors: dict[tuple[Any, ...], list[SecurityEvent]] = {}
    for event in hosts:
        raw = event.attributes.get("raw", {})
        if (event.attributes.get("channel") != "Microsoft-Windows-Sysmon/Operational"
                or event.attributes.get("windows_event_id") != 3
                or not any(e.type == "host" and e.value in endpoints for e in event.entities)
                or not incident.first_seen - timedelta(seconds=30) <= event.event_time
                <= incident.last_seen + timedelta(minutes=2)):
            continue
        try:
            key = (str(ipaddress.ip_address(raw["SourceIp"])),
                   str(ipaddress.ip_address(raw["DestinationIp"])),
                   int(raw["SourcePort"]), int(raw["DestinationPort"]),
                   str(raw["Protocol"]).lower())
        except (KeyError, ValueError, TypeError):
            continue
        anchors.setdefault(key, []).append(event)
    matched = []
    for event in network:
        attrs = event.attributes
        network_key = (event.source_ip, attrs["destination_ip"], attrs["source_port"],
                       attrs["destination_port"], attrs["protocol"])
        ids = [host.event_id for host in anchors.get(network_key, [])
               if event.event_time - timedelta(seconds=2) <= host.event_time
               <= datetime.fromisoformat(attrs["last_packet_time"]) + timedelta(seconds=2)]
        if ids:
            matched.append(event.model_copy(update={"attributes": {
                **attrs, "association": "five_tuple_time_context",
                "matched_host_event_ids": ids,
                "explanation": "Addresses, ports, protocol and time match an endpoint network "
                               "event near this finding. This does not establish maliciousness.",
            }}))
    refs = tuple(EventReference(source=e.source, event_id=e.event_id) for e in matched)
    return incident.model_copy(update={"context_event_refs": refs}), matched
