import hashlib
import json
import struct
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from adaptive_security.api import create_app
from adaptive_security.domain.events import EntityRef, EventCategory, SecurityEvent
from adaptive_security.domain.incidents import Incident
from adaptive_security.otrf_network import link_network, load_network, packet_metadata
from adaptive_security.store import SQLiteStore


def frame(protocol=6):
    transport = (struct.pack('!HH', 50000, 5985) + bytes(8) + b'\x50\x00' + bytes(6)
                 if protocol == 6 else struct.pack('!HHHH', 50000, 5985, 8, 0))
    ip = b'\x45\x00' + struct.pack('!H', 20 + len(transport)) + bytes(5)
    ip += bytes([protocol]) + bytes(2) + bytes([192, 0, 2, 1, 192, 0, 2, 2])
    return bytes(12) + b'\x08\x00' + ip + transport


def pcap(frames, endian='<'):
    header = struct.pack(endian + 'IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    return header + b''.join(struct.pack(endian + 'IIII', 1603355393, n * 100000,
                                        len(f), len(f)) + f for n, f in enumerate(frames))


def network_event():
    return SecurityEvent(
        source='otrf-network', event_id='packet-event', category=EventCategory.NETWORK,
        action='captured_connection', source_ip='192.0.2.1',
        event_time=datetime(2020, 10, 22, 8, 29, 53, tzinfo=UTC),
        observed_time=datetime(2020, 10, 22, 8, 29, 53, tzinfo=UTC),
        attributes={'destination_ip': '192.0.2.2', 'source_port': 50000,
                    'destination_port': 5985, 'protocol': 'tcp',
                    'last_packet_time': '2020-10-22T08:29:53+00:00'},
    )


def host_event():
    return network_event().model_copy(update={
        'source': 'otrf', 'event_id': 'host-anchor',
        'entities': (EntityRef(type='host', value='endpoint'),),
        'attributes': {'channel': 'Microsoft-Windows-Sysmon/Operational', 'windows_event_id': 3,
                       'raw': {'SourceIp': '192.0.2.1', 'DestinationIp': '192.0.2.2',
                               'SourcePort': '50000', 'DestinationPort': '5985',
                               'Protocol': 'tcp'}},
    })


def incident():
    return Incident(incident_id='finding', title='Finding', severity=6, event_ids=('failure',),
                    first_seen=network_event().event_time, last_seen=network_event().event_time,
                    entities=(EntityRef(type='host', value='endpoint'),))


def test_packet_metadata_endian_and_protocols():
    for endian in ('<', '>'):
        packets, counts = packet_metadata(pcap([frame(), frame(17)], endian))
        assert counts == {'total_packets': 2, 'parsed_packets': 2}
        assert packets[0]['source_ip'] == '192.0.2.1'
        assert packets[1]['protocol'] == 'udp'
        assert packets[1]['time'].microsecond == 100000
        assert packets[1]['packet_number'] == 2


def test_packet_metadata_failures_and_skips():
    with pytest.raises(ValueError, match='classic'):
        packet_metadata(b'bad')
    with pytest.raises(ValueError, match='header'):
        packet_metadata(pcap([]) + bytes(2))
    with pytest.raises(ValueError, match='length'):
        packet_metadata(pcap([frame()])[:-1])
    _, counts = packet_metadata(pcap([bytes(5), bytes(14), frame()[:20]]))
    assert counts['total_packets'] == 3
    assert counts['short_ethernet'] == 1
    assert counts['non_ipv4'] == 1
    assert counts['invalid_ipv4'] == 1


def test_pinned_network_and_aggregation(tmp_path: Path, monkeypatch):
    import adaptive_security.otrf_network as module

    capture = tmp_path / 'network.zip'
    with zipfile.ZipFile(capture, 'w') as archive:
        archive.writestr(module.NETWORK_MEMBER, pcap([frame(), frame()]))
    with pytest.raises(ValueError, match='checksum'):
        load_network(capture)
    monkeypatch.setattr(module, 'NETWORK_SHA256', hashlib.sha256(capture.read_bytes()).hexdigest())
    events, inventory = load_network(capture)
    assert inventory['connection_buckets'] == 1
    assert events[0].attributes['packet_numbers'] == [1, 2]
    assert events[0].attributes['packet_count'] == 2
    assert load_network(capture)[0] == events
    assert 'payload' not in events[0].attributes


def test_match_exact_tuple_time_and_endpoint():
    matched_incident, events = link_network(incident(), [host_event()], [network_event()])
    assert len(matched_incident.context_event_refs) == 1
    assert matched_incident.event_ids == ('failure',)
    assert events[0].attributes['matched_host_event_ids'] == ['host-anchor']
    assert 'maliciousness' in events[0].attributes['explanation']
    late = host_event().model_copy(update={
        'event_time': host_event().event_time + timedelta(seconds=3),
    })
    assert not link_network(incident(), [late], [network_event()])[1]
    wrong = host_event().model_copy(update={'entities': (EntityRef(type='host', value='other'),)})
    assert not link_network(incident(), [wrong], [network_event()])[1]
    different_port = network_event().model_copy(update={'attributes': {
        **network_event().attributes, 'destination_port': 445,
    }})
    assert not link_network(incident(), [host_event()], [different_port])[1]


def test_context_authenticated_paged_and_separate(tmp_path: Path):
    store = SQLiteStore(str(tmp_path / 'findings.db'))
    finding, contexts = link_network(incident(), [host_event()], [network_event()])
    with store.transaction() as conn:
        store.put_event(conn, contexts[0])
        store.save_incident(conn, finding, [], set(), host_event())
    client = TestClient(create_app(store.path, 'key'))
    path = '/v1/incidents/finding/context'
    assert client.get(path).status_code == 401
    headers = {'X-API-Key': 'key'}
    assert client.get(path, headers=headers).json()[0]['event_id'] == 'packet-event'
    assert client.get(path + '?offset=1', headers=headers).json() == []
    assert client.get('/v1/incidents/finding/events', headers=headers).json() == []
    assert client.get('/v1/incidents/missing/context', headers=headers).status_code == 404
    assert client.get(path + '?limit=101', headers=headers).status_code == 422
    assert json.loads(finding.model_dump_json())['event_ids'] == ['failure']


def test_context_is_protected_from_unlinked_archives(tmp_path: Path):
    from adaptive_security.archive import _candidates

    store = SQLiteStore(str(tmp_path / 'context.db'))
    finding, contexts = link_network(incident(), [host_event()], [network_event()])
    with store.transaction() as conn:
        store.put_event(conn, contexts[0])
        store.save_incident(conn, finding, [], set(), host_event())
    preview = store.retention_preview(datetime(2021, 1, 1, tzinfo=UTC))
    assert preview.incident_evidence == 1
    assert preview.unlinked_other == 0
    assert list(_candidates(Path(store.path), '2021-01-01T00:00:00+00:00')) == []


def test_shared_network_context_preserves_both_investigation_anchors():
    from adaptive_security.otrf_replay import _merge_context

    first = network_event().model_copy(update={"attributes": {
        **network_event().attributes, "matched_host_event_ids": ["workstation-anchor"]}})
    second = first.model_copy(update={"attributes": {
        **first.attributes, "matched_host_event_ids": ["controller-anchor"]}})
    linked = {}
    _merge_context(linked, first, "spray")
    _merge_context(linked, second, "ticket")
    _merge_context(linked, second, "ticket")
    attrs = linked[first.event_id].attributes
    assert attrs["matched_host_event_ids"] == ["controller-anchor", "workstation-anchor"]
    assert attrs["matched_incident_ids"] == ["spray", "ticket"]
