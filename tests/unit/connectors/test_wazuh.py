from datetime import timedelta

from adaptive_security.connectors.wazuh import WazuhConnector
from adaptive_security.domain.events import EventCategory


def test_normalizes_failed_authentication_alert() -> None:
    payload = {
        "id": "alert-1",
        "timestamp": "2026-09-27T02:00:00Z",
        "rule": {
            "id": "5710",
            "level": 5,
            "groups": ["authentication_failed", "sshd"],
        },
        "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.8"},
        "data": {"srcuser": "alice", "srcip": "198.51.100.20"},
    }

    event = WazuhConnector().normalize(payload)

    assert event.event_id == "alert-1"
    assert event.source == "wazuh"
    assert event.category is EventCategory.AUTHENTICATION
    assert event.event_time.utcoffset() == timedelta(0)
    assert event.outcome == "failure"
    assert event.source_ip == "198.51.100.20"
    assert event.severity == 5
    assert {(entity.type, entity.value) for entity in event.entities} == {
        ("host", "web-01"),
        ("ip", "10.0.0.8"),
        ("user", "alice"),
        ("ip", "198.51.100.20"),
    }
    assert event.attributes["rule_id"] == "5710"


def test_invalid_source_ip_is_ignored() -> None:
    payload = {
        "id": "alert-2",
        "timestamp": "2026-09-27T02:00:00Z",
        "rule": {"id": "5710", "level": 5, "groups": ["authentication_success"]},
        "agent": {"name": "web-01"},
        "data": {"srcuser": "alice", "srcip": "unknown"},
    }
    assert WazuhConnector().normalize(payload).source_ip is None
