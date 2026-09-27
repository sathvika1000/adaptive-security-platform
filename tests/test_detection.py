from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from adaptive_security.api import create_app
from adaptive_security.detection.auth_sequence import detect_auth_sequence
from adaptive_security.domain.events import EntityRef, EventCategory, SecurityEvent


def event(event_id: str, minute: int, outcome: str) -> SecurityEvent:
    timestamp = datetime(2026, 9, 27, 2, minute, tzinfo=UTC)
    return SecurityEvent(
        event_id=event_id,
        source="wazuh",
        category=EventCategory.AUTHENTICATION,
        event_time=timestamp,
        observed_time=timestamp + timedelta(seconds=1),
        outcome=outcome,
        severity=5,
        entities=(EntityRef(type="user", value="alice"), EntityRef(type="host", value="web-01")),
    )


def test_sequence_requires_three_recent_failures_before_success() -> None:
    sequence = [
        event("a", 0, "failure"),
        event("b", 1, "failure"),
        event("c", 2, "failure"),
        event("d", 3, "success"),
    ]
    signals = detect_auth_sequence(sequence)
    assert len(signals) == 1
    assert signals[0].rule_id == "auth.failures_then_success"
    assert signals[0].rule_version == 1
    assert signals[0].evidence_event_ids == ("a", "b", "c", "d")
    assert signals[0].priority == 7
    assert detect_auth_sequence(sequence[:2] + sequence[3:]) == ()
    assert detect_auth_sequence(
        [event("early", 0, "success"), *[event(str(i), i, "failure") for i in (1, 2, 3)]]
    ) == ()
    assert detect_auth_sequence([*sequence[:3], event("d", 18, "success")]) == ()


def test_signal_is_persisted_in_retrievable_incident(tmp_path: Path) -> None:
    path = str(tmp_path / "events.db")
    client = TestClient(create_app(path, "secret"))
    headers = {"x-api-key": "secret"}
    for event_id, minute, outcome in (
        ("a", 0, "failed"), ("b", 1, "failed"), ("c", 2, "failed"), ("d", 3, "success")
    ):
        payload = {
            "id": event_id,
            "timestamp": f"2026-09-27T02:{minute:02d}:00Z",
            "rule": {"id": "5710", "level": 5, "groups": [f"authentication_{outcome}"]},
            "agent": {"name": "web-01"},
            "data": {"srcuser": "alice"},
        }
        response = client.post("/v1/events/wazuh", json=payload, headers=headers)
        assert response.status_code == 200
    incident = response.json()["incident"]
    assert incident["severity"] == 5
    assert incident["signals"][0]["evidence_event_ids"] == ["a", "b", "c", "d"]
    restarted = TestClient(create_app(path, "secret"))
    stored = restarted.get(f"/v1/incidents/{incident['incident_id']}", headers=headers)
    assert stored.json()["signals"] == incident["signals"]
