from datetime import UTC, datetime, timedelta

import pytest

from adaptive_security.correlation.engine import CorrelationEngine
from adaptive_security.domain.events import EntityRef, EventCategory, SecurityEvent


def event(event_id: str, minute: int, severity: int) -> SecurityEvent:
    timestamp = datetime(2026, 9, 27, 2, minute, tzinfo=UTC)
    return SecurityEvent(
        event_id=event_id,
        source="wazuh",
        category=EventCategory.AUTHENTICATION,
        event_time=timestamp,
        observed_time=timestamp + timedelta(seconds=1),
        severity=severity,
        entities=(
            EntityRef(type="user", value="alice"),
            EntityRef(type="host", value="web-01"),
        ),
    )


def test_correlates_events_into_deterministic_incident() -> None:
    incident = CorrelationEngine().correlate(
        [event("event-2", 2, 7), event("event-1", 1, 4)]
    )

    assert incident.incident_id == "inc-3b6ed4b1e38bb0b4"
    assert incident.title == "Correlated authentication activity"
    assert incident.event_ids == ("event-1", "event-2")
    assert incident.severity == 7
    assert incident.first_seen < incident.last_seen
    assert [(entity.type, entity.value) for entity in incident.entities] == [
        ("user", "alice"),
        ("host", "web-01"),
    ]


def test_rejects_empty_event_set() -> None:
    with pytest.raises(ValueError, match="at least one event is required"):
        CorrelationEngine().correlate([])
