from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from adaptive_security.domain.events import EntityRef, EventCategory, SecurityEvent
from adaptive_security.evaluation import EvaluationCase, evaluate
from adaptive_security.service import IngestionService
from adaptive_security.store import SQLiteStore


def auth(event_id: str, minute: int, outcome: str, ip: str | None) -> SecurityEvent:
    timestamp = datetime(2026, 9, 27, tzinfo=UTC) + timedelta(minutes=minute)
    return SecurityEvent(
        event_id=event_id, source="wazuh", category=EventCategory.AUTHENTICATION,
        event_time=timestamp, observed_time=timestamp, outcome=outcome, source_ip=ip,
        severity=5, entities=(EntityRef(type="user", value="alice"),
                              EntityRef(type="host", value="web-01")),
    )


def test_shadow_signal_survives_restart_and_duplicate_without_changing_severity(
    tmp_path: Path,
) -> None:
    path = str(tmp_path / "events.db")
    service = IngestionService(SQLiteStore(path))
    for index in range(5):
        _, incident = service.ingest(auth(f"baseline-{index}", index, "success", "192.0.2.1"))
        assert incident is None

    restarted = IngestionService(SQLiteStore(path))
    restarted.ingest(auth("failure", 10, "failure", "198.51.100.8"))
    novel = auth("novel", 11, "success", "198.51.100.8")
    _, incident = restarted.ingest(novel)
    assert incident is not None
    assert incident.severity == 5
    assert len(incident.signals) == 1
    signal = incident.signals[0]
    assert (signal.rule_id, signal.mode, signal.priority) == (
        "auth.novel_source_ip", "shadow", 4
    )
    assert signal.evidence_event_ids == ("novel",)
    assert restarted.ingest(novel)[1] == incident
    assert len(SQLiteStore(path).event_signals()) == 1

    _, known_incident = restarted.ingest(auth("known", 12, "success", "198.51.100.8"))
    assert known_incident is not None
    assert len(known_incident.signals) == 1


def test_only_valid_successful_ip_observations_train_baseline(tmp_path: Path) -> None:
    store = SQLiteStore(str(tmp_path / "events.db"))
    service = IngestionService(store)
    for index in range(8):
        service.ingest(auth(f"failure-{index}", index, "failure", "192.0.2.1"))
        service.ingest(auth(f"missing-{index}", index, "success", None))
    assert service.ingest(auth("first", 100, "success", "198.51.100.1"))[1] is None
    assert store.event_signals() == []
    for index in range(4):
        service.ingest(auth(f"training-{index}", 101 + index, "success", "198.51.100.1"))
    service.ingest(auth("sixth", 105, "success", "198.51.100.1"))
    assert store.event_signals() == []
    service.ingest(auth("new", 106, "success", "2001:db8::1"))
    assert [signal.evidence_event_ids for signal in store.event_signals()] == [("new",)]


def test_ip_validation_and_canonicalization() -> None:
    assert auth("v6", 0, "success", "2001:0DB8:0:0:0:0:0:1").source_ip == "2001:db8::1"
    with pytest.raises(ValidationError):
        auth("bad", 0, "success", "not-an-ip")


def test_novelty_evaluation_counts_benign_and_cold_start() -> None:
    def case(name: str, label: str, history: int, final_ip: str) -> EvaluationCase:
        events = tuple(auth(f"{name}-{i}", i, "success", "192.0.2.1")
                       for i in range(history))
        return EvaluationCase(case_id=name, label=label, events=(
            *events, auth(f"{name}-last", history, "success", final_ip)
        ))

    summary = evaluate((
        case("attack", "malicious", 5, "198.51.100.2"),
        case("travel", "benign", 5, "198.51.100.2"),
        case("known", "benign", 5, "192.0.2.1"),
        case("cold", "malicious", 4, "198.51.100.2"),
    ), rule_id="auth.novel_source_ip")
    assert (summary.true_positive, summary.false_positive,
            summary.true_negative, summary.false_negative) == (1, 1, 1, 1)
