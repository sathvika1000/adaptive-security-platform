import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from adaptive_security.api import create_app
from adaptive_security.connectors.wazuh import WazuhConnector
from adaptive_security.correlation.engine import CorrelationEngine
from adaptive_security.domain.incidents import IncidentStatus
from adaptive_security.store import SQLiteStore


def alert(event_id: str, minute: int) -> dict:
    return {
        "id": event_id,
        "timestamp": f"2026-09-27T02:{minute:02d}:00Z",
        "rule": {"id": "5710", "level": 5, "groups": ["authentication_failed"]},
        "agent": {"name": "web-01"},
        "data": {"srcuser": "alice"},
    }


def test_existing_database_migrates_without_losing_incident_state(tmp_path: Path) -> None:
    path = tmp_path / "existing.db"
    first, second = (
        WazuhConnector().normalize(alert("one", 10)),
        WazuhConnector().normalize(alert("two", 12)),
    )
    incident = CorrelationEngine().correlate([first, second]).model_copy(
        update={"status": IncidentStatus.CLOSED}
    )
    with sqlite3.connect(path) as conn:
        conn.execute(
            """CREATE TABLE events (
                source TEXT NOT NULL, event_id TEXT NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY (source, event_id)
            )"""
        )
        conn.execute("CREATE TABLE incidents (incident_id TEXT PRIMARY KEY, body TEXT NOT NULL)")
        conn.executemany(
            "INSERT INTO events (source, event_id, body) VALUES (?, ?, ?)",
            [(event.source, event.event_id, event.model_dump_json()) for event in (first, second)],
        )
        conn.execute(
            "INSERT INTO incidents (incident_id, body) VALUES (?, ?)",
            (incident.incident_id, incident.model_dump_json()),
        )

    client = TestClient(create_app(str(path), "secret"))
    headers = {"x-api-key": "secret"}
    stored = client.get(f"/v1/incidents/{incident.incident_id}", headers=headers)
    assert stored.json()["status"] == "closed"
    assert client.get(f"/v1/incidents/{incident.incident_id}/history",
                      headers=headers).json() == []
    updated = client.post("/v1/events/wazuh", json=alert("three", 15), headers=headers)
    assert updated.json()["incident"]["incident_id"] == incident.incident_id
    assert updated.json()["incident"]["status"] == "open"
    assert updated.json()["incident"]["event_ids"] == ["one", "two", "three"]

    with sqlite3.connect(path) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
        assert {"correlation_key", "event_time", "incident_id"} <= columns
        associated = conn.execute(
            "SELECT COUNT(*) FROM events WHERE incident_id = ?", (incident.incident_id,)
        ).fetchone()[0]
        assert associated == 3


def test_existing_transition_history_gains_nullable_actor(tmp_path: Path) -> None:
    path = tmp_path / "existing-history.db"
    SQLiteStore(str(path))
    with sqlite3.connect(path) as conn:
        conn.execute("DROP TABLE incident_transitions")
        conn.execute(
            """CREATE TABLE incident_transitions (
               transition_id INTEGER PRIMARY KEY AUTOINCREMENT,
               incident_id TEXT NOT NULL, action TEXT NOT NULL, occurred_at TEXT NOT NULL,
               request_id TEXT, event_source TEXT, event_id TEXT, merged_into TEXT
            )"""
        )
        conn.execute(
            """INSERT INTO incident_transitions
               (incident_id, action, occurred_at, request_id)
               VALUES ('old', 'closed', '2026-09-27T02:00:00+00:00', 'req')"""
        )
    SQLiteStore(str(path))
    with sqlite3.connect(path) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(incident_transitions)")}
        assert "actor" in columns
        assert conn.execute(
            "SELECT action, request_id, actor FROM incident_transitions"
        ).fetchone() == ("closed", "req", None)
