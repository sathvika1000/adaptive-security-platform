import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from adaptive_security.api import create_app
from adaptive_security.connectors.wazuh import WazuhConnector
from adaptive_security.correlation.engine import CorrelationEngine
from adaptive_security.domain.incidents import IncidentStatus
from tests.test_pipeline import alert


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

