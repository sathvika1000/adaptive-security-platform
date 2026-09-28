import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from adaptive_security.backup import create_backup, verify_backup
from adaptive_security.connectors.wazuh import WazuhConnector
from adaptive_security.service import IngestionService
from adaptive_security.store import SQLiteStore


def _alert(event_id: str, minute: int) -> dict:
    return {
        "id": event_id,
        "timestamp": (datetime(2026, 9, 27, tzinfo=UTC) + timedelta(minutes=minute)).isoformat(),
        "rule": {"id": "5710", "level": 5, "groups": ["authentication_failed"]},
        "agent": {"name": "host"},
        "data": {"srcuser": "alice"},
    }


def test_backup_restores_evidence_aliases_and_transitions(tmp_path: Path) -> None:
    source = tmp_path / "live.db"
    destination = tmp_path / "copy.db"
    store = SQLiteStore(str(source))
    service = IngestionService(store)
    connector = WazuhConnector()
    ids = []
    for event_id, minute in (("a", 0), ("b", 5), ("c", 40), ("d", 45)):
        _, incident = service.ingest(connector.normalize(_alert(event_id, minute)))
        if incident and incident.incident_id not in ids:
            ids.append(incident.incident_id)
    for event_id, minute in (("bridge-1", 20), ("bridge-2", 30)):
        _, merged = service.ingest(connector.normalize(_alert(event_id, minute)))
    assert merged is not None and len(ids) == 2
    store.close_incident(merged.incident_id, request_id="test-close")

    manifest = create_backup(source, destination)
    assert destination.exists() and destination.stat().st_mode & 0o777 == 0o600
    assert verify_backup(destination) == manifest
    assert manifest["counts"]["events"] == 6
    assert manifest["counts"]["incident_aliases"] == 1
    assert manifest["counts"]["incident_transitions"] == 2
    restored = SQLiteStore(str(destination))
    assert restored.incident(ids[1]) == store.incident(ids[0])
    assert [event.event_id for event in restored.incident_events(ids[1]) or []] == [
        "a", "b", "bridge-1", "bridge-2", "c", "d"
    ]
    assert [entry.action for entry in restored.incident_history(ids[1]) or []] == [
        "merged", "closed"
    ]

    with destination.open("ab") as stream:
        stream.write(b"corrupt")
    with pytest.raises(ValueError, match="SHA256"):
        verify_backup(destination)
    assert store.ready()


def test_backup_refuses_to_overwrite_existing_file(tmp_path: Path) -> None:
    source = tmp_path / "live.db"
    SQLiteStore(str(source))
    destination = tmp_path / "existing.db"
    destination.write_bytes(b"keep me")
    with pytest.raises(FileExistsError):
        create_backup(source, destination)
    assert destination.read_bytes() == b"keep me"
    assert not list(tmp_path.glob(".*.tmp"))


def test_backup_from_wal_database_includes_committed_data(tmp_path: Path) -> None:
    source = tmp_path / "wal.db"
    store = SQLiteStore(str(source))
    with sqlite3.connect(source) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
    service = IngestionService(store)
    service.ingest(WazuhConnector().normalize(_alert("committed", 0)))
    destination = tmp_path / "wal-copy.db"
    create_backup(source, destination)
    assert verify_backup(destination)["counts"]["events"] == 1
    assert SQLiteStore(str(destination)).event("wazuh", "committed") is not None
