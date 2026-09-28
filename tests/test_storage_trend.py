from datetime import UTC, datetime
from pathlib import Path

import pytest

from adaptive_security.backup import create_backup
from adaptive_security.connectors.wazuh import WazuhConnector
from adaptive_security.service import IngestionService
from adaptive_security.storage_trend import storage_trend
from adaptive_security.store import SQLiteStore


def test_trend_verifies_backups_and_reports_observed_deltas(tmp_path: Path) -> None:
    source = tmp_path / "live.db"
    store = SQLiteStore(str(source))
    service = IngestionService(store)
    first = tmp_path / "security-first.db"
    create_backup(source, first)

    event = WazuhConnector().normalize({
        "id": "later", "timestamp": datetime.now(UTC).isoformat(),
        "rule": {"id": "510", "level": 7, "groups": []},
        "agent": {"name": "host"},
    })
    service.ingest(event)
    second = tmp_path / "security-second.db"
    create_backup(source, second)

    report = storage_trend([tmp_path, first])
    assert [item["events"] for item in report["snapshots"]] == [0, 1]
    assert [item["database"] for item in report["snapshots"]] == [
        str(first.resolve()), str(second.resolve()),
    ]
    assert report["intervals"][0]["events_delta"] == 1
    assert report["intervals"][0]["incidents_delta"] == 0
    assert report["intervals"][0]["size_bytes_delta"] >= 0
    assert store.event("wazuh", "later") == event

    with second.open("ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(ValueError, match="SHA256"):
        storage_trend([first, second])


def test_trend_requires_two_distinct_backups(tmp_path: Path) -> None:
    path = tmp_path / "security-only.db"
    SQLiteStore(str(tmp_path / "live.db"))
    create_backup(tmp_path / "live.db", path)
    with pytest.raises(ValueError, match="at least two"):
        storage_trend([path, path])
