import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from adaptive_security.archive import (
    create_archive,
    reconcile_archive,
    restore_archive,
    verify_archive,
)
from adaptive_security.backup import create_backup
from adaptive_security.connectors.wazuh import WazuhConnector
from adaptive_security.domain.detections import DetectionSignal
from adaptive_security.service import IngestionService
from adaptive_security.store import SQLiteStore


def _alert(event_id: str, minute: int, user: str = "alice") -> dict:
    return {
        "id": event_id,
        "timestamp": (datetime(2026, 9, 27, tzinfo=UTC) + timedelta(minutes=minute)).isoformat(),
        "rule": {"id": "5710", "level": 5, "groups": ["authentication_failed"]},
        "agent": {"name": "host"},
        "data": {"srcuser": user},
    }


def test_archive_reconciles_only_older_unlinked_other_events(tmp_path: Path) -> None:
    source = tmp_path / "live.db"
    store = SQLiteStore(str(source))
    service = IngestionService(store)
    connector = WazuhConnector()
    payloads = [
        _alert("incident-a", 0), _alert("incident-b", 1),
        _alert("unlinked-auth", 100, "bob"),
        _alert("unlinked-file", 101, "carol"),
        _alert("shadow", 102, "dave"),
        _alert("unlinked-other", 102, "erin"),
        _alert("at-cutoff", 103, "frank"),
    ]
    payloads[3]["rule"]["groups"] = ["syscheck"]
    payloads[4]["rule"]["groups"] = ["authentication_success"]
    payloads[5]["rule"] = {"id": "510", "level": 7, "groups": []}
    for payload in payloads:
        service.ingest(connector.normalize(payload))
    with store.transaction() as conn:
        store.save_event_signal(
            conn, connector.normalize(payloads[4]),
            DetectionSignal(rule_id="shadow", rule_version=1, title="Signal",
                            evidence_event_ids=("shadow",), priority=4, mode="shadow"),
        )

    snapshot = tmp_path / "snapshot.db"
    create_backup(source, snapshot)
    archive = tmp_path / "older.jsonl"
    cutoff = datetime.fromisoformat(payloads[6]["timestamp"])
    result = create_archive(snapshot, archive, cutoff)
    assert result["count"] == store.retention_preview(cutoff).unlinked_other == 2
    assert [json.loads(line)["event_id"] for line in archive.read_text().splitlines()] == [
        "unlinked-file", "unlinked-other",
    ]
    assert archive.stat().st_mode & 0o777 == 0o600
    assert verify_archive(snapshot, archive) == result
    assert store.event("wazuh", "unlinked-other") is not None

    current = tmp_path / "current.db"
    create_backup(source, current)
    matched = reconcile_archive(snapshot, archive, current)
    assert matched["reconciled"]
    assert matched["unchanged_eligible"] == 2
    assert matched["missing"] == matched["changed_or_protected"] == 0
    assert matched["newly_eligible"] == 0

    with store.transaction() as conn:
        conn.execute("UPDATE events SET incident_id = ? WHERE event_id = ?",
                     ("inc-late", "unlinked-file"))
    later_alert = _alert("later-other", 99, "grace")
    later_alert["rule"] = {"id": "510", "level": 7, "groups": []}
    service.ingest(connector.normalize(later_alert))
    later = tmp_path / "later.db"
    create_backup(source, later)
    drift = reconcile_archive(snapshot, archive, later)
    assert not drift["reconciled"]
    assert drift["unchanged_eligible"] == 1
    assert drift["changed_or_protected"] == 1
    assert drift["newly_eligible"] == 1
    assert store.event("wazuh", "unlinked-file") is not None

    restored = tmp_path / "restored.db"
    outcome = restore_archive(archive, restored)
    assert outcome["restored_events"] == 2
    assert restored.stat().st_mode & 0o777 == 0o600
    isolated = SQLiteStore(str(restored))
    assert isolated.event("wazuh", "unlinked-file") == store.event("wazuh", "unlinked-file")
    assert isolated.event("wazuh", "unlinked-other") == store.event("wazuh", "unlinked-other")
    assert isolated.event("wazuh", "incident-a") is None
    assert isolated.retention_preview(cutoff).unlinked_other == 2
    with pytest.raises(FileExistsError):
        restore_archive(archive, restored)

    with store.transaction() as conn:
        conn.execute("DELETE FROM events WHERE event_id = ?", ("unlinked-other",))
    missing_backup = tmp_path / "missing.db"
    create_backup(source, missing_backup)
    missing = reconcile_archive(snapshot, archive, missing_backup)
    assert missing["missing"] == 1
    assert not missing["reconciled"]

    with archive.open("a") as stream:
        stream.write("{}\n")
    with pytest.raises(ValueError, match="SHA256"):
        verify_archive(snapshot, archive)
    with pytest.raises(ValueError, match="SHA256"):
        restore_archive(archive, tmp_path / "bad.db")
    assert not (tmp_path / "bad.db").exists()


def test_archive_rejects_bad_source_and_naive_cutoff(tmp_path: Path) -> None:
    source = tmp_path / "live.db"
    SQLiteStore(str(source))
    snapshot = tmp_path / "snapshot.db"
    create_backup(source, snapshot)
    archive = tmp_path / "older.jsonl"
    with pytest.raises(ValueError, match="timezone"):
        create_archive(snapshot, archive, datetime(2026, 9, 27))
    assert not archive.exists()
    source_archive = create_archive(snapshot, archive, datetime(2026, 9, 27, tzinfo=UTC))
    assert source_archive["count"] == 0
    assert verify_archive(snapshot, archive) == source_archive
    with snapshot.open("ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(ValueError, match="SHA256"):
        verify_archive(snapshot, archive)
    # A valid archive can still be inspected in isolation after the source is lost.
    assert restore_archive(archive, tmp_path / "recovered.db")["restored_events"] == 0


def test_restore_rejects_invalid_event_and_leaves_no_destination(tmp_path: Path) -> None:
    source = tmp_path / "live.db"
    SQLiteStore(str(source))
    snapshot = tmp_path / "snapshot.db"
    create_backup(source, snapshot)
    archive = tmp_path / "older.jsonl"
    create_archive(snapshot, archive, datetime(2026, 9, 28, tzinfo=UTC))
    archive.write_text("{}\n")
    manifest_path = tmp_path / "older.jsonl.manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
    manifest["count"] = 1
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        restore_archive(archive, tmp_path / "invalid.db")
    assert not (tmp_path / "invalid.db").exists()
