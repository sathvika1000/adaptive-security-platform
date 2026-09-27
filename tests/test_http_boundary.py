import json
import logging
from pathlib import Path

from fastapi.testclient import TestClient

from adaptive_security.api import create_app
from adaptive_security.http import MAX_ALERT_BYTES


def alert() -> dict:
    return {
        "id": "boundary-alert",
        "timestamp": "2026-09-27T02:00:00Z",
        "rule": {"id": "5710", "level": 5, "groups": ["authentication_failed"]},
        "agent": {"name": "web-01"},
        "data": {"srcuser": "alice"},
    }


def test_ingestion_body_limit_accepts_boundary_and_rejects_oversize(tmp_path: Path) -> None:
    client = TestClient(create_app(str(tmp_path / "events.db"), "secret"))
    headers = {"x-api-key": "secret", "content-type": "application/json"}
    payload = alert()
    payload["padding"] = ""
    initial = json.dumps(payload, separators=(",", ":")).encode()
    payload["padding"] = "x" * (MAX_ALERT_BYTES - len(initial))
    boundary = json.dumps(payload, separators=(",", ":")).encode()
    assert len(boundary) == MAX_ALERT_BYTES

    accepted = client.post("/v1/events/wazuh", content=boundary, headers=headers)
    assert accepted.status_code == 200
    assert accepted.json()["event"]["event_id"] == "boundary-alert"
    assert accepted.headers["x-request-id"]

    oversized = boundary + b"x"
    rejected = client.post("/v1/events/wazuh", content=oversized, headers=headers)
    assert rejected.status_code == 413
    assert rejected.headers["x-request-id"] != accepted.headers["x-request-id"]
    understated = {**headers, "content-length": "1"}
    response = client.post("/v1/events/wazuh", content=oversized, headers=understated)
    assert response.status_code == 413


def test_request_log_excludes_payload_and_credentials(tmp_path: Path, caplog) -> None:
    client = TestClient(create_app(str(tmp_path / "events.db"), "private-key"))
    with caplog.at_level(logging.INFO, logger="adaptive_security.api"):
        response = client.post(
            "/v1/events/wazuh", json=alert(), headers={"x-api-key": "private-key"}
        )
    assert response.status_code == 200
    entries = [json.loads(record.message) for record in caplog.records
               if record.name == "adaptive_security.api"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["request_id"] == response.headers["x-request-id"]
    assert entry["method"] == "POST"
    assert entry["path"] == "/v1/events/wazuh"
    assert entry["status"] == 200
    assert entry["duration_ms"] >= 0
    assert "alice" not in caplog.text
    assert "private-key" not in caplog.text
