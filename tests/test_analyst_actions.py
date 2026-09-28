import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from adaptive_security.api import create_app


def _alert(event_id: str, minute: int) -> dict:
    return {
        "id": event_id, "timestamp": f"2026-09-27T02:{minute:02d}:00Z",
        "rule": {"id": "5710", "level": 5, "groups": ["authentication_failed"]},
        "agent": {"name": "host"}, "data": {"srcuser": "alice"},
    }


def test_analyst_keys_attribute_close_actions_and_survive_restart(tmp_path: Path) -> None:
    database = str(tmp_path / "events.db")
    configured = {"sathvika": "a" * 64, "reviewer": "b" * 64}
    client = TestClient(create_app(database, "shared-platform-key", configured))
    headers = {"X-API-Key": "shared-platform-key"}
    client.post("/v1/events/wazuh", json=_alert("first", 10), headers=headers)
    incident = client.post("/v1/events/wazuh", json=_alert("second", 12),
                           headers=headers).json()["incident"]
    close = f"/v1/incidents/{incident['incident_id']}/close"
    history = f"/v1/incidents/{incident['incident_id']}/history"
    identity = "/v1/auth/identity"

    assert client.get(identity).status_code == 401
    assert client.get(identity, headers=headers).status_code == 401
    assert client.get(identity, headers={**headers, "X-Analyst-Key": "wrong"})\
        .status_code == 401
    assert client.get(identity, headers={**headers, "X-Analyst-Key": configured["sathvika"]})\
        .json() == {"mode": "analyst", "actor": "sathvika", "permissions": ["close"]}

    assert client.post(close, headers=headers).status_code == 401
    assert client.post(close, headers={**headers, "X-Analyst-Key": "wrong"}).status_code == 401
    assert client.post(close, headers={**headers, "X-Analyst-Key": "shared-platform-key"})\
        .status_code == 401
    assert client.get(history, headers=headers).json() == []

    first = client.post(close, headers={**headers, "X-Analyst-Key": configured["sathvika"]})
    assert first.status_code == 200
    assert first.json()["status"] == "closed"
    client.post(close, headers={**headers, "X-Analyst-Key": configured["reviewer"]})
    assert [row["actor"] for row in client.get(history, headers=headers).json()] == ["sathvika"]

    client.post("/v1/events/wazuh", json=_alert("fresh", 15), headers=headers)
    restarted = TestClient(create_app(database, "shared-platform-key", configured))
    assert restarted.post(close, headers={**headers, "X-Analyst-Key": configured["reviewer"]})\
        .status_code == 200
    rows = restarted.get(history, headers=headers).json()
    assert [(row["action"], row["actor"]) for row in rows] == [
        ("closed", "sathvika"), ("reopened", None), ("closed", "reviewer"),
    ]
    assert rows[0]["request_id"] == first.headers["X-Request-ID"]
    assert "a" * 64 not in str(rows)


def test_analyst_configuration_rejects_duplicate_or_weak_keys(tmp_path: Path) -> None:
    database = str(tmp_path / "events.db")
    with pytest.raises(ValueError, match="unique"):
        create_app(database, "shared", {"one": "a" * 64, "two": "a" * 64})
    with pytest.raises(ValueError, match="at least 32"):
        create_app(database, "shared", {"one": "short"})
    with pytest.raises(ValueError, match="invalid analyst name"):
        create_app(database, "shared", {"name with spaces": "a" * 64})
    with pytest.raises(ValueError, match="distinct"):
        create_app(database, "a" * 64, {"one": "a" * 64})
    with pytest.raises(ValueError, match="permissions"):
        create_app(database, "shared", {"one": {"key": "a" * 64, "permissions": ["admin"]}})
    with pytest.raises(ValueError, match="permissions"):
        create_app(database, "shared", {"one": {"key": "a" * 64,
                                                "permissions": ["close", "close"]}})
    with pytest.raises(ValueError, match="key and permissions"):
        create_app(database, "shared", {"one": {"key": "a" * 64}})


def test_analyst_keys_load_from_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = "c" * 64
    monkeypatch.setenv("ASP_ANALYST_KEYS_JSON", json.dumps({"analyst-1": key}))
    client = TestClient(create_app(str(tmp_path / "events.db"), "shared"))
    headers = {"X-API-Key": "shared"}
    client.post("/v1/events/wazuh", json=_alert("first", 10), headers=headers)
    incident = client.post("/v1/events/wazuh", json=_alert("second", 12),
                           headers=headers).json()["incident"]
    url = f"/v1/incidents/{incident['incident_id']}/close"
    assert client.post(url, headers=headers).status_code == 401
    assert client.post(url, headers={**headers, "X-Analyst-Key": key}).status_code == 200


def test_identity_reports_legacy_shared_mode_without_attributing_actor(tmp_path: Path) -> None:
    client = TestClient(create_app(str(tmp_path / "events.db"), "shared", {}))
    response = client.get("/v1/auth/identity", headers={"X-API-Key": "shared"})
    assert response.status_code == 200
    assert response.json() == {"mode": "shared", "actor": None, "permissions": ["close"]}


def test_read_only_analyst_cannot_close_incident(tmp_path: Path) -> None:
    database = str(tmp_path / "events.db")
    keys = {
        "reviewer": {"key": "r" * 64, "permissions": []},
        "responder": {"key": "c" * 64, "permissions": ["close"]},
    }
    client = TestClient(create_app(database, "shared", keys))
    headers = {"X-API-Key": "shared"}
    client.post("/v1/events/wazuh", json=_alert("first", 10), headers=headers)
    incident = client.post("/v1/events/wazuh", json=_alert("second", 12),
                           headers=headers).json()["incident"]
    url = f"/v1/incidents/{incident['incident_id']}"
    reviewer_headers = {**headers, "X-Analyst-Key": "r" * 64}
    assert client.get("/v1/auth/identity", headers=reviewer_headers).json() == {
        "mode": "analyst", "actor": "reviewer", "permissions": [],
    }
    denied = client.post(url + "/close", headers=reviewer_headers)
    assert denied.status_code == 403
    assert client.get(url, headers=headers).json()["status"] == "open"
    assert client.get(url + "/history", headers=headers).json() == []

    responder_headers = {**headers, "X-Analyst-Key": "c" * 64}
    assert client.get("/v1/auth/identity", headers=responder_headers).json()["permissions"] == [
        "close"
    ]
    assert client.post(url + "/close", headers=responder_headers).json()["status"] == "closed"
    assert client.get(url + "/history", headers=headers).json()[0]["actor"] == "responder"
