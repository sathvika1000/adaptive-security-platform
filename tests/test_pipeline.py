from pathlib import Path

from fastapi.testclient import TestClient

from adaptive_security.api import create_app


def alert(event_id: str, minute: int, user: str = "alice", host: str = "web-01") -> dict:
    return {
        "id": event_id,
        "timestamp": f"2026-09-27T02:{minute:02d}:00Z",
        "rule": {"id": "5710", "level": 5, "groups": ["authentication_failed"]},
        "agent": {"name": host},
        "data": {"srcuser": user},
    }


def test_ingest_correlate_persist_retrieve_and_deduplicate(tmp_path: Path) -> None:
    path = str(tmp_path / "events.db")
    client = TestClient(create_app(path, "secret"))
    headers = {"x-api-key": "secret"}

    assert client.post("/v1/events/wazuh", json=alert("a", 0)).status_code == 401
    assert client.get("/v1/incidents").status_code == 401
    first = client.post("/v1/events/wazuh", json=alert("a", 0), headers=headers)
    assert first.status_code == 200
    assert first.json()["incident"] is None
    second = client.post("/v1/events/wazuh", json=alert("b", 5), headers=headers)
    assert second.status_code == 200
    incident = second.json()["incident"]
    assert incident["event_ids"] == ["a", "b"]
    assert incident["severity"] == 5

    repeat = client.post("/v1/events/wazuh", json=alert("b", 5), headers=headers)
    assert repeat.json()["incident"]["incident_id"] == incident["incident_id"]
    assert client.get("/v1/incidents", headers=headers).json() == [incident]
    restarted = TestClient(create_app(path, "secret"))
    result = restarted.get(f"/v1/incidents/{incident['incident_id']}", headers=headers)
    assert result.json() == incident
    assert restarted.get("/v1/incidents/missing", headers=headers).status_code == 404


def test_correlation_boundaries_and_invalid_payload(tmp_path: Path) -> None:
    client = TestClient(create_app(str(tmp_path / "events.db"), "secret"))
    headers = {"x-api-key": "secret"}
    for payload in (
        alert("a", 0),
        alert("different-user", 1, user="bob"),
        alert("different-host", 2, host="web-02"),
        alert("late", 16),
    ):
        response = client.post("/v1/events/wazuh", json=payload, headers=headers)
        assert response.json()["incident"] is None
    assert client.get("/v1/incidents", headers=headers).json() == []
    invalid = client.post("/v1/events/wazuh", json={"id": "bad"}, headers=headers)
    assert invalid.status_code == 422
    naive = alert("naive", 3)
    naive["timestamp"] = "2026-09-27T02:03:00"
    assert client.post("/v1/events/wazuh", json=naive, headers=headers).status_code == 422


def test_missing_api_key_fails_closed(tmp_path: Path) -> None:
    client = TestClient(create_app(str(tmp_path / "events.db"), api_key=""))
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/v1/incidents").status_code == 503
