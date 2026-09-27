from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from adaptive_security.api import create_app
from adaptive_security.domain.events import SecurityEvent


def alert(event_id: str, minute: int, user: str = "alice", host: str = "web-01") -> dict:
    return {
        "id": event_id,
        "timestamp": (datetime(2026, 9, 27, 2, tzinfo=UTC) +
                      timedelta(minutes=minute)).isoformat(),
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


def test_success_only_activity_does_not_create_incident(tmp_path: Path) -> None:
    client = TestClient(create_app(str(tmp_path / "events.db"), "secret"))
    headers = {"x-api-key": "secret"}
    for event_id, minute in (("one", 0), ("two", 1)):
        payload = alert(event_id, minute)
        payload["rule"]["groups"] = ["authentication_success"]
        response = client.post("/v1/events/wazuh", json=payload, headers=headers)
        assert response.status_code == 200
        assert response.json()["incident"] is None
    assert client.get("/v1/incidents", headers=headers).json() == []


def test_incident_id_survives_growth_late_alerts_and_restart(tmp_path: Path) -> None:
    path = str(tmp_path / "events.db")
    client = TestClient(create_app(path, "secret"))
    headers = {"x-api-key": "secret"}
    for event_id, minute in (("first", 10), ("second", 12)):
        response = client.post("/v1/events/wazuh", json=alert(event_id, minute), headers=headers)
    incident_id = response.json()["incident"]["incident_id"]

    late = client.post("/v1/events/wazuh", json=alert("late", 8), headers=headers)
    assert late.json()["incident"]["incident_id"] == incident_id
    more = client.post("/v1/events/wazuh", json=alert("more", 15), headers=headers)
    assert more.json()["incident"]["incident_id"] == incident_id
    assert more.json()["incident"]["event_ids"] == ["late", "first", "second", "more"]

    restarted = TestClient(create_app(path, "secret"))
    assert restarted.get(f"/v1/incidents/{incident_id}", headers=headers).status_code == 200
    repeated = restarted.post("/v1/events/wazuh", json=alert("second", 12), headers=headers)
    assert repeated.json()["incident"]["incident_id"] == incident_id


def test_bridge_merges_incidents_under_oldest_id(tmp_path: Path) -> None:
    client = TestClient(create_app(str(tmp_path / "events.db"), "secret"))
    headers = {"x-api-key": "secret"}
    ids = []
    for event_id, minute in (("a", 0), ("b", 5), ("c", 40), ("d", 45)):
        response = client.post("/v1/events/wazuh", json=alert(event_id, minute), headers=headers)
        if response.json()["incident"]:
            ids.append(response.json()["incident"]["incident_id"])
    assert len(set(ids)) == 2
    client.post("/v1/events/wazuh", json=alert("bridge-1", 20), headers=headers)
    merged = client.post("/v1/events/wazuh", json=alert("bridge-2", 30), headers=headers)
    assert merged.json()["incident"]["incident_id"] == ids[0]
    assert len(client.get("/v1/incidents", headers=headers).json()) == 1
    alias = client.get(f"/v1/incidents/{ids[1]}", headers=headers)
    assert alias.json() == merged.json()["incident"]


def test_merged_aliases_survive_transitive_merge_restart_and_close(tmp_path: Path) -> None:
    path = str(tmp_path / "events.db")
    client = TestClient(create_app(path, "secret"))
    headers = {"x-api-key": "secret"}
    ids = []
    for event_id, minute in (("a", 0), ("b", 5), ("c", 40), ("d", 45),
                             ("e", 80), ("f", 85)):
        incident = client.post("/v1/events/wazuh", json=alert(event_id, minute),
                               headers=headers).json()["incident"]
        if incident and incident["incident_id"] not in ids:
            ids.append(incident["incident_id"])
    assert len(ids) == 3
    for event_id, minute in (("first-bridge", 60), ("second-bridge", 70),
                             ("third-bridge", 20), ("fourth-bridge", 30)):
        merged = client.post("/v1/events/wazuh", json=alert(event_id, minute),
                             headers=headers).json()["incident"]
    assert merged["incident_id"] == ids[0]

    restarted = TestClient(create_app(path, "secret"))
    for alias_id in ids[1:]:
        response = restarted.get(f"/v1/incidents/{alias_id}", headers=headers)
        assert response.json() == merged
    history = restarted.get(f"/v1/incidents/{ids[2]}/history", headers=headers).json()
    assert [(item["action"], item["merged_into"]) for item in history] == [
        ("merged", ids[1]), ("merged", ids[0])
    ]
    closed = restarted.post(f"/v1/incidents/{ids[2]}/close", headers=headers)
    assert closed.json()["incident_id"] == ids[0]
    assert closed.json()["status"] == "closed"
    assert restarted.get(f"/v1/incidents/{ids[0]}", headers=headers).json() == closed.json()
    assert len(restarted.get("/v1/incidents", headers=headers).json()) == 1
    repeated = restarted.post("/v1/events/wazuh", json=alert("f", 85), headers=headers)
    assert repeated.json()["incident"] == closed.json()


def test_correlation_reads_only_connected_identity_run(tmp_path: Path) -> None:
    client = TestClient(create_app(str(tmp_path / "events.db"), "secret"))
    headers = {"x-api-key": "secret"}
    for index in range(30):
        response = client.post("/v1/events/wazuh", json=alert(str(index), index * 60),
                               headers=headers)
        assert response.json()["incident"] is None

    with patch.object(SecurityEvent, "model_validate_json",
                      wraps=SecurityEvent.model_validate_json) as decode:
        response = client.post("/v1/events/wazuh", json=alert("new", 29 * 60 + 5),
                               headers=headers)
    assert response.json()["incident"]["event_ids"] == ["29", "new"]
    assert decode.call_count == 1


def test_close_late_evidence_and_new_failure_reopen(tmp_path: Path) -> None:
    path = str(tmp_path / "events.db")
    client = TestClient(create_app(path, "secret"))
    headers = {"x-api-key": "secret"}
    for event_id, minute in (("a", 10), ("b", 12)):
        response = client.post("/v1/events/wazuh", json=alert(event_id, minute), headers=headers)
    incident_id = response.json()["incident"]["incident_id"]
    url = f"/v1/incidents/{incident_id}/close"
    assert client.post(url).status_code == 401
    assert client.post("/v1/incidents/missing/close", headers=headers).status_code == 404
    assert client.post(url, headers=headers).json()["status"] == "closed"
    assert client.post(url, headers=headers).json()["status"] == "closed"

    late = client.post("/v1/events/wazuh", json=alert("late", 8), headers=headers)
    assert late.json()["incident"]["status"] == "closed"
    repeated = client.post("/v1/events/wazuh", json=alert("b", 12), headers=headers)
    assert repeated.json()["incident"]["status"] == "closed"
    restarted = TestClient(create_app(path, "secret"))
    stored = restarted.get(f"/v1/incidents/{incident_id}", headers=headers)
    assert stored.json()["status"] == "closed"

    fresh = restarted.post("/v1/events/wazuh", json=alert("fresh", 15), headers=headers)
    assert fresh.json()["incident"]["incident_id"] == incident_id
    assert fresh.json()["incident"]["status"] == "open"


def test_incident_history_records_only_transitions_and_survives_restart(tmp_path: Path) -> None:
    path = str(tmp_path / "events.db")
    client = TestClient(create_app(path, "secret"))
    headers = {"x-api-key": "secret"}
    assert client.get("/v1/incidents/missing/history").status_code == 401
    assert client.get("/v1/incidents/missing/history", headers=headers).status_code == 404
    client.post("/v1/events/wazuh", json=alert("a", 10), headers=headers)
    incident = client.post("/v1/events/wazuh", json=alert("b", 12),
                           headers=headers).json()["incident"]
    incident_id = incident["incident_id"]
    history_url = f"/v1/incidents/{incident_id}/history"
    assert client.get(history_url, headers=headers).json() == []

    closed = client.post(f"/v1/incidents/{incident_id}/close", headers=headers)
    client.post(f"/v1/incidents/{incident_id}/close", headers=headers)
    client.post("/v1/events/wazuh", json=alert("late", 8), headers=headers)
    client.post("/v1/events/wazuh", json=alert("b", 12), headers=headers)
    first_history = client.get(history_url, headers=headers).json()
    assert len(first_history) == 1
    assert first_history[0]["action"] == "closed"
    assert first_history[0]["request_id"] == closed.headers["x-request-id"]
    assert first_history[0]["event_id"] is None
    assert first_history[0]["incident_id"] == incident_id
    assert first_history[0]["occurred_at"]

    client.post("/v1/events/wazuh", json=alert("fresh", 15), headers=headers)
    restarted = TestClient(create_app(path, "secret"))
    history = restarted.get(history_url, headers=headers).json()
    assert [item["action"] for item in history] == ["closed", "reopened"]
    assert [item["transition_id"] for item in history] == sorted(
        item["transition_id"] for item in history
    )
    assert history[1]["event_source"] == "wazuh"
    assert history[1]["event_id"] == "fresh"
    assert history[1]["request_id"] is None


def test_history_follows_merge_aliases(tmp_path: Path) -> None:
    path = str(tmp_path / "events.db")
    client = TestClient(create_app(path, "secret"))
    headers = {"x-api-key": "secret"}
    ids = []
    for event_id, minute in (("a", 0), ("b", 5), ("c", 40), ("d", 45)):
        incident = client.post("/v1/events/wazuh", json=alert(event_id, minute),
                               headers=headers).json()["incident"]
        if incident and incident["incident_id"] not in ids:
            ids.append(incident["incident_id"])
    client.post(f"/v1/incidents/{ids[1]}/close", headers=headers)
    client.post("/v1/events/wazuh", json=alert("bridge-1", 20), headers=headers)
    client.post("/v1/events/wazuh", json=alert("bridge-2", 30), headers=headers)
    restarted = TestClient(create_app(path, "secret"))
    for incident_id in ids:
        history = restarted.get(f"/v1/incidents/{incident_id}/history", headers=headers).json()
        assert len(history) == 2
        assert history[0]["incident_id"] == ids[1]
        assert history[0]["action"] == "closed"
        assert history[1]["incident_id"] == ids[1]
        assert history[1]["action"] == "merged"
        assert history[1]["merged_into"] == ids[0]
        assert history[1]["event_id"] == "bridge-2"


def test_incident_and_history_pagination(tmp_path: Path) -> None:
    client = TestClient(create_app(str(tmp_path / "events.db"), "secret"))
    headers = {"x-api-key": "secret"}
    ids = []
    for index, minute in enumerate((0, 40, 80)):
        client.post("/v1/events/wazuh", json=alert(f"first-{index}", minute),
                    headers=headers)
        incident = client.post("/v1/events/wazuh", json=alert(f"second-{index}", minute + 5),
                               headers=headers).json()["incident"]
        ids.append(incident["incident_id"])

    listed = client.get("/v1/incidents", headers=headers).json()
    assert [item["incident_id"] for item in listed] == sorted(ids)
    pages = [client.get(f"/v1/incidents?limit=1&offset={offset}",
                        headers=headers).json() for offset in range(4)]
    assert pages == [[incident] for incident in listed] + [[]]
    for query in ("limit=0", "limit=101", "offset=-1", "limit=oops"):
        assert client.get(f"/v1/incidents?{query}", headers=headers).status_code == 422

    incident_id = ids[0]
    close_url = f"/v1/incidents/{incident_id}/close"
    history_url = f"/v1/incidents/{incident_id}/history"
    client.post(close_url, headers=headers)
    client.post("/v1/events/wazuh", json=alert("reopen", 10), headers=headers)
    client.post(close_url, headers=headers)
    history = client.get(history_url, headers=headers).json()
    assert [item["action"] for item in history] == ["closed", "reopened", "closed"]
    history_pages = [client.get(f"{history_url}?limit=1&offset={offset}",
                                headers=headers).json() for offset in range(4)]
    assert history_pages == [[entry] for entry in history] + [[]]
    for query in ("limit=0", "limit=101", "offset=-1"):
        assert client.get(f"{history_url}?{query}", headers=headers).status_code == 422
