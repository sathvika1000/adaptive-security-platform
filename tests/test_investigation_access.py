import json
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from test_offline_review import HEADERS, KEY, bundle

from adaptive_security.api import create_app
from adaptive_security.investigation_access import investigation_identities
from adaptive_security.offline_review import ReviewSource, load_review

READ_KEY = "dedicated-read-key-" + "r" * 32
READ_HEADERS = {"X-Investigation-Key": READ_KEY}


@pytest.fixture
def access_fixture(tmp_path, monkeypatch):
    output = bundle(tmp_path, monkeypatch)
    original = load_review(output)
    capture = original.captures["sample"]
    # Simulate an already validated second capture to exercise actual cross-scope reads.
    other = replace(capture, summary=capture.summary.model_copy(update={"capture_id": "other"}))
    snapshot = replace(original, captures={"sample": capture, "other": other})
    monkeypatch.setattr(ReviewSource, "snapshot", lambda self: snapshot)
    finding_id = capture.findings[0].incident_id
    invocation = {
        "capture_id": "sample", "finding_id": finding_id,
        "review_key": snapshot.finding_keys[("sample", finding_id)],
    }
    config = {"research-agent": {"key": READ_KEY, "grants": [
        invocation | {"tools": ["get_finding_evidence", "get_related_events"]},
    ]}}
    client = TestClient(create_app(str(tmp_path / "access.db"), KEY,
                                 offline_review_path=str(output), investigation_keys=config))
    return client, invocation, config, snapshot


def test_request_logs_identify_caller_without_secrets_or_evidence(access_fixture, caplog):
    client, invocation, _, _ = access_fixture
    with caplog.at_level("INFO", logger="uvicorn.error"):
        client.post("/v1/investigation-tools/get_finding_evidence",
                    headers=READ_HEADERS, json=invocation)
        client.post("/v1/investigation-tools/get_telemetry_coverage",
                    headers=READ_HEADERS, json=invocation)
    messages = [record.message for record in caplog.records if record.name == "uvicorn.error"]
    logs = [json.loads(message) for message in messages]
    assert [entry["status"] for entry in logs] == [200, 403]
    assert all(entry["investigation_actor"] == "research-agent" for entry in logs)
    assert all(entry["request_id"] for entry in logs)
    joined = " ".join(messages)
    assert READ_KEY not in joined and invocation["review_key"] not in joined
    assert invocation["finding_id"] not in joined and "private-record" not in joined


def test_dedicated_credential_discovers_only_grants_and_executes_allowed_tools(access_fixture):
    client, invocation, _, _ = access_fixture
    response = client.get("/v1/investigation-tools/scopes", headers=READ_HEADERS)
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    assert response.json()["actor"] == "research-agent"
    assert response.json()["matching"] == 1
    grant = response.json()["entries"][0]
    assert grant == invocation | {
        "tools": ["get_finding_evidence", "get_related_events"], "stale": False,
    }
    assert READ_KEY not in response.text
    for tool in grant["tools"]:
        result = client.post(f"/v1/investigation-tools/{tool}",
                             headers=READ_HEADERS, json=invocation)
        assert result.status_code == 200
        assert result.json()["scope"]["capture_id"] == "sample"


def test_scope_tool_and_fingerprint_escalation_are_denied_without_existence_leaks(access_fixture):
    client, invocation, _, snapshot = access_fixture
    before = client.get("/v1/offline-review/queue", headers=HEADERS).json()
    changes = [
        {"capture_id": "other",
         "review_key": snapshot.finding_keys[("other", invocation["finding_id"])]},
        {"capture_id": "absent"}, {"finding_id": "absent"}, {"review_key": "0" * 64},
    ]
    details = []
    for change in changes:
        result = client.post("/v1/investigation-tools/get_finding_evidence",
                             headers=READ_HEADERS, json=invocation | change)
        assert result.status_code == 403
        details.append(result.json())
    assert all(detail == details[0] for detail in details)
    denied = client.post("/v1/investigation-tools/get_telemetry_coverage",
                         headers=READ_HEADERS, json=invocation)
    assert denied.status_code == 403
    assert client.get("/v1/offline-review/queue", headers=HEADERS).json() == before


@pytest.mark.parametrize("method,path,body", [
    ("get", "/v1/offline-review", None),
    ("get", "/v1/offline-review/queue", None),
    ("get", "/v1/offline-review/captures/sample/events", None),
    ("get", "/v1/incidents", None),
    ("get", "/v1/auth/identity", None),
    ("get", "/v1/storage/retention-preview", None),
    ("post", "/v1/events/wazuh", {}),
    ("post", "/v1/incidents/absent/close", {}),
    ("post", "/v1/offline-review/captures/sample/findings/absent/reviews", {}),
])
def test_investigation_token_cannot_use_other_protected_read_or_write_apis(
    access_fixture, method, path, body,
):
    client, _, _, _ = access_fixture
    for headers in (READ_HEADERS, {"X-API-Key": READ_KEY}):
        assert client.request(method, path, headers=headers, json=body).status_code == 401
    assert client.get("/v1/incidents", headers=HEADERS).json() == []


def test_credential_mixing_invalid_keys_and_admin_discovery_pagination(access_fixture):
    client, invocation, _, _ = access_fixture
    for path in ("/v1/investigation-tools/scopes", "/v1/investigation-tools/get_finding_evidence"):
        call = client.get if path.endswith("scopes") else client.post
        kwargs = {} if path.endswith("scopes") else {"json": invocation}
        assert call(path, headers=READ_HEADERS | HEADERS, **kwargs).status_code == 400
        assert call(path, headers={"X-Investigation-Key": "bad"}, **kwargs).status_code == 401
        assert call(path, headers={"X-API-Key": READ_KEY}, **kwargs).status_code == 401
        assert call(path, **kwargs).status_code == 401
    first = client.get("/v1/investigation-tools/scopes?limit=1", headers=HEADERS).json()
    assert first["matching"] == 2 and first["next_offset"] == 1
    second = client.get("/v1/investigation-tools/scopes?limit=1&offset=1", headers=HEADERS).json()
    assert second["next_offset"] is None
    assert {first["entries"][0]["capture_id"], second["entries"][0]["capture_id"]} == {
        "other", "sample",
    }
    assert client.get(
        "/v1/investigation-tools/scopes?limit=101", headers=READ_HEADERS
    ).status_code == 422


def test_changed_snapshot_does_not_renew_grant_or_disclose_new_fingerprint(
    access_fixture, monkeypatch,
):
    client, invocation, _, snapshot = access_fixture
    capture = snapshot.captures["sample"]
    changed = replace(snapshot, captures={"sample": replace(capture, metadata={"changed": True})})
    monkeypatch.setattr(ReviewSource, "snapshot", lambda self: changed)
    result = client.get("/v1/investigation-tools/scopes", headers=READ_HEADERS).json()
    assert result["entries"][0]["stale"]
    assert result["entries"][0]["review_key"] == invocation["review_key"]
    current = changed.finding_keys[("sample", invocation["finding_id"])]
    assert current != invocation["review_key"] and current not in json.dumps(result)
    assert client.post("/v1/investigation-tools/get_finding_evidence", headers=READ_HEADERS,
                       json=invocation).status_code == 409
    assert client.post("/v1/investigation-tools/get_finding_evidence", headers=READ_HEADERS,
                       json=invocation | {"review_key": current}).status_code == 403


def test_env_config_dedicated_only_operation_and_restart_revocation(
    tmp_path, monkeypatch, access_fixture,
):
    _, invocation, config, _ = access_fixture
    monkeypatch.setenv("ASP_INVESTIGATION_KEYS_JSON", json.dumps(config))
    monkeypatch.delenv("ASP_API_KEY", raising=False)
    dedicated = TestClient(create_app(str(tmp_path / "dedicated.db")))
    assert dedicated.post("/v1/investigation-tools/get_finding_evidence", headers=READ_HEADERS,
                          json=invocation).status_code == 200
    assert dedicated.get("/v1/incidents", headers=READ_HEADERS).status_code == 503
    revoked = TestClient(create_app(str(tmp_path / "revoked.db"), KEY, investigation_keys={}))
    assert revoked.get("/v1/investigation-tools/scopes", headers=READ_HEADERS).status_code == 401
    monkeypatch.setenv("ASP_INVESTIGATION_KEYS_JSON", '{"key":"secret"')
    with pytest.raises(ValueError, match="configuration JSON") as error:
        create_app(str(tmp_path / "invalid.db"), KEY)
    assert "secret" not in str(error.value)


@pytest.mark.parametrize("mutation", [
    "wildcard", "empty", "unknown_tool", "duplicate_tool", "duplicate_scope",
    "extra_field", "reuse_platform", "reuse_analyst", "reuse_identity", "short_key",
    "bad_actor", "non_object", "oversized",
])
def test_malformed_or_overprivileged_config_fails_at_startup(access_fixture, mutation):
    _, _, config, _ = access_fixture
    reserved = set()
    entry = config["research-agent"]
    grant = entry["grants"][0]
    if mutation == "wildcard":
        entry["grants"] = ["*"]
    elif mutation == "empty":
        entry["grants"] = []
    elif mutation == "unknown_tool":
        grant["tools"] = ["execute"]
    elif mutation == "duplicate_tool":
        grant["tools"] = ["get_finding_evidence"] * 2
    elif mutation == "duplicate_scope":
        entry["grants"] *= 2
    elif mutation == "extra_field":
        entry["admin"] = True
    elif mutation in ("reuse_platform", "reuse_analyst"):
        import hashlib
        reserved.add(hashlib.sha256(READ_KEY.encode()).hexdigest())
    elif mutation == "reuse_identity":
        config["second-agent"] = entry
    elif mutation == "short_key":
        entry["key"] = "secret"
    elif mutation == "bad_actor":
        config["unsafe actor"] = config.pop("research-agent")
    elif mutation == "non_object":
        config = []
    elif mutation == "oversized":
        config = {f"agent-{i}": entry for i in range(33)}
    with pytest.raises(ValueError) as error:
        investigation_identities(config, reserved)
    assert READ_KEY not in str(error.value) and "secret" not in str(error.value)


def test_actual_platform_and_analyst_key_collisions_are_rejected(access_fixture, tmp_path):
    _, _, config, _ = access_fixture
    for shared, analyst in [(READ_KEY, {}), (KEY, {"analyst": READ_KEY})]:
        with pytest.raises(ValueError, match="separate"):
            create_app(str(tmp_path / "collision.db"), shared,
                       analyst_keys=analyst, investigation_keys=config)
