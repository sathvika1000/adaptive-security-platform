from pathlib import Path

from fastapi.testclient import TestClient

from adaptive_security.api import create_app
from adaptive_security.connectors.wazuh import WazuhConnector


def test_sca_check_metadata_survives_ingestion_without_raw_details(tmp_path: Path) -> None:
    client = TestClient(create_app(str(tmp_path / "events.db"), "secret"))
    headers = {"X-API-Key": "secret"}
    payload = {
        "id": "sca-check-1",
        "timestamp": "2026-09-27T20:37:19Z",
        "rule": {"id": "19007", "level": 7, "groups": ["sca"]},
        "agent": {"id": "001", "name": "MacBook"},
        "data": {"sca": {
            "type": "check", "policy": "CIS macOS", "scan_id": "42",
            "check": {"id": 123, "title": "Check firewall", "result": "failed",
                      "remediation": "private command", "command": ["sensitive"]},
            "unrelated": "do not store",
        }},
    }
    result = client.post("/v1/events/wazuh", json=payload, headers=headers)
    assert result.status_code == 200
    attributes = result.json()["event"]["attributes"]
    assert attributes == {
        "rule_id": "19007", "groups": ["sca"],
        "sca": {"type": "check", "policy": "CIS macOS", "scan_id": "42",
                "check": {"id": "123", "title": "Check firewall", "result": "failed"}},
    }
    stored = client.get("/v1/events/wazuh/sca-check-1", headers=headers)
    assert stored.json()["attributes"] == attributes


def test_sca_summary_and_not_applicable_fields_are_bounded() -> None:
    base = {
        "id": "sca-2", "timestamp": "2026-09-27T20:37:19Z",
        "rule": {"id": "19009", "level": 3, "groups": ["sca"]},
        "data": {"sca": {
            "type": "check", "policy": "A" * 1000,
            "check": {"id": "5", "status": "Not applicable", "title": "T" * 1000},
        }},
    }
    connector = WazuhConnector()
    sca = connector.normalize(base).attributes["sca"]
    assert sca["check"]["status"] == "Not applicable"
    assert len(sca["policy"]) == 256
    assert len(sca["check"]["title"]) == 256
    base["data"]["sca"] = {"type": "summary", "score": "52", "passed": 50,
                             "failed": "46", "invalid": "87"}
    assert connector.normalize(base).attributes["sca"] == {
        "type": "summary", "score": "52", "passed": "50", "failed": "46", "invalid": "87"
    }
    base["data"]["sca"] = ["malformed"]
    assert "sca" not in connector.normalize(base).attributes
