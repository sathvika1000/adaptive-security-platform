import json
from hashlib import sha256

import pytest
from fastapi.testclient import TestClient

from adaptive_security.api import create_app
from adaptive_security.capture_validation import freeze, run
from adaptive_security.domain.events import EventCategory, SecurityEvent
from adaptive_security.offline_review import BundleReader, load_review

KEY = "offline-test-key"
HEADERS = {"X-API-Key": KEY}


def bundle(tmp_path, monkeypatch, label="unlabeled", number=25):
    import adaptive_security.capture_validation as module

    raw = b"controlled EVTX parser boundary input"
    (tmp_path / "source.evtx").write_bytes(raw)
    capture = {
        "capture_id": "sample",
        "path": "source.evtx",
        "partition": "development",
        "label": label,
        "label_reference": "review-notes",
        "environment": "synthetic test",
        "collection_start": "2020-01-01T00:00:00Z",
        "collection_end": "2020-01-01T00:05:00Z",
    }
    if label != "unlabeled":
        capture.update(
            reviewer="analyst",
            reviewed_at="2020-01-02T00:00:00Z",
            label_basis="Controlled test label",
        )
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
            {"version": 1, "rule_id": "auth.explicit_credential_fanout", "captures": [capture]}
        )
    )
    frozen = tmp_path / "frozen.json"
    freeze(plan, frozen)
    events = [
        SecurityEvent(
            event_id=f"event-{i:03}",
            source="evtx",
            category=EventCategory.OTHER,
            event_time="2020-01-01T00:01:00Z",
            observed_time="2020-01-01T00:01:00Z",
            attributes={
                "capture_sha256": sha256(raw).hexdigest(),
                "channel": "Security",
                "provider": "Microsoft-Windows-Security-Auditing",
                "windows_event_id": 4648,
                "raw_xml": "<private-record />",
                "raw": {
                    "TargetUserName": f"user{i}",
                    "Hostname": "host",
                    "SubjectUserSid": "caller-sid",
                    "SubjectLogonId": "0x123",
                    "ProcessId": "0x456",
                    "TargetServerName": "server",
                },
            },
        )
        for i in range(number)
    ]
    monkeypatch.setattr(module, "load_capture", lambda *args: events)
    output = tmp_path / "review"
    run(frozen, output)
    return output


@pytest.mark.parametrize(
    "label,verdict",
    [
        ("unlabeled", "unlabeled"),
        ("malicious", "true_positive"),
        ("benign", "false_positive"),
    ],
)
def test_validated_snapshot_keeps_capture_label_and_original_evidence(
    tmp_path, monkeypatch, label, verdict
):
    output = bundle(tmp_path, monkeypatch, label)
    snapshot = load_review(output)
    capture = snapshot.captures["sample"]
    assert capture.summary.verdict == verdict and capture.summary.records == 25
    assert capture.summary.partition == "development"
    assert len(capture.findings) == 1 and len(capture.findings[0].event_ids) == 25
    assert capture.events[0].attributes["raw_xml"] == "<private-record />"
    assert "declarations" in snapshot.provenance["review_scope"]


def test_authenticated_read_only_api_evidence_paging_and_live_database_isolation(
    tmp_path, monkeypatch
):
    output = bundle(tmp_path, monkeypatch)
    app = create_app(str(tmp_path / "live.db"), KEY, offline_review_path=str(output))
    client = TestClient(app)
    assert client.get("/v1/offline-review").status_code == 401
    assert client.get("/v1/offline-review/captures/sample").status_code == 401
    assert client.get("/v1/offline-review/captures/sample/events").status_code == 401
    response = client.get("/v1/offline-review", headers=HEADERS)
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    assert response.json()["captures"][0]["finding_count"] == 1
    capture = client.get("/v1/offline-review/captures/sample", headers=HEADERS).json()
    finding_id = capture["findings"][0]["incident_id"]
    page = client.get(
        "/v1/offline-review/captures/sample/events?offset=20&limit=20&finding_id=" + finding_id,
        headers=HEADERS,
    ).json()
    assert len(page) == 5 and page[0]["event_id"] == "event-020"
    assert (
        client.get(
            "/v1/offline-review/captures/sample/events?limit=101", headers=HEADERS
        ).status_code
        == 422
    )
    assert client.get("/v1/offline-review/captures/other", headers=HEADERS).status_code == 404
    assert (
        client.get(
            "/v1/offline-review/captures/sample/events?finding_id=other", headers=HEADERS
        ).status_code
        == 404
    )
    assert (
        client.post("/v1/offline-review/captures/sample/close", headers=HEADERS).status_code == 404
    )
    assert client.get("/v1/incidents", headers=HEADERS).json() == []
    assert client.get("/v1/events/evtx/event-000", headers=HEADERS).status_code == 404
    # Snapshot stays stable if an operator changes the on-disk bundle; restart to load new outputs.
    (output / "report.json").write_text("invalid")
    assert client.get("/v1/offline-review", headers=HEADERS).status_code == 200


def test_disabled_and_invalid_review_leave_live_api_available_without_path_leaks(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("ASP_OFFLINE_REVIEW_PATH", raising=False)
    client = TestClient(create_app(str(tmp_path / "disabled.db"), KEY))
    assert client.get("/v1/offline-review", headers=HEADERS).json() == {
        "configured": False,
        "captures": [],
    }
    assert client.get("/v1/offline-review/captures/sample", headers=HEADERS).status_code == 404
    path = tmp_path / "private-missing-output"
    client = TestClient(
        create_app(str(tmp_path / "invalid.db"), KEY, offline_review_path=str(path))
    )
    response = client.get("/v1/offline-review", headers=HEADERS)
    assert response.status_code == 503 and "private-missing-output" not in response.text
    assert client.get("/ready").status_code == 200
    assert client.get("/v1/incidents", headers=HEADERS).json() == []


@pytest.mark.parametrize(
    "mutation",
    [
        "original",
        "record-count",
        "event-digest",
        "duplicate-event",
        "finding-ref",
        "finding-rule",
        "finding-time",
        "case-checksum",
    ],
)
def test_corrupted_bundle_fails_closed(tmp_path, monkeypatch, mutation):
    output = bundle(tmp_path, monkeypatch, "malicious")
    if mutation == "original":
        (output / "sample.evtx").write_bytes(b"changed")
    elif mutation == "record-count":
        path = output / "report.json"
        report = json.loads(path.read_text())
        report["inventory"][0]["records"] += 1
        path.write_text(json.dumps(report))
    elif mutation in ("event-digest", "duplicate-event"):
        path = output / "sample.events.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        if mutation == "event-digest":
            rows[0]["attributes"]["capture_sha256"] = "0" * 64
        else:
            rows[1]["event_id"] = rows[0]["event_id"]
        path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    elif mutation == "case-checksum":
        (output / "sample.case.jsonl").write_text("modified private case")
    else:
        path = output / "sample.findings.json"
        findings = json.loads(path.read_text())
        if mutation == "finding-ref":
            findings[0]["event_ids"][0] = "foreign"
        if mutation == "finding-rule":
            findings[0]["signals"][0]["rule_id"] = "different"
        if mutation == "finding-time":
            findings[0]["first_seen"] = "2019-01-01T00:00:00Z"
        path.write_text(json.dumps(findings))
    with pytest.raises(ValueError):
        load_review(output)


def test_review_file_paths_and_size_limits(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-outside.json")
    outside.write_text("private")
    (tmp_path / "linked.json").symlink_to(outside)
    with pytest.raises(ValueError, match="escapes"):
        BundleReader(tmp_path).read("linked.json")
    with pytest.raises(ValueError, match="escapes"):
        BundleReader(tmp_path).read("../outside.json")
    (tmp_path / "large").write_bytes(b"xxxx")
    with pytest.raises(ValueError, match="too large"):
        BundleReader(tmp_path).read("large", maximum=3)
