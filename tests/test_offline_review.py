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


def review_endpoint(client):
    capture = client.get("/v1/offline-review/captures/sample", headers=HEADERS).json()
    finding_id = capture["findings"][0]["incident_id"]
    return f"/v1/offline-review/captures/sample/findings/{finding_id}/reviews"


def test_assessment_history_conflict_restart_and_backup(tmp_path, monkeypatch):
    from adaptive_security.backup import create_backup, verify_backup

    output = bundle(tmp_path, monkeypatch)
    original_files = {p.name: p.read_bytes() for p in output.iterdir() if p.is_file()}
    database = tmp_path / "live.db"
    client = TestClient(create_app(str(database), KEY, {}, offline_review_path=str(output)))
    url = review_endpoint(client)
    assert client.get(url).status_code == 401
    initial = client.get(url, headers=HEADERS).json()
    assert initial["revision"] == 0 and initial["entries"] == []
    edit = dict(
        review_key=initial["review_key"],
        expected_revision=0,
        disposition="suspicious",
        note=" Review original XML <script>literal</script> ",
    )
    assert client.post(url, json=edit).status_code == 401
    first = client.post(url, json=edit, headers=HEADERS)
    assert first.status_code == 201
    assert first.json()["actor"] is None
    assert first.json()["request_id"] == first.headers["X-Request-ID"]
    assert first.json()["note"] == edit["note"].strip()
    assert client.post(url, json=edit, headers=HEADERS).status_code == 409
    edit.update(expected_revision=1, disposition="inconclusive", note="Need other evidence")
    assert client.post(url, json=edit, headers=HEADERS).json()["revision"] == 2
    restarted = TestClient(create_app(str(database), KEY, {}, offline_review_path=str(output)))
    page = restarted.get(url + "?limit=1", headers=HEADERS).json()
    assert page["revision"] == 2 and len(page["entries"]) == 1
    assert page["entries"][0]["disposition"] == "inconclusive"
    assert (
        restarted.get(url + "?limit=1&offset=1", headers=HEADERS).json()["entries"][0]
        == first.json()
    )
    assert restarted.get(url + "?limit=101", headers=HEADERS).status_code == 422
    assert restarted.get("/v1/incidents", headers=HEADERS).json() == []
    assert original_files == {p.name: p.read_bytes() for p in output.iterdir() if p.is_file()}
    snapshot = tmp_path / "backup.db"
    create_backup(database, snapshot)
    verify_backup(snapshot)
    restored = TestClient(create_app(str(snapshot), KEY, {}, offline_review_path=str(output)))
    assert restored.get(url, headers=HEADERS).json() == restarted.get(url, headers=HEADERS).json()


def test_named_review_permission_and_server_attribution(tmp_path, monkeypatch):
    output = bundle(tmp_path, monkeypatch)
    keys = {
        "reviewer": {"key": "r" * 64, "permissions": ["review"]},
        "closer": {"key": "c" * 64, "permissions": ["close"]},
        "reader": {"key": "d" * 64, "permissions": []},
    }
    client = TestClient(create_app(str(tmp_path / "live.db"), KEY, keys, str(output)))
    url = review_endpoint(client)
    initial = client.get(url, headers=HEADERS).json()
    edit = dict(
        review_key=initial["review_key"],
        expected_revision=0,
        disposition="benign_activity",
        note="Expected administrative activity",
    )
    assert client.post(url, json=edit, headers=HEADERS).status_code == 401
    for token, status in [("wrong", 401), ("c" * 64, 403), ("d" * 64, 403)]:
        assert (
            client.post(url, json=edit, headers={**HEADERS, "X-Analyst-Key": token}).status_code
            == status
        )
    headers = {**HEADERS, "X-Analyst-Key": "r" * 64}
    assert client.get("/v1/auth/identity", headers=headers).json()["permissions"] == ["review"]
    assert client.post(url, json={**edit, "actor": "fake"}, headers=headers).status_code == 422
    response = client.post(url, json=edit, headers=headers)
    assert response.status_code == 201 and response.json()["actor"] == "reviewer"
    assert "r" * 64 not in response.text
    assert client.post("/v1/incidents/missing/close", headers=headers).status_code == 403


@pytest.mark.parametrize(
    "change",
    [
        dict(note="  "),
        dict(note="x" * 2001),
        dict(disposition="true_positive"),
        dict(expected_revision=-1),
        dict(expected_revision=True),
        dict(review_key="wrong"),
    ],
)
def test_assessment_invalid_input_cannot_write(tmp_path, monkeypatch, change):
    output = bundle(tmp_path, monkeypatch)
    client = TestClient(create_app(str(tmp_path / "live.db"), KEY, {}, str(output)))
    url = review_endpoint(client)
    initial = client.get(url, headers=HEADERS).json()
    edit = dict(
        review_key=initial["review_key"],
        expected_revision=0,
        disposition="needs_review",
        note="Not reviewed yet",
    )
    assert client.post(url, json={**edit, **change}, headers=HEADERS).status_code == 422
    assert client.get(url, headers=HEADERS).json()["revision"] == 0


def test_review_does_not_follow_changed_capture_context(tmp_path, monkeypatch):
    output = bundle(tmp_path, monkeypatch)
    database = str(tmp_path / "live.db")
    client = TestClient(create_app(database, KEY, {}, str(output)))
    url = review_endpoint(client)
    initial = client.get(url, headers=HEADERS).json()
    edit = dict(
        review_key=initial["review_key"],
        expected_revision=0,
        disposition="suspicious",
        note="Initial evidence assessment",
    )
    assert client.post(url, json=edit, headers=HEADERS).status_code == 201
    # Same capture and finding IDs, but different declared run provenance.
    report_path = output / "report.json"
    report = json.loads(report_path.read_text())
    report["interpretation"] = "Reprocessed run with changed context"
    report_path.write_text(json.dumps(report))
    newer = TestClient(create_app(database, KEY, {}, str(output)))
    state = newer.get(url, headers=HEADERS).json()
    assert state["review_key"] != initial["review_key"] and state["revision"] == 0
    assert newer.post(url, json=edit, headers=HEADERS).status_code == 409
    assert (
        newer.get(url.replace("/findings/", "/findings/missing-"), headers=HEADERS).status_code
        == 404
    )


def test_concurrent_assessment_saves_have_one_winner(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    from adaptive_security.offline_annotations import ReviewConflict, ReviewEdit
    from adaptive_security.store import SQLiteStore

    store = SQLiteStore(str(tmp_path / "live.db"))
    key = "a" * 64
    edit = ReviewEdit(review_key=key, expected_revision=0, disposition="suspicious", note="Review")

    def save(request_id):
        try:
            store.append_offline_review(key, edit, "analyst", request_id)
            return "saved"
        except ReviewConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(save, ["one", "two"])) == ["conflict", "saved"]
    assert store.offline_reviews(key, 20, 0).revision == 1


def export_endpoint(client):
    reviews = review_endpoint(client)
    state = client.get(reviews, headers=HEADERS).json()
    return reviews.replace("/reviews", "/export"), state


def test_review_export_auth_scope_hashes_and_saved_history(tmp_path, monkeypatch):
    output = bundle(tmp_path, monkeypatch)
    database = str(tmp_path / "live.db")
    client = TestClient(create_app(database, KEY, {}, str(output)))
    url, state = export_endpoint(client)
    params = {"review_key": state["review_key"], "expected_revision": 0}
    assert client.get(url, params=params).status_code == 401
    assert client.get(url, headers=HEADERS).status_code == 422
    assert (
        client.get(url, params={**params, "review_key": "a" * 64}, headers=HEADERS).status_code
        == 409
    )
    response = client.get(url, params=params, headers=HEADERS)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"].startswith('attachment; filename="sample-')
    assert response.headers["x-content-type-options"] == "nosniff"
    exported = response.json()
    assert exported["format"] == "asp.offline-finding-review" and exported["format_version"] == 1
    assert exported["assessment_history"]["latest_revision"] == 0
    assert exported["scope"]["original_evtx_included"] is False
    assert exported["binding"]["capture"]["label"] == "unlabeled"
    assert exported["scope"]["evidence_records"] == 25
    assert len(exported["binding"]["evidence"]) == 25
    assert exported["binding"]["evidence"][0]["attributes"]["raw_xml"] == "<private-record />"
    assert (
        sha256(
            json.dumps(exported["binding"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        == state["review_key"]
    )
    digest = exported.pop("payload_sha256")
    assert (
        sha256(json.dumps(exported, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        == digest
    )
    # Saved journal changes make the previously displayed export revision stale.
    edit = dict(
        review_key=state["review_key"],
        expected_revision=0,
        disposition="suspicious",
        note="Selected evidence assessment",
    )
    client.post(url.replace("/export", "/reviews"), headers=HEADERS, json=edit)
    assert client.get(url, params=params, headers=HEADERS).status_code == 409
    params["expected_revision"] = 1
    artifact = client.get(url, params=params, headers=HEADERS).json()
    assert artifact["assessment_history"]["entries"][0]["note"] == edit["note"]
    assert artifact["assessment_history"]["history_truncated"] is False
    assert KEY not in json.dumps(artifact)
    assert client.get("/v1/incidents", headers=HEADERS).json() == []


def test_export_omits_other_records_and_flags_truncated_history(tmp_path, monkeypatch):
    from adaptive_security.offline_annotations import ReviewEdit
    from adaptive_security.store import SQLiteStore

    output = bundle(tmp_path, monkeypatch)
    # Leave one record outside the stored finding; the loader checks complete evidence metadata.
    path = output / "sample.findings.json"
    findings = json.loads(path.read_text())
    finding = findings[0]
    finding["event_ids"] = finding["event_ids"][:-1]
    for signal in finding["signals"]:
        signal["evidence_event_ids"] = finding["event_ids"]
    records = [
        SecurityEvent.model_validate_json(line)
        for line in (output / "sample.events.jsonl").read_text().splitlines()
    ]
    refs = set(finding["event_ids"])
    finding["entities"] = [
        entity.model_dump(mode="json")
        for entity in sorted(
            {entity for event in records if event.event_id in refs for entity in event.entities},
            key=lambda entity: (entity.type, entity.value),
        )
    ]
    path.write_text(json.dumps(findings))
    database = str(tmp_path / "live.db")
    client = TestClient(create_app(database, KEY, {}, str(output)))
    url, state = export_endpoint(client)
    store = SQLiteStore(database)
    for revision in range(101):
        store.append_offline_review(
            state["review_key"],
            ReviewEdit(
                review_key=state["review_key"],
                expected_revision=revision,
                disposition="needs_review",
                note=f"Assessment {revision + 1}",
            ),
            None,
            f"test-{revision}",
        )
    artifact = client.get(
        url, params=dict(review_key=state["review_key"], expected_revision=101), headers=HEADERS
    ).json()
    assert artifact["scope"]["capture_records"] == 25
    assert artifact["scope"]["evidence_records"] == 24
    assert len(artifact["binding"]["evidence"]) == 24
    assert records[-1].event_id not in {
        event["event_id"] for event in artifact["binding"]["evidence"]
    }
    history = artifact["assessment_history"]
    assert history["latest_revision"] == 101 and history["included_revisions"] == 100
    assert history["history_truncated"] is True
    assert [entry["revision"] for entry in history["entries"]] == list(range(101, 1, -1))
    assert (
        client.get(
            url.replace("/findings/", "/findings/missing-"),
            params=dict(review_key=state["review_key"], expected_revision=101),
            headers=HEADERS,
        ).status_code
        == 404
    )


def test_queue_latest_disposition_filters_and_progress(tmp_path, monkeypatch):
    output = bundle(tmp_path, monkeypatch)
    database = str(tmp_path / "live.db")
    client = TestClient(create_app(database, KEY, {}, str(output)))
    url = "/v1/offline-review/queue"
    assert client.get(url).status_code == 401
    initial = client.get(url, headers=HEADERS)
    assert initial.headers["cache-control"] == "no-store"
    page = initial.json()
    assert (
        page["counts"]["total"]
        == page["counts"]["needs_review"]
        == page["counts"]["unassessed"]
        == 1
    )
    assert page["entries"][0]["disposition"] == "needs_review"
    review_url = review_endpoint(client)
    state = client.get(review_url, headers=HEADERS).json()
    edit = dict(
        review_key=state["review_key"],
        expected_revision=0,
        disposition="confirmed_malicious",
        note="Supporting evidence note",
    )
    assert client.post(review_url, json=edit, headers=HEADERS).status_code == 201
    page = client.get(url, headers=HEADERS).json()
    assert page["counts"]["assessed"] == 1 and page["counts"]["needs_review"] == 0
    assert page["counts"]["dispositions"]["confirmed_malicious"] == 1
    assert page["capture_counts"]["sample"]["assessed"] == 1
    assert page["entries"][0]["revision"] == 1 and page["entries"][0]["actor"] is None
    assert "Supporting evidence note" not in str(page)
    assert client.get(url + "?disposition=needs_review", headers=HEADERS).json()["matching"] == 0
    assert (
        client.get(url + "?disposition=confirmed_malicious", headers=HEADERS).json()["matching"]
        == 1
    )
    # Reopening review changes workload but retains prior history.
    client.post(
        review_url,
        json={**edit, "expected_revision": 1, "disposition": "needs_review"},
        headers=HEADERS,
    )
    page = client.get(url, headers=HEADERS).json()
    assert page["counts"]["assessed"] == 0 and page["counts"]["needs_review"] == 1
    assert page["counts"]["unassessed"] == 0 and page["entries"][0]["revision"] == 2
    assert client.get(url + "?capture_id=missing", headers=HEADERS).status_code == 404
    for query in ["disposition=invalid", "limit=101", "offset=-1"]:
        assert client.get(url + "?" + query, headers=HEADERS).status_code == 422
    restarted = TestClient(create_app(database, KEY, {}, str(output)))
    assert restarted.get(url, headers=HEADERS).json() == page
    assert client.get("/v1/incidents", headers=HEADERS).json() == []


def test_queue_cross_capture_pagination_and_changed_context(tmp_path, monkeypatch):
    from dataclasses import replace

    from adaptive_security.offline_review import ReviewSource

    output = bundle(tmp_path, monkeypatch)
    original = load_review(output)
    capture = original.captures["sample"]
    findings = tuple(
        capture.findings[0].model_copy(update={"incident_id": f"finding-{i:02}"}) for i in range(23)
    )
    first = replace(capture, findings=findings)
    second = replace(
        capture,
        summary=capture.summary.model_copy(update={"capture_id": "other"}),
        findings=findings[:1],
    )
    holder = {"snapshot": replace(original, captures={"sample": first, "other": second})}
    monkeypatch.setattr(ReviewSource, "snapshot", lambda _self: holder["snapshot"])
    client = TestClient(create_app(str(tmp_path / "live.db"), KEY, {}, str(output)))
    url = "/v1/offline-review/queue"
    page = client.get(url, headers=HEADERS).json()
    assert page["counts"]["total"] == 24 and len(page["entries"]) == 20
    rest = client.get(url + "?offset=20", headers=HEADERS).json()["entries"]
    assert len(rest) == 4
    identities = [(row["capture_id"], row["finding_id"]) for row in page["entries"] + rest]
    assert len(set(identities)) == 24
    review_url = "/v1/offline-review/captures/sample/findings/finding-00/reviews"
    state = client.get(review_url, headers=HEADERS).json()
    client.post(
        review_url,
        json=dict(
            review_key=state["review_key"],
            expected_revision=0,
            disposition="suspicious",
            note="Only the selected finding",
        ),
        headers=HEADERS,
    )
    selected = client.get(url + "?capture_id=sample&disposition=suspicious", headers=HEADERS).json()
    assert selected["matching"] == 1 and selected["entries"][0]["finding_id"] == "finding-00"
    assert selected["counts"]["total"] == 24  # Summary always covers the entire run.
    other = client.get(url + "?capture_id=other", headers=HEADERS).json()
    assert other["entries"][0]["revision"] == 0  # Same finding ID in another capture is separate.
    holder["snapshot"] = replace(holder["snapshot"], provenance={"review_scope": "Changed context"})
    changed = client.get(url, headers=HEADERS).json()
    assert changed["counts"]["assessed"] == 0 and changed["counts"]["unassessed"] == 24


def test_unconfigured_queue_has_zero_counts(tmp_path, monkeypatch):
    monkeypatch.delenv("ASP_OFFLINE_REVIEW_PATH", raising=False)
    client = TestClient(create_app(str(tmp_path / "live.db"), KEY, {}))
    page = client.get("/v1/offline-review/queue", headers=HEADERS).json()
    assert page["configured"] is False and page["entries"] == []
    assert page["counts"]["total"] == page["matching"] == 0


def test_latest_review_batch_is_scoped_and_crosses_sql_chunk_boundary(tmp_path):
    from adaptive_security.offline_annotations import ReviewEdit
    from adaptive_security.store import SQLiteStore

    store = SQLiteStore(str(tmp_path / "live.db"))
    keys = [f"{i:064x}" for i in range(401)]
    for key in [*keys, "f" * 64]:
        edit = ReviewEdit(
            review_key=key, expected_revision=0, disposition="suspicious", note="Initial"
        )
        store.append_offline_review(key, edit, "analyst", "fixture")
    store.append_offline_review(
        keys[-1],
        ReviewEdit(
            review_key=keys[-1], expected_revision=1, disposition="inconclusive", note="Latest"
        ),
        "analyst",
        "latest",
    )
    result = store.latest_offline_reviews(keys)
    assert len(result) == 401 and "f" * 64 not in result
    assert result[keys[-1]].revision == 2
    assert store.latest_offline_reviews([]) == {}


def test_readable_report_contains_complete_export_and_escaped_notes(tmp_path, monkeypatch):
    import re
    from html import unescape

    output = bundle(tmp_path, monkeypatch)
    client = TestClient(create_app(str(tmp_path / "live.db"), KEY, {}, str(output)))
    url, state = export_endpoint(client)
    note = "<script>window.injected=true</script><img src=https://example.test/private>"
    client.post(
        url.replace("/export", "/reviews"),
        headers=HEADERS,
        json=dict(
            review_key=state["review_key"], expected_revision=0, disposition="suspicious", note=note
        ),
    )
    params = dict(review_key=state["review_key"], expected_revision=1, format="html")
    assert client.get(url, params=params).status_code == 401
    response = client.get(url, params=params, headers=HEADERS)
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/html")
    assert response.headers["content-disposition"].endswith('-review.html"')
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-review-history-truncated"] == "false"
    html = response.text
    assert "<script>" not in html and "<img " not in html
    assert "&lt;script&gt;window.injected=true" in html
    assert "First 25 of 25 selected" in html
    raw = re.search(r'<pre id="complete-export">(.*?)</pre>', html, flags=re.S).group(1)
    artifact = json.loads(unescape(raw))
    assert artifact["assessment_history"]["entries"][0]["note"] == note
    assert len(artifact["binding"]["evidence"]) == 25
    expected = artifact.pop("payload_sha256")
    assert (
        sha256(json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        == expected
    )
    assert artifact["binding"]["evidence"][0]["attributes"]["raw_xml"] == "<private-record />"
    assert (
        client.get(url, params={**params, "expected_revision": 0}, headers=HEADERS).status_code
        == 409
    )
    assert client.get(url, params={**params, "format": "pdf"}, headers=HEADERS).status_code == 422


def test_report_overview_caps_rows_without_losing_embedded_evidence(tmp_path, monkeypatch):
    output = bundle(tmp_path, monkeypatch, number=105)
    client = TestClient(create_app(str(tmp_path / "live.db"), KEY, {}, str(output)))
    url, state = export_endpoint(client)
    response = client.get(
        url,
        headers=HEADERS,
        params=dict(review_key=state["review_key"], expected_revision=0, format="html"),
    )
    assert response.status_code == 200
    assert "First 100 of 105 selected" in response.text
    assert "No saved assessments" in response.text
    assert "sample-event" not in response.text
    assert response.text.count("<tr><td>") == 100
    assert "event-104" in response.text
