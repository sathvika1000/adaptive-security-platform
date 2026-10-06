from hashlib import sha256

import pytest
from pydantic import ValidationError

from adaptive_security.capture_validation import CaptureEntry, FrozenPlan, Plan, freeze, run
from adaptive_security.domain.events import EventCategory, SecurityEvent


def entry(**updates):
    return {
        "capture_id": "reviewed-capture",
        "path": "sample.evtx",
        "label_reference": "review-notes/one",
        "environment": "isolated lab",
        "collection_start": "2020-01-01T00:00:00Z",
        "collection_end": "2020-01-01T00:10:00Z",
        **updates,
    }


def prepare(tmp_path, captures=None):
    (tmp_path / "sample.evtx").write_bytes(b"controlled parser boundary bytes")
    path = tmp_path / "plan.json"
    path.write_text(
        Plan(
            version=1,
            rule_id="auth.explicit_credential_fanout",
            captures=tuple(CaptureEntry.model_validate(c) for c in (captures or [entry()])),
        ).model_dump_json()
    )
    return path


def records():
    return [
        SecurityEvent(
            event_id="one",
            source="evtx",
            category=EventCategory.OTHER,
            event_time="2020-01-01T00:01:00Z",
            observed_time="2020-01-01T00:01:00Z",
            attributes={"windows_event_id": 1102, "raw_xml": "private XML"},
        )
    ]


@pytest.mark.parametrize(
    "updates",
    [
        {"label": "benign"},
        {"label": "malicious", "reviewer": "analyst"},
        {"label": "benign", "reviewer": "analyst", "reviewed_at": "2020-01-02T00:00:00Z"},
        {
            "label": "benign",
            "reviewer": " ",
            "reviewed_at": "2020-01-02T00:00:00Z",
            "label_basis": "review",
        },
        {"collection_end": "2020-01-01T00:00:00Z"},
        {"collection_start": "2020-01-01T00:00:00"},
    ],
)
def test_labels_require_explicit_review_and_aware_positive_collection_interval(updates):
    with pytest.raises(ValidationError):
        CaptureEntry.model_validate(entry(**updates))


def test_freeze_does_not_parse_or_default_unknown_background_to_benign(tmp_path, monkeypatch):
    import adaptive_security.capture_validation as module

    path = prepare(tmp_path)
    monkeypatch.setattr(module, "load_capture", lambda *args: pytest.fail("freeze parsed records"))
    frozen_path = tmp_path / "frozen.json"
    frozen = freeze(path, frozen_path)
    assert frozen.captures[0].label == "unlabeled"
    assert frozen.captures[0].partition == "development"
    assert (
        frozen.captures[0].capture_sha256
        == sha256((tmp_path / "sample.evtx").read_bytes()).hexdigest()
    )
    assert frozen_path.stat().st_mode & 0o777 == 0o600
    assert len(frozen.implementation_sha256) == 8
    with pytest.raises(ValueError, match="exists"):
        freeze(path, frozen_path)


@pytest.mark.parametrize("path", ["../outside.evtx", "/tmp/absolute.evtx"])
def test_paths_cannot_escape_plan_root(tmp_path, path):
    plan = prepare(tmp_path, [entry(path=path)])
    with pytest.raises(ValueError, match="inside"):
        freeze(plan, tmp_path / "frozen.json")


def test_symlink_escape_and_moved_reservation_rejected(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside.evtx"
    outside.write_bytes(b"outside")
    (tmp_path / "link.evtx").symlink_to(outside)
    plan = prepare(tmp_path, [entry(path="link.evtx")])
    with pytest.raises(ValueError, match="inside"):
        freeze(plan, tmp_path / "frozen.json")
    with pytest.raises(ValueError, match="beside"):
        freeze(plan, tmp_path.parent / "different-root.json")


def test_duplicates_and_known_development_bytes_reject_heldout(tmp_path, monkeypatch):
    import adaptive_security.capture_validation as module

    plan = prepare(tmp_path, [entry(), entry(capture_id="second")])
    with pytest.raises(ValueError, match="duplicate capture bytes"):
        freeze(plan, tmp_path / "frozen.json")
    plan = prepare(tmp_path, [entry(), entry()])
    with pytest.raises(ValueError, match="duplicate capture ID"):
        freeze(plan, tmp_path / "frozen.json")
    plan = prepare(tmp_path, [entry(partition="held_out")])
    monkeypatch.setattr(
        module, "DEVELOPMENT_DIGESTS", {sha256((tmp_path / "sample.evtx").read_bytes()).hexdigest()}
    )
    with pytest.raises(ValueError, match="development"):
        freeze(plan, tmp_path / "frozen.json")


def test_changed_implementation_or_capture_fails_without_partial_results(tmp_path):
    plan = prepare(tmp_path)
    frozen_path = tmp_path / "frozen.json"
    frozen = freeze(plan, frozen_path)
    original = frozen_path.read_bytes()
    modified = frozen.model_copy(update={"implementation_sha256": {}})
    frozen_path.write_text(modified.model_dump_json())
    output = tmp_path / "result"
    with pytest.raises(ValueError, match="implementation differs"):
        run(frozen_path, output)
    frozen_path.write_bytes(original)
    (tmp_path / "sample.evtx").write_bytes(b"changed")
    with pytest.raises(ValueError, match="checksum"):
        run(frozen_path, output)
    assert not output.exists() and not list(tmp_path.glob(".capture-validation-*"))


@pytest.mark.parametrize("label", ["benign", "malicious", "unlabeled"])
def test_reviewed_labels_route_and_unknown_stays_out_of_metrics(tmp_path, monkeypatch, label):
    import adaptive_security.capture_validation as module

    review = (
        {}
        if label == "unlabeled"
        else {
            "reviewer": "private-analyst",
            "reviewed_at": "2020-01-02T00:00:00Z",
            "label_basis": "Complete capture reviewed against recorded lab activity",
        }
    )
    path = prepare(tmp_path, [entry(label=label, **review)])
    frozen_path = tmp_path / "frozen.json"
    freeze(path, frozen_path)
    monkeypatch.setattr(module, "load_capture", lambda *args: records())
    output = tmp_path / "result"
    report = run(frozen_path, output)
    assert report["inventory"][0]["label"] == label
    assert report["inventory"][0]["records"] == 1
    assert report["inventory"][0]["telemetry_coverage"]["status"] == "no_eligible_telemetry"
    assert report["validation_status"]["captures_without_eligible_telemetry"] == 1
    assert report["validation_status"]["captures_with_eligible_telemetry"] == 0
    assert report["validation_status"]["production_false_alert_rate"] is None
    assert report["validation_status"]["live_deployment"].startswith("disabled")
    if label == "unlabeled":
        assert not report["datasets"]
        assert not (output / "reviewed-capture.case.jsonl").exists()
    else:
        summary = report["datasets"][0]["summary"]
        assert summary["true_negative" if label == "benign" else "false_negative"] == 1
        assert summary["precision"] is None and summary["recall"] is None
    assert (output / "frozen-plan.json").read_bytes() == frozen_path.read_bytes()
    assert output.stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in output.iterdir())
    with pytest.raises(ValueError, match="output exists"):
        run(frozen_path, output)


def test_collection_bounds_do_not_silently_drop_events(tmp_path, monkeypatch):
    import adaptive_security.capture_validation as module

    path = prepare(tmp_path, [entry(collection_end="2020-01-01T00:00:01Z")])
    frozen_path = tmp_path / "frozen.json"
    freeze(path, frozen_path)
    monkeypatch.setattr(module, "load_capture", lambda *args: records())
    with pytest.raises(ValueError, match="outside declared"):
        run(frozen_path, tmp_path / "result")
    assert not (tmp_path / "result").exists()


def test_modified_frozen_manifest_cannot_redeclare_known_data_heldout(tmp_path, monkeypatch):
    import adaptive_security.capture_validation as module

    path = prepare(tmp_path)
    frozen_path = tmp_path / "frozen.json"
    frozen = freeze(path, frozen_path)
    monkeypatch.setattr(module, "DEVELOPMENT_DIGESTS", {frozen.captures[0].capture_sha256})
    frozen = frozen.model_copy(
        update={"captures": (frozen.captures[0].model_copy(update={"partition": "held_out"}),)}
    )
    frozen_path.write_text(frozen.model_dump_json())
    assert FrozenPlan.model_validate_json(frozen_path.read_bytes()).captures
    with pytest.raises(ValueError, match="development"):
        run(frozen_path, tmp_path / "result")


def test_review_cannot_predate_complete_collection():
    with pytest.raises(ValidationError, match="review time"):
        CaptureEntry.model_validate(
            entry(
                label="benign",
                reviewer="analyst",
                label_basis="review",
                reviewed_at="2019-12-31T00:00:00Z",
            )
        )


def test_finding_in_reviewed_benign_capture_is_false_positive(tmp_path, monkeypatch):
    import adaptive_security.capture_validation as module

    plan = prepare(
        tmp_path,
        [
            entry(
                label="benign",
                reviewer="analyst",
                reviewed_at="2020-01-02T00:00:00Z",
                label_basis="Authorized routine authentication; complete review",
            )
        ],
    )
    data = Plan.model_validate_json(plan.read_bytes()).model_copy(
        update={"rule_id": "auth.kerberos_password_spray"}
    )
    plan.write_text(data.model_dump_json())
    frozen = tmp_path / "frozen.json"
    freeze(plan, frozen)
    events = [
        records()[0].model_copy(
            update={
                "event_id": f"event-{i}",
                "source_ip": "192.0.2.1",
                "attributes": {
                    "windows_event_id": 4771,
                    "channel": "Security",
                    "provider": "Microsoft-Windows-Security-Auditing",
                    "raw": {"Hostname": "dc", "TargetUserName": f"user{i}", "Status": "0x18"},
                },
            }
        )
        for i in range(5)
    ]
    monkeypatch.setattr(module, "load_capture", lambda *args: events)
    report = run(frozen, tmp_path / "result")
    assert report["datasets"][0]["summary"]["false_positive"] == 1
    assert report["inventory"][0]["finding_count"] == 1
    assert report["inventory"][0]["telemetry_coverage"]["eligible_records"] == 5
    assert report["validation_status"]["captures_with_eligible_telemetry"] == 1
    assert report["validation_status"]["reviewed_benign_captures"] == 1
    assert report["validation_status"]["production_false_alert_rate"] is None
