import asyncio
import copy
import hashlib
import json
import os

import pytest

from adaptive_security import task_audit, task_session
from adaptive_security.domain.events import EntityRef
from adaptive_security.evidence_brief import MAX_FACTS, build_brief
from adaptive_security.investigation_tools import ToolResult
from adaptive_security.task_review import load_report


def response(index=0):
    task = json.loads(task_session.bundled_suite())["tasks"][index]
    return ToolResult.model_validate(task["evidence"])


def test_unread_empty_and_returned_records_are_distinct():
    unread = build_brief([])
    empty = build_brief([response(1)])
    present = build_brief([response()])
    assert unread["evidence_state"] == "not_queried"
    assert empty["evidence_state"] == "empty_event_pages"
    assert present["evidence_state"] == "returned_records"
    assert present["outcome_counts"] == {"failure": 1}
    assert any(gap["gap_id"] == "event_evidence_unread" for gap in unread["gap_catalog"])
    assert not any(gap["gap_id"] == "event_evidence_unread" for gap in empty["gap_catalog"])
    assert any(gap["gap_id"] == "collection_completeness" for gap in empty["gap_catalog"])


def test_identity_reference_does_not_resolve_authorization():
    result = response()
    assert build_brief([result])["records_without_identity_reference"] == 1
    result.events[0].entities = (EntityRef(type="user", value="account-a"),)
    brief = build_brief([result])
    assert brief["records_without_identity_reference"] == 0
    assert not any(gap["gap_id"] == "identity_context" for gap in brief["gap_catalog"])
    assert any(gap["gap_id"] == "authorization_context" for gap in brief["gap_catalog"])


def test_deduplication_conflicts_and_bounded_assertions():
    result = response()
    assert build_brief([result, result])["unique_returned_records"] == 1
    conflict = result.model_copy(deep=True)
    conflict.events[0].outcome = "success"
    with pytest.raises(ValueError, match="Conflicting"):
        build_brief([result, conflict])
    event = result.events[0]
    result.events = [event.model_copy(update={"event_id": str(i)}) for i in range(30)]
    brief = build_brief([result])
    assert brief["unique_returned_records"] == 30
    assert brief["outcome_counts"] == {"failure": 30}
    assert len(brief["observed_assertions"]) == MAX_FACTS
    assert brief["assertions_truncated"] is True
    assert any(gap["gap_id"] == "event_relationship" for gap in brief["gap_catalog"])


def test_injected_text_remains_inert_exact_returned_data():
    result = response(2)
    brief = build_brief([result])
    action = next(row for row in brief["observed_assertions"] if row["field"] == "action")
    assert action["value"] == result.events[0].action
    assert brief["outcome_counts"] == {"failure": 1}
    assert "verdict" not in brief


def test_next_check_flags_are_specific_and_do_not_claim_semantic_support():
    flags = task_audit.next_check_flags(
        ["get_finding_evidence", " GET_FINDING_EVIDENCE. ", "None available"],
        [response()],
    )
    assert sum(flag["code"] == "repeats_completed_read" for flag in flags) == 2
    assert any(flag["code"] == "duplicate_suggestion" for flag in flags)
    assert any(flag["code"] == "empty_or_placeholder" for flag in flags)
    assert (
        task_audit.next_check_flags(["Review finding evidence for another account."], [response()])
        == []
    )
    assert (
        task_audit.next_check_flags(["Read finding evidence"], [response()])[0]["code"]
        == "repeats_completed_read"
    )
    result = response()
    result.page.exhausted = False
    result.page.next_offset = 1
    assert not any(
        flag["code"] == "repeats_completed_read"
        for flag in task_audit.next_check_flags(["get_finding_evidence"], [result])
    )


@pytest.fixture
def session(tmp_path):
    directory = tmp_path / "session"
    asyncio.run(task_session.create_session(directory))
    return directory


def test_audit_leaves_report_and_review_unchanged_and_binds_input(session, tmp_path, monkeypatch):
    report_path = session / "report.json"
    original_report = report_path.read_bytes()
    original_review = (session / "review.json").read_bytes()
    output = tmp_path / "audit.json"
    monkeypatch.setattr("sys.argv", ["audit", str(session), str(output)])
    assert task_audit.main() == 0
    audit = json.loads(output.read_text())
    assert audit["report_sha256"] == hashlib.sha256(original_report).hexdigest()
    assert audit["task_count"] == 3
    assert all(row["semantic_review"] == "pending-human-review" for row in audit["tasks"])
    assert report_path.read_bytes() == original_report
    assert (session / "review.json").read_bytes() == original_review
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600
    assert task_audit.main() == 2


def test_audit_rejects_tampering_and_bad_journal_scope(session, tmp_path, monkeypatch):
    path = session / "report.json"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    report = load_report(path, digest)
    bad = copy.deepcopy(report)
    entry = next(item for item in bad.tasks[0].run.journal if item.get("outcome") == "accepted")
    entry["response"]["scope"]["capture_id"] = "other"
    with pytest.raises(ValueError, match="scope"):
        task_audit.audit_report(bad, digest)
    path.write_bytes(path.read_bytes() + b" ")
    monkeypatch.setattr("sys.argv", ["audit", str(session), str(tmp_path / "invalid.json")])
    assert task_audit.main() == 2
    assert not (tmp_path / "invalid.json").exists()


def test_direct_report_pin_mode(session, tmp_path, monkeypatch):
    path = session / "report.json"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(
        "sys.argv", ["audit", str(path), str(tmp_path / "audit.json"), "--report-sha256", digest]
    )
    assert task_audit.main() == 0
