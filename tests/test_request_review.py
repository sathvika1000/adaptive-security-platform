import asyncio
import copy
import hashlib
import json

import pytest

from adaptive_security import request_review as review
from adaptive_security.task_review import TaskReport
from adaptive_security.task_session import create_session


@pytest.fixture
def session(tmp_path):
    directory = tmp_path / "session"
    assert asyncio.run(create_session(directory, suite_version="neutral", structured_requests=True))
    raw = (directory / "report.json").read_bytes()
    return directory, TaskReport.model_validate_json(raw), hashlib.sha256(raw).hexdigest()


def rated(report, digest):
    sheet = review.prepare(report, digest)
    sheet.reviewer = "Development reviewer"
    for row in sheet.assessments:
        row.relevance = "supported"
        row.specificity = "concern"
        row.gap_resolution = "not_assessable"
        row.notes = "Needs event and time scope; source availability has not been established."
    return sheet


def test_review_inventory_blank_ratings_and_non_mutation(session):
    _, report, digest = session
    original = report.model_dump_json()
    sheet = review.prepare(report, digest)
    assert len(sheet.assessments) == 10
    for row in sheet.assessments:
        assert row.relevance is None and row.specificity is None and row.gap_resolution is None
        assert row.notes == "" and row.objective and row.gap_basis
        assert (
            row.request_sha256
            == hashlib.sha256(review.canonical(review.request_payload(row.request))).hexdigest()
        )
    sheet.assessments[0].request.evidence_needed = "Changed only on the review copy."
    assert report.model_dump_json() == original


def test_summary_counts_no_pass_score_and_any_review_order(session):
    _, report, digest = session
    sheet = rated(report, digest)
    sheet.assessments.reverse()
    result = review.summarize(report, digest, sheet)
    assert result["requests_reviewed"] == 10
    assert result["ratings"]["gap_resolution"] == {"not_assessable": 10}
    assert len(result["task_inventory"]) == 5
    assert not any(key in result for key in ("score", "accuracy", "passed"))


@pytest.mark.parametrize(
    "change",
    [
        "report",
        "suite",
        "missing",
        "duplicate",
        "task",
        "run",
        "index",
        "hash",
        "wording",
        "objective",
        "basis",
        "reviewer",
        "notes",
        "rating",
    ],
)
def test_incomplete_or_rebound_reviews_rejected(session, change):
    _, report, digest = session
    sheet = rated(report, digest)
    row = sheet.assessments[0]
    if change == "report":
        sheet.report_sha256 = "f" * 64
    elif change == "suite":
        sheet.suite_semantic_sha256 = "f" * 64
    elif change == "missing":
        sheet.assessments.pop()
    elif change == "duplicate":
        sheet.assessments[-1] = row.model_copy(deep=True)
    elif change == "task":
        row.task_id = "other-task"
    elif change == "run":
        row.run_id = "other-run"
    elif change == "index":
        row.request_index = 2
    elif change == "hash":
        row.request_sha256 = "f" * 64
    elif change == "wording":
        row.request.evidence_needed = "Edited requested evidence cannot inherit a review."
    elif change == "objective":
        row.objective = "Edited objective"
    elif change == "basis":
        row.gap_basis = "Edited basis"
    elif change == "reviewer":
        sheet.reviewer = " "
    elif change == "notes":
        row.notes = " "
    elif change == "rating":
        row.gap_resolution = None
    with pytest.raises(ValueError):
        review.summarize(report, digest, sheet)


def test_invalid_links_and_unaccepted_conclusions_rejected(session):
    _, report, digest = session
    corrupt = report.model_copy(deep=True)
    corrupt.tasks[0].run.conclusion.evidence_requests[0].evidence_source = "session_correlation"
    with pytest.raises(ValueError, match="active gap"):
        review.prepare(corrupt, digest)
    corrupt = report.model_copy(deep=True)
    corrupt.tasks[0].run.status = "blocked"
    with pytest.raises(ValueError, match="completed"):
        review.prepare(corrupt, digest)


def test_no_requests_and_tasks_without_conclusions_are_explicit(session):
    _, report, digest = session
    report.tasks[0].run.status = "blocked"
    report.tasks[0].run.conclusion = None
    sheet = rated(report, digest)
    summary = review.summarize(report, digest, sheet)
    assert summary["requests_reviewed"] == 8
    assert summary["task_inventory"][0]["accepted_request_count"] == 0
    assert summary["task_inventory"][0]["status"] == "blocked"
    for task in report.tasks:
        if task.run.conclusion:
            task.run.conclusion.evidence_requests = []
    with pytest.raises(ValueError, match="no accepted"):
        review.prepare(report, digest)


def test_cli_roundtrip_private_pins_and_no_overwrite(session, tmp_path, monkeypatch):
    directory, report, digest = session
    original = (directory / "report.json").read_bytes()
    sheet_path = directory / "request-review-v1.json"
    summary_path = directory / "request-summary-v1.json"

    def call(*args):
        monkeypatch.setattr("sys.argv", ["request-review", *map(str, args)])
        return review.main()

    assert call("prepare", directory, sheet_path) == 0
    assert sheet_path.stat().st_mode & 0o777 == 0o600
    blank = sheet_path.read_bytes()
    assert call("prepare", directory, sheet_path) == 2
    assert sheet_path.read_bytes() == blank
    assert (
        call(
            "summarize",
            directory,
            summary_path,
            "--review",
            sheet_path,
            "--review-sha256",
            hashlib.sha256(blank).hexdigest(),
        )
        == 2
    )
    assert not summary_path.exists()
    sheet_path.write_text(rated(report, digest).model_dump_json(indent=2))
    pin = hashlib.sha256(sheet_path.read_bytes()).hexdigest()
    assert (
        call(
            "summarize",
            directory,
            summary_path,
            "--review",
            sheet_path,
            "--review-sha256",
            "0" * 64,
        )
        == 2
    )
    assert (
        call("summarize", directory, summary_path, "--review", sheet_path, "--review-sha256", pin)
        == 0
    )
    result = json.loads(summary_path.read_bytes())
    assert result["review_file_sha256"] == pin
    assert result["report_sha256"] == digest
    assert (directory / "report.json").read_bytes() == original
    other = tmp_path / "explicit.json"
    assert call("prepare", directory / "report.json", other, "--report-sha256", digest) == 0
    altered = copy.deepcopy(json.loads(sheet_path.read_bytes()))
    altered["assessments"][0]["request"]["command"] = "execute"
    sheet_path.write_text(json.dumps(altered))
    assert (
        call(
            "summarize",
            directory,
            tmp_path / "bad.json",
            "--review",
            sheet_path,
            "--review-sha256",
            hashlib.sha256(sheet_path.read_bytes()).hexdigest(),
        )
        == 2
    )
