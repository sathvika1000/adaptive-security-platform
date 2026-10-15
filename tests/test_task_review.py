import asyncio
import hashlib
import json
import os
from pathlib import Path

import pytest

from adaptive_security import investigation_tasks, task_review


@pytest.fixture
def report_file(tmp_path):
    suite = Path(__file__).resolve().parents[1] / "examples/evaluation/analyst-tasks.json"
    digest = hashlib.sha256(suite.read_bytes()).hexdigest()
    report = asyncio.run(
        investigation_tasks.run_tasks(investigation_tasks.load_tasks(suite, digest))
    )
    report["suite_file_sha256"] = digest
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    pin = hashlib.sha256(path.read_bytes()).hexdigest()
    return path, pin, task_review.load_report(path, pin)


def complete(report, digest):
    sheet = task_review.prepare(report, digest)
    sheet.reviewer = "test-reviewer"
    for row in sheet.assessments:
        row.notes = "Controlled test assessment; no actual model inference."
        for dimension in task_review.DIMENSIONS:
            setattr(row, dimension, "not_assessable")
    return sheet


def test_prepare_has_no_invented_assessments(report_file):
    _, digest, report = report_file
    sheet = task_review.prepare(report, digest)
    assert sheet.reviewer == ""
    assert len(sheet.assessments) == 3
    assert all(row.evidence_support is None for row in sheet.assessments)
    with pytest.raises(ValueError, match="attribution"):
        task_review.summarize(report, digest, sheet)


def test_summary_retains_not_assessable_and_original(report_file):
    path, digest, report = report_file
    before = path.read_bytes()
    summary = task_review.summarize(report, digest, complete(report, digest))
    assert summary["tasks_reviewed"] == 3
    assert summary["mode"] == "deterministic-smoke"
    assert summary["ratings"]["evidence_support"] == {"not_assessable": 3}
    assert summary["run_statuses"] == {"completed": 3}
    assert path.read_bytes() == before
    assert "accuracy" not in summary


@pytest.mark.parametrize(
    "change", ["digest", "suite", "duplicate", "missing", "run", "notes", "rating"]
)
def test_binding_and_completeness(report_file, change):
    _, digest, report = report_file
    sheet = complete(report, digest)
    if change == "digest":
        sheet.report_sha256 = "f" * 64
    elif change == "suite":
        sheet.suite_semantic_sha256 = "f" * 64
    elif change == "duplicate":
        sheet.assessments.append(sheet.assessments[0])
    elif change == "missing":
        sheet.assessments.pop()
    elif change == "run":
        sheet.assessments[0].run_id = "other-run"
    elif change == "notes":
        sheet.assessments[0].notes = " "
    else:
        sheet.assessments[0].evidence_support = None
    with pytest.raises(ValueError):
        task_review.summarize(report, digest, sheet)


def test_tampered_file_and_invalid_schema(report_file, tmp_path):
    path, digest, _ = report_file
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError):
        task_review.load_report(path, digest)
    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"schema_version":1}')
    with pytest.raises(ValueError):
        task_review.load_report(invalid, hashlib.sha256(invalid.read_bytes()).hexdigest())
    with pytest.raises(ValueError):
        task_review.read_pinned(path, digest, 2)


def test_cli_round_trip_permissions_and_no_overwrite(report_file, tmp_path, monkeypatch):
    path, digest, report = report_file
    draft = tmp_path / "draft.json"
    monkeypatch.setattr(
        "sys.argv", ["review", "prepare", str(path), str(draft), "--report-sha256", digest]
    )
    assert task_review.main() == 0
    assert json.loads(draft.read_text())["reviewer"] == ""
    if os.name == "posix":
        assert draft.stat().st_mode & 0o777 == 0o600
    assert task_review.main() == 2
    draft.write_text(complete(report, digest).model_dump_json())
    review_pin = hashlib.sha256(draft.read_bytes()).hexdigest()
    output = tmp_path / "summary.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "review",
            "summarize",
            str(path),
            str(output),
            "--report-sha256",
            digest,
            "--review",
            str(draft),
            "--review-sha256",
            review_pin,
        ],
    )
    assert task_review.main() == 0
    assert json.loads(output.read_text())["review_file_sha256"] == review_pin
    assert path.read_bytes()  # source remains present


def test_failed_runs_and_concerns_are_retained(report_file):
    _, digest, report = report_file
    report.tasks[0].run.status = "failed"
    report.tasks[0].run.conclusion = None
    sheet = complete(report, digest)
    sheet.assessments[1].evidence_support = "concern"
    summary = task_review.summarize(report, digest, sheet)
    assert summary["run_statuses"] == {"failed": 1, "completed": 2}
    assert summary["tasks_reviewed"] == 3
    assert summary["ratings"]["evidence_support"] == {"not_assessable": 2, "concern": 1}


def test_review_schema_rejects_unknown_ratings_and_fields(report_file):
    _, digest, report = report_file
    payload = complete(report, digest).model_dump()
    payload["assessments"][0]["evidence_support"] = "pass"
    with pytest.raises(ValueError):
        task_review.ReviewSheet.model_validate(payload)
    payload = complete(report, digest).model_dump()
    payload["approved_for_production"] = True
    with pytest.raises(ValueError):
        task_review.ReviewSheet.model_validate(payload)
