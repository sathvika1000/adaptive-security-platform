import asyncio
import copy
import hashlib
import json
from datetime import timedelta
from html.parser import HTMLParser

import pytest

from adaptive_security import reasoning_audit as reasoning
from adaptive_security.investigation_runner import ObservationClaim
from adaptive_security.task_review import TaskReport
from adaptive_security.task_session import create_session


@pytest.fixture
def session(tmp_path):
    directory = tmp_path / "session"
    assert asyncio.run(
        create_session(directory, suite_version="neutral", shared_request_scope=True)
    )
    raw = (directory / "report.json").read_bytes()
    return directory, TaskReport.model_validate_json(raw), hashlib.sha256(raw).hexdigest()


def test_explicit_statement_context_and_unrequested_relationship_gap(session):
    _, report, digest = session
    task = report.tasks[4]
    text = "A failure was followed by a success, possibly due to recovery."
    task.run.conclusion.hypotheses = [text]
    task.run.conclusion.alternative_explanations = ["A different session is possible."]
    task.run.conclusion.observations = list(task.rubric.required_observations)
    original = report.model_dump_json()
    worksheet = reasoning.build_worksheet(report, digest)
    row = worksheet.tasks[4]
    assert row.statements[0].text == text
    assert row.statements[0].statement_id == "hypotheses:0"
    assert row.statements[1].statement_id == "alternative_explanations:0"
    assert all(
        statement.citation_linkage == "conclusion_level_only" for statement in row.statements
    )
    assert all(citation["matches_returned_field"] for citation in row.conclusion_citations)
    assert row.temporal_context["state"] == "all_timestamps_equal"
    assert any(gap["gap_id"] == "event_relationship" for gap in row.unrequested_active_gaps)
    assert row.gap_coverage_state == "validated_structured_request_partition"
    assert row.semantic_review == "pending-human-review"
    assert report.model_dump_json() == original
    assert "score" not in worksheet.model_dump()


def test_empty_blocked_legacy_and_invalid_scope_are_distinguished(session):
    _, report, digest = session
    worksheet = reasoning.build_worksheet(report, digest)
    assert worksheet.tasks[1].evidence_state == "empty_event_pages"
    assert worksheet.tasks[1].temporal_context["state"] == "no_returned_events"
    assert worksheet.tasks[1].conclusion_citations == []
    blocked = report.tasks[0]
    blocked.run.status = "blocked"
    blocked.run.conclusion = None
    blocked.run.shared_scope = None
    legacy = report.tasks[1]
    legacy.run.conclusion.evidence_requests = []
    legacy.run.conclusion.next_checks = ["Review collection coverage."]
    corrupt = report.tasks[2]
    corrupt.run.conclusion.evidence_requests[0].scope_ref = "f" * 64
    worksheet = reasoning.build_worksheet(report, digest)
    assert worksheet.tasks[0].gap_coverage_state == "no_accepted_conclusion"
    assert worksheet.tasks[0].statements == []
    assert worksheet.tasks[1].gap_coverage_state == "not_assessable_without_structured_requests"
    assert worksheet.tasks[1].unrequested_active_gaps == []
    assert worksheet.tasks[1].legacy_next_checks == ["Review collection coverage."]
    assert worksheet.tasks[2].gap_coverage_state == "invalid_request_links"
    assert worksheet.tasks[2].unrequested_active_gaps == []


def test_false_citation_is_reported_without_a_semantic_verdict(session):
    _, report, digest = session
    report.tasks[0].run.conclusion.observations = [
        ObservationClaim(source="invented", event_id="invented", field="outcome", value="success")
    ]
    row = reasoning.build_worksheet(report, digest).tasks[0]
    assert row.conclusion_citations[0]["matches_returned_field"] is False
    assert row.semantic_review == "pending-human-review"


def test_hidden_rubrics_and_statement_keywords_do_not_control_gap_or_time_analysis(session):
    _, report, digest = session
    before = reasoning.build_worksheet(report, digest)
    changed = report.model_copy(deep=True)
    for task in changed.tasks:
        task.rubric.required_observations = []
        task.rubric.disposition = "inconclusive"
        task.rubric.review_notes = "Hidden expected answer changed."
        task.checks.disposition_matches = not task.checks.disposition_matches
    assert reasoning.build_worksheet(changed, digest) == before
    changed.tasks[4].run.conclusion.hypotheses = ["No sequence exists."]
    after = reasoning.build_worksheet(changed, digest)
    assert after.tasks[4].temporal_context == before.tasks[4].temporal_context
    assert after.tasks[4].unrequested_active_gaps == before.tasks[4].unrequested_active_gaps
    assert after.tasks[4].statements[0].text == "No sequence exists."


def test_time_groups_are_bounded_without_assuming_causation(session):
    _, report, _ = session
    result = next(
        entry["response"] for entry in report.tasks[4].run.journal if entry.get("kind") == "tool"
    )
    from adaptive_security.investigation_tools import ToolResult

    event = ToolResult.model_validate(result).events[0]
    records = [
        event.model_copy(
            update={"event_id": str(i), "event_time": event.event_time + timedelta(seconds=i)}
        )
        for i in range(12)
    ]
    context = reasoning.temporal_context(records)
    assert context["state"] == "distinct_timestamps_present"
    assert context["distinct_timestamp_count"] == 12 and context["groups_truncated"] is True
    assert len(context["timestamp_groups"]) == 10
    same_time = [event.model_copy(update={"event_id": str(i)}) for i in range(12)]
    context = reasoning.temporal_context(same_time)
    assert context["timestamp_groups"][0]["references_truncated"] is True
    assert context["timestamp_groups"][0]["record_count"] == 12


def test_html_escapes_all_untrusted_text_and_contains_no_active_content(session):
    _, report, digest = session
    payload = '</pre><script>alert("x")</script><img src="https://example.com" onerror="x">'
    report.tasks[0].objective = payload
    report.tasks[0].run.conclusion.hypotheses = [payload]
    worksheet = reasoning.build_worksheet(report, digest)
    page = reasoning.render_html(worksheet)
    assert payload not in page and "&lt;script&gt;" in page

    class Tags(HTMLParser):
        def __init__(self):
            super().__init__()
            self.tags = []

        def handle_starttag(self, tag, attrs):
            self.tags.append((tag, dict(attrs)))

    parser = Tags()
    parser.feed(page)
    assert not any(tag in {"script", "iframe", "img", "link", "form"} for tag, _ in parser.tags)
    assert not any(name.startswith("on") for _, attrs in parser.tags for name in attrs)
    assert "default-src 'none'" in page
    assert all(tag not in {"a", "button", "input"} for tag, _ in parser.tags)


def test_cli_preserves_inputs_writes_private_artifacts_and_checks_pins(
    session, tmp_path, monkeypatch
):
    directory, _report, digest = session
    before = {path.name: path.read_bytes() for path in directory.iterdir() if path.is_file()}
    from adaptive_security.ollama_adapter import OllamaAdapter

    async def forbidden(*args, **kwargs):
        raise AssertionError("Offline worksheet must not invoke a model")

    monkeypatch.setattr(OllamaAdapter, "next_step", forbidden)
    output = directory / "reasoning-v1"

    def call(*args):
        monkeypatch.setattr("sys.argv", ["reasoning-audit", *map(str, args)])
        return reasoning.main()

    assert call(directory, output) == 0
    assert output.stat().st_mode & 0o777 == 0o700
    for path in output.iterdir():
        assert path.stat().st_mode & 0o777 == 0o600
    manifest = json.loads((output / "manifest.json").read_bytes())
    assert manifest["report_sha256"] == digest
    for name, pin in manifest["artifact_sha256"].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == pin
    html_before = (output / "index.html").read_bytes()
    assert call(directory, output) == 2
    assert (output / "index.html").read_bytes() == html_before
    assert {name: (directory / name).read_bytes() for name in before} == before
    explicit = tmp_path / "explicit"
    assert call(directory / "report.json", explicit, "--report-sha256", digest) == 0
    wrong = tmp_path / "wrong"
    assert call(directory / "report.json", wrong, "--report-sha256", "0" * 64) == 2
    assert not wrong.exists()
    session_manifest = json.loads((directory / "manifest.json").read_bytes())
    session_manifest["artifact_sha256"]["report.json"] = "f" * 64
    (directory / "manifest.json").write_text(json.dumps(session_manifest))
    assert call(directory, tmp_path / "tampered") == 2


def test_conflicting_journal_versions_fail_before_output_creation(session):
    _, report, digest = session
    entry = next(entry for entry in report.tasks[0].run.journal if entry.get("kind") == "tool")
    conflict = copy.deepcopy(entry)
    conflict["response"]["events"][0]["outcome"] = "success"
    report.tasks[0].run.journal.append(conflict)
    with pytest.raises(ValueError, match="Conflicting"):
        reasoning.build_worksheet(report, digest)
