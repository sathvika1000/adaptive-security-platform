import asyncio
import json

import pytest
from pydantic import ValidationError
from test_evidence_requests import READ, REQUEST, Script

from adaptive_security import request_review
from adaptive_security.evidence_requests import request_payload
from adaptive_security.investigation_runner import InvestigationRunner
from adaptive_security.investigation_tasks import TaskChannel, TaskSuite
from adaptive_security.request_scope import RequestScope, scope_context, validate_scope
from adaptive_security.task_review import TaskReport
from adaptive_security.task_session import bundled_suite, create_session


def task(index=0):
    return TaskSuite.model_validate_json(bundled_suite("neutral")).tasks[index]


def test_exact_context_empty_equal_times_and_no_invented_search_interval():
    empty = scope_context([task(1).evidence])
    assert empty.event_references == []
    assert empty.collection_interval.model_dump() == {
        "status": "requires_analyst_scope",
        "start": None,
        "end": None,
    }
    mixed = scope_context([task(4).evidence])
    assert len(mixed.event_references) == 2
    assert mixed.event_references[0].event_time == mixed.event_references[1].event_time
    assert mixed.account_scope == mixed.resource_scope == mixed.collector_scope == "not_established"
    mixed.event_references.reverse()
    validate_scope(mixed, [task(4).evidence])


@pytest.mark.parametrize(
    "change", ["event", "time", "source", "missing", "duplicate", "invented-empty"]
)
def test_forged_and_incomplete_references_rejected(change):
    item = task()
    scope = scope_context([item.evidence])
    if change == "event":
        scope.event_references[0].event_id = "fabricated"
    elif change == "time":
        scope.event_references[0].event_time = "2027-01-01T00:00:00Z"
    elif change == "source":
        scope.event_references[0].source = "other"
    elif change == "missing":
        scope.event_references = []
    elif change == "duplicate":
        scope.event_references *= 2
    else:
        item = task(1)
    with pytest.raises(ValueError, match="match all"):
        validate_scope(scope, [item.evidence])


@pytest.mark.parametrize(
    "field,value",
    [
        ("account_scope", "administrator"),
        ("resource_scope", "secret-database"),
        ("collector_scope", "collector-1"),
        (
            "collection_interval",
            {"status": "requires_analyst_scope", "start": "2020-01-01", "end": None},
        ),
    ],
)
def test_no_invented_identity_or_new_interval(field, value):
    raw = scope_context([]).model_dump()
    raw[field] = value
    with pytest.raises(ValidationError):
        RequestScope.model_validate(raw)


@pytest.mark.parametrize("missing", [False, True])
def test_controller_revalidates_even_if_adapter_ignores_schema(missing):
    item = task()
    scope = scope_context([item.evidence]).model_dump()
    scope["event_references"][0]["event_id"] = "invented"
    request = dict(REQUEST) if missing else dict(REQUEST, scope=scope)
    report = asyncio.run(
        InvestigationRunner(
            item.grant,
            TaskChannel(item),
            Script(
                READ,
                {"kind": "finish", "disposition": "inconclusive", "evidence_requests": [request]},
            ),
            required_tools=("get_finding_evidence",),
            scoped_requests=True,
        ).run()
    )
    assert report.status == "blocked" and report.conclusion is None and report.tool_calls == 1


def test_bounded_context_fails_closed_and_conflicting_timestamps():
    result = task().evidence.model_copy(deep=True)
    result.events = [
        result.events[0].model_copy(update={"event_id": f"event-{i}"}) for i in range(6)
    ]
    with pytest.raises(ValueError, match="five"):
        scope_context([result])
    first = task().evidence
    other = first.model_copy(deep=True)
    from datetime import timedelta

    other.events[0].event_time += timedelta(seconds=1)
    with pytest.raises(ValueError, match="Conflicting"):
        scope_context([first, other])


def test_schema_and_mocked_ollama_scoped_roundtrip():
    httpx2 = pytest.importorskip("httpx2")
    jsonschema = pytest.importorskip("jsonschema")
    from test_ollama_adapter import LOCAL_INFO, reply, wire

    from adaptive_security.investigation_tasks import TaskAdapter
    from adaptive_security.ollama_adapter import OllamaAdapter

    item = task(4)
    sent = []

    def handler(request):
        if request.url.path == "/api/show":
            return wire(LOCAL_INFO)
        body = json.loads(request.content)
        context = json.loads(body["messages"][1]["content"])
        assert "rubric" not in context
        sent.append(body)
        decision = (
            dict(READ, offset=0)
            if not context["results"]
            else {
                "kind": "finish",
                "disposition": "inconclusive",
                "observations": [],
                "hypotheses": [],
                "alternative_explanations": ["Identity and order are unknown."],
                "collection_limits": ["Only returned records are available."],
                "next_checks": [],
                "evidence_requests": [dict(REQUEST, scope=context["request_scope"])],
            }
        )
        jsonschema.validate({"decision": decision}, body["format"])
        return wire(reply(decision))

    report = asyncio.run(
        InvestigationRunner(
            item.grant,
            TaskChannel(item),
            TaskAdapter(
                OllamaAdapter("gemma3:4b", transport=httpx2.MockTransport(handler)), item.objective
            ),
            required_tools=("get_finding_evidence",),
            scoped_requests=True,
        ).run()
    )
    assert report.status == "completed" and report.tool_calls == 1 and len(sent) == 2
    assert report.structured_requests and report.scoped_requests
    validate_scope(report.conclusion.evidence_requests[0].scope, [item.evidence])


def test_existing_review_hashes_remain_compatible_and_new_scope_is_bound(tmp_path):
    path = tmp_path / "legacy"
    assert asyncio.run(create_session(path, structured_requests=True))
    report = TaskReport.model_validate_json((path / "report.json").read_bytes())
    sheet = request_review.prepare(report, "a" * 64)
    old = sheet.model_dump(mode="json")
    for row in old["assessments"]:
        row["request"].pop("scope", None)
        row.update(
            relevance="supported",
            specificity="concern",
            gap_resolution="not_assessable",
            notes="Development review.",
        )
    old["reviewer"] = "Development reviewer"
    review = request_review.RequestReview.model_validate(old)
    assert request_review.summarize(report, "a" * 64, review)["requests_reviewed"] == 6
    assert "scope" not in request_payload(report.tasks[0].run.conclusion.evidence_requests[0])
    scoped = tmp_path / "scoped"
    assert asyncio.run(create_session(scoped, suite_version="neutral", scoped_requests=True))
    report = TaskReport.model_validate_json((scoped / "report.json").read_bytes())
    sheet = request_review.prepare(report, "b" * 64)
    for row in sheet.assessments:
        row.relevance = row.specificity = row.gap_resolution = "not_assessable"
        row.notes = "No semantic judgment assigned by test."
    sheet.reviewer = "Test reviewer"
    assert request_review.summarize(report, "b" * 64, sheet)["requests_reviewed"] == 10
    sheet.assessments[0].request.scope.event_references[0].event_id = "edited"
    with pytest.raises(ValueError, match="exact request"):
        request_review.summarize(report, "b" * 64, sheet)


def test_cli_scoped_profile_audit_and_review(tmp_path, monkeypatch):
    from adaptive_security import task_audit, task_session

    directory = tmp_path / "cli"
    monkeypatch.setattr(
        "sys.argv",
        ["session", str(directory), "--smoke", "--suite-version", "neutral", "--scoped-requests"],
    )
    assert task_session.main() == 0
    manifest = json.loads((directory / "manifest.json").read_bytes())
    assert manifest["structured_requests"] and manifest["scoped_requests"]
    report = TaskReport.model_validate_json((directory / "report.json").read_bytes())
    audit = task_audit.audit_report(report, "a" * 64)
    assert all(
        row["request_scope_validation"] == "validated_returned_context" for row in audit["tasks"]
    )
    assert report.tasks[1].run.conclusion.evidence_requests[0].scope.event_references == []
    report.tasks[0].run.conclusion.evidence_requests[0].scope.event_references[
        0
    ].event_id = "forged"
    assert (
        task_audit.audit_report(report, "a" * 64)["tasks"][0]["request_scope_validation"]
        == "scope_validation_failed"
    )
