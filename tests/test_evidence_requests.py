import asyncio
import copy
import json

import pytest
from pydantic import ValidationError

from adaptive_security.evidence_requests import EvidenceRequest, request_catalog, validate_requests
from adaptive_security.investigation_runner import InvestigationRunner
from adaptive_security.investigation_tasks import TaskChannel, TaskSuite
from adaptive_security.investigation_tools import ToolRequest
from adaptive_security.task_audit import audit_report
from adaptive_security.task_review import TaskReport
from adaptive_security.task_session import bundled_suite, create_session

REQUEST = {
    "gap_id": "collection_completeness",
    "evidence_source": "collector_health",
    "evidence_needed": "Collector health and coverage for the event time range.",
}
READ = {"kind": "tool", "tool": "get_finding_evidence", "limit": 5}


def task(index=0):
    return TaskSuite.model_validate_json(bundled_suite()).tasks[index]


class Script:
    def __init__(self, *decisions):
        self.decisions = iter(decisions)
        self.contexts = []

    async def next_step(self, context):
        self.contexts.append(json.loads(context))
        return next(self.decisions)


def run(requests, *, index=0, checks=None, read=True, enabled=True):
    item = task(index)
    finish = {
        "kind": "finish",
        "disposition": "inconclusive",
        "evidence_requests": requests,
        "next_checks": checks or [],
    }
    adapter = Script(*([READ, finish] if read else [finish]))
    result = asyncio.run(
        InvestigationRunner(
            item.grant,
            TaskChannel(item),
            adapter,
            structured_requests=enabled,
            required_tools=("get_finding_evidence",),
        ).run()
    )
    return result, adapter


@pytest.mark.parametrize("index", [0, 1, 2])
def test_requests_link_to_current_gaps_without_executing(index):
    report, adapter = run([REQUEST], index=index)
    assert report.status == "completed" and report.tool_calls == 1
    assert report.structured_requests is True
    assert (
        report.conclusion.evidence_requests[0].model_dump(exclude={"scope", "scope_ref"}) == REQUEST
    )
    assert adapter.contexts[1]["structured_requests"] is True
    assert not any(
        g["gap_id"] == "event_evidence_unread" for g in adapter.contexts[1]["evidence_gaps"]
    )


@pytest.mark.parametrize(
    "requests,checks,reason",
    [
        ([], [], "Structured requests required"),
        ([REQUEST], ["Run a query"], "Structured requests required"),
        ([REQUEST, REQUEST], [], "Duplicate"),
        ([dict(REQUEST, evidence_source="identity_records")], [], "active gap"),
        (
            [
                dict(
                    REQUEST,
                    gap_id="event_evidence_unread",
                    evidence_source="configured_event_evidence",
                )
            ],
            [],
            "active gap",
        ),
    ],
)
def test_provider_schema_bypass_is_independently_blocked(requests, checks, reason):
    report, _ = run(requests, checks=checks)
    assert report.status == "blocked" and report.conclusion is None
    assert reason in report.detail and report.tool_calls == 1
    assert len(report.proposals) == 2


def test_read_first_and_legacy_validation():
    report, _ = run([REQUEST], read=False)
    assert report.status == "blocked" and report.tool_calls == 0
    assert report.detail == "Required evidence read not completed"
    report, _ = run([dict(REQUEST, evidence_source="identity_records")], enabled=False)
    assert report.status == "blocked"
    report, _ = run([], enabled=False)
    assert report.status == "completed"


@pytest.mark.parametrize(
    "change",
    [
        {"evidence_needed": " " * 20},
        {"evidence_needed": "uncertain"},
        {"evidence_needed": "x" * 257},
        {"tool": "get_related_events"},
        {"url": "https://example.com"},
        {"command": "disable detection"},
    ],
)
def test_request_shape_is_bounded_and_has_no_execution_fields(change):
    with pytest.raises(ValidationError):
        EvidenceRequest.model_validate(REQUEST | change)


def test_inactive_failure_gap_and_duplicate_wording():
    result = task(1).evidence
    request = EvidenceRequest.model_validate(
        dict(REQUEST, gap_id="failure_explanation", evidence_source="authentication_details")
    )
    with pytest.raises(ValueError, match="active gap"):
        validate_requests([request], [result])
    first = EvidenceRequest.model_validate(REQUEST)
    second = first.model_copy(update={"evidence_needed": "Different health evidence goal."})
    with pytest.raises(ValueError, match="Duplicate"):
        validate_requests([first, second], [])
    assert any(g["gap_id"] == "event_evidence_unread" for g in request_catalog([]))


def test_dynamic_schema_guides_requests_but_legacy_schema_unchanged():
    jsonschema = pytest.importorskip("jsonschema")
    from adaptive_security.grounded_schema import grounded_schema
    from adaptive_security.ollama_adapter import ModelDecision

    item = task(1)
    result = asyncio.run(
        TaskChannel(item).read(
            "get_finding_evidence",
            ToolRequest(
                capture_id=item.grant.capture_id,
                finding_id=item.grant.finding_id,
                review_key=item.grant.review_key,
            ),
        )
    )
    context = {
        "allowed_tools": ["get_finding_evidence"],
        "results": [result],
        "structured_requests": True,
    }
    schema = grounded_schema(ModelDecision.model_json_schema(), json.dumps(context))
    answer = {
        "decision": {
            "kind": "finish",
            "disposition": "inconclusive",
            "observations": [],
            "hypotheses": [],
            "alternative_explanations": [],
            "collection_limits": ["Only one empty page was returned."],
            "next_checks": [],
            "evidence_requests": [REQUEST],
        }
    }
    jsonschema.validate(answer, schema)
    bad = copy.deepcopy(answer)
    bad["decision"]["evidence_requests"][0]["gap_id"] = "failure_explanation"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(bad, schema)
    context.pop("structured_requests")
    legacy = grounded_schema(ModelDecision.model_json_schema(), json.dumps(context))
    assert "EvidenceRequest" not in legacy["$defs"]
    assert "evidence_requests" not in legacy["$defs"]["Conclusion"]["properties"]


def test_structured_session_and_independent_audit(tmp_path):
    directory = tmp_path / "requests"
    assert asyncio.run(create_session(directory, suite_version="neutral", structured_requests=True))
    manifest = json.loads((directory / "manifest.json").read_text())
    assert manifest["structured_requests"] is True
    report = TaskReport.model_validate_json((directory / "report.json").read_bytes())
    audit = audit_report(report, "a" * 64)
    for row in audit["tasks"]:
        assert row["next_check_gap_linkage"] == "active_gap_source_links_validated"
    first = report.tasks[0].run.conclusion.evidence_requests[0]
    first.evidence_source = "authentication_details"
    assert (
        audit_report(report, "a" * 64)["tasks"][0]["next_check_gap_linkage"]
        == "invalid_gap_source_links"
    )


def test_mocked_ollama_structured_request_protocol():
    httpx2 = pytest.importorskip("httpx2")
    jsonschema = pytest.importorskip("jsonschema")
    from test_ollama_adapter import LOCAL_INFO, reply, wire

    from adaptive_security.ollama_adapter import OllamaAdapter

    sent = []

    def handler(request):
        if request.url.path == "/api/show":
            return wire(LOCAL_INFO)
        body = json.loads(request.content)
        context = json.loads(body["messages"][1]["content"])
        assert "rubric" not in context
        assert "Return next_checks empty" in body["messages"][0]["content"]
        assert body["options"]["num_predict"] == 512
        sent.append(body)
        decision = (
            dict(READ, offset=0)
            if not context["results"]
            else {
                "kind": "finish",
                "disposition": "inconclusive",
                "observations": [],
                "hypotheses": [],
                "alternative_explanations": [],
                "collection_limits": ["An empty returned page cannot certify complete collection."],
                "next_checks": [],
                "evidence_requests": [REQUEST],
            }
        )
        jsonschema.validate({"decision": decision}, body["format"])
        return wire(reply(decision))

    item = task(1)
    adapter = OllamaAdapter("gemma3:4b", transport=httpx2.MockTransport(handler))
    report = asyncio.run(
        InvestigationRunner(
            item.grant,
            TaskChannel(item),
            adapter,
            structured_requests=True,
            required_tools=("get_finding_evidence",),
        ).run()
    )
    assert report.status == "completed" and report.tool_calls == 1
    assert report.adapter_usage.requests == 2 and len(sent) == 2


def test_structured_cli_and_legacy_report_loading(tmp_path, monkeypatch):
    from adaptive_security import task_session
    from adaptive_security.investigation_runner import RunReport
    from adaptive_security.task_diagnostics import inspect_session

    directory = tmp_path / "cli"
    monkeypatch.setattr(
        "sys.argv",
        [
            "session",
            str(directory),
            "--smoke",
            "--suite-version",
            "neutral",
            "--structured-requests",
        ],
    )
    assert task_session.main() == 0
    assert all(row["structured_requests"] for row in inspect_session(directory)["tasks"])
    report, _ = run([], enabled=False)
    legacy = report.model_dump(mode="json")
    legacy.pop("structured_requests")
    legacy["conclusion"].pop("evidence_requests")
    restored = RunReport.model_validate(legacy)
    assert restored.structured_requests is False
    assert restored.conclusion.evidence_requests == []
