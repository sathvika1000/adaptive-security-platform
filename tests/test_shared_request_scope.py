import asyncio
import copy
import json

import pytest
from pydantic import ValidationError
from test_evidence_requests import READ, REQUEST, Script

from adaptive_security import request_review, task_audit, task_session
from adaptive_security.evidence_requests import EvidenceRequest, request_payload, validate_requests
from adaptive_security.investigation_runner import InvestigationRunner, canonical
from adaptive_security.investigation_tasks import TaskAdapter, TaskChannel, TaskSuite
from adaptive_security.request_scope import scope_context, scope_digest
from adaptive_security.task_review import TaskReport


def task(index=4):
    return TaskSuite.model_validate_json(task_session.bundled_suite("neutral")).tasks[index]


def finish(reference):
    return {
        "kind": "finish",
        "disposition": "inconclusive",
        "evidence_requests": [dict(REQUEST, scope_ref=reference)],
    }


def test_controller_records_one_scope_and_no_extra_tools():
    item = task()
    expected = scope_context([item.evidence])
    adapter = Script(READ, finish(scope_digest(expected)))
    report = asyncio.run(
        InvestigationRunner(
            item.grant,
            TaskChannel(item),
            adapter,
            shared_request_scope=True,
            required_tools=("get_finding_evidence",),
        ).run()
    )
    assert report.status == "completed" and report.tool_calls == 1
    assert report.shared_request_scope and report.scoped_requests and report.structured_requests
    assert report.shared_scope == expected
    assert report.conclusion.evidence_requests[0].scope is None
    assert adapter.contexts[1]["request_scope_ref"] == scope_digest(expected)
    assert len(report.shared_scope.event_references) == 2


@pytest.mark.parametrize("mode", ["wrong", "missing", "inline"])
def test_controller_blocks_schema_bypass(mode):
    item = task()
    request = dict(REQUEST)
    if mode == "wrong":
        request["scope_ref"] = "f" * 64
    elif mode == "inline":
        request["scope"] = scope_context([item.evidence]).model_dump(mode="json")
    report = asyncio.run(
        InvestigationRunner(
            item.grant,
            TaskChannel(item),
            Script(
                READ,
                {"kind": "finish", "disposition": "inconclusive", "evidence_requests": [request]},
            ),
            shared_request_scope=True,
        ).run()
    )
    assert report.status == "blocked" and report.conclusion is None
    assert report.shared_scope is None and report.tool_calls == 1


def test_old_page_reference_rejected_after_new_read():
    item = task()
    first = item.evidence.model_copy(deep=True)
    first.events = first.events[:1]
    old_ref = scope_digest(scope_context([first]))
    adapter = Script(dict(READ, limit=1), dict(READ, limit=1, offset=1), finish(old_ref))
    report = asyncio.run(
        InvestigationRunner(
            item.grant,
            TaskChannel(item),
            adapter,
            shared_request_scope=True,
        ).run()
    )
    assert report.status == "blocked" and report.tool_calls == 2
    assert "reference" in report.detail


def test_references_require_current_validated_context_in_every_profile():
    item = task()
    scope = scope_context([item.evidence])
    request = EvidenceRequest.model_validate(dict(REQUEST, scope_ref=scope_digest(scope)))
    with pytest.raises(ValueError, match="reference"):
        validate_requests([request], [item.evidence])
    altered = scope.model_copy(deep=True)
    altered.event_references[0].event_time = "2027-01-01T00:00:00Z"
    with pytest.raises(ValueError, match="timestamps"):
        validate_requests([request], [item.evidence], altered)
    with pytest.raises(ValidationError):
        EvidenceRequest.model_validate(
            dict(REQUEST, scope_ref=scope_digest(scope), scope=scope.model_dump())
        )


@pytest.mark.parametrize("index", [1, 4])
def test_mocked_ollama_shared_roundtrip_preserves_caps_and_schema(index):
    httpx2 = pytest.importorskip("httpx2")
    jsonschema = pytest.importorskip("jsonschema")
    from test_ollama_adapter import LOCAL_INFO, reply, wire

    from adaptive_security.ollama_adapter import OllamaAdapter

    item = task(index)
    sent = []

    def handler(request):
        if request.url.path == "/api/show":
            return wire(LOCAL_INFO)
        body = json.loads(request.content)
        assert body["options"]["num_predict"] == 512
        assert body["options"]["num_ctx"] == 4096
        context = json.loads(body["messages"][1]["content"])
        assert "rubric" not in context
        assert "Do not emit inline scope" in body["messages"][0]["content"]
        assert "RequestScope" not in body["format"]["$defs"]
        decision = dict(READ, offset=0)
        if context["results"]:
            decision = finish(context["request_scope_ref"])
            decision.update(
                observations=[],
                hypotheses=[],
                next_checks=[],
                alternative_explanations=["Identity and sequence are unresolved."],
                collection_limits=["Only returned records are available."],
            )
        jsonschema.validate({"decision": decision}, body["format"])
        if context["results"]:
            bad = copy.deepcopy(decision)
            bad["evidence_requests"][0]["scope_ref"] = "f" * 64
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate({"decision": bad}, body["format"])
        sent.append(body)
        return wire(reply(decision))

    report = asyncio.run(
        InvestigationRunner(
            item.grant,
            TaskChannel(item),
            TaskAdapter(
                OllamaAdapter("gemma3:4b", transport=httpx2.MockTransport(handler)), item.objective
            ),
            shared_request_scope=True,
            required_tools=("get_finding_evidence",),
        ).run()
    )
    assert report.status == "completed" and report.tool_calls == 1 and len(sent) == 2
    assert len(report.shared_scope.event_references) == (0 if index == 1 else 2)


def test_two_request_shared_representation_reduces_response_bytes():
    scope = scope_context([task().evidence])
    requests = [
        dict(REQUEST, scope_ref=scope_digest(scope)),
        dict(
            REQUEST,
            gap_id="identity_context",
            evidence_source="identity_records",
            scope_ref=scope_digest(scope),
        ),
    ]
    inline = [
        dict(request_payload(EvidenceRequest.model_validate(request))) for request in requests
    ]
    for request in inline:
        request.pop("scope_ref")
        request["scope"] = scope.model_dump(mode="json")
    assert len(canonical(requests)) < 0.8 * len(canonical(inline))


def test_cli_audit_and_review_bind_shared_object_once(tmp_path, monkeypatch):
    directory = tmp_path / "shared"
    monkeypatch.setattr(
        "sys.argv",
        [
            "session",
            str(directory),
            "--smoke",
            "--suite-version",
            "neutral",
            "--shared-request-scope",
        ],
    )
    assert task_session.main() == 0
    report = TaskReport.model_validate_json((directory / "report.json").read_bytes())
    manifest = json.loads((directory / "manifest.json").read_bytes())
    assert manifest["shared_request_scope"] is True
    audit = task_audit.audit_report(report, "a" * 64)
    assert all(
        row["request_scope_validation"] == "validated_shared_context" for row in audit["tasks"]
    )
    sheet = request_review.prepare(report, "a" * 64)
    assert len(sheet.shared_scopes) == 5 and len(sheet.assessments) == 10
    for row in sheet.assessments:
        row.relevance = row.specificity = row.gap_resolution = "not_assessable"
        row.notes = "Test only; no human semantic judgment."
    sheet.reviewer = "Test reviewer"
    assert request_review.summarize(report, "a" * 64, sheet)["requests_reviewed"] == 10
    sheet.shared_scopes[report.tasks[0].run.run_id].event_references[0].event_id = "tampered"
    with pytest.raises(ValueError, match="shared scopes"):
        request_review.summarize(report, "a" * 64, sheet)
    report.tasks[0].run.shared_scope = None
    assert (
        task_audit.audit_report(report, "a" * 64)["tasks"][0]["request_scope_validation"]
        == "missing_or_invalid_shared_scope"
    )
    with pytest.raises(ValueError):
        request_review.prepare(report, "a" * 64)
