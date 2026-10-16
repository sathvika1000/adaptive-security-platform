import asyncio
import copy
import json

import pytest
from test_evidence_requests import READ, Script

from adaptive_security import reasoning_audit, request_review, task_audit, task_session
from adaptive_security.evidence_requests import EvidenceRequest, request_payload
from adaptive_security.investigation_runner import InvestigationRunner
from adaptive_security.investigation_tasks import TaskAdapter, TaskChannel, TaskSuite
from adaptive_security.request_scope import scope_context, scope_digest
from adaptive_security.statement_tests import statement_inventory, validate_statement_tests
from adaptive_security.task_review import TaskReport


def task(index=0):
    return TaskSuite.model_validate_json(task_session.bundled_suite("neutral")).tasks[index]


def proposal(index=0):
    item = task(index)
    refs = ["hypotheses:0", "alternative_explanations:0"]
    return {
        "kind": "finish",
        "disposition": "inconclusive",
        "observations": [],
        "hypotheses": ["Incorrect credentials may explain the failure."],
        "alternative_explanations": ["An authentication service fault is also possible."],
        "collection_limits": ["Identity, failure cause and collection coverage are unknown."],
        "next_checks": [],
        "evidence_requests": [
            {
                "gap_id": "failure_explanation",
                "evidence_source": "authentication_details",
                "scope_ref": scope_digest(scope_context([item.evidence])),
                "tests": refs,
                "evidence_needed": "Check event-1 failure detail: "
                "credential errors favor bad credentials; "
                "service errors favor a service fault.",
            }
        ],
    }


def run(decision, enabled=True):
    item = task()
    return asyncio.run(
        InvestigationRunner(
            item.grant,
            TaskChannel(item),
            Script(READ, decision),
            required_tools=("get_finding_evidence",),
            linked_tests=enabled,
            shared_request_scope=True,
        ).run()
    )


def test_controller_checks_links_and_retains_unverified_statements():
    decision = proposal()
    report = run(decision)
    assert report.status == "completed" and report.tool_calls == 1 and report.steps == 2
    assert report.linked_tests and report.shared_request_scope
    assert report.conclusion.hypotheses == decision["hypotheses"]
    assert report.conclusion.evidence_requests[0].tests == [
        "hypotheses:0",
        "alternative_explanations:0",
    ]
    assert report.shared_scope is not None


@pytest.mark.parametrize(
    "change", ["unknown", "duplicate", "unlinked", "too_many", "long", "blank", "goal"]
)
def test_controller_rejects_schema_bypass(change):
    decision = proposal()
    if change == "unknown":
        decision["evidence_requests"][0]["tests"] = ["hypotheses:1"]
    elif change == "duplicate":
        decision["evidence_requests"][0]["tests"] = ["hypotheses:0", "hypotheses:0"]
    elif change == "unlinked":
        decision["evidence_requests"][0]["tests"] = ["hypotheses:0"]
    elif change == "too_many":
        decision["hypotheses"].append("Another explanation.")
    elif change == "long":
        decision["hypotheses"][0] = "x" * 161
    elif change == "blank":
        decision["hypotheses"][0] = " "
    elif change == "goal":
        decision["evidence_requests"][0]["evidence_needed"] = "x" * 161
    report = run(decision)
    assert report.status == "blocked" and report.conclusion is None
    assert report.tool_calls == 1


def test_links_validated_outside_opt_in_and_no_explanation_is_required():
    decision = proposal()
    decision["evidence_requests"][0]["tests"] = ["hypotheses:1"]
    assert run(decision, enabled=False).status == "blocked"
    decision = proposal()
    decision["hypotheses"] = []
    decision["alternative_explanations"] = []
    decision["evidence_requests"][0]["tests"] = []
    assert run(decision).status == "completed"
    validate_statement_tests([], [], [[]], required=True)
    assert statement_inventory(["Text"], ["Other"]) == {
        "hypotheses:0": "Text",
        "alternative_explanations:0": "Other",
    }


@pytest.mark.parametrize("index", [0, 1, 4])
def test_mocked_schema_roundtrip_with_same_token_limits(index):
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
        assert body["options"]["num_predict"] == 512 and body["options"]["num_ctx"] == 4096
        context = json.loads(body["messages"][1]["content"])
        assert context["linked_tests"] is True and "rubric" not in context
        decision = dict(READ, offset=0)
        if context["results"]:
            decision = proposal(index)
            if index == 1:
                decision["hypotheses"] = decision["alternative_explanations"] = []
                decision["evidence_requests"][0].update(
                    gap_id="collection_completeness",
                    evidence_source="collector_health",
                    tests=[],
                    evidence_needed="Check collector health and source/time coverage "
                    "before interpreting the empty page.",
                )
            jsonschema.validate({"decision": decision}, body["format"])
            bad = copy.deepcopy(decision)
            bad["evidence_requests"][0]["tests"] = ["hypotheses:1"]
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate({"decision": bad}, body["format"])
        else:
            jsonschema.validate({"decision": decision}, body["format"])
        sent.append(body)
        return wire(reply(decision))

    adapter = OllamaAdapter("gemma3:4b", token_limit=13824, transport=httpx2.MockTransport(handler))
    report = asyncio.run(
        InvestigationRunner(
            item.grant,
            TaskChannel(item),
            TaskAdapter(adapter, item.objective),
            required_tools=("get_finding_evidence",),
            linked_tests=True,
        ).run()
    )
    assert report.status == "completed" and report.tool_calls == 1 and len(sent) == 2
    assert report.adapter_usage.token_limit == 13824


def test_legacy_schema_and_request_hash_ignore_absent_test_links():
    from adaptive_security.grounded_schema import grounded_schema
    from adaptive_security.ollama_adapter import ModelDecision

    item = task()
    context = {
        "allowed_tools": item.grant.tools,
        "results": [],
        "structured_requests": True,
        "shared_request_scope": True,
    }
    schema = grounded_schema(ModelDecision.model_json_schema(), json.dumps(context))
    assert "tests" not in schema["$defs"]["EvidenceRequest"]["properties"]
    request = EvidenceRequest.model_validate(proposal()["evidence_requests"][0])
    request.tests = []
    assert "tests" not in request_payload(request)


def test_cli_audit_worksheet_and_review_bind_exact_statement_links(tmp_path, monkeypatch):
    path = tmp_path / "linked"
    monkeypatch.setattr(
        "sys.argv",
        ["session", str(path), "--smoke", "--suite-version", "neutral", "--linked-tests"],
    )
    assert task_session.main() == 0
    report = TaskReport.model_validate_json((path / "report.json").read_bytes())
    manifest = json.loads((path / "manifest.json").read_bytes())
    assert manifest["linked_tests"] and manifest["shared_request_scope"]
    audit = task_audit.audit_report(report, "a" * 64)
    assert all(
        row["statement_test_linkage"] == "structural_links_validated" for row in audit["tasks"]
    )
    worksheet = reasoning_audit.build_worksheet(report, "a" * 64)
    assert worksheet.tasks[0].statements[0].testing_request_indices == [0, 1]
    assert "Model-declared testing requests (not evidence support)" in reasoning_audit.render_html(
        worksheet
    )
    sheet = request_review.prepare(report, "a" * 64)
    assert len(sheet.statement_contexts) == 5
    for row in sheet.assessments:
        row.relevance = row.specificity = row.gap_resolution = "not_assessable"
        row.notes = "Test only; test links do not establish semantic quality."
    sheet.reviewer = "Test reviewer"
    assert request_review.summarize(report, "a" * 64, sheet)["requests_reviewed"] == 10
    sheet.statement_contexts[report.tasks[0].run.run_id]["hypotheses:0"] = "Changed text."
    with pytest.raises(ValueError, match="statement context"):
        request_review.summarize(report, "a" * 64, sheet)
    report.tasks[0].run.conclusion.evidence_requests[0].tests = ["hypotheses:4"]
    audit = task_audit.audit_report(report, "a" * 64)
    assert audit["tasks"][0]["statement_test_linkage"] == "invalid_statement_test_links"
    with pytest.raises(ValueError, match="supplied explanation"):
        request_review.prepare(report, "a" * 64)
