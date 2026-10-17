import asyncio
import copy
import hashlib
import json

import pytest

from adaptive_security import catalog_pair, schema_order_pair, task_session
from adaptive_security.catalog_context import (
    catalog_context,
    normalized_catalog_payload,
    validate_catalog,
)
from adaptive_security.investigation_tasks import TaskSuite, run_tasks
from adaptive_security.ollama_adapter import ModelDecision, OllamaAdapter
from adaptive_security.task_pair import saved_report


def suite():
    return TaskSuite.model_validate_json(task_session.bundled_suite("neutral"))


@pytest.mark.parametrize("index", range(5))
def test_catalog_removal_preserves_every_other_context_field_and_schema(index):
    from adaptive_security.evidence_requests import request_catalog
    from adaptive_security.grounded_schema import grounded_schema

    item = suite().tasks[index]
    original = {
        "allowed_tools": item.grant.tools,
        "results": [item.evidence.model_dump(mode="json")],
        "investigation_objective": item.objective,
        "evidence_gaps": request_catalog([item.evidence]),
        "linked_tests": True, "structured_requests": True,
        "scoped_requests": True, "shared_request_scope": True,
        "untrusted_record": {"evidence_needed": "Retain this evidence value verbatim."},
    }
    raw = json.dumps(original)
    assert catalog_context(raw, "suggestions") == raw
    changed_raw = catalog_context(raw, "descriptions-only")
    expected = copy.deepcopy(original)
    for gap in expected["evidence_gaps"]:
        del gap["evidence_needed"]
    assert json.loads(changed_raw) == expected
    assert json.loads(raw) == original
    assert json.dumps(grounded_schema(ModelDecision.model_json_schema(), raw)) == json.dumps(
        grounded_schema(ModelDecision.model_json_schema(), changed_raw)
    )
    payload = {"messages": [{"role": "system", "content": "Same system prompt"},
                            {"role": "user", "content": raw}], "format": {"unchanged": True}}
    without = copy.deepcopy(payload)
    without["messages"][1]["content"] = changed_raw
    assert normalized_catalog_payload(payload) == normalized_catalog_payload(without)
    assert payload["messages"][1]["content"] == raw
    assert normalized_catalog_payload(payload)["format"] == payload["format"]


def test_invalid_modes_and_unlinked_context_fail_before_outputs(tmp_path):
    with pytest.raises(ValueError):
        validate_catalog("unknown")
    with pytest.raises(ValueError):
        OllamaAdapter("qwen2.5-coder:7b", catalog_presentation="unknown")
    for raw in ('{}', '[]', '{"linked_tests":true,"evidence_gaps":{}}'):
        with pytest.raises(ValueError):
            catalog_context(raw, "descriptions-only")
    with pytest.raises(ValueError):
        asyncio.run(task_session.create_session(
            tmp_path / "bad", catalog_presentation="descriptions-only",
        ))
    with pytest.raises(ValueError):
        asyncio.run(run_tasks(suite(), catalog_presentation="descriptions-only"))
    assert not (tmp_path / "bad").exists()


def test_smoke_cli_pins_profiles_and_answers_without_quality_claims(tmp_path, monkeypatch):
    root = tmp_path / "pair"
    monkeypatch.setattr("sys.argv", ["catalog_pair", str(root), "--smoke", "--reverse-run-order"])
    assert catalog_pair.main() == 0
    result = json.loads((root / "pair-summary.json").read_bytes())
    assert result["experiment"] == "catalog-suggestions"
    assert result["execution_order"] == ["descriptions-only", "suggestions"]
    assert result["comparison_checks"]["matched_request_payloads_and_choices"] is None
    assert result["comparison_checks"]["recorded_catalog_presentations"] is None
    assert "winner" not in result and "quality_score" not in result
    for name, digest in result["report_sha256"].items():
        folder = root / name
        report, _ = saved_report(folder)
        assert report.catalog_presentation == name
        assert report.linked_schema_order == "empty-first"
        assert hashlib.sha256((folder / "report.json").read_bytes()).hexdigest() == digest
        assert json.loads((folder / "manifest.json").read_bytes())["catalog_presentation"] == name
    for row in result["tasks"]:
        for arm in row["arms"].values():
            assert arm["conclusion"] is not None
    before = (root / "pair-summary.json").read_bytes()
    assert catalog_pair.main() == 2
    assert (root / "pair-summary.json").read_bytes() == before
    assert (root / "pair-summary.json").stat().st_mode & 0o777 == 0o600


def test_mocked_pair_changes_only_catalog_suggestions_and_records_hashes(tmp_path, monkeypatch):
    import httpx2
    import jsonschema
    from test_ollama_adapter import LOCAL_INFO, reply, wire

    from adaptive_security import ollama_adapter

    bodies = []

    def handler(request):
        if request.url.path == "/api/show":
            return wire(LOCAL_INFO)
        body = json.loads(request.content)
        bodies.append(body)
        context = json.loads(body["messages"][1]["content"])
        assert "rubric" not in context and "catalog_presentation" not in context
        decision = {"kind": "tool", "tool": "get_finding_evidence", "limit": 5, "offset": 0}
        if context["results"]:
            gap = context["evidence_gaps"][0]
            decision = {
                "kind": "finish", "disposition": "inconclusive", "observations": [],
                "hypotheses": [], "alternative_explanations": [],
                "collection_limits": ["Collection coverage is not established."],
                "next_checks": [], "evidence_requests": [{
                    "gap_id": gap["gap_id"], "evidence_source": gap["evidence_source"],
                    "scope_ref": context["request_scope_ref"], "tests": [],
                    "evidence_needed": gap.get(
                        "evidence_needed", "Check coverage to distinguish empty from missing logs.",
                    ),
                }],
            }
        jsonschema.validate({"decision": decision}, body["format"])
        return wire(reply(decision, model=body["model"]))

    def factory(model, token_limit, **kwargs):
        return OllamaAdapter(model, token_limit, transport=httpx2.MockTransport(handler), **kwargs)

    monkeypatch.setattr(ollama_adapter, "OllamaAdapter", factory)
    root = tmp_path / "pair"
    result = asyncio.run(schema_order_pair.collect_pair(
        root, "qwen2.5-coder:7b", slow_local=True, catalog_comparison=True,
    ))
    assert all(value is True for value in result["comparison_checks"].values())
    assert len(bodies) == 20
    for left, right in zip(bodies[:10], bodies[10:], strict=True):
        assert left["messages"][0] == right["messages"][0]
        assert json.dumps(left["format"]) == json.dumps(right["format"])
        assert normalized_catalog_payload(left) == normalized_catalog_payload(right)
        assert left["options"] == right["options"] == {
            "temperature": 0, "num_predict": 512, "num_ctx": 4096,
        }
        assert all("evidence_needed" not in gap for gap in
                   json.loads(right["messages"][1]["content"])["evidence_gaps"])
    for row in result["tasks"]:
        assert row["arms"]["suggestions"]["exact_suggestion_matches"] == 1
        assert row["arms"]["descriptions-only"]["exact_suggestion_matches"] == 0
        assert all(all(value is True for name, value in request.items() if name != "request")
                   for request in row["request_comparisons"])
    left, _ = saved_report(root / "suggestions")
    right, _ = saved_report(root / "descriptions-only")
    right.tasks[0].run.adapter_usage.schema_requests[0].catalog_normalized_payload_sha256 = None
    checks, _ = schema_order_pair.compare_reports(left, right, "qwen2.5-coder:7b",
                                                 catalog_comparison=True)
    assert checks["matched_request_payloads_and_choices"] is False
    right.tasks[1].run.adapter_usage.catalog_presentation = "suggestions"
    checks, _ = schema_order_pair.compare_reports(left, right, "qwen2.5-coder:7b",
                                                 catalog_comparison=True)
    assert checks["recorded_catalog_presentations"] is False


def test_catalog_pair_failure_keeps_first_arm(tmp_path, monkeypatch):
    original = schema_order_pair.create_session
    calls = []

    async def failing(directory, model, **options):
        calls.append(options["catalog_presentation"])
        if len(calls) == 2:
            raise RuntimeError("private model error")
        return await original(directory, model, **options)

    monkeypatch.setattr(schema_order_pair, "create_session", failing)
    root = tmp_path / "pair"
    with pytest.raises(RuntimeError):
        asyncio.run(schema_order_pair.collect_pair(root, catalog_comparison=True))
    assert (root / "suggestions" / "report.json").exists()
    assert not (root / "pair-summary.json").exists()
    assert "private model error" not in (root / "pair-failure.json").read_text()
