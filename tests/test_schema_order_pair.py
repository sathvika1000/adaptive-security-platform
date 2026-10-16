import asyncio
import copy
import hashlib
import json

import pytest

from adaptive_security import schema_order_pair, task_session
from adaptive_security.grounded_schema import grounded_schema
from adaptive_security.investigation_runner import AdapterUsage, canonical
from adaptive_security.investigation_tasks import TaskSuite, run_tasks
from adaptive_security.ollama_adapter import ModelDecision, OllamaAdapter
from adaptive_security.task_pair import saved_report


def suite():
    return TaskSuite.model_validate_json(task_session.bundled_suite("neutral"))


@pytest.mark.parametrize("index", range(5))
def test_only_conclusion_branch_order_changes_for_frozen_task(index):
    item = suite().tasks[index]
    context = json.dumps({
        "allowed_tools": item.grant.tools,
        "results": [item.evidence.model_dump(mode="json")],
        "linked_tests": True, "structured_requests": True,
        "scoped_requests": True, "shared_request_scope": True,
    })
    base = ModelDecision.model_json_schema()
    original = copy.deepcopy(base)
    left = grounded_schema(base, context)
    right = grounded_schema(base, context, linked_schema_order="populated-first")
    assert base == original
    assert len(canonical(left)) == len(canonical(right)) <= 12 * 1024
    assert canonical(left) != canonical(right)
    right["$defs"]["Conclusion"]["anyOf"].reverse()
    assert json.dumps(left) == json.dumps(right)


def test_invalid_or_unlinked_orders_fail_before_output_or_provider(tmp_path):
    with pytest.raises(ValueError, match="Unknown"):
        OllamaAdapter("qwen2.5-coder:7b", linked_schema_order="unknown")
    with pytest.raises(ValueError, match="requires linked"):
        grounded_schema(ModelDecision.model_json_schema(), "{}",
                        linked_schema_order="populated-first")
    with pytest.raises(ValueError, match="requires linked"):
        asyncio.run(task_session.create_session(
            tmp_path / "bad", linked_schema_order="populated-first",
        ))
    assert not (tmp_path / "bad").exists()
    with pytest.raises(ValueError, match="requires linked"):
        asyncio.run(run_tasks(suite(), linked_schema_order="populated-first"))
    with pytest.raises(ValueError):
        asyncio.run(schema_order_pair.collect_pair(tmp_path / "slow", slow_local=True))
    with pytest.raises(ValueError):
        asyncio.run(schema_order_pair.collect_pair(tmp_path / "model", "bad/model"))
    assert not (tmp_path / "model").exists()


def test_fresh_smoke_pair_keeps_order_pins_reviews_and_no_quality_claim(tmp_path, monkeypatch):
    root = tmp_path / "pair"
    monkeypatch.setattr("sys.argv", ["pair", str(root), "--smoke", "--reverse-run-order"])
    assert schema_order_pair.main() == 0
    result = json.loads((root / "pair-summary.json").read_bytes())
    assert result["execution_order"] == ["populated-first", "empty-first"]
    assert result["comparison_checks"]["matched_request_payloads_and_choices"] is None
    assert result["comparison_checks"]["same_model_metadata"] is None
    assert "winner" not in result and "quality_score" not in result
    assert (root / "pair-summary.json").stat().st_mode & 0o777 == 0o600
    for name, digest in result["report_sha256"].items():
        folder = root / name
        assert hashlib.sha256((folder / "report.json").read_bytes()).hexdigest() == digest
        assert (folder / "review.json").exists()
        report, _ = saved_report(folder)
        assert report.linked_schema_order == name
        manifest = json.loads((folder / "manifest.json").read_bytes())
        assert manifest["linked_schema_order"] == name
        assert "schema_order.py" in report.source_sha256
    before = (root / "pair-summary.json").read_bytes()
    assert schema_order_pair.main() == 2
    assert (root / "pair-summary.json").read_bytes() == before


def test_mocked_pair_records_actual_request_equivalence_and_no_prompt_change(tmp_path, monkeypatch):
    import httpx2
    import jsonschema
    from test_ollama_adapter import LOCAL_INFO, reply, wire

    from adaptive_security import ollama_adapter
    from adaptive_security.evidence_requests import request_catalog
    from adaptive_security.investigation_tools import ToolResult

    bodies = []

    def handler(request):
        if request.url.path == "/api/show":
            return wire(LOCAL_INFO)
        body = json.loads(request.content)
        bodies.append(body)
        assert body["options"] == {"temperature": 0, "num_ctx": 4096, "num_predict": 512}
        context = json.loads(body["messages"][1]["content"])
        assert "rubric" not in context and "linked_schema_order" not in context
        decision = {"kind": "tool", "tool": "get_finding_evidence", "limit": 5, "offset": 0}
        if context["results"]:
            results = [ToolResult.model_validate(value) for value in context["results"]]
            gap = request_catalog(results)[0]
            decision = {
                "kind": "finish", "disposition": "inconclusive", "observations": [],
                "hypotheses": [], "alternative_explanations": [],
                "collection_limits": ["Collection completeness is not established."],
                "next_checks": [], "evidence_requests": [{
                    "gap_id": gap["gap_id"], "evidence_source": gap["evidence_source"],
                    "scope_ref": context["request_scope_ref"], "tests": [],
                    "evidence_needed": "Inspect source/time collection coverage for these records.",
                }],
            }
        jsonschema.validate({"decision": decision}, body["format"])
        return wire(reply(decision, model=body["model"]))

    def factory(model, token_limit, **kwargs):
        return OllamaAdapter(model, token_limit, transport=httpx2.MockTransport(handler), **kwargs)

    monkeypatch.setattr(ollama_adapter, "OllamaAdapter", factory)
    root = tmp_path / "pair"
    result = asyncio.run(schema_order_pair.collect_pair(
        root, "qwen2.5-coder:7b", slow_local=True,
    ))
    assert all(value is True for value in result["comparison_checks"].values())
    assert len(bodies) == 20
    for left, right in zip(bodies[:10], bodies[10:], strict=True):
        assert left["messages"] == right["messages"]
        changed = copy.deepcopy(right)
        changed["format"]["$defs"]["Conclusion"]["anyOf"].reverse()
        assert json.dumps(changed) == json.dumps(left)
    for task in result["tasks"]:
        assert task["same_request_count"] is True
        assert len(task["request_comparisons"]) == 2
        assert all(all(value is True for name, value in row.items() if name != "request")
                   for row in task["request_comparisons"])
        for arm in task["arms"].values():
            assert arm["hypotheses"] == arm["test_links"] == 0
    left, _ = saved_report(root / "empty-first")
    right, _ = saved_report(root / "populated-first")
    for index, row in enumerate(left.tasks):
        for step, trace in enumerate(row.run.adapter_usage.schema_requests):
            body = bodies[index * 2 + step]
            expected = hashlib.sha256(json.dumps(
                body["format"], ensure_ascii=False, separators=(",", ":"), allow_nan=False,
            ).encode()).hexdigest()
            assert trace.format_sha256 == expected
    right.tasks[0].run.adapter_usage.schema_requests[0].non_format_payload_sha256 = "a" * 64
    right.tasks[1].run.adapter_usage.metadata_sha256 = "b" * 64
    checks, rows = schema_order_pair.compare_reports(left, right, "qwen2.5-coder:7b")
    assert checks["matched_request_payloads_and_choices"] is False
    assert checks["same_model_metadata"] is False
    assert rows[0]["request_comparisons"][0]["same_non_format_payload"] is False
    right.tasks[0].run.adapter_usage.schema_requests = []
    checks, _ = schema_order_pair.compare_reports(left, right, "qwen2.5-coder:7b")
    assert checks["recorded_schema_orders"] is False


def test_failure_retains_first_arm_without_provider_error_text(tmp_path, monkeypatch):
    original = schema_order_pair.create_session
    calls = []

    async def failing(directory, model, **options):
        calls.append(options["linked_schema_order"])
        if len(calls) == 2:
            raise RuntimeError("private error data")
        return await original(directory, model, **options)

    monkeypatch.setattr(schema_order_pair, "create_session", failing)
    root = tmp_path / "pair"
    with pytest.raises(RuntimeError):
        asyncio.run(schema_order_pair.collect_pair(root))
    assert (root / "empty-first" / "report.json").exists()
    assert not (root / "pair-summary.json").exists()
    assert "private error data" not in (root / "pair-failure.json").read_text()


def test_legacy_reports_do_not_acquire_schema_order_provenance():
    usage = AdapterUsage(model="qwen2.5-coder:7b", requests=0, prompt_tokens=0,
                         generated_tokens=0, charged_tokens=0, token_limit=13824,
                         unconfirmed_requests=0)
    assert usage.linked_schema_order is None and usage.schema_requests == []
