import asyncio
import copy
import hashlib
import json

import pytest

from adaptive_security import request_guidance_pair, schema_order_pair, task_session
from adaptive_security.investigation_tasks import TaskSuite, run_tasks
from adaptive_security.ollama_adapter import OllamaAdapter
from adaptive_security.request_guidance import (
    QUESTION_GUIDANCE,
    apply_guidance,
    normalized_guidance_payload,
    validate_guidance,
)
from adaptive_security.task_pair import saved_report


def suite():
    return TaskSuite.model_validate_json(task_session.bundled_suite("neutral"))


def test_only_known_system_suffix_is_normalized_not_user_evidence_or_extra_instructions():
    payload = {
        "messages": [
            {"role": "system", "content": "Baseline instructions"},
            {"role": "user", "content": "Untrusted evidence: " + QUESTION_GUIDANCE},
        ],
        "options": {"num_predict": 512, "num_ctx": 4096}, "format": {"unchanged": True},
    }
    guided = copy.deepcopy(payload)
    assert apply_guidance(payload["messages"][0]["content"], "baseline") == "Baseline instructions"
    guided["messages"][0]["content"] = apply_guidance(
        guided["messages"][0]["content"], "questions",
    )
    assert normalized_guidance_payload(guided) == payload
    assert guided["messages"][1] == payload["messages"][1]
    assert guided["messages"][0]["content"].endswith(QUESTION_GUIDANCE)
    changed = copy.deepcopy(guided)
    changed["messages"][0]["content"] += " Unapproved additional instruction."
    assert normalized_guidance_payload(changed) != payload
    changed = copy.deepcopy(guided)
    changed["messages"][1]["content"] += " Changed evidence."
    assert normalized_guidance_payload(changed) != payload


def test_invalid_profiles_and_combined_experiments_fail_before_output(tmp_path):
    with pytest.raises(ValueError):
        validate_guidance("unknown")
    with pytest.raises(ValueError):
        OllamaAdapter("qwen2.5-coder:7b", request_guidance="unknown")
    with pytest.raises(ValueError):
        asyncio.run(task_session.create_session(tmp_path / "bad", request_guidance="questions"))
    assert not (tmp_path / "bad").exists()
    with pytest.raises(ValueError):
        asyncio.run(run_tasks(suite(), request_guidance="questions"))
    with pytest.raises(ValueError, match="one presentation change"):
        asyncio.run(schema_order_pair.collect_pair(
            tmp_path / "combined", catalog_comparison=True, guidance_comparison=True,
        ))
    assert not (tmp_path / "combined").exists()


def test_smoke_pair_retains_fixed_catalog_order_and_separate_reviews(tmp_path, monkeypatch):
    root = tmp_path / "pair"
    monkeypatch.setattr("sys.argv", ["pair", str(root), "--smoke", "--reverse-run-order"])
    assert request_guidance_pair.main() == 0
    result = json.loads((root / "pair-summary.json").read_bytes())
    assert result["experiment"] == "request-guidance"
    assert result["execution_order"] == ["questions", "baseline"]
    assert result["comparison_checks"]["matched_request_payloads_and_choices"] is None
    assert result["comparison_checks"]["recorded_request_guidance"] is None
    assert "winner" not in result and "quality_score" not in result
    for name, digest in result["report_sha256"].items():
        report, _ = saved_report(root / name)
        assert report.request_guidance == name
        assert report.catalog_presentation == "descriptions-only"
        assert report.linked_schema_order == "empty-first"
        manifest = json.loads((root / name / "manifest.json").read_bytes())
        assert manifest["request_guidance"] == name
        assert hashlib.sha256((root / name / "report.json").read_bytes()).hexdigest() == digest
        assert (root / name / "review.json").exists()
        assert "request_guidance.py" in report.source_sha256
    for row in result["tasks"]:
        assert all(arm["conclusion"] is not None for arm in row["arms"].values())
    before = (root / "pair-summary.json").read_bytes()
    assert request_guidance_pair.main() == 2
    assert (root / "pair-summary.json").read_bytes() == before


def test_mocked_pair_changes_only_instructions_and_preserves_empty_theories(tmp_path, monkeypatch):
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
        assert "rubric" not in context and "request_guidance" not in context
        assert all("evidence_needed" not in gap for gap in context["evidence_gaps"])
        guided = body["messages"][0]["content"].endswith(QUESTION_GUIDANCE)
        decision = {"kind": "tool", "tool": "get_finding_evidence", "limit": 5, "offset": 0}
        if context["results"]:
            gap = context["evidence_gaps"][0]
            decision = {
                "kind": "finish", "disposition": "inconclusive", "observations": [],
                "hypotheses": [], "alternative_explanations": [],
                "collection_limits": ["Collection completeness remains unverified."],
                "next_checks": [], "evidence_requests": [{
                    "gap_id": gap["gap_id"], "evidence_source": gap["evidence_source"],
                    "scope_ref": context["request_scope_ref"], "tests": [],
                    "evidence_needed":
                    "Which source/time records establish coverage for this capture?" if guided
                    else gap["evidence_source"],
                }],
            }
        jsonschema.validate({"decision": decision}, body["format"])
        return wire(reply(decision, model=body["model"]))

    def factory(model, token_limit, **kwargs):
        return OllamaAdapter(model, token_limit, transport=httpx2.MockTransport(handler), **kwargs)

    monkeypatch.setattr(ollama_adapter, "OllamaAdapter", factory)
    root = tmp_path / "pair"
    result = asyncio.run(schema_order_pair.collect_pair(
        root, "qwen2.5-coder:7b", slow_local=True, guidance_comparison=True,
    ))
    assert all(value is True for value in result["comparison_checks"].values())
    assert len(bodies) == 20
    for baseline, questions in zip(bodies[:10], bodies[10:], strict=True):
        assert questions["messages"][0]["content"] == (
            baseline["messages"][0]["content"] + QUESTION_GUIDANCE
        )
        assert questions["messages"][1] == baseline["messages"][1]
        assert json.dumps(questions["format"]) == json.dumps(baseline["format"])
        assert normalized_guidance_payload(questions) == baseline
        assert questions["options"] == {"temperature": 0, "num_ctx": 4096, "num_predict": 512}
    left, _ = saved_report(root / "baseline")
    right, _ = saved_report(root / "questions")
    for task in result["tasks"]:
        for arm in task["arms"].values():
            assert arm["hypotheses"] == arm["alternatives"] == arm["test_links"] == 0
        assert all(all(value is True for name, value in request.items() if name != "request")
                   for request in task["request_comparisons"])
    for index, row in enumerate(right.tasks):
        for step, trace in enumerate(row.run.adapter_usage.schema_requests):
            body = copy.deepcopy(bodies[10 + index * 2 + step])
            body["messages"][0]["content"] = body["messages"][0]["content"].removesuffix(
                QUESTION_GUIDANCE,
            )
            del body["format"]
            expected = hashlib.sha256(json.dumps(
                body, ensure_ascii=False, separators=(",", ":"), allow_nan=False,
            ).encode()).hexdigest()
            assert trace.guidance_normalized_payload_sha256 == expected
    right.tasks[0].run.adapter_usage.schema_requests[0].guidance_normalized_payload_sha256 = None
    checks, _ = schema_order_pair.compare_reports(left, right, "qwen2.5-coder:7b",
                                                 guidance_comparison=True)
    assert checks["matched_request_payloads_and_choices"] is False
    right.tasks[1].run.adapter_usage.request_guidance = "baseline"
    checks, _ = schema_order_pair.compare_reports(left, right, "qwen2.5-coder:7b",
                                                 guidance_comparison=True)
    assert checks["recorded_request_guidance"] is False
    right.request_guidance = "baseline"
    checks, _ = schema_order_pair.compare_reports(left, right, "qwen2.5-coder:7b",
                                                 guidance_comparison=True)
    assert checks["expected_request_guidance"] is False


def test_guidance_pair_failure_retains_first_session(tmp_path, monkeypatch):
    original = schema_order_pair.create_session
    calls = []

    async def failing(directory, model, **options):
        calls.append(options["request_guidance"])
        if len(calls) == 2:
            raise RuntimeError("private provider error")
        return await original(directory, model, **options)

    monkeypatch.setattr(schema_order_pair, "create_session", failing)
    root = tmp_path / "pair"
    with pytest.raises(RuntimeError):
        asyncio.run(schema_order_pair.collect_pair(root, guidance_comparison=True))
    assert (root / "baseline" / "report.json").exists()
    assert not (root / "pair-summary.json").exists()
    assert "private provider error" not in (root / "pair-failure.json").read_text()
