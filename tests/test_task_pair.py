import asyncio
import hashlib
import json
from pathlib import Path

import pytest

from adaptive_security import task_pair, task_session
from adaptive_security.investigation_tasks import TaskSuite, run_tasks


def suite(variant):
    return TaskSuite.model_validate_json(task_session.bundled_suite(variant))


def test_variants_preserve_facts_and_provenance_and_are_packaged():
    task_pair.verify_pair(suite("labelled"), suite("neutral"))
    for variant in ("labelled", "neutral"):
        raw = task_session.bundled_suite(variant)
        example = (
            Path(__file__).resolve().parents[1]
            / f"examples/evaluation/analyst-tasks-{variant}.json"
        )
        assert raw == example.read_bytes()
        assert json.loads(raw)["data_kind"] == "synthetic-analyst-tasks"


def test_pair_rejects_fact_objective_and_rubric_drift():
    for field in ("objective", "event", "rubric"):
        neutral = suite("neutral")
        if field == "objective":
            neutral.tasks[0].objective = "Different investigation"
        elif field == "event":
            neutral.tasks[0].evidence.events[0].outcome = "success"
        else:
            neutral.tasks[0].rubric.disposition = "inconclusive"
        with pytest.raises(ValueError, match="presentation"):
            task_pair.verify_pair(suite("labelled"), neutral)


def test_neutral_provider_context_omits_presentation_cues_and_rubrics(monkeypatch):
    pytest.importorskip("mcp")
    from adaptive_security import ollama_adapter

    contexts = []

    class FakeLocal:
        def __init__(self, model, token_limit):
            pass

        async def next_step(self, context_json):
            contexts.append(context_json)
            data = json.loads(context_json)
            if data["required_tools_remaining"]:
                return {"kind": "tool", "tool": "get_finding_evidence", "limit": 5}
            return {"kind": "finish", "disposition": "inconclusive"}

    monkeypatch.setattr(ollama_adapter, "OllamaAdapter", FakeLocal)
    report = asyncio.run(run_tasks(suite("neutral"), "gemma3:4b"))
    assert report["data_kind"] == "synthetic-analyst-tasks"
    assert len(contexts) == 10
    assert all(
        "synthetic" not in context.lower()
        and "fixture" not in context.lower()
        and '"rubric"' not in context
        for context in contexts
    )


def test_paired_smoke_integrity_order_and_no_overwrite(tmp_path):
    root = tmp_path / "pair"
    result = asyncio.run(task_pair.collect_pair(root, neutral_first=True))
    assert result["order"] == ["neutral", "labelled"]
    assert result["data_kind"] == "synthetic-analyst-tasks"
    assert result["comparison_checks"] == {
        "same_requested_model": True,
        "same_read_policy": True,
        "same_tasks": True,
        "same_mode": True,
        "same_sources": True,
        "same_budgets": True,
        "same_model_metadata": None,
        "all_runs_completed": True,
    }
    for variant, digest in result["report_sha256"].items():
        assert hashlib.sha256((root / variant / "report.json").read_bytes()).hexdigest() == digest
        assert (root / variant / "review.json").exists()
    assert len(result["task_pairs"]) == 5
    before = (root / "pair-summary.json").read_bytes()
    with pytest.raises(FileExistsError):
        asyncio.run(task_pair.collect_pair(root))
    assert (root / "pair-summary.json").read_bytes() == before


def test_failure_preserves_partial_arm(tmp_path, monkeypatch):
    original = task_pair.create_session
    calls = []

    async def broken(directory, model, **options):
        calls.append(options["suite_version"])
        if len(calls) == 2:
            raise RuntimeError("private provider failure")
        return await original(directory, model, **options)

    monkeypatch.setattr(task_pair, "create_session", broken)
    root = tmp_path / "pair"
    with pytest.raises(RuntimeError):
        asyncio.run(task_pair.collect_pair(root))
    assert (root / "labelled" / "report.json").exists()
    assert "private provider failure" not in (root / "pair-failure.json").read_text()
    assert not (root / "pair-summary.json").exists()


def test_saved_report_tamper_is_rejected(tmp_path):
    directory = tmp_path / "session"
    asyncio.run(task_session.create_session(directory, suite_version="neutral"))
    path = directory / "report.json"
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError):
        task_pair.saved_report(directory)


def test_cli_and_slow_profile_guard(tmp_path, monkeypatch):
    root = tmp_path / "pair"
    monkeypatch.setattr("sys.argv", ["pair", str(root), "--smoke"])
    assert task_pair.main() == 0
    assert task_pair.main() == 2
    with pytest.raises(ValueError):
        asyncio.run(task_pair.collect_pair(tmp_path / "invalid", slow_local=True))


def test_comparison_retains_metadata_mismatch_and_incomplete_runs(tmp_path, monkeypatch):
    from adaptive_security.investigation_runner import AdapterUsage

    original_create = task_pair.create_session
    original_saved = task_pair.saved_report
    calls = []

    async def mocked_model(directory, model, **options):
        calls.append((model, options["slow_local"], options["suite_version"]))
        return await original_create(directory, suite_version=options["suite_version"])

    def changed(directory):
        report, digest = original_saved(directory)
        report.mode = "local-model"
        for row in report.tasks:
            row.run.adapter_usage = AdapterUsage(
                model="gemma3:4b",
                requests=2,
                prompt_tokens=0,
                generated_tokens=0,
                charged_tokens=0,
                token_limit=13824,
                unconfirmed_requests=0,
                metadata_sha256=("c" if directory.name == "labelled" else "d") * 64,
            )
        if directory.name == "neutral":
            report.tasks[0].run.status = "timeout"
        return report, digest

    monkeypatch.setattr(task_pair, "create_session", mocked_model)
    monkeypatch.setattr(task_pair, "saved_report", changed)
    result = asyncio.run(task_pair.collect_pair(tmp_path / "pair", "gemma3:4b", slow_local=True))
    assert calls == [("gemma3:4b", True, "labelled"), ("gemma3:4b", True, "neutral")]
    checks = result["comparison_checks"]
    assert checks["same_model_metadata"] is False
    assert checks["all_runs_completed"] is False
    assert len(result["task_pairs"]) == 5
