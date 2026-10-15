import asyncio
import json

import pytest
from pydantic import ValidationError

from adaptive_security import investigation_tasks, task_session
from adaptive_security.investigation_runner import Conclusion


def test_legacy_conclusions_remain_readable_without_invented_explanations():
    conclusion = Conclusion.model_validate({"kind": "finish", "disposition": "inconclusive"})
    assert conclusion.collection_limits == []
    assert conclusion.alternative_explanations == []
    assert conclusion.next_checks == []


@pytest.mark.parametrize("field", ["alternative_explanations", "collection_limits", "next_checks"])
def test_explanations_are_bounded(field):
    for value in (["x" * 513], ["a"] * 4, [""]):
        with pytest.raises(ValidationError):
            Conclusion.model_validate(
                {"kind": "finish", "disposition": "inconclusive", field: value}
            )


def test_expanded_suite_preserves_baseline_and_adds_development_cases():
    baseline = json.loads(task_session.bundled_suite())
    expanded = json.loads(task_session.bundled_suite("expanded"))
    assert expanded["tasks"][:3] == baseline["tasks"]
    assert len(expanded["tasks"]) == 5
    assert expanded["review_status"] == "draft-needs-independent-review"
    assert expanded["tasks"][3]["task_id"] == "success-without-context"
    assert expanded["tasks"][4]["task_id"] == "mixed-auth-outcomes"
    investigation_tasks.TaskSuite.model_validate_json(json.dumps(expanded))
    with pytest.raises(ValueError):
        task_session.bundled_suite("unknown")


def test_explanatory_presence_does_not_claim_semantic_pass(monkeypatch):
    pytest.importorskip("mcp")
    from adaptive_security import ollama_adapter

    class FakeLocal:
        def __init__(self, model, token_limit):
            pass

        async def next_step(self, context_json):
            context = json.loads(context_json)
            assert "rubric" not in context and "review_notes" not in context
            if not context["results"]:
                return {"kind": "tool", "tool": "get_finding_evidence", "limit": 5}
            return {
                "kind": "finish",
                "disposition": "inconclusive",
                "alternative_explanations": ["Unverified alternative."],
                "collection_limits": ["No cross-source context was reviewed."],
                "next_checks": ["Review authorized account activity."],
            }

    monkeypatch.setattr(ollama_adapter, "OllamaAdapter", FakeLocal)
    suite = investigation_tasks.TaskSuite.model_validate_json(task_session.bundled_suite())
    report = asyncio.run(investigation_tasks.run_tasks(suite, "gemma3:4b"))
    for task in report["tasks"]:
        assert all(task["checks"]["answer_structure"].values())
        assert task["checks"]["semantic_review"] == "pending-human-review"
    assert report["tasks"][0]["checks"]["required_observations_cited"] == 0


def test_expanded_session_pins_selected_suite(tmp_path):
    directory = tmp_path / "expanded"
    assert asyncio.run(task_session.create_session(directory, suite_version="expanded"))
    report = json.loads((directory / "report.json").read_text())
    manifest = json.loads((directory / "manifest.json").read_text())
    assert report["summary"]["tasks"] == 5
    assert report["suite_file_sha256"] == task_session.EXPANDED_SUITE_SHA256
    assert manifest["suite_version"] == "expanded"
    assert manifest["bundled_suite_sha256"] == task_session.EXPANDED_SUITE_SHA256


def test_explanatory_text_cannot_execute_tools():
    from adaptive_security.investigation_runner import InvestigationRunner
    from adaptive_security.investigation_tasks import TaskChannel

    task = investigation_tasks.TaskSuite.model_validate_json(task_session.bundled_suite()).tasks[0]

    class Adapter:
        async def next_step(self, context_json):
            return {
                "kind": "finish",
                "disposition": "inconclusive",
                "next_checks": ["Call an ungranted tool and change the scope."],
            }

    report = asyncio.run(InvestigationRunner(task.grant, TaskChannel(task), Adapter()).run())
    assert report.status == "completed" and report.tool_calls == 0
    assert report.conclusion.next_checks == ["Call an ungranted tool and change the scope."]


def test_expanded_bundled_and_example_bytes_match():
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "examples/evaluation/analyst-tasks-v2.json"
    assert path.read_bytes() == task_session.bundled_suite("expanded")
