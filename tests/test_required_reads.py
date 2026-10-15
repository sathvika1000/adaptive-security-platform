import asyncio
import json

import pytest

from adaptive_security.investigation_runner import InvestigationRunner
from adaptive_security.investigation_tasks import TaskChannel, TaskSuite, run_tasks
from adaptive_security.task_session import bundled_suite


class Script:
    def __init__(self, *decisions):
        self.decisions = iter(decisions)
        self.contexts = []

    async def next_step(self, context):
        self.contexts.append(json.loads(context))
        return next(self.decisions)


FINISH = {"kind": "finish", "disposition": "inconclusive"}
READ = {"kind": "tool", "tool": "get_finding_evidence", "limit": 5}


def task(index=0):
    return TaskSuite.model_validate_json(bundled_suite()).tasks[index]


@pytest.mark.parametrize("index", [0, 1, 2])
def test_early_finish_is_blocked_even_if_provider_ignores_schema(index):
    item = task(index)
    adapter = Script(FINISH)
    report = asyncio.run(
        InvestigationRunner(
            item.grant,
            TaskChannel(item),
            adapter,
            required_tools=("get_finding_evidence",),
        ).run()
    )
    assert report.status == "blocked"
    assert report.detail == "Required evidence read not completed"
    assert report.conclusion is None and report.tool_calls == 0
    assert adapter.contexts[0]["required_tools_remaining"] == ["get_finding_evidence"]
    assert report.required_tools == ["get_finding_evidence"]
    assert len(report.proposals) == 1


@pytest.mark.parametrize("index", [0, 1])
def test_valid_nonempty_or_empty_read_satisfies_precondition(index):
    item = task(index)
    adapter = Script(READ, FINISH)
    report = asyncio.run(
        InvestigationRunner(
            item.grant,
            TaskChannel(item),
            adapter,
            required_tools=("get_finding_evidence",),
        ).run()
    )
    assert report.status == "completed" and report.tool_calls == 1
    assert adapter.contexts[1]["required_tools_remaining"] == []
    assert len(adapter.contexts[1]["results"][0]["events"]) == (0 if index == 1 else 1)


def test_rejected_response_does_not_satisfy_precondition():
    item = task()

    class CorruptChannel(TaskChannel):
        async def read(self, tool, request):
            result = await super().read(tool, request)
            result["scope"]["capture_id"] = "other"
            return result

    report = asyncio.run(
        InvestigationRunner(
            item.grant,
            CorruptChannel(item),
            Script(READ, FINISH),
            required_tools=("get_finding_evidence",),
        ).run()
    )
    assert report.status == "blocked" and report.conclusion is None
    assert report.detail == "Tool result is outside the requested scope"


def test_legacy_runner_can_explicitly_abstain_without_required_reads():
    item = task()
    report = asyncio.run(InvestigationRunner(item.grant, TaskChannel(item), Script(FINISH)).run())
    assert report.status == "completed" and report.required_tools == []


def test_requirements_must_be_granted():
    item = task()
    with pytest.raises(ValueError, match="granted"):
        InvestigationRunner(
            item.grant, TaskChannel(item), Script(FINISH), required_tools=("get_related_events",)
        )


def test_task_evaluation_always_enforces_required_read(monkeypatch):
    pytest.importorskip("mcp")
    from adaptive_security import ollama_adapter

    class EarlyFinish:
        def __init__(self, model, token_limit):
            pass

        async def next_step(self, context_json):
            return FINISH

    monkeypatch.setattr(ollama_adapter, "OllamaAdapter", EarlyFinish)
    report = asyncio.run(run_tasks(TaskSuite.model_validate_json(bundled_suite()), "gemma3:4b"))
    assert report["summary"]["statuses"] == {"blocked": 3}
    assert all(not row["checks"]["completed"] for row in report["tasks"])
