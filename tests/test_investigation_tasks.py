import asyncio
import hashlib
import json
import os
from pathlib import Path

import pytest

from adaptive_security import investigation_tasks as tasks
from adaptive_security.investigation_runner import AdapterUsage
from adaptive_security.investigation_tools import ToolRequest

SUITE = Path(__file__).resolve().parents[1] / "examples/evaluation/analyst-tasks.json"


def load():
    return tasks.load_tasks(SUITE, hashlib.sha256(SUITE.read_bytes()).hexdigest())


def test_smoke_does_not_claim_model_quality():
    report = asyncio.run(tasks.run_tasks(load()))
    assert report["mode"] == "deterministic-smoke"
    assert report["summary"] == {"tasks": 3, "statuses": {"completed": 3}}
    assert all(
        row["checks"]["semantic_review"] == "pending-human-review" for row in report["tasks"]
    )
    # Demo cites category, not the task's requested outcome: expose the missing observations.
    assert report["tasks"][0]["checks"]["required_observations_cited"] == 0
    assert "precision" not in report and "accuracy" not in report


def test_task_channel_pages_by_request():
    task = load().tasks[0]
    channel = tasks.TaskChannel(task)
    request = ToolRequest(
        capture_id=task.grant.capture_id,
        finding_id=task.grant.finding_id,
        review_key=task.grant.review_key,
        limit=1,
        offset=1,
    )
    result = asyncio.run(channel.read("get_finding_evidence", request))
    assert result["events"] == []
    assert result["page"]["offset"] == 1
    assert result["page"]["exhausted"] is True
    assert len(task.evidence.events) == 1
    with pytest.raises(ValueError):
        asyncio.run(channel.read("get_related_events", request))


@pytest.mark.parametrize("change", ["duplicate", "rubric", "scope", "tool", "event"])
def test_invalid_task_suite(change):
    payload = json.loads(SUITE.read_text())
    task = payload["tasks"][0]
    if change == "duplicate":
        payload["tasks"].append(task)
    elif change == "rubric":
        task["rubric"]["required_observations"][0]["value"] = "success"
    elif change == "scope":
        task["evidence"]["scope"]["capture_id"] = "other"
    elif change == "tool":
        task["grant"]["tools"] = ["get_related_events"]
    else:
        task["evidence"]["events"].append(task["evidence"]["events"][0])
    with pytest.raises(ValueError):
        tasks.TaskSuite.model_validate_json(json.dumps(payload))


def test_pin_rejects_tampering(tmp_path):
    path = tmp_path / "suite.json"
    path.write_bytes(SUITE.read_bytes() + b" ")
    with pytest.raises(ValueError, match="digest"):
        tasks.load_tasks(path, hashlib.sha256(SUITE.read_bytes()).hexdigest())


def test_local_adapter_context_usage_and_rubric(monkeypatch):
    pytest.importorskip("mcp")
    from adaptive_security import ollama_adapter

    contexts = []

    class FakeLocal:
        def __init__(self, model, token_limit):
            assert model == "gemma3:4b" and token_limit == 13824
            self.calls = 0

        def usage(self):
            return AdapterUsage(
                model="gemma3:4b",
                requests=self.calls,
                prompt_tokens=0,
                generated_tokens=0,
                charged_tokens=0,
                token_limit=13824,
                unconfirmed_requests=0,
            )

        async def next_step(self, context_json):
            self.calls += 1
            context = json.loads(context_json)
            contexts.append(context)
            if not context["results"]:
                return {"kind": "tool", "tool": "get_finding_evidence", "limit": 5}
            events = context["results"][0]["events"]
            return {
                "kind": "finish",
                "disposition": "needs_review" if events else "inconclusive",
                "observations": [
                    dict(
                        source=e["source"],
                        event_id=e["event_id"],
                        field="outcome",
                        value=e["outcome"],
                    )
                    for e in events
                ],
            }

    monkeypatch.setattr(ollama_adapter, "OllamaAdapter", FakeLocal)
    report = asyncio.run(tasks.run_tasks(load(), "gemma3:4b"))
    assert report["mode"] == "local-model"
    for context in contexts:
        assert "investigation_objective" in context
        assert "rubric" not in context and "required_observations" not in context
    for row in report["tasks"]:
        assert row["run"]["adapter_usage"]["requests"] == 2
        assert row["checks"]["disposition_matches"]
        assert (
            row["checks"]["required_observations_cited"] == row["checks"]["required_observations"]
        )


def test_cli_requires_mode_and_private_no_overwrite(tmp_path, monkeypatch):
    path = tmp_path / "report.json"
    args = [
        "tasks",
        str(SUITE),
        str(path),
        "--suite-sha256",
        hashlib.sha256(SUITE.read_bytes()).hexdigest(),
    ]
    monkeypatch.setattr("sys.argv", args)
    with pytest.raises(SystemExit):
        tasks.main()
    monkeypatch.setattr("sys.argv", [*args, "--smoke"])
    assert tasks.main() == 0
    body = path.read_bytes()
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
    assert tasks.main() == 2
    assert path.read_bytes() == body
