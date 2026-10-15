import copy
import json
from pathlib import Path

import pytest

pytest.importorskip("mcp")
pytest.importorskip("jsonschema")

import jsonschema

from adaptive_security.grounded_schema import grounded_schema
from adaptive_security.investigation_runner import RunStopped
from adaptive_security.ollama_adapter import ModelDecision


def context(empty=False):
    path = Path(__file__).resolve().parents[1] / "examples/evaluation/analyst-tasks.json"
    task = json.loads(path.read_text())["tasks"][1 if empty else 0]
    result = task["evidence"]
    count = len(result["events"])
    result["page"] = {
        "offset": 0,
        "matched_records": count,
        "returned_records": count,
        "next_offset": None,
        "exhausted": True,
    }
    return {"allowed_tools": task["grant"]["tools"], "results": [result]}


def finish(claims):
    return {
        "decision": {
            "kind": "finish",
            "disposition": "inconclusive",
            "observations": claims,
            "hypotheses": [],
            "alternative_explanations": [
                "A legitimate retry is possible; authorization is unknown."
            ],
            "collection_limits": ["Only the returned capture is available."],
            "next_checks": ["Review account and session context."],
        }
    }


def claim(source="synthetic", event_id="event-1", value="failure"):
    return {"source": source, "event_id": event_id, "field": "outcome", "value": value}


def test_grounded_schema_accepts_exact_claim_and_rejects_reported_source_error():
    base = ModelDecision.model_json_schema()
    before = copy.deepcopy(base)
    schema = grounded_schema(base, json.dumps(context()))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(finish([claim()]), schema)
    for bad in (claim(source="event-1"), claim(event_id="invented"), claim(value="failed")):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(finish([bad]), schema)
    assert base == before


def test_empty_capture_disallows_invented_observations():
    schema = grounded_schema(ModelDecision.model_json_schema(), json.dumps(context(empty=True)))
    jsonschema.validate(finish([]), schema)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(finish([claim()]), schema)
    wrong = finish([])
    wrong["decision"]["disposition"] = "needs_review"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(wrong, schema)


def test_completed_page_is_not_reread_even_with_a_different_limit():
    schema = grounded_schema(ModelDecision.model_json_schema(), json.dumps(context()))
    for limit in (2, 5):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(
                {
                    "decision": {
                        "kind": "tool",
                        "tool": "get_finding_evidence",
                        "offset": 0,
                        "limit": limit,
                    }
                },
                schema,
            )


def test_first_and_next_page_are_available():
    data = context()
    initial = grounded_schema(
        ModelDecision.model_json_schema(), json.dumps({**data, "results": []})
    )
    tool = {"decision": {"kind": "tool", "tool": "get_finding_evidence", "offset": 0, "limit": 5}}
    jsonschema.validate(tool, initial)
    page = data["results"][0]["page"]
    page.update(matched_records=2, exhausted=False, next_offset=1)
    schema = grounded_schema(ModelDecision.model_json_schema(), json.dumps(data))
    tool["decision"]["offset"] = 1
    jsonschema.validate(tool, schema)
    tool["decision"]["offset"] = 0
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(tool, schema)


def test_size_and_bad_context_stop_before_provider_call():
    with pytest.raises(ValueError):
        grounded_schema(ModelDecision.model_json_schema(), "[]")
    with pytest.raises(ValueError):
        grounded_schema(ModelDecision.model_json_schema(), '{"allowed_tools":["execute"]}')
    data = context()
    event = data["results"][0]["events"][0]
    data["results"][0]["events"] = [dict(event, event_id=str(index)) for index in range(100)]
    with pytest.raises(RunStopped) as stopped:
        # RunStopped deliberately stores a structured detail rather than exception text.
        try:
            grounded_schema(ModelDecision.model_json_schema(), json.dumps(data))
        except RunStopped as error:
            assert error.status == "budget_exhausted"
            raise
    assert "12 KiB" in stopped.value.detail


@pytest.mark.parametrize("task_index", [0, 1, 2])
def test_each_task_flows_through_grounded_format_and_controller(task_index):
    import asyncio

    import httpx2
    from test_ollama_adapter import LOCAL_INFO, reply, wire

    from adaptive_security.investigation_runner import InvestigationRunner
    from adaptive_security.investigation_tasks import AnalystTask, TaskAdapter, TaskChannel
    from adaptive_security.ollama_adapter import OllamaAdapter

    path = Path(__file__).resolve().parents[1] / "examples/evaluation/analyst-tasks.json"
    task = AnalystTask.model_validate_json(
        json.dumps(json.loads(path.read_text())["tasks"][task_index])
    )
    requests = []

    def handler(request):
        if request.url.path == "/api/show":
            return wire(LOCAL_INFO)
        body = json.loads(request.content)
        data = json.loads(body["messages"][1]["content"])
        if not data["results"]:
            decision = {"kind": "tool", "tool": "get_finding_evidence", "limit": 5, "offset": 0}
        else:
            events = data["results"][0]["events"]
            decision = finish([claim()] if events else [])["decision"]
            decision["disposition"] = "needs_review" if events else "inconclusive"
        jsonschema.validate({"decision": decision}, body["format"])
        requests.append(body)
        return wire(reply(decision))

    adapter = OllamaAdapter("gemma3:4b", transport=httpx2.MockTransport(handler))
    report = asyncio.run(
        InvestigationRunner(
            task.grant,
            TaskChannel(task),
            TaskAdapter(adapter, task.objective),
        ).run()
    )
    assert report.status == "completed" and len(requests) == 2
    assert report.tool_calls == 1
    assert report.conclusion is not None
    assert report.adapter_usage.unconfirmed_requests == 0


def test_grounded_finish_requires_explicit_context_and_next_evidence_checks():
    schema = grounded_schema(ModelDecision.model_json_schema(), json.dumps(context()))
    good = finish([claim()])
    jsonschema.validate(good, schema)
    for field in ("collection_limits", "next_checks", "alternative_explanations"):
        missing = copy.deepcopy(good)
        missing["decision"].pop(field)
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(missing, schema)
        blank = copy.deepcopy(good)
        blank["decision"][field] = []
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(blank, schema)
