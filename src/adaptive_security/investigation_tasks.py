"""Synthetic analyst tasks with explicit observation rubrics and local model runs."""

import argparse
import asyncio
import hashlib
import json
import os
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from adaptive_security.investigation_access import InvestigationGrant
from adaptive_security.investigation_runner import (
    EvidenceReviewAdapter,
    InvestigationRunner,
    ObservationClaim,
    ReasoningAdapter,
    RunBudget,
    StrictModel,
    canonical,
)
from adaptive_security.investigation_tools import ToolName, ToolRequest, ToolResult


class TaskRubric(StrictModel):
    disposition: Literal["needs_review", "inconclusive"]
    required_observations: list[ObservationClaim] = Field(max_length=10)
    review_notes: str = Field(min_length=1, max_length=2048)


class AnalystTask(StrictModel):
    task_id: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    objective: str = Field(min_length=1, max_length=1024)
    grant: InvestigationGrant
    evidence: ToolResult
    rubric: TaskRubric

    @model_validator(mode="after")
    def validate_fixture(self) -> "AnalystTask":
        if self.grant.tools != ["get_finding_evidence"]:
            raise ValueError("Task fixtures support finding evidence only")
        scope = self.evidence.scope
        if (scope.capture_id, scope.finding_id, scope.review_key) != (
            self.grant.capture_id,
            self.grant.finding_id,
            self.grant.review_key,
        ):
            raise ValueError("Fixture scope must match grant")
        if (
            self.evidence.tool != "get_finding_evidence"
            or self.evidence.relationship != "finding_evidence"
            or self.evidence.coverage is not None
        ):
            raise ValueError("Expected finding evidence fixture")
        records = {(event.source, event.event_id): event for event in self.evidence.events}
        if len(records) != len(self.evidence.events):
            raise ValueError("Duplicate fixture event")
        for claim in self.rubric.required_observations:
            event = records.get((claim.source, claim.event_id))
            if event is None or event.model_dump(mode="json").get(claim.field) != claim.value:
                raise ValueError("Rubric must cite fixture observations")
        return self


class TaskSuite(StrictModel):
    schema_version: Literal[1]
    data_kind: Literal["synthetic-analyst-tasks"]
    review_status: Literal["draft-needs-independent-review"]
    tasks: list[AnalystTask] = Field(min_length=1, max_length=10)

    @model_validator(mode="after")
    def unique_tasks(self) -> "TaskSuite":
        if len({task.task_id for task in self.tasks}) != len(self.tasks):
            raise ValueError("Task IDs must be unique")
        return self


class TaskChannel:
    def __init__(self, task: AnalystTask) -> None:
        self.task = task

    async def read(self, tool: ToolName, request: ToolRequest) -> object:
        if tool != "get_finding_evidence":
            raise ValueError("Unsupported fixture tool")
        result = self.task.evidence.model_copy(deep=True)
        events = result.events
        result.events = events[request.offset : request.offset + request.limit]
        end = request.offset + len(result.events)
        from adaptive_security.investigation_tools import EvidencePage

        result.page = EvidencePage(
            matched_records=len(events),
            returned_records=len(result.events),
            offset=request.offset,
            next_offset=None if end >= len(events) else end,
            exhausted=end >= len(events),
        )
        return result.model_dump(mode="json")


class TaskAdapter:
    def __init__(self, adapter: ReasoningAdapter, objective: str) -> None:
        self.adapter = adapter
        self.objective = objective

    async def next_step(self, context_json: str) -> object:
        context = json.loads(context_json)
        context["investigation_objective"] = self.objective
        return await self.adapter.next_step(canonical(context).decode())

    def __getattr__(self, name: str) -> object:
        return getattr(self.adapter, name)


def load_tasks(path: Path, digest: str) -> TaskSuite:
    with path.open("rb") as stream:
        raw = stream.read(512 * 1024 + 1)
    if len(raw) > 512 * 1024 or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("Task file size or digest mismatch")
    return TaskSuite.model_validate_json(raw)


async def run_tasks(
    suite: TaskSuite,
    model: str | None = None,
    *,
    slow_local: bool = False,
    structured_requests: bool = False,
    scoped_requests: bool = False,
) -> dict[str, object]:
    if slow_local and model is None:
        raise ValueError("Slow local profile requires an Ollama model")
    suite = suite.model_copy(deep=True)
    rows = []
    statuses: Counter[str] = Counter()
    for task in suite.tasks:
        adapter: ReasoningAdapter = EvidenceReviewAdapter()
        if model is not None:
            from adaptive_security.ollama_adapter import OllamaAdapter

            adapter = (
                OllamaAdapter(model, token_limit=13_824, request_timeout_seconds=85.0)
                if slow_local
                else OllamaAdapter(model, token_limit=13_824)
            )
        report = await InvestigationRunner(
            task.grant,
            TaskChannel(task),
            TaskAdapter(adapter, task.objective),
            budget=RunBudget(
                max_steps=3,
                max_tool_calls=2,
                total_seconds=270.0 if slow_local else 90.0,
                operation_seconds=90.0 if slow_local else 30.0,
            ),
            adapter_name="deterministic-task-smoke" if model is None else "ollama-local-task",
            required_tools=("get_finding_evidence",),
            structured_requests=structured_requests,
            scoped_requests=scoped_requests,
        ).run()
        actual = report.conclusion
        observed = (
            {canonical(claim.model_dump()) for claim in actual.observations} if actual else set()
        )
        required = {canonical(claim.model_dump()) for claim in task.rubric.required_observations}
        statuses[report.status] += 1
        rows.append(
            {
                "task_id": task.task_id,
                "objective": task.objective,
                "rubric": task.rubric.model_dump(),
                "run": report.model_dump(mode="json"),
                "checks": {
                    "completed": report.status == "completed",
                    "required_observations": len(required),
                    "required_observations_cited": len(required & observed),
                    "disposition_matches": actual is not None
                    and actual.disposition == task.rubric.disposition,
                    "semantic_review": "pending-human-review",
                    "answer_structure": {
                        field: actual is not None
                        and any(text.strip() for text in getattr(actual, field))
                        for field in (
                            "alternative_explanations",
                            "collection_limits",
                            "next_checks",
                        )
                    },
                },
            }
        )
    return {
        "schema_version": 1,
        "data_kind": suite.data_kind,
        "review_status": suite.review_status,
        "mode": "deterministic-smoke" if model is None else "local-model",
        "suite_semantic_sha256": hashlib.sha256(
            canonical(suite.model_dump(mode="json"))
        ).hexdigest(),
        "source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "investigation_tasks.py",
                "investigation_runner.py",
                "ollama_adapter.py",
                "grounded_schema.py",
                "evidence_requests.py",
                "request_scope.py",
                "evidence_brief.py",
                "investigation_tools.py",
            )
        },
        "summary": {"tasks": len(rows), "statuses": dict(statuses)},
        "tasks": rows,
        "limitations": [
            "Draft synthetic tasks; not independently reviewed or held-out customer evidence.",
            "Exact field and disposition checks do not grade hypothesis semantics or attack truth.",
            "Review hypotheses for unsupported claims, alternatives and injected instructions.",
            "Empty evidence cannot establish benign activity; no detector precision or recall.",
            "Independent per-task budgets; local inference is nondeterministic.",
            "Fixture channel only; no live MCP, SIEM, EDR or response execution.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("--suite-sha256", required=True)
    parser.add_argument("--slow-local", action="store_true")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--ollama-model")
    mode.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    try:
        report = asyncio.run(
            run_tasks(
                load_tasks(args.suite, args.suite_sha256),
                args.ollama_model,
                slow_local=args.slow_local,
            )
        )
        report["suite_file_sha256"] = args.suite_sha256
        args.report.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(report, stream, indent=2)
    except (OSError, ValueError, RuntimeError, ImportError):
        print("Task run failed; check dependencies, suite digest and unused report path.")
        return 2
    print(json.dumps(report["summary"], indent=2))
    return 0  # Successful report generation is not a model quality pass.


if __name__ == "__main__":
    raise SystemExit(main())
