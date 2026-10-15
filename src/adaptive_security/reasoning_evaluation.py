"""Hash-pinned synthetic controller evaluation; never detector accuracy."""

import argparse
import asyncio
import hashlib
import json
import os
from collections import Counter
from pathlib import Path
from typing import Literal, cast

from pydantic import Field, model_validator

from adaptive_security.investigation_access import InvestigationGrant
from adaptive_security.investigation_runner import (
    InvestigationRunner,
    ReasoningAdapter,
    RunBudget,
    RunReport,
    StrictModel,
    canonical,
)
from adaptive_security.investigation_tools import ToolName, ToolRequest


class Expected(StrictModel):
    detail: str = Field(min_length=1, max_length=256)
    status: Literal["completed", "blocked", "budget_exhausted", "timeout", "failed"]
    disposition: Literal["inconclusive", "needs_review"] | None = None


class EvaluationCase(StrictModel):
    case_id: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    purpose: str = Field(min_length=1, max_length=512)
    grant: InvestigationGrant
    budget: RunBudget = Field(default_factory=RunBudget)
    responses: list[dict[str, object]] = Field(default_factory=list, max_length=10)
    decisions: list[dict[str, object]] = Field(min_length=1, max_length=20)
    expected: Expected


class EvaluationSuite(StrictModel):
    schema_version: Literal[1]
    data_kind: Literal["synthetic-controller-cases"]
    cases: list[EvaluationCase] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def unique_cases(self) -> "EvaluationSuite":
        if len({case.case_id for case in self.cases}) != len(self.cases):
            raise ValueError("Case IDs must be unique")
        return self


class ReplayAdapter:
    def __init__(self, decisions: list[dict[str, object]]) -> None:
        self.decisions = iter(decisions)

    async def next_step(self, context_json: str) -> object:
        return next(self.decisions)


class FixtureChannel:
    def __init__(self, responses: list[dict[str, object]]) -> None:
        self.responses = iter(responses)

    async def read(self, tool: ToolName, request: ToolRequest) -> object:
        return next(self.responses)


def load_suite(path: Path, expected_sha256: str) -> EvaluationSuite:
    with path.open("rb") as stream:
        raw = stream.read(512 * 1024 + 1)
    if len(raw) > 512 * 1024:
        raise ValueError("Suite exceeds 512 KiB")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("Suite digest mismatch")
    return EvaluationSuite.model_validate_json(raw)


async def evaluate(suite: EvaluationSuite) -> dict[str, object]:
    # Snapshot once: concurrent caller mutation cannot change cases or expectations.
    suite = suite.model_copy(deep=True)
    rows: list[dict[str, object]] = []
    statuses: Counter[str] = Counter()
    dispositions: Counter[str] = Counter()
    matches = 0
    for case in suite.cases:
        adapter: ReasoningAdapter = ReplayAdapter(case.decisions)
        report: RunReport = await InvestigationRunner(
            case.grant,
            FixtureChannel(case.responses),
            adapter,
            budget=case.budget,
            adapter_name="controlled-replay",
        ).run()
        disposition = report.conclusion.disposition if report.conclusion else None
        matched = (
            report.status == case.expected.status
            and disposition == case.expected.disposition
            and report.detail == case.expected.detail
        )
        matches += matched
        statuses[report.status] += 1
        if disposition is not None:
            dispositions[disposition] += 1
        rows.append(
            {
                "case_id": case.case_id,
                "expected": case.expected.model_dump(),
                "matches_expectation": matched,
                "run": report.model_dump(mode="json"),
            }
        )
    return {
        "schema_version": 1,
        "data_kind": suite.data_kind,
        "adapter": "controlled-replay",
        "suite_semantic_sha256": hashlib.sha256(
            canonical(suite.model_dump(mode="json"))
        ).hexdigest(),
        "implementation_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "reasoning_evaluation.py", "investigation_runner.py", "investigation_tools.py"
            )
        },
        "summary": {
            "cases": len(rows),
            "expectation_matches": matches,
            "statuses": dict(statuses),
            "dispositions": dict(dispositions),
        },
        "cases": rows,
        "limitations": [
            "Synthetic evidence and supplied replay decisions test controller enforcement only.",
            "Expectation matches do not measure detector accuracy or semantic reasoning quality.",
            "Inconclusive dispositions are counted, not graded as useful abstentions.",
            "No real MCP server, customer telemetry or response action is exercised.",
            "No model inference is performed; this is not a model quality benchmark.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("--suite-sha256", required=True)
    args = parser.parse_args()
    try:
        suite = load_suite(args.suite, args.suite_sha256)
        report = asyncio.run(evaluate(suite))
        report["suite_file_sha256"] = args.suite_sha256
        encoded = json.dumps(report, indent=2).encode()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
    except (OSError, ValueError, RuntimeError):
        print("Evaluation failed; verify suite digest, configuration and unused report path.")
        return 2
    print(json.dumps(report["summary"], indent=2))
    summary = cast(dict[str, object], report["summary"])
    return 0 if summary["expectation_matches"] == summary["cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
