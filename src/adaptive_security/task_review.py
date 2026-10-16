"""Content-bound human review records for synthetic analyst-task runs."""

import argparse
import hashlib
import json
import os
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from adaptive_security.investigation_runner import RunReport, StrictModel
from adaptive_security.investigation_tasks import TaskRubric
from adaptive_security.schema_order import SchemaOrder

Rating = Literal["supported", "concern", "not_assessable"]
DIMENSIONS = (
    "evidence_support",
    "alternative_explanations",
    "collection_limits",
    "instruction_handling",
)


class TaskChecks(StrictModel):
    completed: bool
    required_observations: int = Field(ge=0, le=10)
    required_observations_cited: int = Field(ge=0, le=10)
    disposition_matches: bool
    semantic_review: Literal["pending-human-review"]
    answer_structure: dict[str, bool] = Field(default_factory=dict)


class TaskRun(StrictModel):
    task_id: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    objective: str = Field(min_length=1, max_length=1024)
    rubric: TaskRubric
    run: RunReport
    checks: TaskChecks


class TaskReport(StrictModel):
    schema_version: Literal[1]
    data_kind: Literal["synthetic-analyst-tasks"]
    review_status: Literal["draft-needs-independent-review"]
    mode: Literal["deterministic-smoke", "local-model"]
    suite_semantic_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    suite_file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    linked_schema_order: SchemaOrder | None = None
    source_sha256: dict[str, str]
    summary: dict[str, object]
    tasks: list[TaskRun] = Field(min_length=1, max_length=10)
    limitations: list[str]

    @model_validator(mode="after")
    def unique_tasks(self) -> "TaskReport":
        if len({row.task_id for row in self.tasks}) != len(self.tasks):
            raise ValueError("Duplicate task IDs")
        return self


class Assessment(StrictModel):
    task_id: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    run_id: str = Field(min_length=1, max_length=128)
    evidence_support: Rating | None = None
    alternative_explanations: Rating | None = None
    collection_limits: Rating | None = None
    instruction_handling: Rating | None = None
    notes: str = Field(default="", max_length=4096)


class ReviewSheet(StrictModel):
    schema_version: Literal[1] = 1
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    suite_semantic_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer: str = Field(default="", max_length=128)
    assessments: list[Assessment] = Field(min_length=1, max_length=10)


def read_pinned(path: Path, digest: str, maximum: int) -> bytes:
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("File size or digest mismatch")
    return raw


def load_report(path: Path, digest: str) -> TaskReport:
    return TaskReport.model_validate_json(read_pinned(path, digest, 8 * 1024 * 1024))


def prepare(report: TaskReport, digest: str) -> ReviewSheet:
    return ReviewSheet(
        report_sha256=digest,
        suite_semantic_sha256=report.suite_semantic_sha256,
        assessments=[
            Assessment(task_id=row.task_id, run_id=row.run.run_id) for row in report.tasks
        ],
    )


def summarize(report: TaskReport, digest: str, review: ReviewSheet) -> dict[str, object]:
    if (
        review.report_sha256 != digest
        or review.suite_semantic_sha256 != report.suite_semantic_sha256
    ):
        raise ValueError("Review is bound to a different report")
    expected = {(row.task_id, row.run.run_id) for row in report.tasks}
    actual = [(row.task_id, row.run_id) for row in review.assessments]
    if len(set(actual)) != len(actual) or set(actual) != expected:
        raise ValueError("Review must cover every task and exact run once")
    if not review.reviewer.strip():
        raise ValueError("Reviewer attribution required")
    counts: dict[str, Counter[str]] = {dimension: Counter() for dimension in DIMENSIONS}
    for row in review.assessments:
        if not row.notes.strip():
            raise ValueError("Every assessment needs explanatory notes")
        for dimension in DIMENSIONS:
            rating = getattr(row, dimension)
            if rating is None:
                raise ValueError("Every review dimension must be explicitly rated")
            counts[dimension][rating] += 1
    return {
        "schema_version": 1,
        "data_kind": report.data_kind,
        "mode": report.mode,
        "report_sha256": digest,
        "suite_semantic_sha256": report.suite_semantic_sha256,
        "reviewer": review.reviewer,
        "tasks_reviewed": len(actual),
        "ratings": {dimension: dict(count) for dimension, count in counts.items()},
        "assessments": [row.model_dump() for row in review.assessments],
        "run_statuses": dict(Counter(row.run.status for row in report.tasks)),
        "limitations": [
            "Reviewer attribution is self-declared and has not been independently verified.",
            "Ratings are human judgments; no model accuracy or production readiness is inferred.",
            "Review does not promote draft rubrics or modify the original run or suite.",
            "Not-assessable ratings remain in denominators; no aggregate pass score is assigned.",
        ],
    }


def write_private(path: Path, value: object) -> None:
    body = json.dumps(value, indent=2).encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(body)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "summarize"):
        command = subcommands.add_parser(name)
        command.add_argument("report", type=Path)
        command.add_argument("output", type=Path)
        command.add_argument("--report-sha256", required=True)
        if name == "summarize":
            command.add_argument("--review", type=Path, required=True)
            command.add_argument("--review-sha256", required=True)
    args = parser.parse_args()
    try:
        report = load_report(args.report, args.report_sha256)
        if args.command == "prepare":
            value = prepare(report, args.report_sha256).model_dump()
        else:
            review = ReviewSheet.model_validate_json(
                read_pinned(args.review, args.review_sha256, 128 * 1024)
            )
            value = summarize(report, args.report_sha256, review)
            value["review_file_sha256"] = args.review_sha256
        write_private(args.output, value)
    except (OSError, ValueError):
        print("Review failed; check file digests, complete assessments and unused output path.")
        return 2
    print("Private review artifact created.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
