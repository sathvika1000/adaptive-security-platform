"""Human assessments bound to exact accepted evidence-request proposals."""

import argparse
import hashlib
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import Field

from adaptive_security.evidence_requests import (
    EvidenceRequest,
    request_catalog,
    request_payload,
    validate_requests,
)
from adaptive_security.investigation_runner import StrictModel, canonical
from adaptive_security.request_scope import RequestScope
from adaptive_security.statement_tests import statement_inventory, validate_statement_tests
from adaptive_security.task_audit import accepted_results
from adaptive_security.task_pair import saved_report
from adaptive_security.task_review import (
    Rating,
    TaskReport,
    load_report,
    read_pinned,
    write_private,
)

DIMENSIONS = ("relevance", "specificity", "gap_resolution")
IDENTITY_FIELDS = (
    "task_id",
    "run_id",
    "request_index",
    "request_sha256",
    "request",
    "objective",
    "gap_basis",
)


class RequestAssessment(StrictModel):
    task_id: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    run_id: str = Field(min_length=1, max_length=128)
    request_index: int = Field(ge=0, le=2)
    request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    request: EvidenceRequest
    objective: str = Field(min_length=1, max_length=1024)
    gap_basis: str = Field(min_length=1, max_length=1024)
    relevance: Rating | None = None
    specificity: Rating | None = None
    gap_resolution: Rating | None = None
    notes: str = Field(default="", max_length=2048)


class RequestReview(StrictModel):
    schema_version: Literal[1] = 1
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    suite_semantic_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer: str = Field(default="", max_length=128)
    statement_contexts: dict[str, dict[str, str]] = Field(default_factory=dict, max_length=10)
    shared_scopes: dict[str, RequestScope] = Field(default_factory=dict, max_length=10)
    assessments: list[RequestAssessment] = Field(min_length=1, max_length=30)


def prepare(report: TaskReport, digest: str) -> RequestReview:
    rows = []
    shared_scopes = {}
    statement_contexts = {}
    for task in report.tasks:
        conclusion = task.run.conclusion
        if conclusion is None:
            continue
        if task.run.status != "completed":
            raise ValueError("Only completed conclusions can contain accepted requests")
        results = accepted_results(task.run)
        validate_requests(conclusion.evidence_requests, results, task.run.shared_scope)
        if (
            task.run.shared_request_scope
            and conclusion.evidence_requests
            and (
                task.run.shared_scope is None
                or any(request.scope_ref is None for request in conclusion.evidence_requests)
            )
        ):
            raise ValueError("Missing required shared scope or reference")
        if task.run.shared_scope is not None and conclusion.evidence_requests:
            if task.run.run_id in shared_scopes:
                raise ValueError("Duplicate shared-scope run ID")
            shared_scopes[task.run.run_id] = task.run.shared_scope.model_copy(deep=True)
        validate_statement_tests(
            conclusion.hypotheses,
            conclusion.alternative_explanations,
            [request.tests for request in conclusion.evidence_requests],
            required=task.run.linked_tests,
            evidence_goals=[request.evidence_needed for request in conclusion.evidence_requests],
        )
        if task.run.linked_tests or any(request.tests for request in conclusion.evidence_requests):
            if task.run.run_id in statement_contexts:
                raise ValueError("Duplicate statement-context run ID")
            statement_contexts[task.run.run_id] = statement_inventory(
                conclusion.hypotheses, conclusion.alternative_explanations
            )
        gaps = {gap["gap_id"]: gap for gap in request_catalog(results)}
        for index, request in enumerate(conclusion.evidence_requests):
            rows.append(
                RequestAssessment(
                    task_id=task.task_id,
                    run_id=task.run.run_id,
                    request_index=index,
                    request_sha256=hashlib.sha256(canonical(request_payload(request))).hexdigest(),
                    request=request.model_copy(deep=True),
                    objective=task.objective,
                    gap_basis=gaps[request.gap_id]["basis"],
                )
            )
    if not rows:
        raise ValueError("Report contains no accepted evidence requests to review")
    return RequestReview(
        report_sha256=digest,
        suite_semantic_sha256=report.suite_semantic_sha256,
        assessments=rows,
        shared_scopes=shared_scopes,
        statement_contexts=statement_contexts,
    )


def summarize(report: TaskReport, digest: str, review: RequestReview) -> dict[str, object]:
    expected = prepare(report, digest)
    if (
        review.report_sha256 != expected.report_sha256
        or review.suite_semantic_sha256 != expected.suite_semantic_sha256
    ):
        raise ValueError("Review is bound to a different report")

    if review.shared_scopes != expected.shared_scopes:
        raise ValueError("Review shared scopes differ from accepted report context")

    if review.statement_contexts != expected.statement_contexts:
        raise ValueError("Review statement context differs from original explanations")

    def identity(row: RequestAssessment) -> bytes:
        data = row.model_dump(include=set(IDENTITY_FIELDS))
        data["request"] = request_payload(row.request)
        return canonical(data)

    identities = [identity(row) for row in review.assessments]
    if len(set(identities)) != len(identities) or set(identities) != {
        identity(row) for row in expected.assessments
    }:
        raise ValueError("Review must cover every exact request and context once")
    if not review.reviewer.strip():
        raise ValueError("Reviewer attribution required")
    counts: dict[str, Counter[str]] = {dimension: Counter() for dimension in DIMENSIONS}
    for row in review.assessments:
        if not row.notes.strip():
            raise ValueError("Every assessment needs explanatory notes")
        for dimension in DIMENSIONS:
            rating = getattr(row, dimension)
            if rating is None:
                raise ValueError("Every dimension must be explicitly rated")
            counts[dimension][rating] += 1
    return {
        "schema_version": 1,
        "data_kind": report.data_kind,
        "mode": report.mode,
        "report_sha256": digest,
        "suite_semantic_sha256": report.suite_semantic_sha256,
        "reviewer": review.reviewer,
        "requests_reviewed": len(identities),
        "statement_contexts": review.statement_contexts,
        "shared_scopes": {
            key: value.model_dump(mode="json") for key, value in review.shared_scopes.items()
        },
        "ratings": {dimension: dict(count) for dimension, count in counts.items()},
        "assessments": [row.model_dump(mode="json") for row in review.assessments],
        "task_inventory": [
            {
                "task_id": task.task_id,
                "run_id": task.run.run_id,
                "status": task.run.status,
                "accepted_request_count": len(task.run.conclusion.evidence_requests)
                if task.run.conclusion
                else 0,
            }
            for task in report.tasks
        ],
        "review_source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "request_review.py",
                "evidence_requests.py",
                "request_scope.py",
                "statement_tests.py",
                "evidence_brief.py",
                "task_audit.py",
            )
        },
        "limitations": [
            "Reviewer attribution is self-declared and not independently authenticated.",
            "Ratings are human judgments; request links do not approve wording or source access.",
            "Only accepted requests are assessed; "
            "omitted gaps and rejected proposals are ungraded.",
            "Not-assessable ratings remain in counts; no aggregate pass score is assigned.",
            "Original reports, suites and task reviews are unchanged; no request is executed.",
            "No model accuracy, injection resistance or production readiness is inferred.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "summarize"):
        command = commands.add_parser(name)
        command.add_argument("session", type=Path)
        command.add_argument("output", type=Path)
        command.add_argument("--report-sha256")
        if name == "summarize":
            command.add_argument("--review", type=Path, required=True)
            command.add_argument("--review-sha256", required=True)
    args = parser.parse_args()
    try:
        if args.report_sha256:
            report = load_report(args.session, args.report_sha256)
            digest = args.report_sha256
        else:
            report, digest = saved_report(args.session)
        if args.command == "prepare":
            value = prepare(report, digest).model_dump(mode="json")
        else:
            review = RequestReview.model_validate_json(
                read_pinned(args.review, args.review_sha256, 256 * 1024)
            )
            value = summarize(report, digest, review)
            value["review_file_sha256"] = args.review_sha256
        write_private(args.output, value)
    except (OSError, ValueError):
        print("Request review failed; check pins, exact requests, ratings and unused output path.")
        return 2
    print("Private request-review artifact created; no request was executed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
