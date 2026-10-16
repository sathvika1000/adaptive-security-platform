"""Offline reasoning worksheet: evidence context and unrequested gaps, without scoring."""

import argparse
import hashlib
import html
import json
import os
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from pydantic import Field

from adaptive_security.investigation_runner import StrictModel
from adaptive_security.investigation_tools import EvidenceRecord
from adaptive_security.task_audit import accepted_results, audit_report
from adaptive_security.task_pair import saved_report
from adaptive_security.task_review import TaskReport, load_report, write_private

QUESTIONS = [
    "Which returned fields support this statement, and which parts are assumptions?",
    "What evidence could distinguish this explanation from plausible alternatives?",
    "Does the statement imply identity, authorization, order or causation not established here?",
]
LIMITATIONS = [
    "Advisory worksheet only; statements and returned data remain untrusted.",
    "Citations belong to the whole conclusion; per-statement evidence links were not recorded.",
    "Exact field matches do not establish the truth of a hypothesis or source authenticity.",
    "Model-declared testing links do not establish semantic relevance, support or test quality.",
    "Unrequested active gaps are candidates for review, not mandatory actions or model errors.",
    "Equal timestamps do not establish order; "
    "distinct timestamps do not prove shared identity or cause.",
    "No flags, scores, model calls, connector queries or response actions are produced.",
    "Existing reports and reviews are unchanged; semantic review remains pending.",
]


class Statement(StrictModel):
    statement_id: str
    section: str
    index: int
    text: str
    citation_linkage: str = "conclusion_level_only"
    test_linkage: str = "not_recorded"
    testing_request_indices: list[int] = Field(default_factory=list)
    review_questions: list[str] = Field(default_factory=lambda: list(QUESTIONS))


class ReasoningRow(StrictModel):
    task_id: str
    run_id: str
    objective: str
    run_status: str
    evidence_state: str
    observed_assertions: list[dict[str, str]]
    assertions_truncated: bool
    temporal_context: dict[str, object]
    statements: list[Statement]
    conclusion_citations: list[dict[str, object]]
    model_requests: list[dict[str, object]]
    legacy_next_checks: list[str]
    collection_limits: list[str]
    gap_coverage_state: str
    requested_gap_ids: list[str]
    unrequested_active_gaps: list[dict[str, str]]
    shared_scope: dict[str, object] | None
    statement_test_linkage: str
    scope_validation: str
    semantic_review: str = "pending-human-review"


class Worksheet(StrictModel):
    schema_version: int = 1
    data_kind: str
    mode: str
    report_sha256: str
    source_sha256: dict[str, str]
    tasks: list[ReasoningRow]
    limitations: list[str] = Field(default_factory=lambda: list(LIMITATIONS))


def temporal_context(records: list[EvidenceRecord]) -> dict[str, object]:
    groups: dict[datetime, list[EvidenceRecord]] = defaultdict(list)
    for event in records:
        groups[event.event_time].append(event)
    state = (
        "no_returned_events"
        if not records
        else "one_returned_event"
        if len(records) == 1
        else "all_timestamps_equal"
        if len(groups) == 1
        else "distinct_timestamps_present"
    )
    displayed = []
    for timestamp in sorted(groups)[:10]:
        events = sorted(groups[timestamp], key=lambda event: (event.source, event.event_id))
        displayed.append(
            {
                "timestamp_utc": timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z"),
                "record_count": len(events),
                "event_references": [
                    {
                        "source": event.source,
                        "event_id": event.event_id,
                        "event_time": event.model_dump(mode="json")["event_time"],
                    }
                    for event in events[:10]
                ],
                "references_truncated": len(events) > 10,
            }
        )
    return {
        "state": state,
        "unique_returned_records": len(records),
        "distinct_timestamp_count": len(groups),
        "timestamp_groups": displayed,
        "groups_truncated": len(groups) > 10,
        "interpretation": "Recorded timestamps do not establish causal order, shared identity "
        "or complete collection. Equal timestamps leave event order unresolved.",
    }


def build_worksheet(report: TaskReport, digest: str) -> Worksheet:
    audited = cast(list[dict[str, Any]], audit_report(report, digest)["tasks"])
    rows = []
    for task, audit in zip(report.tasks, audited, strict=True):
        results = accepted_results(task.run)
        records = {
            (event.source, event.event_id): event for result in results for event in result.events
        }
        conclusion = task.run.conclusion if task.run.status == "completed" else None
        statements = []
        citations = []
        if conclusion:
            for section in ("hypotheses", "alternative_explanations"):
                for index, text in enumerate(getattr(conclusion, section)):
                    statements.append(
                        Statement(
                            statement_id=f"{section}:{index}",
                            section=section,
                            index=index,
                            text=text,
                            test_linkage=audit["statement_test_linkage"],
                            testing_request_indices=[
                                i
                                for i, request in enumerate(conclusion.evidence_requests)
                                if f"{section}:{index}" in request.tests
                            ]
                            if audit["statement_test_linkage"] == "structural_links_validated"
                            else [],
                        )
                    )
            for claim in conclusion.observations:
                event = records.get((claim.source, claim.event_id))
                citations.append(
                    {
                        "claim": claim.model_dump(mode="json"),
                        "matches_returned_field": event is not None
                        and event.model_dump(mode="json").get(claim.field) == claim.value,
                    }
                )
        gap_state = "no_accepted_conclusion"
        requested: list[str] = []
        unrequested = []
        if conclusion and conclusion.evidence_requests:
            scope_state = audit["request_scope_validation"]
            valid = audit[
                "next_check_gap_linkage"
            ] == "active_gap_source_links_validated" and scope_state not in {
                "missing_required_scope",
                "scope_validation_failed",
                "missing_or_invalid_shared_scope",
            }
            gap_state = (
                "validated_structured_request_partition" if valid else "invalid_request_links"
            )
            if valid:
                requested = sorted({request.gap_id for request in conclusion.evidence_requests})
                unrequested = [
                    gap
                    for gap in audit["evidence_brief"]["gap_catalog"]
                    if gap["gap_id"] not in requested
                ]
        elif conclusion:
            gap_state = "not_assessable_without_structured_requests"
        brief = audit["evidence_brief"]
        rows.append(
            ReasoningRow(
                task_id=task.task_id,
                run_id=task.run.run_id,
                objective=task.objective,
                run_status=task.run.status,
                evidence_state=brief["evidence_state"],
                observed_assertions=brief["observed_assertions"],
                assertions_truncated=brief["assertions_truncated"],
                temporal_context=temporal_context(list(records.values())),
                statements=statements,
                conclusion_citations=citations,
                model_requests=[
                    request.model_dump(mode="json") for request in conclusion.evidence_requests
                ]
                if conclusion
                else [],
                legacy_next_checks=list(conclusion.next_checks) if conclusion else [],
                collection_limits=list(conclusion.collection_limits) if conclusion else [],
                gap_coverage_state=gap_state,
                requested_gap_ids=requested,
                unrequested_active_gaps=unrequested,
                shared_scope=audit["shared_scope"],
                scope_validation=audit["request_scope_validation"],
                statement_test_linkage=audit["statement_test_linkage"],
            )
        )
    return Worksheet(
        data_kind=report.data_kind,
        mode=report.mode,
        report_sha256=digest,
        source_sha256={
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "reasoning_audit.py",
                "task_audit.py",
                "evidence_brief.py",
                "evidence_requests.py",
                "request_scope.py",
                "statement_tests.py",
                "task_review.py",
                "task_pair.py",
                "investigation_runner.py",
                "investigation_tools.py",
            )
        },
        tasks=rows,
    )


def render_html(worksheet: Worksheet) -> str:
    def escape(value: str) -> str:
        return html.escape(value, quote=True)

    def block(title: str, value: object) -> str:
        return f"<h3>{escape(title)}</h3><pre>{escape(json.dumps(value, indent=2))}</pre>"

    def tests_for(statement: Statement, row: ReasoningRow) -> str:
        if statement.test_linkage != "structural_links_validated":
            return "<p>Testing links: " + escape(statement.test_linkage) + "</p>"
        if not statement.testing_request_indices:
            return "<p>No testing request is declared for this statement.</p>"
        return (
            "<p>Model-declared testing requests (not evidence support):</p><ul>"
            + "".join(
                f"<li>Request {index}: "
                f"{escape(str(row.model_requests[index]['evidence_needed']))}</li>"
                for index in statement.testing_request_indices
            )
            + "</ul>"
        )

    sections = []
    for row in worksheet.tasks:
        statements = (
            "".join(
                f"<article><h3>{escape(statement.statement_id)}</h3>"
                f"<blockquote>{escape(statement.text)}</blockquote><ul>"
                + "".join(f"<li>{escape(question)}</li>" for question in statement.review_questions)
                + "</ul>"
                + tests_for(statement, row)
                + "</article>"
                for statement in row.statements
            )
            or "<p>No accepted hypothesis or alternative explanation was recorded.</p>"
        )
        sections.append(
            f"<section class='task'><h2>{escape(row.task_id)}</h2><p>{escape(row.objective)}</p>"
            f"<p>Run status: {escape(row.run_status)} · Semantic review: pending human review</p>"
            "<div class='columns'><section><h3>Returned evidence context</h3>"
            + block("Evidence state", row.evidence_state)
            + block("Observed assertions (bounded)", row.observed_assertions)
            + f"<p>Assertions truncated: {row.assertions_truncated}</p>"
            + block("Recorded timestamps", row.temporal_context)
            + block("Conclusion-level citations", row.conclusion_citations)
            + "<p>These citations are not mapped to individual statements. Exact matches do not "
            "establish statement truth.</p></section><section><h3>Untrusted model statements</h3>"
            + statements
            + block("Statement test linkage", row.statement_test_linkage)
            + block("Model collection limitations", row.collection_limits)
            + block("Legacy free-text next checks", row.legacy_next_checks)
            + block("Gap coverage state", row.gap_coverage_state)
            + block("Requested gap IDs", row.requested_gap_ids)
            + block(
                "Unrequested active gaps: analyst review candidates", row.unrequested_active_gaps
            )
            + "<p>Not every active gap needs a request. "
            "No automatic omission error is assigned.</p>"
            + "<details><summary>Requests and shared context</summary>"
            + block("Model request proposals", row.model_requests)
            + block("Shared scope", row.shared_scope)
            + block("Scope validation", row.scope_validation)
            + "</details></section></div></section>"
        )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
        "<title>Offline reasoning worksheet</title><style>"
        "body{font:16px/1.5 system-ui,sans-serif;margin:24px;color:#192b3b;background:#f5f7fa}"
        "main{max-width:1500px;margin:auto}.task{background:white;padding:24px;margin:24px 0;"
        "border:1px solid #d6dee5;border-radius:8px}.columns{display:grid;"
        "grid-template-columns:1fr 1fr;gap:28px}.columns>section{min-width:0}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px;background:#eef2f6;"
        "padding:12px}blockquote{margin:0;padding:12px;border-left:4px solid #607d99}"
        "article{margin-bottom:24px}h3{font-size:16px}@media(max-width:850px){"
        ".columns{grid-template-columns:1fr}body{margin:12px}.task{padding:16px}}"
        "</style></head><body><main><h1>Offline reasoning worksheet</h1>"
        f"<p>Original report SHA-256: <code>{escape(worksheet.report_sha256)}</code></p>"
        "<p>All event values and model statements are untrusted text. This page executes no "
        "scripts, queries or actions. It does not decide whether statements are supported.</p><ul>"
        + "".join(f"<li>{escape(limit)}</li>" for limit in worksheet.limitations)
        + "</ul>"
        + "".join(sections)
        + "</main></body></html>"
    )


def save_worksheet(directory: Path, worksheet: Worksheet) -> None:
    page = render_html(worksheet).encode()
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    write_private(directory / "worksheet.json", worksheet.model_dump(mode="json"))
    descriptor = os.open(directory / "index.html", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(page)
    write_private(
        directory / "manifest.json",
        {
            "schema_version": 1,
            "state": "advisory-worksheet-created-review-pending",
            "report_sha256": worksheet.report_sha256,
            "source_sha256": worksheet.source_sha256,
            "artifact_sha256": {
                name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                for name in ("worksheet.json", "index.html")
            },
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("session", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--report-sha256")
    args = parser.parse_args()
    try:
        if args.report_sha256:
            report = load_report(args.session, args.report_sha256)
            digest = args.report_sha256
        else:
            report, digest = saved_report(args.session)
        save_worksheet(args.output, build_worksheet(report, digest))
    except (OSError, ValueError):
        print("Worksheet failed; verify the report pin and use a new output directory.")
        return 2
    print("Offline worksheet created. Open index.html; semantic review remains pending.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
