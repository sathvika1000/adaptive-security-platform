"""Read-only advisory audit of existing task sessions; no model requests or rescoring."""

import argparse
import hashlib
import json
import re
from pathlib import Path

from adaptive_security.evidence_brief import build_brief
from adaptive_security.evidence_requests import validate_requests
from adaptive_security.investigation_runner import RunReport, canonical
from adaptive_security.investigation_tools import ToolResult
from adaptive_security.statement_tests import statement_inventory, validate_statement_tests
from adaptive_security.task_pair import saved_report
from adaptive_security.task_review import TaskReport, load_report, write_private

TOOLS = {"get_finding_evidence", "get_related_events", "get_telemetry_coverage"}
EMPTY_SUGGESTIONS = {"", "none", "none available", "n/a", "no further checks", "uncertain"}


def normalized(text: str) -> str:
    return " ".join(text.casefold().split()).strip(" .!?")


def accepted_results(run: RunReport) -> list[ToolResult]:
    if len(run.journal) > 100:
        raise ValueError("Audit journal exceeds 100 entries")
    results = []
    anchor: tuple[str, str] | None = None
    for entry in run.journal:
        if entry.get("kind") != "tool" or entry.get("outcome") != "accepted":
            continue
        if len(canonical(entry.get("response"))) > 64 * 1024:
            raise ValueError("Accepted response exceeds 64 KiB")
        result = ToolResult.model_validate(entry.get("response"))
        if (result.scope.capture_id, result.scope.finding_id, result.scope.review_key) != (
            run.scope.capture_id,
            run.scope.finding_id,
            run.scope.review_key,
        ):
            raise ValueError("Accepted result is outside report scope")
        if entry.get("tool") != result.tool:
            raise ValueError("Accepted result tool does not match journal")
        current = (result.scope.capture_sha256, result.scope.rule_id)
        if anchor is not None and current != anchor:
            raise ValueError("Accepted evidence source changed")
        anchor = current
        if result.tool != "get_telemetry_coverage" and result.page is None:
            raise ValueError("Accepted event result is missing page metadata")
        results.append(result)
    return results


def next_check_flags(checks: list[str], results: list[ToolResult]) -> list[dict[str, object]]:
    flags: list[dict[str, object]] = []
    seen: dict[str, int] = {}
    latest: dict[str, ToolResult] = {result.tool: result for result in results}
    for index, text in enumerate(checks):
        value = normalized(text)
        if value in EMPTY_SUGGESTIONS:
            flags.append({"index": index, "code": "empty_or_placeholder"})
        if value in seen:
            flags.append(
                {"index": index, "code": "duplicate_suggestion", "first_index": seen[value]}
            )
        else:
            seen[value] = index
        tool = value.removesuffix("()")
        if tool in TOOLS:
            flags.append({"index": index, "code": "bare_tool_without_evidence_goal", "tool": tool})
        elif re.fullmatch(r"(?:read|retrieve|get|review) (?:the )?finding evidence", value):
            tool = "get_finding_evidence"
        else:
            continue
        returned = latest.get(tool)
        if returned is not None and (returned.page is None or returned.page.exhausted):
            flags.append({"index": index, "code": "repeats_completed_read", "tool": tool})
    return flags


def audit_report(report: TaskReport, digest: str) -> dict[str, object]:
    rows = []
    for task in report.tasks:
        results = accepted_results(task.run)
        conclusion = task.run.conclusion
        linkage = "not_encoded_in_legacy_free_text"
        if conclusion and conclusion.evidence_requests:
            try:
                validate_requests(conclusion.evidence_requests, results, task.run.shared_scope)
                linkage = "active_gap_source_links_validated"
            except ValueError:
                linkage = "invalid_gap_source_links"
        elif task.run.structured_requests:
            linkage = "no_accepted_structured_requests"
        scope_state = "not_recorded"
        if conclusion and any(
            request.scope is not None for request in conclusion.evidence_requests
        ):
            scope_state = (
                "validated_returned_context"
                if linkage == "active_gap_source_links_validated"
                else "scope_validation_failed"
            )
        if task.run.scoped_requests and (
            not conclusion
            or not conclusion.evidence_requests
            or any(request.scope is None for request in conclusion.evidence_requests)
        ):
            scope_state = "missing_required_scope"
        if task.run.shared_request_scope:
            scope_state = (
                "validated_shared_context"
                if conclusion
                and conclusion.evidence_requests
                and task.run.shared_scope is not None
                and all(request.scope_ref is not None for request in conclusion.evidence_requests)
                and linkage == "active_gap_source_links_validated"
                else "missing_or_invalid_shared_scope"
            )
        test_linkage = "not_recorded"
        inventory = {}
        if conclusion:
            inventory = statement_inventory(
                conclusion.hypotheses, conclusion.alternative_explanations
            )
            if task.run.linked_tests or any(
                request.tests for request in conclusion.evidence_requests
            ):
                try:
                    validate_statement_tests(
                        conclusion.hypotheses,
                        conclusion.alternative_explanations,
                        [request.tests for request in conclusion.evidence_requests],
                        required=task.run.linked_tests,
                        evidence_goals=[
                            request.evidence_needed for request in conclusion.evidence_requests
                        ],
                    )
                    test_linkage = "structural_links_validated"
                except ValueError:
                    test_linkage = "invalid_statement_test_links"
        elif task.run.linked_tests:
            test_linkage = "no_accepted_conclusion"
        rows.append(
            {
                "task_id": task.task_id,
                "run_id": task.run.run_id,
                "run_status": task.run.status,
                "evidence_brief": build_brief(results),
                "model_draft": conclusion.model_dump(mode="json") if conclusion else None,
                "next_check_flags": next_check_flags(conclusion.next_checks, results)
                if conclusion
                else [],
                "next_check_gap_linkage": linkage,
                "structured_requests": task.run.structured_requests,
                "scoped_requests": task.run.scoped_requests,
                "shared_request_scope": task.run.shared_request_scope,
                "shared_scope": task.run.shared_scope.model_dump(mode="json")
                if task.run.shared_scope
                else None,
                "request_scope_validation": scope_state,
                "statement_test_linkage": test_linkage,
                "statement_inventory": inventory,
                "linked_tests": task.run.linked_tests,
                "semantic_review": "pending-human-review",
            }
        )
    return {
        "schema_version": 1,
        "data_kind": report.data_kind,
        "mode": report.mode,
        "report_sha256": digest,
        "audit_source_sha256": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in (
                "task_audit.py",
                "evidence_brief.py",
                "evidence_requests.py",
                "request_scope.py",
                "statement_tests.py",
            )
        },
        "task_count": len(rows),
        "tasks": rows,
        "limitations": [
            "Advisory artifact only; original runs, reviews and scores are unchanged.",
            "Text checks recognize narrow literal patterns, not the meaning or truth of an answer.",
            "No flags does not establish useful planning or an evidence-supported hypothesis.",
            "Gaps and source suggestions are application rules needing analyst judgment.",
            "Structured links do not verify request wording, source existence or permission.",
            "Statement test links identify proposed tests, not evidential support or test quality.",
            "No model, live source or response action is called; semantic review remains pending.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--report-sha256")
    args = parser.parse_args()
    try:
        if args.report_sha256:
            report = load_report(args.directory, args.report_sha256)
            digest = args.report_sha256
        else:
            report, digest = saved_report(args.directory)
        result = audit_report(report, digest)
        write_private(args.output, result)
    except (OSError, ValueError):
        print("Audit failed; verify the session manifest and use an unused output path.")
        return 2
    print(json.dumps({"tasks": result["task_count"], "semantic_review": "pending-human-review"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
