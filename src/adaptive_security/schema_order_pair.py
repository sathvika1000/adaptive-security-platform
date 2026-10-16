"""Collect matched schema-order development sessions; no automatic quality verdict."""

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
from typing import cast

from adaptive_security.schema_order import SchemaOrder
from adaptive_security.task_pair import saved_report
from adaptive_security.task_review import TaskReport, write_private
from adaptive_security.task_session import create_session


def compare_reports(
    left: TaskReport, right: TaskReport, model: str | None,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    left_rows = {row.task_id: row for row in left.tasks}
    right_rows = {row.task_id: row for row in right.tasks}
    same_tasks = left_rows.keys() == right_rows.keys()
    rows: list[dict[str, object]] = []
    matched_requests = True
    for task_id in left_rows.keys() & right_rows.keys():
        pair = [left_rows[task_id], right_rows[task_id]]
        traces = [row.run.adapter_usage.schema_requests if row.run.adapter_usage else []
                  for row in pair]
        matched_requests = matched_requests and bool(traces[0]) and len(traces[0]) == len(traces[1])
        matched_requests = matched_requests and all(
            a.non_format_payload_sha256 == b.non_format_payload_sha256
            and a.order_normalized_format_sha256 == b.order_normalized_format_sha256
            and a.format_sha256 != b.format_sha256
            for a, b in zip(*traces, strict=False)
        )
        arms = {}
        for name, row in zip(("empty-first", "populated-first"), pair, strict=True):
            conclusion = row.run.conclusion
            arms[name] = {
                "status": row.run.status,
                "reason": row.run.detail,
                "checks": row.checks.model_dump(),
                "hypotheses": len(conclusion.hypotheses) if conclusion else None,
                "alternatives": len(conclusion.alternative_explanations) if conclusion else None,
                "requests": len(conclusion.evidence_requests) if conclusion else None,
                "test_links": sum(len(request.tests) for request in conclusion.evidence_requests)
                if conclusion else None,
                "schema_requests": [record.model_dump() for record in
                                    (row.run.adapter_usage.schema_requests
                                     if row.run.adapter_usage else [])],
            }
        rows.append({
            "task_id": task_id,
            "arms": arms,
            "same_request_count": len(traces[0]) == len(traces[1]) if model else None,
            "request_comparisons": [
                {
                    "request": index + 1,
                    "same_non_format_payload": a.non_format_payload_sha256
                    == b.non_format_payload_sha256,
                    "same_format_after_normalizing_conclusion_order":
                    a.order_normalized_format_sha256 == b.order_normalized_format_sha256,
                    "different_format_bytes": a.format_sha256 != b.format_sha256,
                }
                for index, (a, b) in enumerate(zip(*traces, strict=False))
            ],
        })
    reports = (left, right)
    metadata = [row.run.adapter_usage.metadata_sha256 if row.run.adapter_usage else None
                for report in reports for row in report.tasks]
    checks: dict[str, object] = {
        "same_tasks": same_tasks,
        "same_suite": left.suite_file_sha256 == right.suite_file_sha256
        and left.suite_semantic_sha256 == right.suite_semantic_sha256,
        "same_sources": left.source_sha256 == right.source_sha256,
        "same_mode": left.mode == right.mode
        == ("local-model" if model else "deterministic-smoke"),
        "same_budgets_and_read_policy": same_tasks and all(
            left_rows[key].run.budget == right_rows[key].run.budget
            and left_rows[key].run.required_tools == right_rows[key].run.required_tools
            for key in left_rows
        ),
        "linked_protocol_in_both_arms": all(
            row.run.linked_tests and row.run.shared_request_scope and row.run.scoped_requests
            and row.run.structured_requests for report in reports for row in report.tasks
        ),
        "expected_schema_orders": left.linked_schema_order == "empty-first"
        and right.linked_schema_order == "populated-first",
        "same_requested_model": model is None or all(
            row.run.adapter_usage is not None and row.run.adapter_usage.model == model
            for report in reports for row in report.tasks
        ),
        "same_model_metadata": len(set(metadata)) == 1 and None not in metadata if model else None,
        "recorded_schema_orders": all(
            row.run.adapter_usage is not None and row.run.adapter_usage.schema_requests
            and row.run.adapter_usage.linked_schema_order == expected
            for expected, report in zip(("empty-first", "populated-first"), reports, strict=True)
            for row in report.tasks
        ) if model else None,
        "matched_request_payloads_and_choices": matched_requests if model else None,
        "all_runs_completed": all(row.run.status == "completed"
                                  for report in reports for row in report.tasks),
    }
    # Use frozen task order, never hash/set iteration order, in saved summaries.
    rows.sort(key=lambda row: list(left_rows).index(cast(str, row["task_id"])))
    return checks, rows


async def collect_pair(
    directory: Path, model: str | None = None, *, slow_local: bool = False,
    reverse_run_order: bool = False,
) -> dict[str, object]:
    if slow_local and model is None:
        raise ValueError("Slow profile requires a local model")
    if model is not None:
        from adaptive_security.ollama_adapter import OllamaAdapter

        OllamaAdapter(model, token_limit=13_824)
    order: list[SchemaOrder] = ["empty-first", "populated-first"]
    if reverse_run_order:
        order.reverse()
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    write_private(directory / "pair-started.json", {
        "schema_version": 1, "data_kind": "synthetic-analyst-tasks",
        "state": "started-not-complete", "model": model,
        "slow_local": slow_local, "execution_order": order,
        "suite_version": "neutral", "linked_tests": True,
    })
    try:
        for variant in order:
            await create_session(
                directory / variant, model, slow_local=slow_local,
                suite_version="neutral", linked_tests=True, linked_schema_order=variant,
            )
        left, left_digest = saved_report(directory / "empty-first")
        right, right_digest = saved_report(directory / "populated-first")
        checks, rows = compare_reports(left, right, model)
        result = {
            "schema_version": 1, "data_kind": "synthetic-analyst-tasks",
            "state": "collected-human-review-pending", "model": model,
            "execution_order": order, "slow_local": slow_local,
            "orchestrator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "report_sha256": {"empty-first": left_digest, "populated-first": right_digest},
            "comparison_checks": checks, "tasks": rows,
            "limitations": [
                "Both arms are fresh synthetic development runs, not held-out evaluations.",
                "Only linked Conclusion.anyOf order differs; no theory is forced.",
                "Hashes cover constructed chat payloads, not actual server behavior.",
                "Compare ordinal requests only when their non-format payload hashes match.",
                "Model-selected tool pages can cause later contexts and schema hashes to differ.",
                "Old runs without schema traces cannot be used as a matched arm.",
                "Smoke mode bypasses model/schema sampling and cannot test order sensitivity.",
                "Sequential execution, warm-up, nondeterminism and a small suite limit inference.",
                "More explanations or links do not establish usefulness or injection resistance.",
                "Separate human review remains pending; no winner or quality score is assigned.",
            ],
        }
        write_private(directory / "pair-summary.json", result)
        return result
    except (OSError, ValueError, RuntimeError, ImportError):
        write_private(directory / "pair-failure.json", {
            "state": "pair-incomplete",
            "detail": "Partial sessions retained; retry in a fresh directory.",
        })
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--slow-local", action="store_true")
    parser.add_argument("--reverse-run-order", action="store_true")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--ollama-model")
    mode.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    try:
        result = asyncio.run(collect_pair(
            args.directory, args.ollama_model, slow_local=args.slow_local,
            reverse_run_order=args.reverse_run_order,
        ))
    except (OSError, ValueError, RuntimeError, ImportError):
        print("Schema-order pair failed; partial sessions retained. Use a fresh directory.")
        return 2
    print(json.dumps(result, indent=2))
    checks = cast(dict[str, object], result["comparison_checks"])
    return 0 if all(value is True for value in checks.values() if value is not None) else 1


if __name__ == "__main__":
    raise SystemExit(main())
