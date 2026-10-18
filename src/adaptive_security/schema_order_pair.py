"""Collect matched schema-order development sessions; no automatic quality verdict."""

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
from typing import cast

from adaptive_security.catalog_context import CatalogPresentation
from adaptive_security.evidence_requests import request_catalog
from adaptive_security.investigation_runner import SchemaRequest
from adaptive_security.request_guidance import RequestGuidance
from adaptive_security.schema_order import SchemaOrder
from adaptive_security.task_audit import accepted_results
from adaptive_security.task_pair import saved_report
from adaptive_security.task_review import TaskReport, write_private
from adaptive_security.task_session import create_session


def _arm_names(catalog: bool, guidance: bool) -> tuple[str, str]:
    if catalog and guidance:
        raise ValueError("Compare one presentation change at a time")
    if guidance:
        return ("baseline", "questions")
    return ("suggestions", "descriptions-only") if catalog else ("empty-first", "populated-first")


def request_comparison(
    left: SchemaRequest, right: SchemaRequest, *, catalog_comparison: bool = False,
    guidance_comparison: bool = False,
) -> dict[str, bool]:
    _arm_names(catalog_comparison, guidance_comparison)
    if guidance_comparison:
        return {
            "same_payload_after_removing_request_guidance":
            left.guidance_normalized_payload_sha256 is not None
            and left.guidance_normalized_payload_sha256 == right.guidance_normalized_payload_sha256,
            "same_format_bytes": left.format_sha256 == right.format_sha256,
            "different_non_format_payload":
            left.non_format_payload_sha256 != right.non_format_payload_sha256,
        }
    if catalog_comparison:
        return {
            "same_payload_after_removing_catalog_suggestions":
            left.catalog_normalized_payload_sha256 is not None
            and left.catalog_normalized_payload_sha256 == right.catalog_normalized_payload_sha256,
            "same_format_bytes": left.format_sha256 == right.format_sha256,
            "different_non_format_payload":
            left.non_format_payload_sha256 != right.non_format_payload_sha256,
        }
    return {
        "same_non_format_payload":
        left.non_format_payload_sha256 == right.non_format_payload_sha256,
        "same_format_after_normalizing_conclusion_order":
        left.order_normalized_format_sha256 == right.order_normalized_format_sha256,
        "different_format_bytes": left.format_sha256 != right.format_sha256,
    }


def compare_reports(
    left: TaskReport, right: TaskReport, model: str | None, *,
    catalog_comparison: bool = False, guidance_comparison: bool = False,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    arm_names = _arm_names(catalog_comparison, guidance_comparison)
    expected_catalogs = ("descriptions-only", "descriptions-only") if guidance_comparison else (
        "suggestions", "descriptions-only",
    )
    expected_orders = ("empty-first", "empty-first") if (
        catalog_comparison or guidance_comparison
    ) else (
        "empty-first", "populated-first",
    )
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
            all(request_comparison(
                a, b, catalog_comparison=catalog_comparison,
                guidance_comparison=guidance_comparison,
            ).values())
            for a, b in zip(*traces, strict=False)
        )
        arms: dict[str, dict[str, object]] = {}
        for name, row in zip(arm_names, pair, strict=True):
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
            if catalog_comparison or guidance_comparison:
                arms[name]["conclusion"] = (
                    conclusion.model_dump(mode="json") if conclusion else None
                )
                templates = {
                    gap["gap_id"]: gap["evidence_needed"]
                    for gap in request_catalog(accepted_results(row.run))
                } if conclusion else {}
                arms[name]["exact_suggestion_matches"] = sum(
                    request.evidence_needed == templates.get(request.gap_id)
                    for request in conclusion.evidence_requests
                ) if conclusion else None
        rows.append({
            "task_id": task_id,
            "arms": arms,
            "same_request_count": len(traces[0]) == len(traces[1]) if model else None,
            "request_comparisons": [
                {
                    "request": index + 1,
                    **request_comparison(
                        a, b, catalog_comparison=catalog_comparison,
                        guidance_comparison=guidance_comparison,
                    ),
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
        "expected_schema_orders": left.linked_schema_order == expected_orders[0]
        and right.linked_schema_order == expected_orders[1],
        "same_requested_model": model is None or all(
            row.run.adapter_usage is not None and row.run.adapter_usage.model == model
            for report in reports for row in report.tasks
        ),
        "same_model_metadata": len(set(metadata)) == 1 and None not in metadata if model else None,
        "recorded_schema_orders": all(
            row.run.adapter_usage is not None and row.run.adapter_usage.schema_requests
            and row.run.adapter_usage.linked_schema_order == expected
            for expected, report in zip(expected_orders, reports, strict=True)
            for row in report.tasks
        ) if model else None,
        "matched_request_payloads_and_choices": matched_requests if model else None,
        "all_runs_completed": all(row.run.status == "completed"
                                  for report in reports for row in report.tasks),
    }
    if catalog_comparison or guidance_comparison:
        checks["expected_catalog_presentations"] = (
            left.catalog_presentation == expected_catalogs[0]
            and right.catalog_presentation == expected_catalogs[1]
        )
        checks["recorded_catalog_presentations"] = all(
            row.run.adapter_usage is not None
            and row.run.adapter_usage.catalog_presentation == expected
            for expected, report in zip(expected_catalogs, reports, strict=True)
            for row in report.tasks
        ) if model else None
    else:
        checks["same_catalog_presentation"] = (
            left.catalog_presentation == right.catalog_presentation
        )
    if guidance_comparison:
        checks["expected_request_guidance"] = (
            left.request_guidance == "baseline" and right.request_guidance == "questions"
        )
        checks["recorded_request_guidance"] = all(
            row.run.adapter_usage is not None
            and row.run.adapter_usage.request_guidance == expected
            for expected, report in zip(arm_names, reports, strict=True)
            for row in report.tasks
        ) if model else None
    else:
        checks["same_request_guidance"] = left.request_guidance == right.request_guidance
    # Use frozen task order, never hash/set iteration order, in saved summaries.
    rows.sort(key=lambda row: list(left_rows).index(cast(str, row["task_id"])))
    return checks, rows


async def collect_pair(
    directory: Path, model: str | None = None, *, slow_local: bool = False,
    reverse_run_order: bool = False, catalog_comparison: bool = False,
    guidance_comparison: bool = False,
) -> dict[str, object]:
    arm_names = _arm_names(catalog_comparison, guidance_comparison)
    experiment = "request-guidance" if guidance_comparison else (
        "catalog-suggestions" if catalog_comparison else "schema-order"
    )
    if slow_local and model is None:
        raise ValueError("Slow profile requires a local model")
    if model is not None:
        from adaptive_security.ollama_adapter import OllamaAdapter

        OllamaAdapter(model, token_limit=13_824)
    order = list(arm_names)
    if reverse_run_order:
        order.reverse()
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    write_private(directory / "pair-started.json", {
        "schema_version": 1, "data_kind": "synthetic-analyst-tasks",
        "state": "started-not-complete", "model": model,
        "slow_local": slow_local, "execution_order": order,
        "suite_version": "neutral", "linked_tests": True,
        "experiment": experiment,
    })
    try:
        for variant in order:
            if guidance_comparison:
                await create_session(
                    directory / variant, model, slow_local=slow_local,
                    suite_version="neutral", linked_tests=True,
                    catalog_presentation="descriptions-only",
                    request_guidance=cast(RequestGuidance, variant),
                )
            elif catalog_comparison:
                await create_session(
                    directory / variant, model, slow_local=slow_local,
                    suite_version="neutral", linked_tests=True,
                    catalog_presentation=cast(CatalogPresentation, variant),
                )
            else:
                await create_session(
                    directory / variant, model, slow_local=slow_local,
                    suite_version="neutral", linked_tests=True,
                    linked_schema_order=cast(SchemaOrder, variant),
                )
        left, left_digest = saved_report(directory / arm_names[0])
        right, right_digest = saved_report(directory / arm_names[1])
        checks, rows = compare_reports(
            left, right, model, catalog_comparison=catalog_comparison,
            guidance_comparison=guidance_comparison,
        )
        result = {
            "schema_version": 1, "data_kind": "synthetic-analyst-tasks",
            "state": "collected-human-review-pending", "model": model,
            "execution_order": order, "slow_local": slow_local,
            "experiment": experiment,
            "orchestrator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "report_sha256": {arm_names[0]: left_digest, arm_names[1]: right_digest},
            "comparison_checks": checks, "tasks": rows,
            "limitations": [
                "Both arms are fresh synthetic development runs, not held-out evaluations.",
                "Only request-goal instruction text is appended; catalogs and schemas stay fixed."
                if guidance_comparison else
                "Only catalog evidence_needed suggestions are removed; schemas remain fixed."
                if catalog_comparison else
                "Only linked Conclusion.anyOf order differs; no theory is forced.",
                "Hashes cover constructed chat payloads, not actual server behavior.",
                "Compare requests only when inputs match after removing the exact guidance suffix."
                if guidance_comparison else
                "Compare ordinal requests only when inputs match after suggestion removal."
                if catalog_comparison else
                "Compare ordinal requests only when their non-format payload hashes match.",
                "Model-selected tool pages can cause later contexts and schema hashes to differ.",
                "Old runs without schema traces cannot be used as a matched arm.",
                "Smoke mode bypasses model sampling and cannot test presentation sensitivity.",
                "Exact catalog matches indicate wording overlap, not causal copying or quality.",
                "Sequential execution, warm-up, nondeterminism and a small suite limit inference.",
                "More explanations or links do not establish usefulness or injection resistance.",
                "Separate human review remains pending; no winner or quality score is assigned.",
            ],
        }
        if catalog_comparison or guidance_comparison:
            entrypoint = "request_guidance_pair.py" if guidance_comparison else "catalog_pair.py"
            result["entrypoint_sha256"] = hashlib.sha256(
                Path(__file__).with_name(entrypoint).read_bytes()
            ).hexdigest()
        write_private(directory / "pair-summary.json", result)
        return result
    except (OSError, ValueError, RuntimeError, ImportError):
        write_private(directory / "pair-failure.json", {
            "state": "pair-incomplete",
            "detail": "Partial sessions retained; retry in a fresh directory.",
        })
        raise


def main(*, catalog_comparison: bool = False, guidance_comparison: bool = False) -> int:
    parser = argparse.ArgumentParser(
        description="Collect a paired request-guidance comparison." if guidance_comparison else
        "Collect a paired catalog-suggestion comparison." if catalog_comparison else __doc__,
    )
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
            reverse_run_order=args.reverse_run_order, catalog_comparison=catalog_comparison,
            guidance_comparison=guidance_comparison,
        ))
    except (OSError, ValueError, RuntimeError, ImportError):
        print("Pair collection failed; partial sessions retained. Use a fresh directory.")
        return 2
    print(json.dumps(result, indent=2))
    checks = cast(dict[str, object], result["comparison_checks"])
    return 0 if all(value is True for value in checks.values() if value is not None) else 1


if __name__ == "__main__":
    raise SystemExit(main())
