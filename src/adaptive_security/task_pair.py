"""Collect paired presentation-label development runs without changing model settings."""

import argparse
import asyncio
import copy
import hashlib
import json
from pathlib import Path
from typing import cast

from adaptive_security.investigation_runner import canonical
from adaptive_security.investigation_tasks import TaskSuite
from adaptive_security.task_review import TaskReport, load_report, write_private
from adaptive_security.task_session import bundled_suite, create_session


def verify_pair(labelled: TaskSuite, neutral: TaskSuite) -> None:
    normalized = copy.deepcopy(labelled.model_dump(mode="json"))
    for task in normalized["tasks"]:
        task["grant"]["capture_id"] = "capture-01"
        task["grant"]["finding_id"] = "finding-01"
        scope = task["evidence"]["scope"]
        scope["capture_id"] = "capture-01"
        scope["finding_id"] = "finding-01"
        scope["rule_id"] = "auth.capture-review"
        for event in task["evidence"]["events"]:
            event["source"] = "auth-records"
        for claim in task["rubric"]["required_observations"]:
            claim["source"] = "auth-records"
        task["evidence"]["limitations"] = [
            text for text in task["evidence"]["limitations"] if text != "Synthetic fixture only"
        ]
    if canonical(normalized) != canonical(neutral.model_dump(mode="json")):
        raise ValueError("Paired suites differ beyond approved presentation fields")


def saved_report(directory: Path) -> tuple[TaskReport, str]:
    with (directory / "manifest.json").open("rb") as stream:
        raw = stream.read(64 * 1024 + 1)
    if len(raw) > 64 * 1024:
        raise ValueError("Session manifest too large")
    manifest = json.loads(raw)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("artifact_sha256"), dict):
        raise ValueError("Invalid session manifest")
    digest = manifest["artifact_sha256"].get("report.json")
    if not isinstance(digest, str):
        raise ValueError("Missing report digest")
    return load_report(directory / "report.json", digest), digest


async def collect_pair(
    directory: Path,
    model: str | None = None,
    *,
    slow_local: bool = False,
    neutral_first: bool = False,
) -> dict[str, object]:
    if slow_local and model is None:
        raise ValueError("Slow profile requires a local model")
    verify_pair(
        TaskSuite.model_validate_json(bundled_suite("labelled")),
        TaskSuite.model_validate_json(bundled_suite("neutral")),
    )
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    order = ("neutral", "labelled") if neutral_first else ("labelled", "neutral")
    write_private(
        directory / "pair-started.json",
        {
            "schema_version": 1,
            "data_kind": "synthetic-analyst-tasks",
            "model": model,
            "order": list(order),
            "slow_local": slow_local,
            "state": "started-not-complete",
        },
    )
    try:
        for variant in order:
            await create_session(
                directory / variant, model, slow_local=slow_local, suite_version=variant
            )
        left, left_digest = saved_report(directory / "labelled")
        right, right_digest = saved_report(directory / "neutral")
        left_rows = {row.task_id: row for row in left.tasks}
        right_rows = {row.task_id: row for row in right.tasks}
        same_tasks = left_rows.keys() == right_rows.keys()
        metadata = [
            row.run.adapter_usage.metadata_sha256 if row.run.adapter_usage else None
            for report in (left, right)
            for row in report.tasks
        ]
        fingerprints = {value for value in metadata if value is not None}
        metadata_match = len(fingerprints) == 1 and None not in metadata if model else None
        task_pairs = [
            {
                "task_id": task_id,
                "labelled": {
                    "status": left_rows[task_id].run.status,
                    "checks": left_rows[task_id].checks.model_dump(),
                },
                "neutral": {
                    "status": right_rows[task_id].run.status,
                    "checks": right_rows[task_id].checks.model_dump(),
                },
            }
            for task_id in left_rows
            if task_id in right_rows
        ]
        result = {
            "schema_version": 1,
            "data_kind": "synthetic-analyst-tasks",
            "state": "collected-human-review-pending",
            "model": model,
            "mode": left.mode,
            "order": list(order),
            "slow_local": slow_local,
            "orchestrator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "report_sha256": {"labelled": left_digest, "neutral": right_digest},
            "suite_file_sha256": {
                "labelled": left.suite_file_sha256,
                "neutral": right.suite_file_sha256,
            },
            "comparison_checks": {
                "same_tasks": same_tasks,
                "same_mode": left.mode
                == right.mode
                == ("local-model" if model else "deterministic-smoke"),
                "same_requested_model": model is None
                or all(
                    row.run.adapter_usage is not None and row.run.adapter_usage.model == model
                    for report in (left, right)
                    for row in report.tasks
                ),
                "same_read_policy": same_tasks
                and all(
                    left_rows[key].run.required_tools == right_rows[key].run.required_tools
                    for key in left_rows
                ),
                "same_sources": left.source_sha256 == right.source_sha256,
                "same_budgets": same_tasks
                and all(
                    left_rows[key].run.budget == right_rows[key].run.budget for key in left_rows
                ),
                "same_model_metadata": metadata_match,
                "all_runs_completed": all(
                    row.run.status == "completed"
                    for report in (left, right)
                    for row in report.tasks
                ),
            },
            "task_pairs": task_pairs,
            "limitations": [
                "Both arms are synthetic development cases; no held-out or customer evidence.",
                "Presentation labels change; event facts and objectives are held fixed.",
                "Both arms share factual collection limits; earlier expanded runs differ.",
                "Counts do not measure semantic quality or prove a causal effect from labels.",
                "Sequential runs retain order, warm-up and model variability as confounders.",
                "Source hashes do not lock dependencies or authenticate provenance.",
                "Review arms separately; no winner, accuracy score or approval is assigned.",
            ],
        }
        write_private(directory / "pair-summary.json", result)
        return result
    except (OSError, ValueError, RuntimeError, ImportError):
        write_private(
            directory / "pair-failure.json",
            {
                "state": "pair-incomplete",
                "detail": "Partial arm sessions retained; retry in a new directory.",
            },
        )
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--slow-local", action="store_true")
    parser.add_argument("--neutral-first", action="store_true")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--ollama-model")
    mode.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    try:
        result = asyncio.run(
            collect_pair(
                args.directory,
                args.ollama_model,
                slow_local=args.slow_local,
                neutral_first=args.neutral_first,
            )
        )
    except (OSError, ValueError, RuntimeError, ImportError):
        print("Pair collection failed; use a new directory. Partial files may remain.")
        return 2
    print(json.dumps(result["comparison_checks"], indent=2))
    print("Read each arm's report and complete separate reviews; no semantic score was assigned.")
    checks = cast(dict[str, object], result["comparison_checks"])
    return 0 if all(value is True for value in checks.values() if value is not None) else 1


if __name__ == "__main__":
    raise SystemExit(main())
