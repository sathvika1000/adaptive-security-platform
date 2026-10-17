"""Run bundled draft analyst tasks and prepare a private human-review session."""

import argparse
import asyncio
import hashlib
import os
from importlib.resources import files
from pathlib import Path

from adaptive_security.catalog_context import CatalogPresentation, validate_catalog
from adaptive_security.investigation_tasks import TaskOptions, TaskSuite, run_tasks
from adaptive_security.schema_order import SchemaOrder, validate_order
from adaptive_security.task_review import TaskReport, prepare, write_private

SUITE_SHA256 = "0d7d919ead8f04304204fa3e4fd821b2afb3cd19a767f6d1a6f8ad98a003ad12"

EXPANDED_SUITE_SHA256 = "bf1f1ee908e1cac35e775a0317e382ad41d542909b3db44379d6fbfd2ad9337b"


def bundled_suite(version: str = "baseline") -> bytes:
    variants = {
        "baseline": ("analyst-tasks.json", SUITE_SHA256),
        "expanded": ("analyst-tasks-v2.json", EXPANDED_SUITE_SHA256),
        "labelled": (
            "analyst-tasks-labelled.json",
            "da17d740c282e38b1237a38405ef643feae563343d2b5fbfdcbc48e75c0072df",
        ),
        "neutral": (
            "analyst-tasks-neutral.json",
            "eaf49c2548ce3c0101f0422c6131e81fde417687f365b8f45e81efba8eaa6c19",
        ),
    }
    if version not in variants:
        raise ValueError("Unknown bundled suite version")
    filename, expected = variants[version]
    raw = files("adaptive_security").joinpath("fixtures", filename).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("Bundled suite digest mismatch")
    return raw


async def create_session(
    directory: Path,
    model: str | None = None,
    *,
    slow_local: bool = False,
    suite_version: str = "baseline",
    structured_requests: bool = False,
    scoped_requests: bool = False,
    shared_request_scope: bool = False,
    linked_tests: bool = False,
    linked_schema_order: SchemaOrder = "empty-first",
    catalog_presentation: CatalogPresentation = "suggestions",
) -> bool:
    if slow_local and model is None:
        raise ValueError("Slow local profile requires an Ollama model")
    validate_order(linked_schema_order, linked_tests=linked_tests)
    validate_catalog(catalog_presentation, linked_tests=linked_tests)
    shared_request_scope = shared_request_scope or linked_tests
    scoped_requests = scoped_requests or shared_request_scope
    structured_requests = structured_requests or scoped_requests
    raw = bundled_suite(suite_version)
    suite_digest = hashlib.sha256(raw).hexdigest()
    suite = TaskSuite.model_validate_json(raw)
    if model is not None:
        from adaptive_security.ollama_adapter import OllamaAdapter

        OllamaAdapter(
            model, token_limit=13_824
        )  # Validate before creating output or calling provider.
    # Reserving the directory rejects reruns, existing files and symlinks before inference.
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    write_private(
        directory / "started.json",
        {
            "schema_version": 1,
            "suite_sha256": suite_digest,
            "mode": "deterministic-smoke" if model is None else "local-model",
            "model": model,
            "slow_local": slow_local,
            "suite_version": suite_version,
            "structured_requests": structured_requests,
            "scoped_requests": scoped_requests,
            "shared_request_scope": shared_request_scope,
            "linked_tests": linked_tests,
            "linked_schema_order": linked_schema_order if linked_tests else None,
            "catalog_presentation": catalog_presentation if linked_tests else None,
            "state": "started-not-complete",
        },
    )
    try:
        # Preserve the exact frozen input with the run, without requiring a repository checkout.
        descriptor = os.open(directory / "suite.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
        options: TaskOptions = {}
        if slow_local:
            options["slow_local"] = True
        if structured_requests:
            options["structured_requests"] = True
        if scoped_requests:
            options["scoped_requests"] = True
        if shared_request_scope:
            options["shared_request_scope"] = True
        if linked_tests:
            options["linked_tests"] = True
        if linked_schema_order != "empty-first":
            options["linked_schema_order"] = linked_schema_order
        if catalog_presentation != "suggestions":
            options["catalog_presentation"] = catalog_presentation
        report = await run_tasks(suite, model, **options)
        report["suite_file_sha256"] = suite_digest
        parsed = TaskReport.model_validate(report)
        write_private(directory / "report.json", report)
        report_digest = hashlib.sha256((directory / "report.json").read_bytes()).hexdigest()
        review = prepare(parsed, report_digest)
        write_private(directory / "review.json", review.model_dump())
        completed = all(task.run.status == "completed" for task in parsed.tasks)
        artifacts = {
            name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in ("suite.json", "report.json", "review.json", "started.json")
        }
        write_private(
            directory / "manifest.json",
            {
                "schema_version": 1,
                "state": "run-finished-review-pending",
                "all_runs_completed": completed,
                "mode": parsed.mode,
                "model": model,
                "slow_local": slow_local,
                "suite_version": suite_version,
                "structured_requests": structured_requests,
                "scoped_requests": scoped_requests,
                "shared_request_scope": shared_request_scope,
                "linked_tests": linked_tests,
                "linked_schema_order": linked_schema_order if linked_tests else None,
                "catalog_presentation": catalog_presentation if linked_tests else None,
                "bundled_suite_sha256": suite_digest,
                "artifact_sha256": artifacts,
                "run_summary": report["summary"],
                "limitations": [
                    "Run completion is not a model quality pass; human review remains pending.",
                    "Draft synthetic tasks do not establish held-out or production performance.",
                    "Review digest identifies the blank sheet; hash edited reviews separately.",
                    "Hashes identify bytes, not trusted provenance or authenticated authorship.",
                ],
            },
        )
        return completed
    except (OSError, ValueError, RuntimeError, ImportError):
        write_private(
            directory / "failure.json",
            {
                "schema_version": 1,
                "state": "session-incomplete",
                "detail": "Session failed; partial files retained. Retry in a new directory.",
            },
        )
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--slow-local", action="store_true")
    parser.add_argument("--structured-requests", action="store_true")
    parser.add_argument("--scoped-requests", action="store_true")
    parser.add_argument("--shared-request-scope", action="store_true")
    parser.add_argument("--linked-tests", action="store_true")
    parser.add_argument(
        "--suite-version",
        choices=("baseline", "expanded", "labelled", "neutral"),
        default="baseline",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--ollama-model")
    mode.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    options = TaskOptions(
        slow_local=args.slow_local, structured_requests=args.structured_requests,
    )
    if args.scoped_requests:
        options["scoped_requests"] = True
    if args.shared_request_scope:
        options["shared_request_scope"] = True
    if args.linked_tests:
        options["linked_tests"] = True
    try:
        completed = asyncio.run(
            create_session(
                args.directory,
                args.ollama_model,
                suite_version=args.suite_version,
                **options,
            )
        )
    except (OSError, ValueError, RuntimeError, ImportError):
        print(
            "Session failed; check dependencies and use a new directory. Partial files may remain."
        )
        return 2
    print("Session saved. Read report.json, then fill review.json using docs/TASK_REVIEW.md.")
    if not completed:
        print("Some runs did not complete. Inspect task statuses and model usage in report.json.")
        return 1
    print("All runs completed; model quality still requires human review.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
