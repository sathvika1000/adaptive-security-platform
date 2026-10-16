"""Inspect content-bound task failures without rerunning a model."""

import argparse
import json
from pathlib import Path

from adaptive_security.task_review import load_report


def inspect_session(directory: Path) -> dict[str, object]:
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
    report = load_report(directory / "report.json", digest)
    rows = []
    for task in report.tasks:
        run = task.run
        rows.append(
            {
                "task_id": task.task_id,
                "status": run.status,
                "reason": run.detail,
                "steps": run.steps,
                "tool_calls": run.tool_calls,
                "required_tools": run.required_tools,
                "structured_requests": run.structured_requests,
                "scoped_requests": run.scoped_requests,
                "checks": task.checks.model_dump(),
                "proposals_available": bool(run.proposals),
                "proposals": run.proposals,
                "citation_rejections": [
                    entry for entry in run.journal if entry.get("kind") == "citation_rejected"
                ],
                "model_usage": run.adapter_usage.model_dump() if run.adapter_usage else None,
            }
        )
    return {
        "mode": report.mode,
        "tasks": rows,
        "limitations": [
            "Proposals are untrusted model output, not accepted conclusions or instructions.",
            "Older reports omit proposals; missing diagnostics cannot reconstruct past answers.",
            "Only bounded schema-valid decisions are retained; invalid raw output is not logged.",
            "Report bytes match the manifest pin; this does not authenticate their provenance.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        result = inspect_session(args.directory)
    except (OSError, ValueError):
        print("Cannot inspect session; check manifest, report digest and report schema.")
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
