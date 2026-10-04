"""Prepare private unlabeled validation inputs without parsing EVTX records."""

import argparse
import json
import os
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from adaptive_security.capture_validation import CaptureEntry, Plan
from adaptive_security.detection.windows_auth import RULES, AuthRule


class CollectionInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    version: Literal[1]
    exporter: Literal["asp.security_export.v1"]
    capture_id: str = Field(pattern=r"^[a-z0-9-]+$")
    capture_file: Literal["Security.evtx"]
    channel: Literal["Security"]
    capture_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bytes: int = Field(gt=0, le=5_000_000)
    record_count: int = Field(gt=0, le=10000)
    collection_start: AwareDatetime
    collection_end: AwareDatetime
    exported_at: AwareDatetime
    environment: str = Field(min_length=1)
    machine: str = Field(min_length=1)
    query: str = Field(min_length=1)


def prepare(
    capture_path: Path,
    destination: Path,
    rule_id: AuthRule,
    *,
    collection_info: Path | None = None,
    capture_id: str = "capture-01",
    start: str | None = None,
    end: str | None = None,
    environment: str | None = None,
) -> Plan:
    if destination.exists():
        raise ValueError("output exists")
    if capture_path.suffix.casefold() != ".evtx":
        raise ValueError("expected an EVTX file")
    with capture_path.open("rb") as file:
        raw = file.read(5_000_001)
    if len(raw) > 5_000_000 or not raw.startswith(b"ElfFile\0"):
        raise ValueError("EVTX size or header invalid")
    metadata = None
    if collection_info is not None:
        if (
            any(value is not None for value in (start, end, environment))
            or capture_id != "capture-01"
        ):
            raise ValueError("collection metadata cannot be overridden")
        metadata = CollectionInfo.model_validate_json(collection_info.read_bytes())
        if (
            metadata.capture_sha256 != sha256(raw).hexdigest()
            or metadata.bytes != len(raw)
            or metadata.exported_at < metadata.collection_end
        ):
            raise ValueError("collection metadata does not match the complete export")
        capture_id = metadata.capture_id
        start, end = metadata.collection_start.isoformat(), metadata.collection_end.isoformat()
        environment = metadata.environment
    if start is None or end is None or environment is None:
        raise ValueError("provide collection metadata or start, end and environment")
    capture = CaptureEntry.model_validate(
        {
            "capture_id": capture_id,
            "path": "Security.evtx",
            "partition": "development",
            "label": "unlabeled",
            "label_reference": "collection.json" if metadata else "review-notes.md",
            "environment": environment,
            "collection_start": start,
            "collection_end": end,
        }
    )
    plan = Plan(version=1, rule_id=rule_id, captures=(capture,))
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".capture-prepare-", dir=destination.parent) as work:
        output = Path(work) / "result"
        output.mkdir(mode=0o700)
        (output / "Security.evtx").write_bytes(raw)
        (output / "plan.json").write_text(plan.model_dump_json(indent=2) + "\n")
        if metadata:
            (output / "collection.json").write_text(metadata.model_dump_json(indent=2) + "\n")
        (output / "review-notes.md").write_text(
            "# Collection review notes\n\nLabel: unlabeled. No review has been performed.\n\n"
            "Record the actual collection activity, audit/log retention gaps, expected origins, "
            "accounts and automation, supporting transcript references, and review decisions.\n"
            "Keep uncertain activity unlabeled; an absence of findings does not prove benignness.\n"
            "Collection metadata describes the export; complete auditing remains unverified.\n"
        )
        for path in output.iterdir():
            os.chmod(path, 0o600)
        output.rename(destination)
    return plan


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--rule", choices=RULES, required=True)
    parser.add_argument("--collection-info", type=Path)
    parser.add_argument("--capture-id", default="capture-01")
    parser.add_argument("--start", help="timezone-aware collection start")
    parser.add_argument("--end", help="timezone-aware collection end")
    parser.add_argument("--environment")
    args = parser.parse_args()
    try:
        prepare(
            args.capture,
            args.output,
            args.rule,
            collection_info=args.collection_info,
            capture_id=args.capture_id,
            start=args.start,
            end=args.end,
            environment=args.environment,
        )
    except (OSError, ValueError):
        parser.error(
            "capture preparation failed; check input, collection bounds, metadata and output"
        )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "status": "prepared; unlabeled development input",
                "records_parsed": False,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
