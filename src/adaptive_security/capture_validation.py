"""Freeze and evaluate explicitly reviewed local EVTX captures offline."""

import argparse
import json
import os
import tempfile
from collections import Counter
from datetime import UTC, datetime
from hashlib import sha1, sha256
from pathlib import Path
from typing import Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from adaptive_security.connectors.windows_auth import extend_auth
from adaptive_security.detection.windows_auth import RULES, AuthRule, detect_windows_auth
from adaptive_security.evaluation import EvaluationCase
from adaptive_security.evaluation_suite import Dataset, Suite, evaluate_suite
from adaptive_security.evtx_evaluation import load_capture

# Pin the normalization and evaluation boundary as well as the detector itself.
PINNED_FILES = (
    "connectors/evtx.py",
    "connectors/otrf.py",
    "connectors/windows_auth.py",
    "detection/windows_auth.py",
    "evaluation.py",
    "evaluation_suite.py",
    "evtx_evaluation.py",
    "capture_validation.py",
)
# Known inspected captures cannot be re-declared held out for the new rules.
DEVELOPMENT_DIGESTS = {
    "de910e6c86476db2898d8b5f22201c7505a52c90d6a3b03f9362eebe8f242029",
    "4a0a1c7132e216dbc704c806e9429df9ae3ac00485d5238e50c776e3099ae11d",
}


class CaptureEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    capture_id: str = Field(pattern=r"^[a-z0-9-]+$")
    path: str = Field(min_length=1)
    partition: Literal["development", "held_out"] = "development"
    label: Literal["malicious", "benign", "unlabeled"] = "unlabeled"
    label_reference: str = Field(min_length=1)
    reviewer: str | None = Field(default=None, min_length=1)
    reviewed_at: AwareDatetime | None = None
    label_basis: str | None = Field(default=None, min_length=1)
    environment: str = Field(min_length=1)
    collection_start: AwareDatetime
    collection_end: AwareDatetime

    @model_validator(mode="after")
    def validate_review(self) -> Self:
        if self.collection_end <= self.collection_start:
            raise ValueError("collection interval must have positive duration")
        if self.label != "unlabeled" and not (
            self.reviewer and self.reviewed_at and self.label_basis
        ):
            raise ValueError("labeled captures require reviewer, review time and label basis")
        if self.reviewed_at is not None and self.reviewed_at < self.collection_end:
            raise ValueError("review time must follow the complete collection interval")
        return self


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[1]
    rule_id: AuthRule
    captures: tuple[CaptureEntry, ...] = Field(min_length=1, max_length=20)


class FrozenCapture(CaptureEntry):
    capture_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    git_blob_sha: str = Field(pattern=r"^[0-9a-f]{40}$")


class FrozenPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[1]
    rule_id: AuthRule
    frozen_at: AwareDatetime
    implementation_sha256: dict[str, str]
    captures: tuple[FrozenCapture, ...] = Field(min_length=1, max_length=20)


def _hash_implementation() -> dict[str, str]:
    root = Path(__file__).parent
    return {name: sha256((root / name).read_bytes()).hexdigest() for name in PINNED_FILES}


def _inside(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    if Path(relative).is_absolute() or not path.is_relative_to(root):
        raise ValueError("capture paths must stay inside the plan directory")
    return path


def _check_entries(captures: tuple[CaptureEntry, ...]) -> None:
    if len({c.capture_id for c in captures}) != len(captures):
        raise ValueError("duplicate capture ID")


def freeze(plan_path: Path, destination: Path) -> FrozenPlan:
    """Hash bytes only; do not parse records or run detectors during reservation."""
    plan = Plan.model_validate_json(plan_path.read_bytes())
    _check_entries(plan.captures)
    if destination.exists():
        raise ValueError("output exists")
    # Output must share the input root so that pinned relative paths keep their meaning.
    root = plan_path.resolve().parent
    if destination.resolve().parent != root:
        raise ValueError("frozen plan must be beside the input plan")
    captures = []
    digests: set[str] = set()
    for capture in plan.captures:
        with _inside(root, capture.path).open("rb") as file:
            raw = file.read(5_000_001)
        if not raw or len(raw) > 5_000_000:
            raise ValueError("capture size outside supported limits")
        digest = sha256(raw).hexdigest()
        if digest in digests:
            raise ValueError("duplicate capture bytes")
        digests.add(digest)
        if digest in DEVELOPMENT_DIGESTS and capture.partition == "held_out":
            raise ValueError("previously inspected capture must use development partition")
        captures.append(
            FrozenCapture(
                **capture.model_dump(),
                capture_sha256=digest,
                git_blob_sha=sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
            )
        )
    frozen = FrozenPlan(
        version=1,
        rule_id=plan.rule_id,
        frozen_at=datetime.now(UTC),
        implementation_sha256=_hash_implementation(),
        captures=tuple(captures),
    )
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as file:
        file.write(frozen.model_dump_json(indent=2) + "\n")
    return frozen


def run(frozen_path: Path, destination: Path) -> dict[str, object]:
    frozen_bytes = frozen_path.read_bytes()
    frozen = FrozenPlan.model_validate_json(frozen_bytes)
    if frozen.implementation_sha256 != _hash_implementation():
        raise ValueError("implementation differs from frozen plan; reserve a new evaluation")
    _check_entries(frozen.captures)
    digests = [c.capture_sha256 for c in frozen.captures]
    if len(set(digests)) != len(digests):
        raise ValueError("duplicate capture bytes")
    if any(
        c.partition == "held_out" and c.capture_sha256 in DEVELOPMENT_DIGESTS
        for c in frozen.captures
    ):
        raise ValueError("previously inspected capture must use development partition")
    if destination.exists():
        raise ValueError("output exists")
    root = frozen_path.resolve().parent
    # Validate every path before copying any records.
    paths = [_inside(root, c.path) for c in frozen.captures]
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".capture-validation-", dir=destination.parent) as work:
        output = Path(work) / "result"
        output.mkdir(mode=0o700)
        datasets = []
        inventory = []
        for capture, path in zip(frozen.captures, paths, strict=True):
            original = output / f"{capture.capture_id}.evtx"
            with path.open("rb") as source:
                original.write_bytes(source.read(5_000_001))
            events = [extend_auth(e) for e in load_capture(original, capture)]
            if any(
                not capture.collection_start <= e.event_time <= capture.collection_end
                for e in events
            ):
                raise ValueError(
                    "records outside declared collection interval; no silent filtering"
                )
            findings = detect_windows_auth(events, frozen.rule_id)
            (output / f"{capture.capture_id}.events.jsonl").write_text(
                "".join(e.model_dump_json() + "\n" for e in events)
            )
            (output / f"{capture.capture_id}.findings.json").write_text(
                json.dumps([i.model_dump(mode="json") for i in findings], indent=2) + "\n"
            )
            selected_id = 4648 if frozen.rule_id == RULES[0] else 4771
            row = {
                "capture_id": capture.capture_id,
                "partition": capture.partition,
                "label": capture.label,
                "records": len(events),
                "windows_event_ids": dict(
                    Counter(str(e.attributes["windows_event_id"]) for e in events)
                ),
                "selected_event_records": sum(
                    e.attributes.get("windows_event_id") == selected_id for e in events
                ),
                "finding_count": len(findings),
                "label_review": capture.model_dump(mode="json", exclude={"path"}),
            }
            inventory.append(row)
            if capture.label == "unlabeled":
                continue
            case = EvaluationCase(
                case_id=capture.capture_id, label=capture.label, events=tuple(events)
            )
            case_path = output / f"{capture.capture_id}.case.jsonl"
            case_path.write_text(case.model_dump_json() + "\n")
            datasets.append(
                Dataset(
                    dataset_id=capture.capture_id,
                    cases_file=case_path.name,
                    cases_sha256=sha256(case_path.read_bytes()).hexdigest(),
                    kind="captured",
                    partition=capture.partition,
                    capture_id=capture.capture_id,
                    capture_sha256=capture.capture_sha256,
                    label_reference=capture.label_reference,
                )
            )
        if datasets:
            suite_path = output / "evaluation-suite.json"
            suite_path.write_text(
                Suite(version=1, rule_id=frozen.rule_id, datasets=tuple(datasets)).model_dump_json(
                    indent=2
                )
                + "\n"
            )
            report = evaluate_suite(suite_path)
        else:
            report = {
                "version": 1,
                "rule_id": frozen.rule_id,
                "datasets": [],
                "limitations": ["All captures unlabeled; no accuracy metrics calculated."],
            }
        report.update(
            {
                "inventory": inventory,
                "frozen_plan_sha256": sha256(frozen_bytes).hexdigest(),
                "frozen_at": frozen.frozen_at.isoformat(),
                "implementation_sha256": frozen.implementation_sha256,
                "validation_status": {
                    "held_out_attack_captures": sum(
                        c.label == "malicious" and c.partition == "held_out"
                        for c in frozen.captures
                    ),
                    "reviewed_benign_captures": sum(c.label == "benign" for c in frozen.captures),
                    "unlabeled_captures": sum(c.label == "unlabeled" for c in frozen.captures),
                    "live_deployment": "disabled for these rules",
                    "production_false_alert_rate": None,
                },
                "review_limitations": [
                    "Labels, environments and held-out partitions are supplied declarations.",
                    "Freeze time and hashes do not certify that records were previously unseen.",
                    "One case per complete capture; unlabeled records never receive benign labels.",
                    "Event counts do not certify eligible or representative benign coverage.",
                    "No pooled metrics, no production rate, and no live enablement decision.",
                ],
            }
        )
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        # Retain the exact private reservation so results remain traceable.
        (output / "frozen-plan.json").write_bytes(frozen_bytes)
        for path in output.iterdir():
            os.chmod(path, 0o600)
        output.rename(destination)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("freeze", "run"):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("plan", type=Path)
        command_parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result: dict[str, object]
    try:
        if args.command == "freeze":
            freeze(args.plan, args.output)
            result = {"output": str(args.output), "status": "frozen; no records parsed"}
        else:
            report = run(args.plan, args.output)
            result = {"output": str(args.output), "validation_status": report["validation_status"]}
    except (OSError, ValueError):
        # Validation errors can contain file paths, reviewer names and private event payloads.
        parser.error("capture validation failed; check paths, labels, hashes and collection bounds")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
