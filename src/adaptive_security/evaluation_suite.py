"""Provenance-aware evaluation with explicit capture boundaries and no pooled score."""

import argparse
import json
from hashlib import sha256
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from adaptive_security.evaluation import EvaluationCase, EvaluationReport, EvaluationRule
from adaptive_security.evaluation import evaluate_report as evaluate_cases


class Dataset(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    dataset_id: str = Field(min_length=1)
    cases_file: str = Field(min_length=1)
    cases_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    kind: Literal["synthetic", "captured"]
    partition: Literal["control", "development", "held_out"]
    capture_id: str = Field(min_length=1)
    capture_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    label_reference: str = Field(min_length=1)

    @model_validator(mode="after")
    def check_provenance(self) -> Self:
        if self.kind == "synthetic" and self.partition != "control":
            raise ValueError("synthetic datasets must use the control partition")
        if self.kind == "captured" and (
            self.partition == "control" or self.capture_sha256 is None
        ):
            raise ValueError("captured datasets require a capture digest and evaluation partition")
        return self


class Suite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    rule_id: EvaluationRule
    datasets: tuple[Dataset, ...] = Field(min_length=1)


def _load_cases(directory: Path, dataset: Dataset) -> tuple[EvaluationCase, ...]:
    relative = Path(dataset.cases_file)
    path = (directory / relative).resolve()
    if relative.is_absolute() or not path.is_relative_to(directory):
        raise ValueError("case files must stay inside the manifest directory")
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != dataset.cases_sha256:
        raise ValueError("case file checksum mismatch")
    cases = []
    try:
        for line_number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
            if line.strip():
                try:
                    cases.append(EvaluationCase.model_validate_json(line))
                except ValidationError:
                    raise ValueError(f"invalid labeled case at line {line_number}") from None
    except UnicodeDecodeError:
        raise ValueError("case file must be UTF-8") from None
    if not cases:
        raise ValueError("at least one labeled case is required per dataset")
    return tuple(cases)


def evaluate_suite(path: Path) -> dict[str, object]:
    """Validate all inputs before evaluation; declarations do not certify held-out status."""
    try:
        suite = Suite.model_validate_json(path.read_bytes())
    except ValidationError:
        raise ValueError("invalid suite manifest") from None
    directory = path.resolve().parent
    loaded: list[tuple[Dataset, tuple[EvaluationCase, ...]]] = []
    dataset_ids: set[str] = set()
    case_ids: set[str] = set()
    partitions: dict[tuple[str, str], str] = {}
    for dataset in suite.datasets:
        if dataset.dataset_id in dataset_ids:
            raise ValueError("duplicate dataset ID")
        dataset_ids.add(dataset.dataset_id)
        cases = _load_cases(directory, dataset)
        keys = [("capture", dataset.capture_id), ("cases_digest", dataset.cases_sha256)]
        if dataset.capture_sha256 is not None:
            keys.append(("capture_digest", dataset.capture_sha256))
        for case in cases:
            if case.case_id in case_ids:
                raise ValueError("duplicate case ID across suite")
            case_ids.add(case.case_id)
            keys.extend(("event", json.dumps([event.source, event.event_id]))
                        for event in case.events)
        for key in keys:
            previous = partitions.setdefault(key, dataset.partition)
            if previous != dataset.partition:
                raise ValueError("capture, case file, or event overlaps evaluation partitions")
        loaded.append((dataset, cases))
    reports = []
    for dataset, cases in loaded:
        report: EvaluationReport = evaluate_cases(cases, rule_id=suite.rule_id)
        row = report.model_dump(mode="json")
        # Positive-only captures demonstrate coverage, not precision on benign traffic.
        labels = {case.label for case in cases}
        row["label_counts"] = {label: sum(case.label == label for case in cases)
                               for label in ("malicious", "benign")}
        row["interpretation"] = (
            "synthetic_control" if dataset.kind == "synthetic" else
            "labeled_case_evaluation" if len(labels) == 2 else "single_label_coverage"
        )
        if dataset.kind == "captured" and len(labels) < 2:
            row["summary"]["precision"] = None
            row["summary"]["recall"] = None
        row["dataset"] = dataset.model_dump(mode="json")
        reports.append(row)
    return {
        "version": 1,
        "rule_id": suite.rule_id,
        "datasets": reports,
        "limitations": [
            "Provenance and partitions are supplied declarations, not independently certified.",
            "Metrics describe labeled cases only; unlabeled background is excluded.",
            "Synthetic controls, development captures, and held-out captures are not pooled.",
            "These reports do not establish production accuracy or a live false-alert rate.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate checksum-pinned labeled datasets")
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        report = evaluate_suite(args.manifest)
    except (OSError, ValueError):
        # File paths and validation payloads may contain private telemetry.
        parser.error("suite validation or evaluation failed; check manifest, files, and partitions")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
