"""Reproduce reserved captured-case evaluation without changing live ingestion or rules."""

import argparse
import json
import os
import shutil
import tempfile
from collections import Counter
from hashlib import sha1, sha256
from importlib import import_module
from pathlib import Path
from typing import Literal
from urllib.parse import quote
from urllib.request import urlopen

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from adaptive_security.connectors.evtx import normalize
from adaptive_security.connectors.windows_auth import extend_auth
from adaptive_security.detection.windows_auth import RULES, AuthRule, detect_windows_auth
from adaptive_security.domain.events import SecurityEvent
from adaptive_security.evaluation import EvaluationCase
from adaptive_security.evaluation_suite import Dataset, Suite, evaluate_suite


class Capture(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capture_id: str = Field(pattern=r"^[a-z0-9-]+$")
    repository: str = Field(pattern=r"^[A-Za-z0-9_-]+/[A-Za-z0-9_-]+$")
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    path: str = Field(min_length=1)
    git_blob_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    capture_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    label_reference: str = Field(min_length=1)


class Reservation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[1]
    reserved_at: str
    frozen_rule_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    rule_sha256: dict[str, str]
    rule_id: Literal["auth.password_spray"]
    partition: Literal["held_out"]
    label: Literal["malicious"]
    label_scope: str
    captures: tuple[Capture, ...] = Field(min_length=1)


def _verify_rules(reservation: Reservation) -> None:
    root = Path(__file__).parent
    required = {"src/adaptive_security/detection/password_spray.py",
                "src/adaptive_security/detection/rc4_tickets.py"}
    if set(reservation.rule_sha256) != required:
        raise ValueError("reservation must pin both detector files")
    for path, digest in reservation.rule_sha256.items():
        target = root / "detection" / Path(path).name
        if sha256(target.read_bytes()).hexdigest() != digest:
            raise ValueError("detector differs from reservation; do not reuse held-out label")


def load_capture(path: Path, capture: Capture) -> list[SecurityEvent]:
    raw = path.read_bytes()
    if (len(raw) > 5_000_000 or sha256(raw).hexdigest() != capture.capture_sha256 or
            sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            != capture.git_blob_sha):
        raise ValueError("EVTX capture checksum or size mismatch")
    try:
        reader = import_module("Evtx.Evtx")
    except ImportError:
        raise ValueError("EVTX import requires the optional evtx dependencies") from None
    events = []
    try:
        with reader.Evtx(str(path)) as source:
            for ordinal, record in enumerate(source.records(), 1):
                if ordinal > 10000:
                    raise ValueError("record limit exceeded")
                events.append(normalize(record.xml(), capture_sha256=capture.capture_sha256,
                                        member=capture.path, ordinal=ordinal))
    except Exception:
        raise ValueError("EVTX capture parsing failed; no records silently skipped") from None
    if not events:
        raise ValueError("empty EVTX capture")
    return events


def run(reservation_path: Path, destination: Path, capture_directory: Path | None = None,
        development_rule: AuthRule | None = None
        ) -> dict[str, object]:
    try:
        reservation = Reservation.model_validate_json(reservation_path.read_bytes())
    except ValidationError:
        raise ValueError("invalid evaluation reservation") from None
    _verify_rules(reservation)
    if development_rule is not None and development_rule not in RULES:
        raise ValueError("unsupported development rule")
    if destination.exists():
        raise ValueError("output exists; choose a new directory")
    if len({c.capture_id for c in reservation.captures}) != len(reservation.captures):
        raise ValueError("duplicate capture ID")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".evtx-eval-", dir=destination.parent) as directory:
        output = Path(directory) / "result"
        output.mkdir(mode=0o700)
        datasets = []
        inventory = []
        for capture in reservation.captures:
            original = output / f"{capture.capture_id}.evtx"
            if capture_directory is not None:
                shutil.copyfile(capture_directory / original.name, original)
            else:
                url = (f"https://raw.githubusercontent.com/{capture.repository}/"
                       f"{capture.source_commit}/{quote(capture.path, safe='/')}")
                with urlopen(url, timeout=30) as response:
                    original.write_bytes(response.read(5_000_001))
            events = load_capture(original, capture)
            if development_rule is not None:
                events = [extend_auth(event) for event in events]
                findings = detect_windows_auth(events, development_rule)
                (output / f"{capture.capture_id}.findings.json").write_text(
                    json.dumps([finding.model_dump(mode="json") for finding in findings], indent=2)
                    + "\n")
            normalized = output / f"{capture.capture_id}.events.jsonl"
            normalized.write_text("".join(e.model_dump_json() + "\n" for e in events))
            case = EvaluationCase(case_id=capture.capture_id, label=reservation.label,
                                  events=tuple(events))
            cases = output / f"{capture.capture_id}.case.jsonl"
            cases.write_text(case.model_dump_json() + "\n")
            datasets.append(Dataset(
                dataset_id=capture.capture_id, cases_file=cases.name,
                cases_sha256=sha256(cases.read_bytes()).hexdigest(), kind="captured",
                partition="development" if development_rule else reservation.partition,
                capture_id=capture.capture_id,
                capture_sha256=capture.capture_sha256, label_reference=capture.label_reference,
            ))
            inventory.append({"capture_id": capture.capture_id, "records": len(events),
                              "windows_event_ids": dict(Counter(
                                  str(e.attributes["windows_event_id"]) for e in events)),
                              "mapped_records": sum(e.action is not None for e in events),
                              "logon_failure_records": sum(e.action == "logon" and
                                                           e.outcome == "failure" for e in events)})
        suite = Suite(version=1, rule_id=development_rule or reservation.rule_id,
                      datasets=tuple(datasets))
        suite_path = output / "evaluation-suite.json"
        suite_path.write_text(suite.model_dump_json(indent=2) + "\n")
        report = evaluate_suite(suite_path)
        report.update({"frozen_rule_commit": reservation.frozen_rule_commit,
                       "reservation": reservation.model_dump(mode="json"), "inventory": inventory,
                       "label_scope": reservation.label_scope,
                       "benign_evaluation": "not performed; no representative benign capture",
                       "interpretation": "Independent publisher-designated attack cases; "
                                         "case-level misses include missing telemetry coverage. "
                                         "No thresholds changed after observing these captures."})
        if development_rule is not None:
            root = Path(__file__).parent
            report.update({
                "baseline_rule_commit": report.pop("frozen_rule_commit"),
                "development_rule_sha256": {
                    name: sha256((root / name).read_bytes()).hexdigest()
                    for name in ("connectors/windows_auth.py", "detection/windows_auth.py")},
                "interpretation": "Previously inspected captures reused for development. "
                                  "No held-out performance claim; fresh validation required.",
            })
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        for path in output.iterdir():
            os.chmod(path, 0o600)
        output.rename(destination)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reservation", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--capture-directory", type=Path, help="local pinned EVTX files")
    parser.add_argument("--development-rule", choices=RULES,
                        help="opt-in new rule; inspected captures become development data")
    args = parser.parse_args()
    try:
        report = run(args.reservation, args.output, args.capture_directory, args.development_rule)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    rows = report["datasets"]
    assert isinstance(rows, list)
    print(json.dumps({"output": str(args.output), "inventory": report["inventory"],
                      "verdicts": [{"dataset_id": row["dataset"]["dataset_id"],
                                    "summary": row["summary"], "cases": row["cases"]}
                                   for row in rows]}, indent=2))


if __name__ == "__main__":
    main()
