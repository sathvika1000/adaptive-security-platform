"""Read a bounded EVTX review snapshot without writing to the incident database."""

import json
import re
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from threading import Lock
from typing import Any

from pydantic import BaseModel

from adaptive_security.capture_validation import DEVELOPMENT_DIGESTS, FrozenPlan
from adaptive_security.detection.windows_auth import RULES
from adaptive_security.domain.events import SecurityEvent
from adaptive_security.domain.incidents import Incident
from adaptive_security.evaluation import EvaluationCase
from adaptive_security.evaluation_suite import Suite
from adaptive_security.evtx_evaluation import Reservation


class CaptureSummary(BaseModel):
    capture_id: str
    partition: str
    label: str
    verdict: str
    records: int
    selected_event_records: int
    finding_count: int
    capture_sha256: str
    label_reference: str


@dataclass(frozen=True)
class CaptureSnapshot:
    summary: CaptureSummary
    metadata: dict[str, Any]
    events: tuple[SecurityEvent, ...]
    findings: tuple[Incident, ...]


@dataclass(frozen=True)
class ReviewSnapshot:
    rule_id: str
    provenance: dict[str, Any]
    captures: dict[str, CaptureSnapshot]


class BundleReader:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.used = 0

    def read(self, name: str, maximum: int = 40_000_000) -> bytes:
        path = (self.root / name).resolve()
        if not path.is_relative_to(self.root):
            raise ValueError("review file escapes bundle")
        with path.open("rb") as file:
            raw = file.read(maximum + 1)
        self.used += len(raw)
        if len(raw) > maximum or self.used > 128_000_000:
            raise ValueError("review bundle too large")
        return raw

    def json(self, name: str, maximum: int = 1_000_000) -> Any:
        return json.loads(self.read(name, maximum))


def load_review(root: Path) -> ReviewSnapshot:
    reader = BundleReader(root)
    report = reader.json("report.json")
    rule = report["rule_id"]
    if rule not in RULES:
        raise ValueError("unsupported offline review rule")
    inventory = report["inventory"]
    if not isinstance(inventory, list) or not 1 <= len(inventory) <= 20:
        raise ValueError("invalid review inventory")
    metadata: dict[str, dict[str, Any]] = {}
    if (reader.root / "frozen-plan.json").exists():
        frozen_bytes = reader.read("frozen-plan.json", 1_000_000)
        frozen = FrozenPlan.model_validate_json(frozen_bytes)
        if (
            frozen.rule_id != rule
            or sha256(frozen_bytes).hexdigest() != report["frozen_plan_sha256"]
        ):
            raise ValueError("review reservation mismatch")
        for capture in frozen.captures:
            metadata[capture.capture_id] = capture.model_dump(mode="json")
    else:
        reserved = Reservation.model_validate(report["reservation"])
        for reserved_capture in reserved.captures:
            metadata[reserved_capture.capture_id] = {
                **reserved_capture.model_dump(mode="json"),
                "partition": "development",
                "label": reserved.label,
                "label_scope": reserved.label_scope,
            }
    if len(metadata) != len(inventory):
        raise ValueError("review inventory/reservation mismatch")
    # Labeled case files are checksum-pinned by the producer's suite. Unknown captures have no case.
    datasets = {}
    if (reader.root / "evaluation-suite.json").exists():
        suite = Suite.model_validate_json(reader.read("evaluation-suite.json", 1_000_000))
        if suite.rule_id != rule:
            raise ValueError("review suite rule mismatch")
        for dataset in suite.datasets:
            if dataset.dataset_id in datasets:
                raise ValueError("duplicate review dataset")
            raw = reader.read(dataset.cases_file)
            if sha256(raw).hexdigest() != dataset.cases_sha256:
                raise ValueError("review case checksum mismatch")
            cases = [
                EvaluationCase.model_validate_json(line)
                for line in raw.splitlines()
                if line.strip()
            ]
            if len(cases) != 1:
                raise ValueError("one complete capture case required")
            datasets[dataset.dataset_id] = (dataset, cases[0])
    captures = {}
    for row in inventory:
        identifier = row["capture_id"]
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-z0-9-]+", identifier):
            raise ValueError("invalid capture ID")
        if identifier in captures or identifier not in metadata:
            raise ValueError("duplicate or unknown capture")
        info = metadata[identifier]
        digest = info["capture_sha256"]
        if info["partition"] == "held_out" and digest in DEVELOPMENT_DIGESTS:
            raise ValueError("known development capture cannot be held out")
        original = reader.read(f"{identifier}.evtx", 5_000_000)
        if sha256(original).hexdigest() != digest:
            raise ValueError("review original checksum mismatch")
        events = tuple(
            SecurityEvent.model_validate_json(line)
            for line in reader.read(f"{identifier}.events.jsonl").splitlines()
            if line.strip()
        )
        if (
            not 1 <= len(events) <= 10000
            or len(events) != row["records"]
            or len({event.event_id for event in events}) != len(events)
        ):
            raise ValueError("invalid review record counts/identities")
        if any(
            event.source != "evtx" or event.attributes.get("capture_sha256") != digest
            for event in events
        ):
            raise ValueError("review event provenance mismatch")
        counts = dict(Counter(str(event.attributes["windows_event_id"]) for event in events))
        if counts != row["windows_event_ids"]:
            raise ValueError("review event inventory mismatch")
        if info["label"] != "unlabeled":
            dataset, case = datasets.pop(identifier)
            if (
                dataset.capture_id != identifier
                or dataset.capture_sha256 != digest
                or dataset.partition != info["partition"]
                or case.case_id != identifier
                or case.label != info["label"]
                or case.events != events
            ):
                raise ValueError("review case/event mismatch")
        elif identifier in datasets:
            raise ValueError("unknown capture cannot have a labeled case")
        findings = tuple(
            Incident.model_validate(item)
            for item in reader.json(f"{identifier}.findings.json", 5_000_000)
        )
        if len({i.incident_id for i in findings}) != len(findings):
            raise ValueError("duplicate review finding")
        by_id = {event.event_id: event for event in events}
        for finding in findings:
            if (
                not finding.event_ids
                or len(set(finding.event_ids)) != len(finding.event_ids)
                or finding.context_event_refs
                or not finding.signals
                or any(i not in by_id for i in finding.event_ids)
                or any(
                    s.rule_id != rule or s.evidence_event_ids != finding.event_ids
                    for s in finding.signals
                )
            ):
                raise ValueError("finding evidence does not belong to capture/rule")
            evidence = [by_id[i] for i in finding.event_ids]
            if (
                finding.first_seen != min(e.event_time for e in evidence)
                or finding.last_seen != max(e.event_time for e in evidence)
                or set(finding.entities) != {entity for e in evidence for entity in e.entities}
            ):
                raise ValueError("finding evidence metadata mismatch")
        label = info["label"]
        verdict = (
            "unlabeled"
            if label == "unlabeled"
            else "true_positive"
            if findings and label == "malicious"
            else "false_positive"
            if findings
            else "false_negative"
            if label == "malicious"
            else "true_negative"
        )
        captures[identifier] = CaptureSnapshot(
            summary=CaptureSummary(
                capture_id=identifier,
                partition=info["partition"],
                label=label,
                verdict=verdict,
                records=len(events),
                selected_event_records=sum(
                    e.attributes.get("windows_event_id") == (4648 if rule == RULES[0] else 4771)
                    for e in events
                ),
                finding_count=len(findings),
                capture_sha256=digest,
                label_reference=info["label_reference"],
            ),
            metadata=info,
            events=tuple(sorted(events, key=lambda e: (e.event_time, e.event_id))),
            findings=findings,
        )
    if datasets:
        raise ValueError("suite includes unknown captures")
    provenance = {
        key: report[key]
        for key in (
            "interpretation",
            "label_scope",
            "baseline_rule_commit",
            "development_rule_sha256",
            "implementation_sha256",
            "frozen_at",
            "frozen_plan_sha256",
            "review_limitations",
            "limitations",
            "validation_status",
        )
        if key in report
    }
    provenance["review_scope"] = "Stored offline results; provenance and labels are declarations."
    return ReviewSnapshot(rule_id=rule, provenance=provenance, captures=captures)


class ReviewSource:
    def __init__(self, path: str | None):
        self.path = Path(path) if path else None
        self._snapshot: ReviewSnapshot | None = None
        self._lock = Lock()

    def snapshot(self) -> ReviewSnapshot | None:
        if self.path is None:
            return None
        with self._lock:
            if self._snapshot is None:
                self._snapshot = load_review(self.path)
            return self._snapshot


def finding_review_key(
    snapshot: ReviewSnapshot, capture: CaptureSnapshot, finding: Incident
) -> str:
    """Bind notes to stored evidence, labels, and detector/run provenance, not an ID alone."""
    references = set(finding.event_ids)
    body = {
        "rule_id": snapshot.rule_id,
        "provenance": snapshot.provenance,
        "capture": capture.summary.model_dump(mode="json"),
        "metadata": capture.metadata,
        "finding": finding.model_dump(mode="json"),
        "evidence": [e.model_dump(mode="json") for e in capture.events if e.event_id in references],
    }
    return sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
