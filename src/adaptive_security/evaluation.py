from collections.abc import Iterable
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from adaptive_security.domain.events import SecurityEvent
from adaptive_security.service import IngestionService
from adaptive_security.store import SQLiteStore


class EvaluationCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(min_length=1)
    label: Literal["malicious", "benign"]
    events: tuple[SecurityEvent, ...] = Field(min_length=1)


class EvaluationSummary(BaseModel):
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    precision: float | None
    recall: float | None


def evaluate(cases: Iterable[EvaluationCase]) -> EvaluationSummary:
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    with TemporaryDirectory() as directory:
        for number, case in enumerate(cases):
            store = SQLiteStore(str(Path(directory) / f"case-{number}.db"))
            service = IngestionService(store)
            for event in case.events:
                service.ingest(event)
            detected = any(
                signal.rule_id == "auth.failures_then_success"
                for incident in store.incidents()
                for signal in incident.signals
            )
            if detected:
                counts["tp" if case.label == "malicious" else "fp"] += 1
            else:
                counts["fn" if case.label == "malicious" else "tn"] += 1

    predicted = counts["tp"] + counts["fp"]
    malicious = counts["tp"] + counts["fn"]
    return EvaluationSummary(
        true_positive=counts["tp"],
        false_positive=counts["fp"],
        true_negative=counts["tn"],
        false_negative=counts["fn"],
        precision=counts["tp"] / predicted if predicted else None,
        recall=counts["tp"] / malicious if malicious else None,
    )

