from collections.abc import Iterable, Iterator
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from adaptive_security.detection.password_spray import detect_password_spray
from adaptive_security.detection.rc4_tickets import detect_rc4_tickets
from adaptive_security.detection.windows_auth import RULES, detect_windows_auth
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


EvaluationRule = Literal[
    "auth.failures_then_success", "auth.novel_source_ip", "auth.password_spray",
    "auth.rc4_service_ticket_burst",
    "auth.explicit_credential_fanout", "auth.kerberos_password_spray",
]
EvaluationVerdict = Literal["true_positive", "false_positive", "true_negative", "false_negative"]


class EvaluationCaseResult(BaseModel):
    case_id: str
    label: Literal["malicious", "benign"]
    detected: bool
    verdict: EvaluationVerdict


class EvaluationReport(BaseModel):
    rule_id: EvaluationRule
    summary: EvaluationSummary
    cases: tuple[EvaluationCaseResult, ...]


def _case_results(
    cases: Iterable[EvaluationCase], rule_id: EvaluationRule
) -> Iterator[EvaluationCaseResult]:
    seen: set[str] = set()
    with TemporaryDirectory() as directory:
        for number, case in enumerate(cases):
            if case.case_id in seen:
                raise ValueError("duplicate case ID")
            seen.add(case.case_id)
            store = SQLiteStore(str(Path(directory) / f"case-{number}.db"))
            service = IngestionService(store)
            for event in case.events:
                service.ingest(event)
            signals = (store.event_signals() if rule_id == "auth.novel_source_ip" else
                       [signal for incident in store.incidents() for signal in incident.signals])
            if rule_id == "auth.password_spray":
                signals = [signal for incident in detect_password_spray(list(case.events))
                           for signal in incident.signals]
            elif rule_id == "auth.rc4_service_ticket_burst":
                signals = [signal for incident in detect_rc4_tickets(list(case.events))
                           for signal in incident.signals]
            elif rule_id in RULES:
                signals = [signal for incident in detect_windows_auth(list(case.events), rule_id)
                           for signal in incident.signals]
            detected = any(signal.rule_id == rule_id for signal in signals)
            verdict: EvaluationVerdict
            if detected:
                verdict = "true_positive" if case.label == "malicious" else "false_positive"
            else:
                verdict = "false_negative" if case.label == "malicious" else "true_negative"
            yield EvaluationCaseResult(
                case_id=case.case_id, label=case.label, detected=detected, verdict=verdict
            )


def _summary(results: Iterable[EvaluationCaseResult]) -> EvaluationSummary:
    counts = dict.fromkeys(
        ("true_positive", "false_positive", "true_negative", "false_negative"), 0
    )
    for result in results:
        counts[result.verdict] += 1
    predicted = counts["true_positive"] + counts["false_positive"]
    malicious = counts["true_positive"] + counts["false_negative"]
    return EvaluationSummary(
        **counts,
        precision=counts["true_positive"] / predicted if predicted else None,
        recall=counts["true_positive"] / malicious if malicious else None,
    )


def evaluate(
    cases: Iterable[EvaluationCase], rule_id: EvaluationRule = "auth.failures_then_success"
) -> EvaluationSummary:
    return _summary(_case_results(cases, rule_id))


def evaluate_report(
    cases: Iterable[EvaluationCase], rule_id: EvaluationRule = "auth.failures_then_success"
) -> EvaluationReport:
    results = tuple(_case_results(cases, rule_id))
    return EvaluationReport(rule_id=rule_id, summary=_summary(results), cases=results)
