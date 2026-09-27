from datetime import UTC, datetime, timedelta

from adaptive_security.domain.events import EntityRef, EventCategory, SecurityEvent
from adaptive_security.evaluation import EvaluationCase, evaluate


def event(event_id: str, minute: int, outcome: str) -> SecurityEvent:
    timestamp = datetime(2026, 9, 27, 2, tzinfo=UTC) + timedelta(minutes=minute)
    return SecurityEvent(
        event_id=event_id,
        source="wazuh",
        category=EventCategory.AUTHENTICATION,
        event_time=timestamp,
        observed_time=timestamp + timedelta(seconds=1),
        outcome=outcome,
        severity=5,
        entities=(EntityRef(type="user", value="alice"), EntityRef(type="host", value="web-01")),
    )


def case(case_id: str, label: str, sequence: list[tuple[int, str]]) -> EvaluationCase:
    return EvaluationCase.model_validate(
        {
            "case_id": case_id,
            "label": label,
            "events": [
                event(str(i), minute, outcome)
                for i, (minute, outcome) in enumerate(sequence)
            ],
        }
    )


def test_evaluation_isolates_cases_and_counts_benign_lookalikes() -> None:
    matched = [(0, "failure"), (1, "failure"), (2, "failure"), (3, "success")]
    cases = [
        case("attack", "malicious", matched),
        case("mistyped-password", "benign", matched),
        case("two-retries", "benign", matched[1:]),
        case(
            "slow-sequence",
            "malicious",
            [(0, "failure"), (10, "failure"), (20, "failure"), (30, "success")],
        ),
    ]
    summary = evaluate(cases)
    assert summary.model_dump() == {
        "true_positive": 1,
        "false_positive": 1,
        "true_negative": 1,
        "false_negative": 1,
        "precision": 0.5,
        "recall": 0.5,
    }
