import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from adaptive_security.domain.events import EntityRef, EventCategory, SecurityEvent
from adaptive_security.evaluation import EvaluationCase, evaluate, evaluate_report


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


def test_evaluation_cli_rejects_invalid_case_without_echoing_telemetry(tmp_path: Path) -> None:
    cases = tmp_path / "cases.jsonl"
    cases.write_text('{"case_id":"private-secret","events":"invalid"}\n')
    script = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_signal.py"
    result = subprocess.run(
        [sys.executable, str(script), str(cases)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "invalid case at line 1" in result.stderr
    assert "private-secret" not in result.stderr


def test_detailed_report_accounts_for_each_case_without_event_data() -> None:
    matched = [(0, "failure"), (1, "failure"), (2, "failure"), (3, "success")]
    cases = [
        case("attack", "malicious", matched),
        case("mistyped-password", "benign", matched),
        case("two-retries", "benign", matched[1:]),
        case("missed", "malicious", [(0, "success")]),
    ]
    report = evaluate_report(iter(cases))
    assert report.summary == evaluate(iter(cases))
    assert [(row.case_id, row.detected, row.verdict) for row in report.cases] == [
        ("attack", True, "true_positive"),
        ("mistyped-password", True, "false_positive"),
        ("two-retries", False, "true_negative"),
        ("missed", False, "false_negative"),
    ]
    assert "alice" not in report.model_dump_json()
    assert "web-01" not in report.model_dump_json()
    assert all(set(row.model_dump()) == {"case_id", "label", "detected", "verdict"}
               for row in report.cases)


def test_detailed_report_rejects_ambiguous_duplicate_case_ids() -> None:
    repeated = case("same", "benign", [(0, "success")])
    with pytest.raises(ValueError, match="duplicate case ID"):
        evaluate_report([repeated, repeated])


@pytest.mark.parametrize("name,rule", [
    ("auth-sequence.synthetic.jsonl", "auth.failures_then_success"),
    ("auth-novel-source.synthetic.jsonl", "auth.novel_source_ip"),
])
def test_evaluation_examples_expose_benign_lookalikes_and_misses(name: str, rule: str) -> None:
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "evaluate_signal.py"
    path = root / "examples" / "evaluation" / name
    command = [sys.executable, str(script), str(path), "--rule", rule]
    summary_result = subprocess.run(command, capture_output=True, text=True, check=True)
    detail_result = subprocess.run([*command, "--details"], capture_output=True,
                                   text=True, check=True)
    summary = json.loads(summary_result.stdout)
    detail = json.loads(detail_result.stdout)
    assert detail["summary"] == summary
    assert summary == {
        "true_positive": 1, "false_positive": 1, "true_negative": 1, "false_negative": 1,
        "precision": 0.5, "recall": 0.5,
    }
    assert [row["verdict"] for row in detail["cases"]] == [
        "true_positive", "false_positive", "true_negative", "false_negative",
    ]
    assert detail["rule_id"] == rule
    assert "synthetic-" not in summary_result.stdout
    assert "demo-user" not in detail_result.stdout
    assert "198.51.100.2" not in detail_result.stdout
