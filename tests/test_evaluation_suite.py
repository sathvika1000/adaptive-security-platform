import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest

from adaptive_security.domain.events import EntityRef, EventCategory, SecurityEvent
from adaptive_security.evaluation import EvaluationCase
from adaptive_security.evaluation_suite import evaluate_suite


def case(case_id: str, label: str, sequence: list[tuple[int, str]]) -> EvaluationCase:
    start = datetime(2026, 9, 27, tzinfo=UTC)
    events = [SecurityEvent(
        event_id=str(number), source="wazuh", category=EventCategory.AUTHENTICATION,
        event_time=start + timedelta(minutes=minute),
        observed_time=start + timedelta(minutes=minute, seconds=1),
        outcome=outcome, severity=5,
        entities=(EntityRef(type="user", value="alice"), EntityRef(type="host", value="web-01")),
    ) for number, (minute, outcome) in enumerate(sequence)]
    return EvaluationCase.model_validate({"case_id": case_id, "label": label, "events": events})


def dataset(tmp_path: Path, name: str, partition: str = "development",
            labels: tuple[str, ...] = ("malicious", "benign")) -> dict[str, object]:
    cases = [case(f"{name}-{number}", label,
                  [(0, "failure"), (1, "failure"), (2, "failure"), (3, "success")])
             for number, label in enumerate(labels)]
    # Different captures must have independently scoped event identities.
    cases = [c.model_copy(update={"events": tuple(
        e.model_copy(update={"event_id": f"{name}-{n}-{e.event_id}"}) for e in c.events
    )}) for n, c in enumerate(cases)]
    raw = "".join(c.model_dump_json() + "\n" for c in cases).encode()
    (tmp_path / f"{name}.jsonl").write_bytes(raw)
    return {
        "dataset_id": name, "cases_file": f"{name}.jsonl",
        "cases_sha256": sha256(raw).hexdigest(), "kind": "captured",
        "partition": partition, "capture_id": name,
        "capture_sha256": sha256(name.encode()).hexdigest(),
        "label_reference": "test declaration; constructed records",
    }


def manifest(tmp_path: Path, datasets: list[dict[str, object]]) -> Path:
    path = tmp_path / "suite.json"
    path.write_text(json.dumps({"version": 1, "rule_id": "auth.failures_then_success",
                                "datasets": datasets}))
    return path


def test_suite_keeps_partitions_separate_and_omits_telemetry(tmp_path: Path) -> None:
    development = dataset(tmp_path, "dev")
    held_out = dataset(tmp_path, "held", "held_out")
    report = evaluate_suite(manifest(tmp_path, [development, held_out]))
    assert "summary" not in report
    assert len(report["datasets"]) == 2
    assert report["datasets"][0]["summary"]["false_positive"] == 1
    assert report["datasets"][1]["dataset"]["partition"] == "held_out"
    serialized = json.dumps(report)
    assert "alice" not in serialized and "web-01" not in serialized
    assert "events" not in serialized


@pytest.mark.parametrize("key", ["capture_id", "capture_sha256"])
def test_suite_rejects_whole_capture_leakage(tmp_path: Path, key: str) -> None:
    development = dataset(tmp_path, "dev")
    held_out = dataset(tmp_path, "held", "held_out")
    held_out[key] = development[key]
    with pytest.raises(ValueError, match="overlaps"):
        evaluate_suite(manifest(tmp_path, [development, held_out]))


def test_suite_rejects_reused_events_even_after_capture_rename(tmp_path: Path) -> None:
    development = dataset(tmp_path, "dev")
    held_out = dataset(tmp_path, "held", "held_out")
    original = json.loads((tmp_path / "dev.jsonl").read_text().splitlines()[0])
    original["case_id"] = "renamed-case"
    raw = json.dumps(original).encode()
    (tmp_path / "held.jsonl").write_bytes(raw)
    held_out["cases_sha256"] = sha256(raw).hexdigest()
    with pytest.raises(ValueError, match="overlaps"):
        evaluate_suite(manifest(tmp_path, [development, held_out]))


def test_suite_rejects_changed_case_file(tmp_path: Path) -> None:
    row = dataset(tmp_path, "dev")
    (tmp_path / "dev.jsonl").write_text("private modified telemetry")
    with pytest.raises(ValueError, match="checksum"):
        evaluate_suite(manifest(tmp_path, [row]))


@pytest.mark.parametrize("labels", [("malicious",), ("benign",)])
def test_single_label_capture_reports_counts_without_performance_metrics(
    tmp_path: Path, labels: tuple[str, ...]
) -> None:
    report = evaluate_suite(manifest(tmp_path, [dataset(tmp_path, "dev", labels=labels)]))
    row = report["datasets"][0]
    assert row["interpretation"] == "single_label_coverage"
    assert row["summary"]["precision"] is None
    assert row["summary"]["recall"] is None
    assert sum(row["label_counts"].values()) == 1


def test_synthetic_data_cannot_be_declared_held_out(tmp_path: Path) -> None:
    row = dataset(tmp_path, "control", "held_out")
    row["kind"] = "synthetic"
    with pytest.raises(ValueError, match="invalid suite"):
        evaluate_suite(manifest(tmp_path, [row]))
    row["partition"] = "control"
    assert evaluate_suite(manifest(tmp_path, [row]))["datasets"][0][
        "interpretation"] == "synthetic_control"


def test_capture_requires_digest(tmp_path: Path) -> None:
    row = dataset(tmp_path, "dev")
    row.pop("capture_sha256")
    with pytest.raises(ValueError, match="invalid suite"):
        evaluate_suite(manifest(tmp_path, [row]))


def test_suite_rejects_duplicate_dataset_and_case_ids(tmp_path: Path) -> None:
    row = dataset(tmp_path, "dev")
    with pytest.raises(ValueError, match="duplicate dataset"):
        evaluate_suite(manifest(tmp_path, [row, row]))
    other = {**row, "dataset_id": "renamed"}
    with pytest.raises(ValueError, match="duplicate case"):
        evaluate_suite(manifest(tmp_path, [row, other]))


@pytest.mark.parametrize("path", ["../private.jsonl", "/tmp/private.jsonl"])
def test_suite_rejects_paths_outside_manifest_directory(tmp_path: Path, path: str) -> None:
    row = dataset(tmp_path, "dev")
    row["cases_file"] = path
    with pytest.raises(ValueError, match="inside"):
        evaluate_suite(manifest(tmp_path, [row]))


def test_cli_fails_without_echoing_private_validation_fields(tmp_path: Path) -> None:
    row = dataset(tmp_path, "dev")
    row["private-secret"] = "private telemetry"
    result = subprocess.run([sys.executable, "-m", "adaptive_security.evaluation_suite",
                             str(manifest(tmp_path, [row]))], capture_output=True, text=True)
    assert result.returncode == 2
    assert "private-secret" not in result.stderr and "private telemetry" not in result.stderr


def test_checked_in_synthetic_suite_runs_as_documented() -> None:
    root = Path(__file__).resolve().parents[1]
    report = evaluate_suite(root / "examples/evaluation/password-spray.suite.json")
    row = report["datasets"][0]
    assert row["interpretation"] == "synthetic_control"
    assert row["summary"]["true_positive"] == 1
    assert row["summary"]["false_positive"] == 1
    assert row["summary"]["false_negative"] == 1
