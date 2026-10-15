import asyncio
import hashlib
import json
import os
from pathlib import Path

import pytest

from adaptive_security import reasoning_evaluation as evaluation

SUITE = Path(__file__).resolve().parents[1] / "examples/evaluation/reasoning-controls.json"


def load():
    return evaluation.load_suite(SUITE, hashlib.sha256(SUITE.read_bytes()).hexdigest())


def test_frozen_cases_and_no_detector_metrics():
    report = asyncio.run(evaluation.evaluate(load()))
    assert report["summary"] == {
        "cases": 8, "expectation_matches": 8,
        "statuses": {"completed": 2, "blocked": 5, "budget_exhausted": 1},
        "dispositions": {"needs_review": 1, "inconclusive": 1},
    }
    assert "precision" not in report and "recall" not in report
    assert len(report["implementation_sha256"]) == 3
    assert all(row["run"]["journal"] for row in report["cases"])


def test_pin_rejects_changes_and_oversize(tmp_path):
    path = tmp_path / "suite.json"
    path.write_bytes(SUITE.read_bytes() + b" ")
    with pytest.raises(ValueError, match="digest mismatch"):
        evaluation.load_suite(path, hashlib.sha256(SUITE.read_bytes()).hexdigest())
    path.write_bytes(b" " * (512 * 1024 + 1))
    with pytest.raises(ValueError, match="512 KiB"):
        evaluation.load_suite(path, "a" * 64)


def test_duplicate_ids_and_extra_fields_rejected():
    payload = json.loads(SUITE.read_text())
    payload["cases"].append(payload["cases"][0])
    with pytest.raises(ValueError, match="unique"):
        evaluation.EvaluationSuite.model_validate_json(json.dumps(payload))
    payload = json.loads(SUITE.read_text())
    payload["external_url"] = "https://example.com"
    with pytest.raises(ValueError):
        evaluation.EvaluationSuite.model_validate_json(json.dumps(payload))


def test_failed_fixture_is_counted_as_failure():
    suite = load()
    suite.cases = [suite.cases[0]]
    suite.cases[0].responses = []
    report = asyncio.run(evaluation.evaluate(suite))
    assert report["summary"]["expectation_matches"] == 0
    assert report["summary"]["statuses"] == {"failed": 1}


def test_cli_private_no_overwrite_and_digest(tmp_path, monkeypatch):
    output = tmp_path / "run.json"
    digest = hashlib.sha256(SUITE.read_bytes()).hexdigest()
    monkeypatch.setattr("sys.argv", ["evaluate", str(SUITE), str(output),
                                    "--suite-sha256", digest])
    assert evaluation.main() == 0
    original = output.read_bytes()
    assert json.loads(original)["suite_file_sha256"] == digest
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600
    assert evaluation.main() == 2
    assert output.read_bytes() == original


def test_adapter_never_receives_oracles_or_purpose(monkeypatch):
    contexts = []
    original = evaluation.ReplayAdapter.next_step

    async def recording(self, context_json):
        contexts.append(json.loads(context_json))
        return await original(self, context_json)

    monkeypatch.setattr(evaluation.ReplayAdapter, "next_step", recording)
    asyncio.run(evaluation.evaluate(load()))
    assert contexts
    assert all(set(context) == {"scope", "allowed_tools", "results", "trust"}
               for context in contexts)
