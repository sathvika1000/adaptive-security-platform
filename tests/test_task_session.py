import asyncio
import hashlib
import json
import os
from pathlib import Path

import pytest

from adaptive_security import task_session
from adaptive_security.task_review import load_report


def test_bundled_fixture_matches_versioned_example():
    example = Path(__file__).resolve().parents[1] / "examples/evaluation/analyst-tasks.json"
    assert task_session.bundled_suite() == example.read_bytes()


def test_smoke_session_integrity_and_permissions(tmp_path):
    directory = tmp_path / "session"
    assert asyncio.run(task_session.create_session(directory))
    manifest = json.loads((directory / "manifest.json").read_text())
    assert manifest["state"] == "run-finished-review-pending"
    assert manifest["mode"] == "deterministic-smoke"
    for name, digest in manifest["artifact_sha256"].items():
        assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == digest
        if os.name == "posix":
            assert (directory / name).stat().st_mode & 0o777 == 0o600
    if os.name == "posix":
        assert directory.stat().st_mode & 0o777 == 0o700
    report = load_report(directory / "report.json", manifest["artifact_sha256"]["report.json"])
    assert report.suite_file_sha256 == manifest["artifact_sha256"]["suite.json"]
    review = json.loads((directory / "review.json").read_text())
    assert review["reviewer"] == ""
    assert all(row["evidence_support"] is None for row in review["assessments"])


def test_existing_directory_rejected_before_adapter_call(tmp_path, monkeypatch):
    async def forbidden(*args):
        pytest.fail("Should not run adapter")

    monkeypatch.setattr(task_session, "run_tasks", forbidden)
    with pytest.raises(FileExistsError):
        asyncio.run(task_session.create_session(tmp_path))


def test_incomplete_run_retained(tmp_path, monkeypatch):
    original = task_session.run_tasks

    async def failed(suite, model):
        report = await original(suite)
        report["tasks"][0]["run"]["status"] = "failed"
        report["tasks"][0]["run"]["conclusion"] = None
        report["summary"]["statuses"] = {"failed": 1, "completed": 2}
        return report

    monkeypatch.setattr(task_session, "run_tasks", failed)
    directory = tmp_path / "session"
    assert not asyncio.run(task_session.create_session(directory))
    manifest = json.loads((directory / "manifest.json").read_text())
    assert manifest["all_runs_completed"] is False
    assert (directory / "review.json").is_file()


def test_provider_setup_failure_leaves_marker(tmp_path, monkeypatch):
    async def broken(*args):
        raise RuntimeError("private exception")

    monkeypatch.setattr(task_session, "run_tasks", broken)
    directory = tmp_path / "session"
    with pytest.raises(RuntimeError):
        asyncio.run(task_session.create_session(directory))
    assert (directory / "started.json").is_file()
    failure = (directory / "failure.json").read_text()
    assert "private exception" not in failure
    assert not (directory / "manifest.json").exists()


def test_bundled_pin_checked_before_creating_session(tmp_path, monkeypatch):
    monkeypatch.setattr(task_session, "SUITE_SHA256", "0" * 64)
    directory = tmp_path / "session"
    with pytest.raises(ValueError, match="digest"):
        asyncio.run(task_session.create_session(directory))
    assert not directory.exists()


def test_cli_exit_codes(tmp_path, monkeypatch):
    directory = tmp_path / "session"
    monkeypatch.setattr("sys.argv", ["session", str(directory), "--smoke"])
    assert task_session.main() == 0
    assert task_session.main() == 2

    async def incomplete(*args, **kwargs):
        return False

    monkeypatch.setattr(task_session, "create_session", incomplete)
    assert task_session.main() == 1


def test_model_validation_before_output(tmp_path):
    pytest.importorskip("mcp")
    directory = tmp_path / "session"
    with pytest.raises(ValueError):
        asyncio.run(task_session.create_session(directory, "remote/cloud"))
    assert not directory.exists()


def test_slow_profile_requires_model_before_creating_directory(tmp_path):
    directory = tmp_path / "session"
    with pytest.raises(ValueError, match="requires"):
        asyncio.run(task_session.create_session(directory, slow_local=True))
    assert not directory.exists()


def test_slow_cli_forwards_profile(tmp_path, monkeypatch):
    calls = []

    async def recording(directory, model, *, slow_local, suite_version):
        calls.append((directory, model, slow_local, suite_version))
        return True

    directory = tmp_path / "session"
    monkeypatch.setattr(task_session, "create_session", recording)
    monkeypatch.setattr(
        "sys.argv", ["session", str(directory), "--ollama-model", "gemma3:4b", "--slow-local"]
    )
    assert task_session.main() == 0
    assert calls == [(directory, "gemma3:4b", True, "baseline")]
