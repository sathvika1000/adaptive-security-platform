import asyncio
import hashlib
import json

import pytest

from adaptive_security import task_diagnostics, task_session


def test_inspect_without_rerun_and_tamper_rejection(tmp_path):
    directory = tmp_path / "session"
    asyncio.run(task_session.create_session(directory))
    before = (directory / "report.json").read_bytes()
    report = task_diagnostics.inspect_session(directory)
    assert len(report["tasks"]) == 3
    assert all(row["proposals_available"] for row in report["tasks"])
    assert (directory / "report.json").read_bytes() == before
    (directory / "report.json").write_bytes(before + b" ")
    with pytest.raises(ValueError, match="digest"):
        task_diagnostics.inspect_session(directory)


def test_old_report_omits_proposals_but_remains_readable(tmp_path):
    directory = tmp_path / "session"
    asyncio.run(task_session.create_session(directory))
    path = directory / "report.json"
    report = json.loads(path.read_text())
    for row in report["tasks"]:
        row["run"].pop("proposals")
    path.write_text(json.dumps(report))
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["artifact_sha256"]["report.json"] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    assert not any(
        row["proposals_available"] for row in task_diagnostics.inspect_session(directory)["tasks"]
    )


def test_cli_and_bad_manifest(tmp_path, monkeypatch):
    directory = tmp_path / "session"
    asyncio.run(task_session.create_session(directory))
    monkeypatch.setattr("sys.argv", ["inspect", str(directory)])
    assert task_diagnostics.main() == 0
    for raw in ("[]", "{}", '{"artifact_sha256":{"report.json":3}}', " " * 65537):
        (directory / "manifest.json").write_text(raw)
        assert task_diagnostics.main() == 2
