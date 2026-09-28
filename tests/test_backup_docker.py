import shutil
import subprocess
from pathlib import Path
from runpy import run_path

import pytest

from adaptive_security.backup import create_backup, verify_backup
from adaptive_security.store import SQLiteStore

script = run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "backup_docker.py"))
backup_docker = script["backup_docker"]
verify_host_copy = script["verify_host_copy"]


def test_docker_backup_publishes_verified_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    volume = tmp_path / "volume"
    volume.mkdir()
    SQLiteStore(str(volume / "security.db"))
    calls: list[list[str]] = []

    def fake_run(command: list[str], *, check: bool) -> None:
        assert check
        calls.append(command)
        if command[1] == "exec":
            remote = volume / Path(command[-1]).name
            if command[-3] == "create":
                create_backup(volume / "security.db", remote)
            else:
                verify_backup(remote)
        else:
            shutil.copy2(volume / Path(command[-2]).name, command[-1])

    monkeypatch.setattr(subprocess, "run", fake_run)
    copied = backup_docker("platform-test", tmp_path / "host")
    assert copied.exists()
    assert Path(f"{copied}.manifest.json").exists()
    verify_host_copy(copied)
    assert len(calls) == 4
    assert not list((tmp_path / "host").glob(".*"))


def test_docker_backup_does_not_publish_bad_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    volume = tmp_path / "volume"
    volume.mkdir()
    SQLiteStore(str(volume / "security.db"))

    def fake_run(command: list[str], *, check: bool) -> None:
        assert check
        if command[1] == "exec":
            remote = volume / Path(command[-1]).name
            if command[-3] == "create":
                create_backup(volume / "security.db", remote)
            else:
                verify_backup(remote)
        else:
            shutil.copy2(volume / Path(command[-2]).name, command[-1])
            if command[-2].endswith(".db"):
                with Path(command[-1]).open("ab") as stream:
                    stream.write(b"tampered")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ValueError, match="checksum"):
        backup_docker("platform-test", tmp_path / "host")
    assert not list((tmp_path / "host").iterdir())
