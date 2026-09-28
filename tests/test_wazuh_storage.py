import subprocess
from pathlib import Path
from runpy import run_path

import pytest

script = run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "wazuh_storage.py"))
path_bytes = script["path_bytes"]
wazuh_storage = script["wazuh_storage"]


def test_wazuh_storage_reads_expected_paths_only(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    sizes = {
        "/var/lib/wazuh-indexer": 2048,
        "/var/ossec/logs": 300,
        "/var/ossec/logs/alerts": 100,
    }

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert kwargs == {"check": True, "capture_output": True, "text": True}
        path = command[-1]
        return subprocess.CompletedProcess(command, 0, f"{sizes[path]}\t{path}\n", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    report = wazuh_storage("indexer", "manager")
    assert report["indexer_data_bytes"] == 2048 * 1024
    assert report["manager_logs_bytes"] == 300 * 1024
    assert report["manager_alerts_bytes"] == 100 * 1024
    assert calls == [
        ["docker", "exec", "indexer", "du", "-sk", "/var/lib/wazuh-indexer"],
        ["docker", "exec", "manager", "du", "-sk", "/var/ossec/logs"],
        ["docker", "exec", "manager", "du", "-sk", "/var/ossec/logs/alerts"],
    ]


def test_wazuh_storage_rejects_mismatched_path(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "12\t/other\n", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ValueError, match="unexpected storage output"):
        path_bytes("indexer", "/var/lib/wazuh-indexer")
