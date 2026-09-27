import json
from pathlib import Path

import pytest

from adaptive_security.forwarder import forward_once


def write_alerts(path: Path, ids: list[str], partial: bool = False) -> None:
    lines = [json.dumps({"id": event_id}) + "\n" for event_id in ids]
    path.write_text("".join(lines) + ('{"id": "partial"' if partial else ""))


def test_forwarder_resumes_and_waits_for_complete_lines(tmp_path: Path) -> None:
    alerts = tmp_path / "alerts.json"
    checkpoint = tmp_path / "state" / "cursor.json"
    write_alerts(alerts, ["one", "two"], partial=True)
    sent: list[str] = []

    def send(alert: dict) -> None:
        sent.append(alert["id"])

    assert forward_once(alerts, checkpoint, send) == 2
    assert forward_once(alerts, checkpoint, send) == 0
    with alerts.open("a") as output:
        output.write("}\n")
    assert forward_once(alerts, checkpoint, send) == 1
    assert sent == ["one", "two", "partial"]


def test_forwarder_retries_failed_delivery_and_handles_truncation(tmp_path: Path) -> None:
    alerts = tmp_path / "alerts.json"
    checkpoint = tmp_path / "cursor.json"
    write_alerts(alerts, ["one", "two"])
    seen: list[str] = []

    def fail_second(alert: dict) -> None:
        if alert["id"] == "two":
            raise ConnectionError("platform unavailable")
        seen.append(alert["id"])

    with pytest.raises(ConnectionError):
        forward_once(alerts, checkpoint, fail_second)
    assert seen == ["one"]
    assert forward_once(alerts, checkpoint, lambda alert: seen.append(alert["id"])) == 1
    assert seen == ["one", "two"]

    write_alerts(alerts, ["new"])
    assert forward_once(alerts, checkpoint, lambda alert: seen.append(alert["id"])) == 1
    assert seen[-1] == "new"

