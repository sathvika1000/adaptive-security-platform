import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from urllib.error import HTTPError

import pytest

from adaptive_security import forwarder
from adaptive_security.forwarder import forward_once, send_alert


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


def test_checkpoint_detects_truncation_and_regrowth_past_saved_offset(tmp_path: Path) -> None:
    alerts = tmp_path / "alerts.json"
    checkpoint = tmp_path / "cursor.json"
    write_alerts(alerts, ["one", "two"])
    seen: list[str] = []
    assert forward_once(alerts, checkpoint, lambda item: seen.append(item["id"])) == 2
    old_inode = os.stat(alerts).st_ino
    old_offset = json.loads(checkpoint.read_text())["offset"]

    write_alerts(alerts, ["new-one", "new-two"])
    assert os.stat(alerts).st_ino == old_inode
    assert os.stat(alerts).st_size >= old_offset
    assert forward_once(alerts, checkpoint, lambda item: seen.append(item["id"])) == 2
    assert seen == ["one", "two", "new-one", "new-two"]


def test_legacy_checkpoint_replays_for_safe_upgrade(tmp_path: Path) -> None:
    alerts = tmp_path / "alerts.json"
    checkpoint = tmp_path / "cursor.json"
    write_alerts(alerts, ["one"])
    checkpoint.write_text(json.dumps({
        "inode": os.stat(alerts).st_ino, "offset": os.stat(alerts).st_size,
    }))
    seen: list[str] = []
    assert forward_once(alerts, checkpoint, lambda item: seen.append(item["id"])) == 1
    assert seen == ["one"]
    assert json.loads(checkpoint.read_text())["version"] == 2


def test_transport_does_not_follow_redirect_with_api_key() -> None:
    visited: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            visited.append(self.path)
            self.send_response(302)
            self.send_header("Location", "/capture")
            self.end_headers()

        def do_GET(self) -> None:
            visited.append(self.path)
            self.send_response(200)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(HTTPError) as error:
            send_alert(f"http://127.0.0.1:{server.server_port}/alerts", "secret", {"id": "one"})
        assert error.value.code == 302
        assert visited == ["/alerts"]
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def test_cli_logs_delivery_count_without_alert_or_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    alerts = tmp_path / "alerts.json"
    alerts.write_text('{"id":"secret-alert"}\n')
    checkpoint = tmp_path / "cursor.json"
    sent: list[str] = []
    monkeypatch.setenv("ASP_API_KEY", "secret-key")
    monkeypatch.setattr(sys, "argv", [
        "forwarder", str(alerts), "--checkpoint", str(checkpoint)
    ])
    monkeypatch.setattr(forwarder, "send_alert", lambda endpoint, key, alert: sent.append(
        alert["id"]
    ))

    with caplog.at_level(logging.INFO):
        forwarder.main()

    assert sent == ["secret-alert"]
    assert json.loads(caplog.records[-1].message) == {
        "event": "wazuh_alerts_forwarded", "count": 1
    }
    assert "secret-key" not in caplog.text
    assert "secret-alert" not in caplog.text
