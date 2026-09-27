"""Replay two Wazuh-shaped alerts against a running local API."""

import json
import os
from urllib.request import Request, urlopen


def request(method: str, path: str, key: str, payload: dict | None = None) -> dict:
    base = os.environ.get("ASP_URL", "http://127.0.0.1:8000").rstrip("/")
    body = json.dumps(payload).encode() if payload is not None else None
    req = Request(
        base + path,
        data=body,
        method=method,
        headers={"X-API-Key": key, "Content-Type": "application/json"},
    )
    with urlopen(req, timeout=10) as response:
        result: dict = json.load(response)
    return result


def main() -> None:
    key = os.environ.get("ASP_API_KEY")
    if not key:
        raise SystemExit("Set ASP_API_KEY before running the replay")
    for alert_id, timestamp, groups in (
        ("demo-failure", "2026-09-27T02:00:00Z", ["authentication_failed", "sshd"]),
        ("demo-success", "2026-09-27T02:05:00Z", ["authentication_success", "sshd"]),
    ):
        alert = {
            "id": alert_id,
            "timestamp": timestamp,
            "rule": {"id": "5710", "level": 5, "groups": groups},
            "agent": {"name": "web-01"},
            "data": {"srcuser": "alice"},
        }
        result = request("POST", "/v1/events/wazuh", key, alert)
        incident_label = result["incident"]["incident_id"] if result["incident"] else "no incident"
        print(f"{result['event']['event_id']}: {incident_label}")
    if result["incident"] is None:
        raise RuntimeError("replay did not create an incident")
    incident_id = result["incident"]["incident_id"]
    incident = request("GET", f"/v1/incidents/{incident_id}", key)
    if incident["event_ids"] != ["demo-failure", "demo-success"]:
        raise RuntimeError("retrieved incident did not contain both alerts")
    print(f"retrieved incident {incident_id} with {len(incident['event_ids'])} events")


if __name__ == "__main__":
    main()
