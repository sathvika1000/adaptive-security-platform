"""Forward Wazuh's JSON alert file to the platform API."""

import argparse
import json
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

MAX_LINE = 1024 * 1024


def forward_once(
    alerts: Path, checkpoint: Path, send: Callable[[dict[str, Any]], None]
) -> int:
    with alerts.open("rb") as stream:
        stat = os.fstat(stream.fileno())
        offset = 0
        if checkpoint.exists():
            saved = json.loads(checkpoint.read_text())
            if saved["inode"] == stat.st_ino and saved["offset"] <= stat.st_size:
                offset = saved["offset"]
        stream.seek(offset)
        count = 0
        while line := stream.readline(MAX_LINE + 1):
            if len(line) > MAX_LINE:
                raise ValueError("alert exceeds 1 MiB")
            if not line.endswith(b"\n"):
                break
            alert = json.loads(line)
            if not isinstance(alert, dict):
                raise ValueError("alert must be a JSON object")
            send(alert)
            offset = stream.tell()
            checkpoint.parent.mkdir(parents=True, exist_ok=True)
            temporary = checkpoint.with_name(checkpoint.name + ".tmp")
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as output:
                json.dump({"inode": stat.st_ino, "offset": offset}, output)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, checkpoint)
            count += 1
        return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Forward Wazuh JSON alerts")
    parser.add_argument("alerts", type=Path, help="Wazuh alerts.json path")
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--follow", action="store_true")
    args = parser.parse_args()

    key = os.environ.get("ASP_API_KEY")
    if not key:
        parser.error("ASP_API_KEY is required")
    parsed = urlsplit(args.url)
    if parsed.scheme != "https" and not (
        parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    ):
        parser.error("use HTTPS, or HTTP to a loopback address")
    endpoint = args.url.rstrip("/") + "/v1/events/wazuh"

    def send(alert: dict[str, Any]) -> None:
        request = Request(
            endpoint,
            data=json.dumps(alert).encode(),
            headers={"Content-Type": "application/json", "X-API-Key": key},
            method="POST",
        )
        with urlopen(request, timeout=10) as response:
            response.read()

    while True:
        forward_once(args.alerts, args.checkpoint, send)
        if not args.follow:
            return
        time.sleep(1)


if __name__ == "__main__":
    main()

