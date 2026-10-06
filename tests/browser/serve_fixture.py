"""Disposable synthetic review server for actual browser checks; no external capture data."""

import argparse
import json
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory

import uvicorn

from adaptive_security.api import create_app
from adaptive_security.capture_validation import freeze, run
from adaptive_security.domain.events import EventCategory, SecurityEvent

KEY = "browser-fixture-platform-key"
ANALYST_KEY = "browser-fixture-review-key-32-characters"


def serve(port: int, named: bool) -> None:
    import adaptive_security.capture_validation as producer

    with TemporaryDirectory(prefix="asp-browser-") as directory:
        root = Path(directory)
        captures = []
        records = {}
        for identifier, number in (("sample", 25), ("thin-sample", 2), ("other-sample", 6)):
            raw = f"synthetic parser boundary {identifier}".encode()
            path = root / f"{identifier}.evtx"
            path.write_bytes(raw)
            captures.append(
                {
                    "capture_id": identifier,
                    "path": path.name,
                    "partition": "development",
                    "label": "unlabeled",
                    "label_reference": "browser-fixture-not-real-validation",
                    "environment": "Synthetic browser fixture; not Windows capture validation",
                    "collection_start": "2020-01-01T00:00:00Z",
                    "collection_end": "2020-01-01T00:05:00Z",
                }
            )
            records[path.name] = [
                SecurityEvent(
                    event_id=f"{identifier}-event-{i:03}",
                    source="evtx",
                    category=EventCategory.OTHER,
                    event_time="2020-01-01T00:01:00Z",
                    observed_time="2020-01-01T00:01:00Z",
                    attributes={
                        "capture_sha256": sha256(raw).hexdigest(),
                        "channel": "Security",
                        "provider": "Microsoft-Windows-Security-Auditing",
                        "windows_event_id": 4648,
                        "raw_xml": "<synthetic-browser-record />",
                        "raw": {
                            "TargetUserName": f"user{i}",
                            "Hostname": "fixture-host",
                            "SubjectUserSid": "fixture-caller",
                            "SubjectLogonId": "0x123",
                            "ProcessId": "0x456",
                            "TargetServerName": "fixture-server",
                        },
                    },
                )
                for i in range(number)
            ]
        plan = root / "plan.json"
        plan.write_text(
            json.dumps(
                {"version": 1, "rule_id": "auth.explicit_credential_fanout", "captures": captures}
            )
        )
        frozen = root / "frozen.json"
        freeze(plan, frozen)
        original_parser = producer.load_capture
        producer.load_capture = lambda path, *_args: records[path.name]
        try:
            run(frozen, root / "review")
        finally:
            producer.load_capture = original_parser
        keys = (
            {"browser-reviewer": {"key": ANALYST_KEY, "permissions": ["review"]}} if named else {}
        )
        app = create_app(str(root / "journal.db"), KEY, keys, str(root / "review"))
        uvicorn.run(app, host="127.0.0.1", port=port)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("port", type=int)
    parser.add_argument("--named", action="store_true")
    args = parser.parse_args()
    serve(args.port, args.named)
