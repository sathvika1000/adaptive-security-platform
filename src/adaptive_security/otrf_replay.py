"""Pinned OTRF host capture import and isolated replay. Never contacts the live API."""

import argparse
import json
import os
import shutil
import tempfile
import zipfile
from collections import Counter
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from urllib.request import urlopen

from adaptive_security.connectors.otrf import normalize
from adaptive_security.detection.password_spray import detect_password_spray
from adaptive_security.domain.events import SecurityEvent
from adaptive_security.evaluation import EvaluationCase
from adaptive_security.service import IngestionService
from adaptive_security.store import SQLiteStore

URL = ("https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
       "datasets/atomic/windows/lateral_movement/host/purplesharp_ad_playbook_I.zip")
SHA256 = "2a2d80e7b8d8ee6821a1754118f3ab908b4bac84cf4ed3d018e281f631bd2870"
MEMBER = "purplesharp_ad_playbook_I_2020-10-22042947.json"
DOCUMENTATION = "https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-201022042947.html"


def load_capture(path: Path) -> tuple[list[SecurityEvent], dict[str, int]]:
    if sha256(path.read_bytes()).hexdigest() != SHA256:
        raise ValueError("capture checksum mismatch; expected the documented PurpleSharp host ZIP")
    events = []
    inventory: Counter[str] = Counter()
    with zipfile.ZipFile(path) as archive:
        if archive.namelist() != [MEMBER]:
            raise ValueError("unexpected ZIP members")
        if archive.getinfo(MEMBER).file_size > 250_000_000:
            raise ValueError("capture is too large")
        with archive.open(MEMBER) as source:
            for line, raw in enumerate(source, 1):
                if not raw.strip():
                    continue
                try:
                    record = json.loads(raw)
                    event = normalize(record, capture_sha256=SHA256, member=MEMBER,
                                      line=line, timezone="America/New_York")
                except (ValueError, KeyError, TypeError) as error:
                    raise ValueError(f"invalid capture record at line {line}: {error}") from error
                events.append(event)
                inventory[f"{event.attributes['channel']}:{record['EventID']}"] += 1
    return events, dict(sorted(inventory.items()))


def replay(capture: Path, destination: Path) -> dict[str, object]:
    """Create a new directory atomically; refuse existing destinations."""
    if destination.exists():
        raise ValueError("output already exists; choose a new directory")
    events, inventory = load_capture(capture)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".otrf-", dir=destination.parent) as temporary:
        output = Path(temporary) / "result"
        output.mkdir(mode=0o700)
        shutil.copyfile(capture, output / "capture.zip")
        store = SQLiteStore(str(output / "replay.db"))
        service = IngestionService(store)
        ordered = sorted(events, key=lambda e: (
            e.event_time, e.observed_time, e.attributes["raw_line"]
        ))
        with (output / "events.jsonl").open("x", encoding="utf-8") as normalized:
            for event in ordered:
                normalized.write(event.model_dump_json() + "\n")
                service.ingest(event)
        spray = detect_password_spray(ordered)
        finding_store = SQLiteStore(str(output / "findings.db"))
        by_id = {event.event_id: event for event in ordered}
        with finding_store.transaction() as conn:
            for event in ordered:
                finding_store.put_event(conn, event)
            for incident in spray:
                members: list[tuple[SecurityEvent, str | None]] = [
                    (by_id[event_id], None) for event_id in incident.event_ids
                ]
                finding_store.save_incident(conn, incident, members, set(), members[-1][0])
        with (output / "spray-incidents.jsonl").open("x", encoding="utf-8") as findings:
            for incident in spray:
                findings.write(incident.model_dump_json() + "\n")
        # A narrow documented attack case, not labels for the rest of this capture.
        documented = [e for e in ordered if e.attributes["windows_event_id"] == 4625
                      and e.attributes["channel"] == "Security"
                      and e.attributes["source_workstation"] == "WORKSTATION5"
                      and e.event_time == datetime(2020, 10, 22, 8, 29, 53, tzinfo=UTC)]
        if len(documented) != 7:
            raise ValueError("documented scenario evidence differs from the inspected capture")
        case = EvaluationCase(case_id="purplesharp-T1110.003-workstation5",
                              label="malicious", events=tuple(documented))
        (output / "attack-case.jsonl").write_text(case.model_dump_json() + "\n")
        documented_ids = {e.event_id for e in documented}
        detected = any(documented_ids and documented_ids <= set(i.event_ids) for i in spray)
        report: dict[str, object] = {
            "dataset": "OTRF PurpleSharp Active Directory Playbook I (host)",
            "source_url": URL, "documentation": DOCUMENTATION, "capture_sha256": SHA256,
            "raw_records": len(events), "normalized_events": len(events),
            "inventory": inventory,
            "time_policy": "Sysmon UtcTime; otherwise EventTime in America/New_York. "
                           "@timestamp is observation time, not event time.",
            "category_counts": dict(Counter(e.category.value for e in events)),
            "authentication_missing_source_ip": sum(
                e.category.value == "authentication" and e.source_ip is None for e in events
            ),
            "production_auth_incidents": len(store.incidents()),
            "password_spray_candidates": len(spray),
            "evaluation": {
                "case_id": "purplesharp-T1110.003-workstation5", "label": "malicious",
                "label_basis": "Publisher simulation transcript: seven accounts at 04:29:53 local",
                "evidence_count": len(documented), "detected": detected,
                "verdict": "true_positive" if detected else "false_negative",
                "precision": None, "recall": None,
                "limitation": "One development attack capture. Background unlabeled; "
                              "no held-out performance or benign false-alert estimate.",
            },
            "coverage": {
                "password_spray": "batch replay candidate detection",
                "failures_then_success": "existing production detector replayed",
                "novel_source_ip": "existing shadow detector replayed; baseline sufficiency "
                                   "and absent addresses prevent a labeled accuracy claim",
                "kerberoasting": "ticket telemetry preserved; detector not implemented",
                "share_discovery": "share telemetry preserved; detector not implemented",
                "winrm_lateral_movement": "process/network telemetry preserved; "
                                          "detector not implemented",
            },
            "deployment": "Password spray is an offline batch detector; "
                          "spray incidents are separate from production "
                          "per-user incident assignments.",
        }
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        # Timeline is supporting telemetry around each finding, not causal attribution.
        with (output / "timeline.jsonl").open("x", encoding="utf-8") as timeline:
            for incident in spray:
                hosts = {e.value for e in incident.entities if e.type == "host"}
                for event in ordered:
                    if (incident.first_seen - timedelta(seconds=30) <= event.event_time
                            <= incident.last_seen + timedelta(minutes=2)
                            and event.action is not None):
                        timeline.write(json.dumps({
                            "incident_id": incident.incident_id, "event_id": event.event_id,
                            "event_time": event.event_time.isoformat(), "action": event.action,
                            "evidence": event.event_id in incident.event_ids,
                            "association": ("same_endpoint" if any(
                                e.type == "host" and e.value in hosts for e in event.entities
                            ) else "capture_context"),
                            "raw_member": MEMBER, "raw_line": event.attributes["raw_line"],
                        }) + "\n")
        for file in output.iterdir():
            os.chmod(file, 0o600)
        output.rename(destination)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new isolated output directory")
    parser.add_argument("--capture", type=Path, help="existing pinned host ZIP; otherwise download")
    args = parser.parse_args()
    try:
        if args.output.exists():
            raise ValueError("output already exists; choose a new directory")
        with tempfile.TemporaryDirectory() as directory:
            capture = args.capture
            if capture is None:
                capture = Path(directory) / "capture.zip"
                with urlopen(URL, timeout=60) as response, capture.open("wb") as target:
                    shutil.copyfileobj(response, target)
            report = replay(capture, args.output)
        print(json.dumps({"output": str(args.output), "records": report["normalized_events"],
                          "evaluation": report["evaluation"]}, indent=2))
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
