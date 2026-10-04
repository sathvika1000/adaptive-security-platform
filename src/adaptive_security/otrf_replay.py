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
from adaptive_security.detection.rc4_tickets import detect_rc4_tickets
from adaptive_security.domain.events import SecurityEvent
from adaptive_security.evaluation import EvaluationCase
from adaptive_security.evaluation_suite import Dataset, Suite
from adaptive_security.otrf_network import (
    NETWORK_SHA256,
    NETWORK_URL,
    link_network,
    load_network,
)
from adaptive_security.service import IngestionService
from adaptive_security.store import SQLiteStore

URL = ("https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
       "datasets/atomic/windows/lateral_movement/host/purplesharp_ad_playbook_I.zip")
SHA256 = "2a2d80e7b8d8ee6821a1754118f3ab908b4bac84cf4ed3d018e281f631bd2870"
MEMBER = "purplesharp_ad_playbook_I_2020-10-22042947.json"
DOCUMENTATION = "https://securitydatasets.com/notebooks/atomic/windows/lateral_movement/SDWIN-201022042947.html"


def _merge_context(linked: dict[str, SecurityEvent], event: SecurityEvent,
                   incident_id: str) -> None:
    previous = linked.get(event.event_id)
    old = previous.attributes if previous else {}
    attrs = event.attributes
    linked[event.event_id] = event.model_copy(update={"attributes": {
        **attrs,
        "matched_host_event_ids": sorted(set(old.get("matched_host_event_ids", [])) |
                                         set(attrs["matched_host_event_ids"])),
        "matched_incident_ids": sorted(set(old.get("matched_incident_ids", [])) | {incident_id}),
        "explanation": "Addresses, ports, protocol and time match endpoint network events "
                       "around the linked investigations. This is supporting metadata, "
                       "not proof of maliciousness or compromise.",
    }})


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


def replay(capture: Path, destination: Path,
           network_capture: Path | None = None) -> dict[str, object]:
    """Create a new directory atomically; refuse existing destinations."""
    if destination.exists():
        raise ValueError("output already exists; choose a new directory")
    events, inventory = load_capture(capture)
    network_events, network_inventory = (load_network(network_capture)
                                         if network_capture else ([], {}))
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".otrf-", dir=destination.parent) as temporary:
        output = Path(temporary) / "result"
        output.mkdir(mode=0o700)
        shutil.copyfile(capture, output / "capture.zip")
        if network_capture:
            shutil.copyfile(network_capture, output / "network-capture.zip")
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
        tickets = detect_rc4_tickets(ordered)
        linked: dict[str, SecurityEvent] = {}
        enriched = []
        for incident in (*spray, *tickets):
            incident, matches = link_network(incident, ordered, network_events)
            enriched.append(incident)
            for event in matches:
                _merge_context(linked, event, incident.incident_id)
        findings = tuple(enriched)
        spray = tuple(i for i in findings if i.incident_id.startswith("spray-"))
        tickets = tuple(i for i in findings if i.incident_id.startswith("tgs-"))
        network_events = [linked.get(event.event_id, event) for event in network_events]
        if network_capture:
            with (output / "network-events.jsonl").open("x", encoding="utf-8") as target:
                for event in network_events:
                    target.write(event.model_dump_json() + "\n")
        finding_store = SQLiteStore(str(output / "findings.db"))
        by_id = {event.event_id: event for event in ordered}
        with finding_store.transaction() as conn:
            for event in [*ordered, *network_events]:
                finding_store.put_event(conn, event)
            for incident in findings:
                members: list[tuple[SecurityEvent, str | None]] = [
                    (by_id[event_id], None) for event_id in incident.event_ids
                ]
                finding_store.save_incident(conn, incident, members, set(), members[-1][0])
        with (output / "spray-incidents.jsonl").open("x", encoding="utf-8") as spray_file:
            for incident in spray:
                spray_file.write(incident.model_dump_json() + "\n")
        with (output / "rc4-ticket-incidents.jsonl").open("x", encoding="utf-8") as ticket_file:
            for incident in tickets:
                ticket_file.write(incident.model_dump_json() + "\n")
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
        suite = Suite(version=1, rule_id="auth.password_spray", datasets=(Dataset(
            dataset_id="purplesharp-playbook-I-development",
            cases_file="attack-case.jsonl",
            cases_sha256=sha256((output / "attack-case.jsonl").read_bytes()).hexdigest(),
            kind="captured", partition="development",
            capture_id="OTRF-PurpleSharp-AD-Playbook-I", capture_sha256=SHA256,
            label_reference=DOCUMENTATION,
        ),))
        (output / "evaluation-suite.json").write_text(suite.model_dump_json(indent=2) + "\n")
        ticket_services = {"sysmonsvc", "nxlogsvc", "defensesvc", "otrsvc", "mordorsvc"}
        documented_tickets = [e for e in ordered
            if e.attributes.get("windows_event_id") == 4769
            and e.attributes.get("channel") == "Security"
            and e.attributes.get("ticket_status") == 0
            and e.attributes.get("ticket_encryption_type") == 23
            and e.attributes.get("service_name") in ticket_services
            and e.source_ip == "172.18.39.5"
            and any(entity.type == "user" and entity.value.casefold() == "pgustavo@theshire.local"
                    for entity in e.entities)
            and datetime(2020, 10, 22, 8, 29, 53, tzinfo=UTC) <= e.event_time
                <= datetime(2020, 10, 22, 8, 29, 54, tzinfo=UTC)]
        if (len(documented_tickets) != 5 or
                {e.attributes["service_name"] for e in documented_tickets} != ticket_services):
            raise ValueError("documented ticket evidence differs from the inspected capture")
        ticket_case = EvaluationCase(case_id="purplesharp-T1558.003-rc4-tickets",
                                     label="malicious", events=tuple(documented_tickets))
        ticket_path = output / "rc4-ticket-case.jsonl"
        ticket_path.write_text(ticket_case.model_dump_json() + "\n")
        ticket_suite = Suite(version=1, rule_id="auth.rc4_service_ticket_burst", datasets=(Dataset(
            dataset_id="purplesharp-rc4-tickets-development", cases_file=ticket_path.name,
            cases_sha256=sha256(ticket_path.read_bytes()).hexdigest(),
            kind="captured", partition="development",
            capture_id="OTRF-PurpleSharp-AD-Playbook-I", capture_sha256=SHA256,
            label_reference=DOCUMENTATION,
        ),))
        (output / "rc4-ticket-suite.json").write_text(ticket_suite.model_dump_json(indent=2) + "\n")
        ticket_ids = {e.event_id for e in documented_tickets}
        ticket_detected = any(ticket_ids <= set(i.event_ids) for i in tickets)
        documented_ids = {e.event_id for e in documented}
        detected = any(documented_ids and documented_ids <= set(i.event_ids) for i in spray)
        report: dict[str, object] = {
            "dataset": "OTRF PurpleSharp Active Directory Playbook I (host)",
            "source_url": URL, "documentation": DOCUMENTATION, "capture_sha256": SHA256,
            "raw_records": len(events), "normalized_events": len(events),
            "inventory": inventory,
            "network_inventory": network_inventory,
            "network_context_events": len(linked),
            "network_source_url": NETWORK_URL if network_capture else None,
            "network_capture_sha256": NETWORK_SHA256 if network_capture else None,
            "time_policy": "Sysmon UtcTime; otherwise EventTime in America/New_York. "
                           "@timestamp is observation time, not event time.",
            "category_counts": dict(Counter(e.category.value for e in events)),
            "authentication_missing_source_ip": sum(
                e.category.value == "authentication" and e.source_ip is None for e in events
            ),
            "production_auth_incidents": len(store.incidents()),
            "password_spray_candidates": len(spray),
            "rc4_ticket_candidates": len(tickets),
            "rc4_ticket_evaluation": {
                "case_id": ticket_case.case_id, "label": "malicious",
                "label_basis": "Publisher T1558.003 simulation lists five service accounts",
                "evidence_count": len(documented_tickets), "detected": ticket_detected,
                "verdict": "true_positive" if ticket_detected else "false_negative",
                "precision": None, "recall": None,
                "limitation": "Development capture only. RC4 issuance does not prove cracking; "
                              "background remains unlabeled and live deployment is disabled.",
            },
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
                "kerberoasting": "offline RC4 service-ticket burst candidate; "
                                 "AES requests and slow or single-service attacks not covered",
                "share_discovery": "share telemetry preserved; detector not implemented",
                "winrm_lateral_movement": "process/network telemetry preserved; "
                                          "detector not implemented",
            },
            "deployment": "Password spray and RC4 ticket bursts are offline batch detectors; "
                          "their incidents are separate from production "
                          "per-user incident assignments.",
        }
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        # Timeline is supporting telemetry around each finding, not causal attribution.
        with (output / "timeline.jsonl").open("x", encoding="utf-8") as timeline:
            for incident in (*spray, *tickets):
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
    parser.add_argument("--with-network", action="store_true", help="download paired network ZIP")
    parser.add_argument("--network-capture", type=Path, help="existing paired pinned network ZIP")
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
            network_capture = args.network_capture
            if args.with_network and network_capture is None:
                network_capture = Path(directory) / "network.zip"
                with (urlopen(NETWORK_URL, timeout=60) as response,
                      network_capture.open("wb") as target):
                    shutil.copyfileobj(response, target)
            report = replay(capture, args.output, network_capture)
        print(json.dumps({"output": str(args.output), "records": report["normalized_events"],
                          "evaluation": report["evaluation"],
                          "rc4_ticket_evaluation": report["rc4_ticket_evaluation"]}, indent=2))
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
