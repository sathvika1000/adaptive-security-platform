from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from adaptive_security.connectors.otrf import normalize
from adaptive_security.detection.password_spray import detect_password_spray
from adaptive_security.domain.events import EntityRef, EventCategory
from adaptive_security.evaluation import EvaluationCase, evaluate_report
from adaptive_security.otrf_replay import load_capture, replay


def record(**updates):
    return {"Channel": "Security", "EventID": 4625,
            "EventTime": "2020-10-22 04:29:53", "@timestamp": "2020-10-22T08:29:55Z",
            "Hostname": "endpoint.local", "host": "collector.local",
            "TargetUserName": "alice", "TargetDomainName": "EXAMPLE",
            "WorkstationName": "ORIGIN", "IpAddress": "-", **updates}


def converted(**updates):
    return normalize(record(**updates), capture_sha256="digest", member="capture.json",
                     line=1, timezone="America/New_York")


def failures(count=7, **updates):
    result = []
    for number in range(count):
        event = converted(TargetUserName=f"user{number}")
        result.append(event.model_copy(update={"event_id": str(number), **updates}))
    return result


def test_normalize_time_identity_provenance():
    event = converted()
    assert event.event_time == datetime(2020, 10, 22, 8, 29, 53, tzinfo=UTC)
    assert event.observed_time.second == 55
    assert event.source_ip is None
    assert EntityRef(type="host", value="endpoint.local") in event.entities
    assert EntityRef(type="host", value="collector.local") not in event.entities
    assert EntityRef(type="user", value="EXAMPLE\\alice") in event.entities
    assert event.attributes["raw_line"] == 1
    assert converted().event_id == event.event_id
    assert converted(IpAddress="::ffff:192.0.2.1").source_ip == "192.0.2.1"
    assert converted(IpAddress="invalid").source_ip is None


def test_provider_scoping_and_sysmon_time():
    event = converted(Channel="Microsoft-Windows-Sysmon/Operational", EventID=1,
                      UtcTime="2020-10-22 08:29:52.016")
    assert event.category == EventCategory.PROCESS
    assert event.event_time.microsecond == 16000
    assert converted(Channel="System", EventID=4625).outcome is None
    assert converted(EventID=4769).outcome is None
    assert converted(EventID=4776, Status="0x0").outcome == "success"
    assert converted(EventID=5140).action == "share_access"
    with pytest.raises(ValueError, match="timezone"):
        converted(**{"@timestamp": "2020-10-22T08:29:55"})


def test_spray_evidence_duplicate_and_order():
    events = failures()
    incidents = detect_password_spray(events)
    assert len(incidents) == 1
    assert len(incidents[0].event_ids) == 7
    assert incidents[0].signals[0].evidence_event_ids == incidents[0].event_ids
    assert detect_password_spray(list(reversed(events)) + events) == incidents
    report = evaluate_report([EvaluationCase(case_id="spray", label="malicious",
                                            events=tuple(events))], "auth.password_spray")
    assert report.summary.true_positive == 1


def test_spray_boundaries_and_missing_origin():
    assert not detect_password_spray(failures(4))
    same_user = [e.model_copy(update={"entities": (EntityRef(type="user", value="same"),)})
                 for e in failures()]
    assert not detect_password_spray(same_user)
    assert not detect_password_spray(failures(attributes={}))
    assert not detect_password_spray(failures(action="credential_validation"))
    assert not detect_password_spray(failures(outcome="success"))
    spread = [e.model_copy(update={"event_time": e.event_time + timedelta(minutes=n * 2)})
              for n, e in enumerate(failures())]
    assert not detect_password_spray(spread)
    ip_events = failures(source_ip="192.0.2.1")
    assert detect_password_spray(ip_events)
    mixed = [e.model_copy(update={"source_ip": f"192.0.2.{n}"})
             for n, e in enumerate(failures())]
    assert not detect_password_spray(mixed)


def test_refuse_modified_capture_and_existing_output(tmp_path: Path):
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"not the pinned capture")
    with pytest.raises(ValueError, match="checksum"):
        load_capture(bad)
    output = tmp_path / "existing"
    output.mkdir()
    with pytest.raises(ValueError, match="exists"):
        replay(bad, output)
    assert not list(output.iterdir())


def test_separate_windows_and_sources():
    first = failures(5)
    later = [e.model_copy(update={"event_id": f"later-{e.event_id}",
                                  "event_time": e.event_time + timedelta(minutes=6)})
             for e in first]
    assert len(detect_password_spray(first + later)) == 2
    mixed = [e.model_copy(update={"source": f"source{n}"}) for n, e in enumerate(first)]
    assert not detect_password_spray(mixed)


def test_isolated_replay_artifacts(tmp_path: Path, monkeypatch):
    import hashlib
    import json
    import zipfile

    import adaptive_security.otrf_replay as module
    from adaptive_security.store import SQLiteStore

    capture = tmp_path / "capture.zip"
    with zipfile.ZipFile(capture, "w") as archive:
        archive.writestr(module.MEMBER, "\n".join(
            json.dumps(record(TargetUserName=f"user{n}", WorkstationName="WORKSTATION5"))
            for n in range(7)
        ))
    monkeypatch.setattr(module, "SHA256", hashlib.sha256(capture.read_bytes()).hexdigest())
    destination = tmp_path / "results"
    report = module.replay(capture, destination)
    assert report["password_spray_candidates"] == 1
    assert report["normalized_events"] == 7
    assert report["production_auth_incidents"] == 0
    store = SQLiteStore(str(destination / "findings.db"))
    incident = store.incidents()[0]
    assert len(incident.event_ids) == 7
    assert (destination / "capture.zip").read_bytes() == capture.read_bytes()
    assert len((destination / "events.jsonl").read_text().splitlines()) == 7
    assert len((destination / "timeline.jsonl").read_text().splitlines()) == 7
    case = EvaluationCase.model_validate_json((destination / "attack-case.jsonl").read_text())
    assert evaluate_report([case], "auth.password_spray").summary.true_positive == 1
    assert destination.stat().st_mode & 0o777 == 0o700
    with pytest.raises(ValueError, match="exists"):
        module.replay(capture, destination)
