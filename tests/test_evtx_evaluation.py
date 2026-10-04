import json
from hashlib import sha1, sha256
from pathlib import Path

import pytest

pytest.importorskip("defusedxml")

from adaptive_security.connectors.evtx import normalize
from adaptive_security.evtx_evaluation import Capture, Reservation, _verify_rules, load_capture, run


def xml(event_id=4625, provider="Microsoft-Windows-Security-Auditing", fields=None):
    data = fields or ('<Data Name="TargetUserName">alice</Data>'
                     '<Data Name="IpAddress">192.0.2.1</Data>')
    return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f'<System><Provider Name="{provider}"/><EventID>{event_id}</EventID>'
            '<TimeCreated SystemTime="2020-07-22 20:29:27.321770+00:00"/>'
            '<EventRecordID>42</EventRecordID><Channel>Security</Channel>'
            f'<Computer>endpoint</Computer></System><EventData>{data}</EventData></Event>')


def convert(text):
    return normalize(text, capture_sha256="digest", member="sample.evtx", ordinal=1)


def reservation():
    root = Path(__file__).resolve().parents[1]
    return Reservation.model_validate_json(
        (root / "docs/EVALUATION_RESERVATIONS.json").read_bytes())


def test_evtx_provenance_utc_time_and_actual_provider_mapping():
    event = convert(xml())
    assert event.source == "evtx" and event.action == "logon" and event.outcome == "failure"
    assert event.source_ip == "192.0.2.1"
    assert event.attributes["raw_xml"] == xml()
    assert event.attributes["evtx_record_id"] == "42"
    assert event.observed_time == event.event_time
    assert event.event_time.utcoffset().total_seconds() == 0
    assert "unavailable" in event.attributes["observation_time_basis"]
    assert convert(xml()).event_id == event.event_id
    assert convert(xml(provider="Other-Provider")).action is None


@pytest.mark.parametrize("event_id", [4648, 4771, 4768, 1102])
def test_unsupported_evidence_is_preserved_without_fabricated_failure(event_id):
    event = convert(xml(event_id))
    assert event.action is None and event.outcome is None
    assert event.attributes["windows_event_id"] == event_id
    assert event.attributes["raw_xml"] == xml(event_id)


@pytest.mark.parametrize("value", [
    "private malformed telemetry",
    '<!DOCTYPE Event [<!ENTITY leak "private-secret">]>' + xml(),
    xml(fields='<Data Name="TargetUserName">alice</Data>'
               '<Data Name="TargetUserName">bob</Data>'),
    xml().replace('2020-07-22 20:29:27.321770+00:00', '2020-07-22 20:29:27'),
])
def test_xml_invalid_ambiguous_or_unsafe_records_fail_without_echoing_data(value):
    with pytest.raises(ValueError, match="invalid EVTX XML") as error:
        convert(value)
    assert "private" not in str(error.value)


def test_reservation_requires_frozen_rules_and_existing_output_is_not_modified(tmp_path):
    original = reservation()
    _verify_rules(original)
    changed = original.model_copy(update={"rule_sha256": {
        **original.rule_sha256, "src/adaptive_security/detection/password_spray.py": "0" * 64}})
    with pytest.raises(ValueError, match="differs"):
        _verify_rules(changed)
    with pytest.raises(ValueError, match="pin both"):
        _verify_rules(original.model_copy(update={"rule_sha256": {}}))
    path = tmp_path / "reservation.json"
    path.write_text(original.model_dump_json())
    destination = tmp_path / "existing"
    destination.mkdir()
    with pytest.raises(ValueError, match="output exists"):
        run(path, destination)
    assert not list(destination.iterdir())


def test_modified_evtx_rejected_before_parser(tmp_path):
    path = tmp_path / "bad.evtx"
    path.write_bytes(b"modified")
    with pytest.raises(ValueError, match="checksum"):
        load_capture(path, reservation().captures[0])


def test_runner_preserves_all_records_and_reports_miss_without_metrics(tmp_path, monkeypatch):
    import adaptive_security.evtx_evaluation as module

    capture = reservation().captures[0]
    original = reservation().model_copy(update={"captures": (capture,)})
    reservation_path = tmp_path / "reserved.json"
    reservation_path.write_text(original.model_dump_json())
    local = tmp_path / "captures"
    local.mkdir()
    (local / f"{capture.capture_id}.evtx").write_bytes(b"test capture")
    events = [convert(xml(4648)), normalize(xml(4771), capture_sha256="digest",
                                         member="sample.evtx", ordinal=2)]
    monkeypatch.setattr(module, "load_capture", lambda path, capture: events)
    output = tmp_path / "results"
    report = run(reservation_path, output, local)
    assert report["inventory"][0]["records"] == 2
    assert report["datasets"][0]["summary"]["false_negative"] == 1
    assert report["datasets"][0]["summary"]["precision"] is None
    assert report["datasets"][0]["summary"]["recall"] is None
    assert report["datasets"][0]["dataset"]["partition"] == "held_out"
    assert "alice" not in json.dumps(report)
    assert len((output / f"{capture.capture_id}.events.jsonl").read_text().splitlines()) == 2
    assert (output / f"{capture.capture_id}.evtx").read_bytes() == b"test capture"
    assert output.stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in output.iterdir())


def test_parser_boundary_preserves_yielded_records_and_fails_on_error(tmp_path, monkeypatch):
    import adaptive_security.evtx_evaluation as module

    raw = b"controlled parser input"
    path = tmp_path / "sample.evtx"
    path.write_bytes(raw)
    c = Capture.model_validate({**reservation().captures[0].model_dump(),
        "capture_sha256": sha256(raw).hexdigest(),
        "git_blob_sha": sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()})
    class Record:
        def xml(self):
            return xml(4771)
    class Reader:
        def __init__(self, path):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def records(self):
            yield Record()
            yield Record()
    class API:
        Evtx = Reader
    monkeypatch.setattr(module, "import_module", lambda name: API)
    events = load_capture(path, c)
    assert len(events) == 2 and events[0].event_id != events[1].event_id
    monkeypatch.setattr(Record, "xml", lambda self: "invalid private record")
    with pytest.raises(ValueError, match="no records silently skipped"):
        load_capture(path, c)
