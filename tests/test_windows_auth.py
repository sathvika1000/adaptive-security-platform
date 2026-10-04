import json
from datetime import timedelta
from pathlib import Path

import pytest

from adaptive_security.connectors.evtx import normalize
from adaptive_security.connectors.windows_auth import extend_auth
from adaptive_security.detection.windows_auth import RULES, detect_windows_auth
from adaptive_security.evaluation import EvaluationCase, evaluate_report
from adaptive_security.evtx_evaluation import Reservation, run


def event(number=4648, ordinal=0, **updates):
    fields = {
        "TargetUserName": f"user{ordinal}",
        "TargetDomainName": "DOMAIN",
        "SubjectUserName": "caller",
        "SubjectUserSid": "S-1-5-21-1234",
        "SubjectLogonId": "0x123",
        "SubjectDomainName": "DOMAIN",
        "ProcessId": "0x456",
        "ProcessName": "C:\\Windows\\tool.exe",
        "TargetServerName": "server",
        "IpAddress": "::ffff:192.0.2.1",
        "Status": "0x00000018",
    }
    fields.update(updates)
    data = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in fields.items() if v is not None)
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><Provider Name="Microsoft-Windows-Security-Auditing"/>'
        f'<EventID>{number}</EventID><TimeCreated SystemTime="2020-01-01T00:00:00Z"/>'
        f"<EventRecordID>{ordinal}</EventRecordID><Channel>Security</Channel>"
        f"<Computer>endpoint</Computer></System><EventData>{data}</EventData></Event>"
    )
    return extend_auth(normalize(xml, capture_sha256="digest", member="test.evtx", ordinal=ordinal))


@pytest.mark.parametrize("number,rule", [(4648, RULES[0]), (4771, RULES[1])])
def test_five_distinct_targets_boundary_order_duplicate_evidence_and_version(number, rule):
    records = [event(number, i) for i in range(5)]
    records[-1] = records[-1].model_copy(
        update={"event_time": records[0].event_time + timedelta(minutes=5)}
    )
    (incident,) = detect_windows_auth([*list(reversed(records)), records[0]], rule)
    assert len(incident.event_ids) == 5
    assert incident.signals[0].rule_id == rule and incident.signals[0].rule_version == 1
    assert detect_windows_auth(records, rule) == (incident,)
    records[-1] = records[-1].model_copy(
        update={"event_time": records[-1].event_time + timedelta(microseconds=1)}
    )
    assert not detect_windows_auth(records, rule)


@pytest.mark.parametrize("number,rule", [(4648, RULES[0]), (4771, RULES[1])])
def test_repeated_account_machine_targets_and_untrusted_provider_do_not_qualify(number, rule):
    assert not detect_windows_auth(
        [event(number, i, TargetUserName="alice") for i in range(10)], rule
    )
    assert not detect_windows_auth(
        [event(number, i, TargetUserName=f"host{i}$") for i in range(5)], rule
    )
    records = [event(number, i) for i in range(5)]
    records[0] = records[0].model_copy(
        update={"attributes": {**records[0].attributes, "provider": "Other-Provider"}}
    )
    assert not detect_windows_auth(records, rule)
    assert not detect_windows_auth(
        [e.model_copy(update={"source": "wazuh"}) for e in records], rule
    )


@pytest.mark.parametrize(
    "field", ["SubjectLogonId", "ProcessId", "ProcessName", "TargetServerName"]
)
def test_explicit_groups_do_not_pool_processes_sessions_servers_or_missing_fields(field):
    records = [event(4648, i) for i in range(5)]
    records[0] = event(4648, 0, **{field: "different"})
    assert not detect_windows_auth(records, RULES[0])
    missing = detect_windows_auth([event(4648, i, **{field: None}) for i in range(5)], RULES[0])
    assert bool(missing) == (field == "ProcessName")


def test_mapping_preserves_xml_and_unknown_explicit_outcome_and_caller_separation():
    record = event()
    assert record.outcome is None and record.action == "explicit_credentials"
    assert record.attributes["raw_xml"] and record.entities[-1].value == "DOMAIN\\user0"
    assert not any(e.type == "user" and e.value.endswith("caller") for e in record.entities)
    records = [event(4648, i, SubjectUserSid=None) for i in range(5)]
    assert detect_windows_auth(records, RULES[0])
    records[0] = event(4648, 0, SubjectUserSid="different")
    assert not detect_windows_auth(records, RULES[0])
    assert not detect_windows_auth(
        [event(4648, i, SubjectUserSid=None, SubjectUserName=None) for i in range(5)], RULES[0]
    )
    # The default XML normalizer remains unchanged; only the offline projection opts in.
    xml = record.attributes["raw_xml"]
    original = normalize(xml, capture_sha256="digest", member="test.evtx", ordinal=0)
    assert original.action is None and original.outcome is None
    assert (
        extend_auth(
            original.model_copy(
                update={"attributes": {**original.attributes, "provider": "Other-Provider"}}
            )
        ).action
        is None
    )


@pytest.mark.parametrize("status", ["0x0", "0x17", "0x10", "unknown", None])
def test_kerberos_only_bad_password_status_counts(status):
    assert not detect_windows_auth([event(4771, i, Status=status) for i in range(5)], RULES[1])


def test_kerberos_origins_controllers_and_event_families_do_not_pool():
    records = [event(4771, i, Status=24) for i in range(5)]
    assert detect_windows_auth(records, RULES[1])
    records[0] = event(4771, 0, IpAddress="192.0.2.2")
    assert not detect_windows_auth(records, RULES[1])
    records[0] = event(4771, 0).model_copy(
        update={
            "attributes": {
                **event(4771, 0).attributes,
                "raw": {**event(4771, 0).attributes["raw"], "Hostname": "other-dc"},
            }
        }
    )
    assert not detect_windows_auth(records, RULES[1])
    for origin in (None, "invalid", "0.0.0.0", "::"):
        assert not detect_windows_auth(
            [event(4771, i, IpAddress=origin) for i in range(5)], RULES[1]
        )
    assert not detect_windows_auth(
        [event(4771, i) for i in range(2)] + [event(4648, i + 2) for i in range(3)], RULES[1]
    )
    assert extend_auth(event(4768)).action is None


@pytest.mark.parametrize("number,rule", [(4648, RULES[0]), (4771, RULES[1])])
def test_new_rule_routes_through_case_evaluation(number, rule):
    malicious = EvaluationCase(
        case_id="attack", label="malicious", events=tuple(event(number, i) for i in range(5))
    )
    benign = EvaluationCase(case_id="control", label="benign", events=(event(number),))
    report = evaluate_report([malicious, benign], rule)
    assert report.summary.true_positive == report.summary.true_negative == 1


def test_development_runner_forces_partition_and_keeps_reservation_as_baseline(
    tmp_path, monkeypatch
):
    import adaptive_security.evtx_evaluation as module

    root = Path(__file__).resolve().parents[1]
    original = Reservation.model_validate_json(
        (root / "docs/EVALUATION_RESERVATIONS.json").read_bytes()
    )
    capture = original.captures[0]
    reserved = tmp_path / "reserved.json"
    reserved.write_text(original.model_copy(update={"captures": (capture,)}).model_dump_json())
    local = tmp_path / "captures"
    local.mkdir()
    (local / f"{capture.capture_id}.evtx").write_bytes(b"controlled capture")
    monkeypatch.setattr(
        module, "load_capture", lambda path, capture: [event(4648, i) for i in range(5)]
    )
    report = run(reserved, tmp_path / "result", local, RULES[0])
    row = report["datasets"][0]
    assert row["dataset"]["partition"] == "development"
    assert row["summary"]["true_positive"] == 1
    assert row["summary"]["precision"] is None and row["summary"]["recall"] is None
    assert report["reservation"]["partition"] == "held_out"
    assert "frozen_rule_commit" not in report and len(report["development_rule_sha256"]) == 2
    assert "alice" not in json.dumps(report)
    findings = json.loads((tmp_path / "result" / f"{capture.capture_id}.findings.json").read_text())
    assert len(findings) == 1 and len(findings[0]["event_ids"]) == 5
