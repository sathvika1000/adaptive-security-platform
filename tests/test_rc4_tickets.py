from datetime import timedelta
from pathlib import Path

import pytest

from adaptive_security.connectors.otrf import normalize
from adaptive_security.detection.rc4_tickets import detect_rc4_tickets
from adaptive_security.domain.events import EntityRef
from adaptive_security.evaluation import EvaluationCase, evaluate_report
from adaptive_security.evaluation_suite import evaluate_suite
from adaptive_security.service import IngestionService
from adaptive_security.store import SQLiteStore


def tickets(count=5, **updates):
    return [normalize({
        "Channel": "Security", "EventID": 4769,
        "EventTime": "2020-10-22 04:29:54", "@timestamp": "2020-10-22T08:29:55Z",
        "Hostname": "dc.example", "TargetUserName": "requester@EXAMPLE",
        "ServiceName": f"svc{number}", "TicketEncryptionType": "0x17", "Status": "0x0",
        "IpAddress": "::ffff:192.0.2.5", **updates,
    }, capture_sha256="synthetic", member="records.json", line=number + 1,
        timezone="America/New_York") for number in range(count)]


def test_ticket_normalization_preserves_requester_and_raw_without_logon_outcome():
    event = tickets()[0]
    assert event.outcome is None
    assert event.attributes["ticket_status"] == 0
    assert event.attributes["ticket_encryption_type"] == 23
    assert event.source_ip == "192.0.2.5"
    assert EntityRef(type="service_account", value="svc0") in event.entities
    assert EntityRef(type="user", value="requester@EXAMPLE") in event.entities
    assert event.attributes["raw"]["TicketEncryptionType"] == "0x17"
    assert tickets(TicketEncryptionType=23, Status=0)[0].attributes["ticket_status"] == 0


def test_ticket_candidate_preserves_exact_ordered_deduplicated_evidence():
    events = tickets()
    found = detect_rc4_tickets(events)
    assert len(found) == 1
    assert detect_rc4_tickets(list(reversed(events)) + events) == found
    assert len(found[0].event_ids) == 5
    assert found[0].signals[0].evidence_event_ids == found[0].event_ids


@pytest.mark.parametrize("updates", [
    {"TicketEncryptionType": "0x12"}, {"TicketEncryptionType": None},
    {"TicketEncryptionType": True}, {"TicketEncryptionType": "invalid"},
    {"Status": "0x6"}, {"Status": None}, {"Status": False},
    {"ServiceName": "krbtgt"}, {"ServiceName": "MACHINE$"},
    {"ServiceName": "-"}, {"ServiceName": "  "}, {"IpAddress": "-"},
    {"TargetUserName": "-"}, {"Hostname": "-"}, {"Channel": "System"},
    {"EventID": 4624},
])
def test_incomplete_failed_aes_or_unrelated_records_are_excluded(updates):
    assert not detect_rc4_tickets(tickets(**updates))


def test_distinct_services_and_inclusive_five_minute_boundary():
    assert not detect_rc4_tickets(tickets(4))
    assert not detect_rc4_tickets(tickets(ServiceName="same"))
    varied_case = tickets(ServiceName="Same")
    varied_case[-1] = varied_case[-1].model_copy(update={"attributes": {
        **varied_case[-1].attributes, "service_name": "same"}})
    assert not detect_rc4_tickets(varied_case)
    events = tickets()
    events[-1] = events[-1].model_copy(update={
        "event_time": events[-1].event_time + timedelta(minutes=5)})
    assert detect_rc4_tickets(events)
    events[-1] = events[-1].model_copy(update={
        "event_time": events[-1].event_time + timedelta(microseconds=1)})
    assert not detect_rc4_tickets(events)


@pytest.mark.parametrize("field", ["source", "source_ip", "requester", "controller"])
def test_different_origins_and_requesters_cannot_complete_a_burst(field):
    events = tickets()
    last = events[-1]
    if field in ("source", "source_ip"):
        last = last.model_copy(update={field: "other" if field == "source" else "192.0.2.6"})
    else:
        kind = "user" if field == "requester" else "host"
        last = last.model_copy(update={"entities": tuple(
            EntityRef(type=entity.type, value="different") if entity.type == kind else entity
            for entity in last.entities)})
    events[-1] = last
    assert not detect_rc4_tickets(events)


def test_ticket_issuance_does_not_update_logon_baseline_or_live_incidents(tmp_path: Path):
    store = SQLiteStore(str(tmp_path / "live.db"))
    service = IngestionService(store)
    for event in tickets():
        _, incident = service.ingest(event)
        assert incident is None
    assert store.incidents() == []
    assert store.event_signals() == []
    with store.transaction() as conn:
        assert conn.execute("SELECT COUNT(*) FROM auth_baselines").fetchone()[0] == 0


def test_rule_evaluation_exposes_legacy_lookalike_and_slow_miss():
    matched = tuple(tickets())
    slow = tuple(e.model_copy(update={"event_time": e.event_time + timedelta(minutes=n * 2)})
                 for n, e in enumerate(matched))
    report = evaluate_report([
        EvaluationCase(case_id="synthetic-attack", label="malicious", events=matched),
        EvaluationCase(case_id="synthetic-legacy-app", label="benign", events=matched),
        EvaluationCase(case_id="synthetic-aes", label="benign",
                       events=tuple(tickets(TicketEncryptionType="0x12"))),
        EvaluationCase(case_id="synthetic-slow", label="malicious", events=slow),
    ], "auth.rc4_service_ticket_burst")
    assert [row.verdict for row in report.cases] == [
        "true_positive", "false_positive", "true_negative", "false_negative"]


def test_checked_in_ticket_controls_use_provenance_aware_evaluation():
    root = Path(__file__).resolve().parents[1]
    report = evaluate_suite(root / "examples/evaluation/rc4-tickets.suite.json")
    row = report["datasets"][0]
    assert row["interpretation"] == "synthetic_control"
    assert row["summary"] == {"true_positive": 1, "true_negative": 3,
                              "false_positive": 1, "false_negative": 1,
                              "precision": 0.5, "recall": 0.5}
