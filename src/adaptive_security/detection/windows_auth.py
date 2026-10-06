"""Offline candidates from distinct Windows authentication telemetry families."""

from collections import Counter, defaultdict
from datetime import timedelta
from hashlib import sha256
from typing import Any, Literal

from adaptive_security.domain.detections import DetectionSignal
from adaptive_security.domain.events import SecurityEvent
from adaptive_security.domain.incidents import Incident

AuthRule = Literal["auth.explicit_credential_fanout", "auth.kerberos_password_spray"]
RULES: tuple[AuthRule, ...] = ("auth.explicit_credential_fanout", "auth.kerberos_password_spray")


def _field(raw: dict[str, Any], name: str) -> str | None:
    value = raw.get(name)
    return value.casefold() if isinstance(value, str) and value not in ("", "-", "N/A") else None


def _group_events(
    events: list[SecurityEvent], rule_id: AuthRule
) -> tuple[dict[tuple[str, ...], list[SecurityEvent]], Counter[str]]:
    """Share the exact eligibility boundary between detection and coverage reporting."""
    if rule_id not in RULES:
        raise ValueError("unsupported Windows auth rule")
    groups: dict[tuple[str, ...], list[SecurityEvent]] = defaultdict(list)
    excluded: Counter[str] = Counter()
    seen: set[tuple[str, str]] = set()
    for event in sorted(events, key=lambda e: (e.event_time, e.event_id)):
        identity = (event.source, event.event_id)
        if identity in seen:
            excluded["duplicate_identity"] += 1
            continue
        seen.add(identity)
        if (event.source != "evtx" or event.attributes.get("channel") != "Security" or
                event.attributes.get("provider") != "Microsoft-Windows-Security-Auditing" or
                event.attributes.get("auth_mapping_version") != 1):
            excluded["unsupported_origin_or_mapping"] += 1
            continue
        raw = event.attributes["raw"]
        target = _field(raw, "TargetUserName")
        if not target or target.endswith("$"):
            excluded["missing_or_machine_target"] += 1
            continue
        host = _field(raw, "Hostname")
        if rule_id == RULES[0]:
            if (event.action != "explicit_credentials" or event.outcome is not None or
                    event.attributes.get("windows_event_id") != 4648):
                excluded["wrong_event_family_or_outcome"] += 1
                continue
            caller = _field(raw, "SubjectUserSid")
            if not caller:
                domain, name = _field(raw, "SubjectDomainName"), _field(raw, "SubjectUserName")
                caller = f"{domain}\\{name}" if domain and name else None
            parts = [host, caller, _field(raw, "SubjectLogonId"), _field(raw, "ProcessId"),
                     _field(raw, "ProcessName") or "<unavailable>", _field(raw, "TargetServerName")]
        else:
            if (event.action != "kerberos_preauth" or event.outcome != "failure" or
                    event.attributes.get("windows_event_id") != 4771 or
                    event.attributes.get("kerberos_status") != 0x18):
                excluded["wrong_event_family_or_outcome"] += 1
                continue
            origin = event.source_ip
            if origin in ("0.0.0.0", "::"):
                origin = None
            parts = [host, origin]
        if all(isinstance(part, str) and part for part in parts):
            groups[(event.source, *(str(part) for part in parts))].append(event)
        else:
            excluded["missing_grouping_fields"] += 1
    return groups, excluded


def auth_telemetry_coverage(events: list[SecurityEvent], rule_id: AuthRule) -> dict[str, Any]:
    """Eligibility counts, not evidence of representative coverage or detection accuracy."""
    groups, excluded = _group_events(events, rule_id)
    eligible = [event for records in groups.values() for event in records]
    return {
        "input_records": len(events),
        "eligible_records": len(eligible),
        "eligible_groups": len(groups),
        "distinct_target_accounts": len({
            entity.value.casefold() for event in eligible for entity in event.entities
            if entity.type == "user"
        }),
        "excluded_records": dict(sorted(excluded.items())),
        "status": "eligible_telemetry_present" if eligible else "no_eligible_telemetry",
        "limitations": [
            "Eligibility uses the same record and grouping checks as the detector.",
            "Account counts span all eligible groups and times; they are not threshold windows.",
            "Eligible telemetry does not certify complete collection or representative activity.",
            "No finding does not establish benign behavior or production readiness.",
        ],
    }


def detect_windows_auth(events: list[SecurityEvent], rule_id: AuthRule) -> tuple[Incident, ...]:
    """Five distinct nonmachine target accounts in five minutes; no mixed event families."""
    groups, _ = _group_events(events, rule_id)
    incidents = []
    title = ("Explicit credential account fan-out" if rule_id == RULES[0]
             else "Possible Kerberos password spraying")
    for key, records in sorted(groups.items()):
        start = 0
        while start < len(records):
            end = start + 1
            while (end < len(records) and
                   records[end].event_time - records[start].event_time <= timedelta(minutes=5)):
                end += 1
            window = records[start:end]
            targets = {entity.value.casefold() for e in window for entity in e.entities
                       if entity.type == "user"}
            if len(targets) < 5:
                start += 1
                continue
            ids = tuple(e.event_id for e in window)
            digest = sha256(repr((rule_id, key, ids)).encode()).hexdigest()[:16]
            signal = DetectionSignal(rule_id=rule_id, rule_version=1, title=title,
                                     evidence_event_ids=ids, priority=5)
            incidents.append(Incident(
                incident_id=f"win-auth-{digest}", title=title, first_seen=window[0].event_time,
                last_seen=window[-1].event_time, severity=5, event_ids=ids,
                entities=tuple(dict.fromkeys(entity for e in window for entity in e.entities)),
                signals=(signal,),
            ))
            start = end
    return tuple(incidents)
