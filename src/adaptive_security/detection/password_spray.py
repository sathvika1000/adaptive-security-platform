"""Batch password-spray detection for isolated, event-time ordered replay."""

from collections import defaultdict
from datetime import timedelta
from hashlib import sha256

from adaptive_security.domain.detections import DetectionSignal
from adaptive_security.domain.events import EventCategory, SecurityEvent
from adaptive_security.domain.incidents import Incident

RULE_ID = "auth.password_spray"


def detect_password_spray(events: list[SecurityEvent]) -> tuple[Incident, ...]:
    """Five distinct accounts in five minutes from an explicit origin.

    Use logon failures only: credential validation records can describe the same attempt.
    Findings are heuristic candidates, not a conclusion that compromise occurred.
    """
    groups: dict[tuple[str, str, str], list[SecurityEvent]] = defaultdict(list)
    seen: set[tuple[str, str]] = set()
    for event in sorted(events, key=lambda e: (e.event_time, e.event_id)):
        if (event.source, event.event_id) in seen:
            continue
        seen.add((event.source, event.event_id))
        if (event.category != EventCategory.AUTHENTICATION or event.outcome != "failure"
                or event.action != "logon"):
            continue
        user = next((e.value for e in event.entities if e.type == "user"), None)
        origin = event.source_ip or event.attributes.get("source_workstation")
        if user and isinstance(origin, str) and origin:
            kind = "ip" if event.source_ip else "workstation"
            groups[(event.source, kind, origin.casefold())].append(event)
    incidents = []
    for key, failures in sorted(groups.items()):
        start = 0
        while start < len(failures):
            end = start + 1
            while (end < len(failures) and
                   failures[end].event_time - failures[start].event_time <= timedelta(minutes=5)):
                end += 1
            window = failures[start:end]
            users = {e.value.casefold() for event in window for e in event.entities
                     if e.type == "user"}
            if len(users) < 5:
                start += 1
                continue
            ids = tuple(e.event_id for e in window)
            digest = sha256(repr((key, ids)).encode()).hexdigest()[:16]
            entities = tuple(dict.fromkeys(e for event in window for e in event.entities))
            signal = DetectionSignal(
                rule_id=RULE_ID, rule_version=1, title="Possible password spraying",
                evidence_event_ids=ids, priority=6,
            )
            incidents.append(Incident(
                incident_id=f"spray-{digest}", title="Possible password spraying",
                first_seen=window[0].event_time, last_seen=window[-1].event_time,
                severity=6, event_ids=ids, entities=entities, signals=(signal,),
            ))
            start = end
    return tuple(incidents)
