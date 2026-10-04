"""Offline RC4 service-ticket burst candidates, with exact Windows audit evidence."""

from collections import defaultdict
from datetime import timedelta
from hashlib import sha256

from adaptive_security.domain.detections import DetectionSignal
from adaptive_security.domain.events import EventCategory, SecurityEvent
from adaptive_security.domain.incidents import Incident

RULE_ID = "auth.rc4_service_ticket_burst"


def detect_rc4_tickets(events: list[SecurityEvent]) -> tuple[Incident, ...]:
    """Five distinct nonmachine service accounts in five minutes.

    Group by source, requester, explicit client IP and issuing domain controller.
    RC4 use is a review lead, not proof of Kerberoasting or password cracking.
    """
    groups: dict[tuple[str, str, str, str], list[SecurityEvent]] = defaultdict(list)
    seen: set[tuple[str, str]] = set()
    for event in sorted(events, key=lambda e: (e.event_time, e.event_id)):
        identity = (event.source, event.event_id)
        if identity in seen:
            continue
        seen.add(identity)
        attrs = event.attributes
        service = attrs.get("service_name")
        if (event.category != EventCategory.AUTHENTICATION
                or event.action != "service_ticket_request"
                or attrs.get("channel") != "Security"
                or attrs.get("windows_event_id") != 4769
                or type(attrs.get("ticket_status")) is not int
                or attrs["ticket_status"] != 0
                or type(attrs.get("ticket_encryption_type")) is not int
                or attrs["ticket_encryption_type"] != 23
                or not isinstance(service, str) or not service.strip()
                or service.strip().endswith("$") or service.strip().casefold() == "krbtgt"):
            continue
        user = next((e.value for e in event.entities if e.type == "user"), None)
        host = next((e.value for e in event.entities if e.type == "host"), None)
        if user and host and event.source_ip:
            key = (event.source, user.casefold(), event.source_ip, host.casefold())
            groups[key].append(event)
    incidents = []
    for key, tickets in sorted(groups.items()):
        start = 0
        while start < len(tickets):
            end = start + 1
            while (end < len(tickets) and
                   tickets[end].event_time - tickets[start].event_time <= timedelta(minutes=5)):
                end += 1
            window = tickets[start:end]
            services = {event.attributes["service_name"].strip().casefold() for event in window}
            if len(services) < 5:
                start += 1
                continue
            ids = tuple(e.event_id for e in window)
            digest = sha256(repr((key, ids)).encode()).hexdigest()[:16]
            title = "Suspicious RC4 service-ticket burst"
            signal = DetectionSignal(rule_id=RULE_ID, rule_version=1, title=title,
                                     evidence_event_ids=ids, priority=6)
            incidents.append(Incident(
                incident_id=f"tgs-{digest}", title=title,
                first_seen=window[0].event_time, last_seen=window[-1].event_time,
                severity=6, event_ids=ids,
                entities=tuple(dict.fromkeys(e for event in window for e in event.entities)),
                signals=(signal,),
            ))
            start = end
    return tuple(incidents)
