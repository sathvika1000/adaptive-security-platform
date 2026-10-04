"""Opt-in offline mappings; preserve the original EVTX normalization baseline."""

from adaptive_security.connectors.otrf import _code, _text
from adaptive_security.domain.events import EntityRef, EventCategory, SecurityEvent


def extend_auth(event: SecurityEvent) -> SecurityEvent:
    if (event.source != "evtx" or event.attributes.get("channel") != "Security" or
            event.attributes.get("provider") != "Microsoft-Windows-Security-Auditing"):
        return event
    number = event.attributes.get("windows_event_id")
    if number not in (4648, 4771):
        return event
    raw = event.attributes["raw"]
    user = _text(raw.get("TargetUserName"))
    domain = _text(raw.get("TargetDomainName"))
    if user and domain and "\\" not in user and "@" not in user:
        user = f"{domain}\\{user}"
    entities = tuple(e for e in event.entities if e.type != "user")
    if user:
        entities += (EntityRef(type="user", value=user),)
    return event.model_copy(update={
        "category": EventCategory.AUTHENTICATION,
        "action": "explicit_credentials" if number == 4648 else "kerberos_preauth",
        # 4648 is an attempt, not evidence of a successful or failed target logon.
        "outcome": None if number == 4648 else "failure",
        "entities": entities,
        "attributes": {**event.attributes, "auth_mapping_version": 1,
                       "kerberos_status": _code(raw.get("Status")) if number == 4771 else None},
    })
