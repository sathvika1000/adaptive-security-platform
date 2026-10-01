"""Normalize flat OTRF Windows host records without inventing missing telemetry."""

from datetime import UTC, datetime
from hashlib import sha256
from ipaddress import IPv6Address, ip_address
from typing import Any
from zoneinfo import ZoneInfo

from adaptive_security.domain.events import EntityRef, EventCategory, SecurityEvent


def _text(value: Any) -> str | None:
    return str(value) if value not in (None, "", "-", "N/A") else None


def normalize(record: dict[str, Any], *, capture_sha256: str, member: str,
              line: int, timezone: str) -> SecurityEvent:
    channel = str(record.get("Channel", ""))
    event_id = int(record["EventID"])
    observed = datetime.fromisoformat(str(record["@timestamp"]).replace("Z", "+00:00"))
    if observed.tzinfo is None:
        raise ValueError("@timestamp must have a timezone")
    if record.get("UtcTime"):
        event_time = datetime.fromisoformat(str(record["UtcTime"]))
        event_time = (event_time.replace(tzinfo=UTC) if event_time.tzinfo is None
                      else event_time.astimezone(UTC))
        time_basis = "UtcTime"
    else:
        event_time = datetime.fromisoformat(str(record["EventTime"]))
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=ZoneInfo(timezone))
        time_basis = f"EventTime:{timezone}"
    category = EventCategory.OTHER
    action = None
    outcome = None
    if channel == "Security":
        if event_id in (4624, 4625, 4776):
            category = EventCategory.AUTHENTICATION
            action = "credential_validation" if event_id == 4776 else "logon"
            outcome = ("failure" if event_id == 4625 else "success" if event_id == 4624
                       else "success" if record.get("Status") == "0x0"
                       else "failure" if str(record.get("Status", "")).startswith("0x")
                       else None)
        elif event_id == 4769:
            category, action = EventCategory.AUTHENTICATION, "service_ticket_request"
        elif event_id in (5140, 5145):
            category, action = EventCategory.FILE, "share_access"
        elif event_id == 4688:
            category, action = EventCategory.PROCESS, "process_start"
    elif channel == "Microsoft-Windows-Sysmon/Operational":
        if event_id in (1, 5):
            category = EventCategory.PROCESS
            action = "process_start" if event_id == 1 else "process_end"
        elif event_id == 3:
            category, action = EventCategory.NETWORK, "connection"
        elif event_id == 22:
            category, action = EventCategory.DNS, "query"
        elif event_id in (11, 23):
            category = EventCategory.FILE
            action = "file_create" if event_id == 11 else "file_delete"
    entities = []
    host = _text(record.get("Hostname"))  # 'host' is the collector, not the endpoint.
    if host:
        entities.append(EntityRef(type="host", value=host))
    user = _text(record.get("TargetUserName")) if action in (
        "logon", "credential_validation", "service_ticket_request"
    ) else _text(record.get("User")) or _text(record.get("SubjectUserName"))
    if user:
        domain = _text(record.get("TargetDomainName"))
        if domain and "@" not in user and "\\" not in user:
            user = f"{domain}\\{user}"
        entities.append(EntityRef(type="user", value=user))
    source_ip = None
    raw_ip = _text(record.get("IpAddress")) or _text(record.get("SourceIp"))
    if raw_ip:
        try:
            address = ip_address(raw_ip)
            if isinstance(address, IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            source_ip = str(address)
        except ValueError:
            pass
    if source_ip:
        entities.append(EntityRef(type="ip", value=source_ip))
    workstation = _text(record.get("WorkstationName")) or _text(record.get("Workstation"))
    if workstation:
        entities.append(EntityRef(type="source_host", value=workstation))
    identifier = sha256(f"{capture_sha256}:{member}:{line}".encode()).hexdigest()
    return SecurityEvent(
        event_id=identifier, source="otrf", category=category, event_time=event_time,
        observed_time=observed, action=action, outcome=outcome, source_ip=source_ip,
        entities=tuple(entities), attributes={
            "capture_sha256": capture_sha256, "raw_member": member, "raw_line": line,
            "windows_event_id": event_id, "channel": channel, "time_basis": time_basis,
            "source_workstation": workstation, "raw": record,
        },
    )
