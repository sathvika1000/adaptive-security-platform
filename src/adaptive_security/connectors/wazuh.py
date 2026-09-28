from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from adaptive_security.domain.events import EntityRef, EventCategory, SecurityEvent


class WazuhAgent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str | None = None
    name: str | None = None
    ip: str | None = None


class WazuhRule(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str | int
    level: int = Field(ge=0)
    groups: list[str] = Field(default_factory=list)


class WazuhAlert(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    timestamp: AwareDatetime
    rule: WazuhRule
    agent: WazuhAgent | None = None
    data: dict[str, Any] = Field(default_factory=dict)


_CATEGORY_BY_GROUP = {
    "authentication_failed": EventCategory.AUTHENTICATION,
    "authentication_success": EventCategory.AUTHENTICATION,
    "authentication": EventCategory.AUTHENTICATION,
    "process": EventCategory.PROCESS,
    "network": EventCategory.NETWORK,
    "dns": EventCategory.DNS,
    "syscheck": EventCategory.FILE,
    "file": EventCategory.FILE,
}


def _sca_metadata(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}

    def copy_fields(source: dict[str, Any], names: tuple[str, ...], limit: int) -> dict[str, str]:
        return {
            name: str(item)[:limit]
            for name in names
            if isinstance((item := source.get(name)), (str, int)) and not isinstance(item, bool)
        }

    metadata: dict[str, Any] = copy_fields(
        value, ("type", "policy", "policy_id", "scan_id"), 256
    )
    check = value.get("check")
    if isinstance(check, dict):
        metadata["check"] = copy_fields(check, ("id", "title", "result", "status"), 256)
    metadata.update(copy_fields(value, ("score", "passed", "failed", "invalid"), 64))
    return metadata


class WazuhConnector:
    def normalize(self, payload: dict[str, Any]) -> SecurityEvent:
        alert = WazuhAlert.model_validate(payload)
        groups = {group.lower() for group in alert.rule.groups}
        category = next(
            (_CATEGORY_BY_GROUP[group] for group in sorted(groups) if group in _CATEGORY_BY_GROUP),
            EventCategory.OTHER,
        )

        entities: list[EntityRef] = []
        if alert.agent:
            if alert.agent.name:
                entities.append(EntityRef(type="host", value=alert.agent.name))
            if alert.agent.ip:
                entities.append(EntityRef(type="ip", value=alert.agent.ip))

        # SSH decoders use dstuser for the account being accessed; some rules
        # provide only srcuser (for example an invalid username).
        user = alert.data.get("dstuser") or alert.data.get("srcuser") or alert.data.get("user")
        if isinstance(user, str) and user:
            entities.append(EntityRef(type="user", value=user))

        source_ip = alert.data.get("srcip")
        if isinstance(source_ip, str) and source_ip:
            try:
                source_ip = str(ip_address(source_ip))
            except ValueError:
                source_ip = None
            if source_ip is not None:
                entities.append(EntityRef(type="ip", value=source_ip))
        else:
            source_ip = None

        outcome = None
        if "authentication_failed" in groups:
            outcome = "failure"
        elif "authentication_success" in groups:
            outcome = "success"

        attributes: dict[str, Any] = {"rule_id": str(alert.rule.id), "groups": sorted(groups)}
        sca = _sca_metadata(alert.data.get("sca"))
        if sca:
            attributes["sca"] = sca

        return SecurityEvent(
            event_id=alert.id,
            source="wazuh",
            category=category,
            event_time=alert.timestamp,
            observed_time=datetime.now(UTC),
            outcome=outcome,
            source_ip=source_ip,
            severity=min(alert.rule.level, 10),
            entities=tuple(entities),
            attributes=attributes,
        )
