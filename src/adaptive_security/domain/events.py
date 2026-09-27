from enum import StrEnum
from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class EventCategory(StrEnum):
    AUTHENTICATION = "authentication"
    PROCESS = "process"
    NETWORK = "network"
    DNS = "dns"
    FILE = "file"
    PRIVILEGE = "privilege"
    EMAIL = "email"
    OTHER = "other"


class EntityRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: str = Field(min_length=1)
    value: str = Field(min_length=1)


class SecurityEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    category: EventCategory
    event_time: AwareDatetime
    observed_time: AwareDatetime
    action: str | None = None
    outcome: str | None = None
    severity: int = Field(default=0, ge=0, le=10)
    entities: tuple[EntityRef, ...] = ()
    attributes: dict[str, Any] = Field(default_factory=dict)
