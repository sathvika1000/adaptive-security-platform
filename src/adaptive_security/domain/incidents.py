from enum import StrEnum
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from adaptive_security.domain.detections import DetectionSignal
from adaptive_security.domain.events import EntityRef


class IncidentStatus(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class Incident(BaseModel):
    model_config = ConfigDict(frozen=True)

    incident_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    status: IncidentStatus = IncidentStatus.OPEN
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    severity: int = Field(ge=0, le=10)
    event_ids: tuple[str, ...]
    entities: tuple[EntityRef, ...] = ()
    signals: tuple[DetectionSignal, ...] = ()


class IncidentTransition(BaseModel):
    model_config = ConfigDict(frozen=True)

    transition_id: int = Field(ge=1)
    incident_id: str = Field(min_length=1)
    action: Literal["closed", "reopened", "merged"]
    occurred_at: AwareDatetime
    request_id: str | None = None
    actor: str | None = None
    event_source: str | None = None
    event_id: str | None = None
    merged_into: str | None = None
