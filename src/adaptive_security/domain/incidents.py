from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from adaptive_security.domain.events import EntityRef


class IncidentStatus(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class Incident(BaseModel):
    model_config = ConfigDict(frozen=True)

    incident_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    status: IncidentStatus = IncidentStatus.OPEN
    first_seen: datetime
    last_seen: datetime
    severity: int = Field(ge=0, le=10)
    event_ids: tuple[str, ...]
    entities: tuple[EntityRef, ...] = ()
