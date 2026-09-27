from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class DetectionSignal(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(min_length=1)
    rule_version: int = Field(ge=1)
    title: str = Field(min_length=1)
    evidence_event_ids: tuple[str, ...] = Field(min_length=1)
    priority: int = Field(ge=0, le=10)
    mode: Literal["active", "shadow"] = "active"
