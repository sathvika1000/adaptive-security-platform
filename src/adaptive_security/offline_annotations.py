"""Analyst assessments, distinct from detector verdicts and capture labels."""

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

Disposition = Literal[
    "needs_review", "suspicious", "benign_activity", "confirmed_malicious", "inconclusive"
]


class ReviewEdit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    disposition: Disposition
    note: str = Field(min_length=1, max_length=2000)
    review_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_revision: int = Field(ge=0, strict=True)

    @field_validator("note")
    @classmethod
    def nonblank_note(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Review note must explain the assessment")
        return value.strip()


class ReviewEntry(BaseModel):
    revision: int
    disposition: Disposition
    note: str
    actor: str | None
    occurred_at: AwareDatetime
    request_id: str


class ReviewPage(BaseModel):
    review_key: str
    revision: int
    entries: list[ReviewEntry]


class ReviewConflict(Exception):
    """The client edited an older review revision."""
