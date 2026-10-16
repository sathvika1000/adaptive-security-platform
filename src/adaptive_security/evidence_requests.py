"""Bounded proposals linked to deterministic gaps; never executable actions."""

from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator

from adaptive_security.evidence_brief import build_brief
from adaptive_security.investigation_tools import ToolResult
from adaptive_security.request_scope import RequestScope, validate_scope


class EvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    gap_id: Literal[
        "collection_completeness",
        "event_evidence_unread",
        "identity_context",
        "authorization_context",
        "failure_explanation",
        "event_relationship",
    ]
    evidence_source: Literal[
        "collector_health",
        "configured_event_evidence",
        "identity_records",
        "authorization_records",
        "authentication_details",
        "session_correlation",
    ]
    scope: RequestScope | None = None
    evidence_needed: str = Field(min_length=8, max_length=256)

    @field_validator("evidence_needed")
    @classmethod
    def substantive_text(cls, value: str) -> str:
        if len(value.strip()) < 8 or value.strip().lower() in {
            "not available",
            "uncertain",
            "unknown",
        }:
            raise ValueError("Evidence goal must be nonblank and specific")
        return value


def request_catalog(results: list[ToolResult]) -> list[dict[str, str]]:
    return cast(list[dict[str, str]], build_brief(results)["gap_catalog"])


def validate_requests(requests: list[EvidenceRequest], results: list[ToolResult]) -> None:
    active = {gap["gap_id"]: gap["evidence_source"] for gap in request_catalog(results)}
    seen = set()
    for request in requests:
        if active.get(request.gap_id) != request.evidence_source:
            raise ValueError("Evidence request does not match an active gap and source category")
        key = (request.gap_id, request.evidence_source)
        if key in seen:
            raise ValueError("Duplicate evidence request")
        seen.add(key)
        if request.scope is not None:
            validate_scope(request.scope, results)


def request_payload(request: EvidenceRequest) -> dict[str, object]:
    # Preserve canonical hashes of requests saved before scope fields existed.
    return request.model_dump(mode="json", exclude={"scope"} if request.scope is None else set())
