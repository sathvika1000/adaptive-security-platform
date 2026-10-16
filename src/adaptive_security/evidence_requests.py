"""Bounded proposals linked to deterministic gaps; never executable actions."""

from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from adaptive_security.evidence_brief import build_brief
from adaptive_security.investigation_tools import ToolResult
from adaptive_security.request_scope import RequestScope, scope_digest, validate_scope


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
    scope_ref: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    evidence_needed: str = Field(min_length=8, max_length=256)

    @model_validator(mode="after")
    def one_scope_form(self) -> "EvidenceRequest":
        if self.scope is not None and self.scope_ref is not None:
            raise ValueError("Use either inline scope or shared scope reference")
        return self

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


def validate_requests(
    requests: list[EvidenceRequest],
    results: list[ToolResult],
    shared_scope: RequestScope | None = None,
) -> None:
    if shared_scope is not None:
        validate_scope(shared_scope, results)
    active = {gap["gap_id"]: gap["evidence_source"] for gap in request_catalog(results)}
    seen = set()
    for request in requests:
        if active.get(request.gap_id) != request.evidence_source:
            raise ValueError("Evidence request does not match an active gap and source category")
        key = (request.gap_id, request.evidence_source)
        if key in seen:
            raise ValueError("Duplicate evidence request")
        seen.add(key)
        if request.scope_ref is not None and (
            shared_scope is None or request.scope_ref != scope_digest(shared_scope)
        ):
            raise ValueError("Request scope reference does not match validated shared scope")
        if request.scope is not None:
            validate_scope(request.scope, results)


def request_payload(request: EvidenceRequest) -> dict[str, object]:
    # Preserve canonical hashes of requests saved before scope fields existed.
    absent = {name for name in ("scope", "scope_ref") if getattr(request, name) is None}
    return request.model_dump(mode="json", exclude=absent)
