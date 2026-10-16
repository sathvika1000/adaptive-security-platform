"""Exact returned-record context; collection scope still requires analyst definition."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from adaptive_security.investigation_tools import ToolResult


class ScopeModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EventReference(ScopeModel):
    source: str = Field(min_length=1, max_length=128)
    event_id: str = Field(min_length=1, max_length=256)
    event_time: str = Field(min_length=1, max_length=64)


class CollectionInterval(ScopeModel):
    status: Literal["requires_analyst_scope"] = "requires_analyst_scope"
    start: None = None
    end: None = None


class RequestScope(ScopeModel):
    event_references: list[EventReference] = Field(max_length=5)
    collection_interval: CollectionInterval
    account_scope: Literal["not_established"]
    resource_scope: Literal["not_established"]
    collector_scope: Literal["not_established"]


def scope_context(results: list[ToolResult]) -> RequestScope:
    references: dict[tuple[str, str], EventReference] = {}
    for result in results:
        for event in result.events:
            reference = EventReference(
                source=event.source,
                event_id=event.event_id,
                event_time=event.model_dump(mode="json")["event_time"],
            )
            key = (event.source, event.event_id)
            if key in references and references[key] != reference:
                raise ValueError("Conflicting returned event timestamps")
            references[key] = reference
    if len(references) > 5:
        raise ValueError("Request scope exceeds five returned event references")
    return RequestScope(
        event_references=[references[key] for key in sorted(references)],
        collection_interval=CollectionInterval(),
        account_scope="not_established",
        resource_scope="not_established",
        collector_scope="not_established",
    )


def validate_scope(scope: RequestScope, results: list[ToolResult]) -> None:
    # Compare sets so harmless reordering is allowed, but duplicates remain invalid.
    expected = scope_context(results)
    keys = [(ref.source, ref.event_id, ref.event_time) for ref in scope.event_references]
    wanted = {(ref.source, ref.event_id, ref.event_time) for ref in expected.event_references}
    if len(keys) != len(set(keys)) or set(keys) != wanted:
        raise ValueError("Request scope must match all returned event references and timestamps")
