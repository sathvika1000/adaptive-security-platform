"""Deterministic, bounded descriptions of returned evidence and known schema limits."""

from collections import Counter

from adaptive_security.investigation_tools import EvidenceRecord, ToolName, ToolResult

FIELDS = ("outcome", "category", "action", "source_ip", "event_time")
MAX_FACTS = 40


def build_brief(results: list[ToolResult]) -> dict[str, object]:
    records: dict[tuple[str, str], EvidenceRecord] = {}
    tools: dict[ToolName, ToolResult] = {}
    for result in results:
        tools[result.tool] = result
        for event in result.events:
            key = (event.source, event.event_id)
            if key in records and records[key] != event:
                raise ValueError("Conflicting accepted event versions")
            records[key] = event
    event_reads = [result for result in results if result.page is not None]
    state = (
        "returned_records"
        if records
        else "empty_event_pages"
        if event_reads
        else "coverage_only"
        if results
        else "not_queried"
    )
    facts: list[dict[str, str]] = []
    total_facts = 0
    for event in records.values():
        values = event.model_dump(mode="json")
        for field in FIELDS:
            value = values.get(field)
            if not isinstance(value, str) or not value:
                continue
            total_facts += 1
            if (
                len(facts) < MAX_FACTS
                and len(value) <= 512
                and len(event.source) <= 128
                and len(event.event_id) <= 256
            ):
                facts.append(
                    {
                        "source": event.source,
                        "event_id": event.event_id,
                        "field": field,
                        "value": value,
                    }
                )
    gaps = [
        {
            "gap_id": "collection_completeness",
            "basis": "Returned pages do not certify source health or complete collection.",
            "evidence_source": "collector_health",
            "evidence_needed": "Collector health and source/time coverage.",
        }
    ]
    if not event_reads:
        gaps.append(
            {
                "gap_id": "event_evidence_unread",
                "basis": "No accepted event page is present; this is not an empty-source finding.",
                "evidence_source": "configured_event_evidence",
                "evidence_needed": "A validated read of the permitted event evidence.",
            }
        )
    missing_identity = sum(
        not any(
            entity.type.casefold() in {"user", "account", "principal"} for entity in event.entities
        )
        for event in records.values()
    )
    if missing_identity:
        gaps.append(
            {
                "gap_id": "identity_context",
                "basis": "Some returned records lack user, account or principal entity references.",
                "evidence_source": "identity_records",
                "evidence_needed": "Account/session identity mapped to the returned event IDs.",
            }
        )
    gaps.append(
        {
            "gap_id": "authorization_context",
            "basis": "The tool schema supplies no authorization decision or access policy.",
            "evidence_source": "authorization_records",
            "evidence_needed": "Access policy and authorization decisions.",
        }
    )
    outcomes = Counter(event.outcome for event in records.values() if event.outcome is not None)
    if outcomes.get("failure", 0):
        gaps.append(
            {
                "gap_id": "failure_explanation",
                "basis": "An outcome alone does not supply a structured failure cause.",
                "evidence_source": "authentication_details",
                "evidence_needed": "Failure detail matched to returned event IDs.",
            }
        )
    if len(records) > 1:
        gaps.append(
            {
                "gap_id": "event_relationship",
                "basis": "Multiple records do not establish shared identity or causal sequence.",
                "evidence_source": "session_correlation",
                "evidence_needed": "Account/session correlation and event ordering.",
            }
        )
    return {
        "schema_version": 1,
        "evidence_state": state,
        "accepted_responses": len(results),
        "unique_returned_records": len(records),
        "outcome_counts": dict(outcomes),
        "records_without_identity_reference": missing_identity,
        "observed_assertions": facts,
        "assertions_truncated": total_facts > len(facts),
        "latest_reads": [
            {
                "tool": tool,
                "offset": result.page.offset if result.page else None,
                "exhausted": result.page.exhausted if result.page else None,
            }
            for tool, result in sorted(tools.items())
        ],
        "gap_catalog": gaps,
        "limitations": [
            "Observed assertions are returned untrusted values, not authenticated ground truth.",
            "Gaps describe returned fields and tool-schema boundaries, not an entire environment.",
            "Entity references do not establish identity ownership or authorization.",
            "Evidence sources are proposed analyst checks; no connector or action is invoked.",
            "The fact list is bounded; counts include all accepted records.",
        ],
    }
