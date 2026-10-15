"""Build provider guidance from returned observations, never expected task answers."""

import copy
import json

from adaptive_security.investigation_runner import RunStopped, canonical
from adaptive_security.investigation_tools import ToolResult

FIELDS = ("outcome", "category", "action", "source_ip", "event_time")


def grounded_schema(base: dict[str, object], context_json: str) -> dict[str, object]:
    context = json.loads(context_json)
    if not isinstance(context, dict):
        raise ValueError("Invalid controller context")
    results = [ToolResult.model_validate(value) for value in context.get("results", [])]
    allowed = context.get("allowed_tools", [])
    if not isinstance(allowed, list) or not all(isinstance(tool, str) for tool in allowed):
        raise ValueError("Invalid permitted tool list")
    # Work on a copy so later adapter requests never retain prior evidence constraints.
    schema = copy.deepcopy(base)
    definitions = schema["$defs"]
    if not isinstance(definitions, dict):
        raise ValueError("Expected decision definitions")
    tool_schema = definitions["LocalToolStep"]
    claim_schema = definitions["ObservationClaim"]
    conclusion = definitions["Conclusion"]
    choices = []
    for tool in dict.fromkeys(allowed):
        if tool not in {"get_finding_evidence", "get_related_events", "get_telemetry_coverage"}:
            raise ValueError("Unsupported permitted tool")
        returned = [result for result in results if result.tool == tool]
        offset = 0
        if returned:
            page = returned[-1].page
            if page is None or page.exhausted or page.next_offset is None:
                continue
            offset = page.next_offset
        candidate = copy.deepcopy(tool_schema)
        candidate["properties"]["tool"] = {"type": "string", "const": tool}
        candidate["properties"]["offset"] = {"type": "integer", "const": offset}
        candidate["required"] = ["kind", "tool", "limit", "offset"]
        choices.append(candidate)
    claims = []
    seen = set()
    for result in results:
        for event in result.events:
            record = event.model_dump(mode="json")
            for field in FIELDS:
                value = record.get(field)
                if (
                    not isinstance(value, str)
                    or not value
                    or len(value) > 512
                    or not 0 < len(event.source) <= 128
                    or not 0 < len(event.event_id) <= 256
                ):
                    continue
                claim = {
                    "source": event.source,
                    "event_id": event.event_id,
                    "field": field,
                    "value": value,
                }
                key = canonical(claim)
                if key in seen:
                    continue
                seen.add(key)
                candidate = copy.deepcopy(claim_schema)
                candidate["properties"] = {
                    name: {"type": "string", "const": text} for name, text in claim.items()
                }
                candidate["required"] = list(claim)
                claims.append(candidate)
    observations = conclusion["properties"]["observations"]
    if claims:
        observations["items"] = {"anyOf": claims}
    else:
        observations["maxItems"] = 0
    conclusion["required"] = ["kind", "disposition", "observations", "hypotheses"]
    if results and not claims:
        conclusion["properties"]["disposition"] = {"type": "string", "const": "inconclusive"}
    choices.append({"$ref": "#/$defs/Conclusion"})
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise ValueError("Expected decision properties")
    properties["decision"] = {"anyOf": choices}
    if len(canonical(schema)) > 12 * 1024:
        raise RunStopped("budget_exhausted", "Grounded response schema exceeds 12 KiB")
    return schema
