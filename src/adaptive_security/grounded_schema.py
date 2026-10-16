"""Build provider guidance from returned observations, never expected task answers."""

import copy
import json

from adaptive_security.evidence_requests import request_catalog
from adaptive_security.investigation_runner import RunStopped, canonical
from adaptive_security.investigation_tools import ToolResult
from adaptive_security.request_scope import scope_context

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
    conclusion["required"] = [
        "kind",
        "disposition",
        "observations",
        "hypotheses",
        "alternative_explanations",
        "collection_limits",
        "next_checks",
    ]
    conclusion["properties"]["collection_limits"]["minItems"] = 1
    conclusion["properties"]["next_checks"]["minItems"] = 1
    if context.get("structured_requests") is True:
        request_schema = definitions["EvidenceRequest"]
        if context.get("scoped_requests") is True:
            request_schema["properties"]["scope"] = {"$ref": "#/$defs/RequestScope"}
            request_schema["required"].append("scope")
            definitions["RequestScope"] = {"const": scope_context(results).model_dump(mode="json")}
        else:
            request_schema["properties"].pop("scope", None)
        requests = []
        for gap in request_catalog(results):
            candidate = copy.deepcopy(request_schema)
            for name in ("gap_id", "evidence_source"):
                candidate["properties"][name] = {"type": "string", "const": gap[name]}
            requests.append(candidate)
        conclusion["properties"]["evidence_requests"] = {
            "type": "array",
            "minItems": 1,
            "maxItems": 2,
            "items": {"anyOf": requests},
        }
        conclusion["required"].append("evidence_requests")
        conclusion["properties"]["next_checks"].update(minItems=0, maxItems=0)
    else:
        conclusion["properties"].pop("evidence_requests", None)
        definitions.pop("EvidenceRequest", None)
    if context.get("scoped_requests") is not True:
        for name in ("RequestScope", "EventReference", "CollectionInterval"):
            definitions.pop(name, None)
    if claims:
        conclusion["properties"]["alternative_explanations"]["minItems"] = 1
    if results and not claims:
        conclusion["properties"]["disposition"] = {"type": "string", "const": "inconclusive"}
    required = context.get("required_tools_remaining", [])
    if not isinstance(required, list) or not all(
        isinstance(tool, str) and tool in allowed for tool in required
    ):
        raise ValueError("Invalid required-read metadata")
    if not required:
        choices.append({"$ref": "#/$defs/Conclusion"})
    if not choices:
        raise RunStopped("blocked", "No available decision satisfies required reads")
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        raise ValueError("Expected decision properties")
    properties["decision"] = {"anyOf": choices}
    if len(canonical(schema)) > 12 * 1024:
        raise RunStopped("budget_exhausted", "Grounded response schema exceeds 12 KiB")
    return schema
