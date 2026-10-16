"""Build provider guidance from returned observations, never expected task answers."""

import copy
import json
from typing import Any

from adaptive_security.evidence_requests import request_catalog
from adaptive_security.investigation_runner import RunStopped, canonical
from adaptive_security.investigation_tools import ToolResult
from adaptive_security.request_scope import scope_context, scope_digest
from adaptive_security.schema_order import SchemaOrder, validate_order

FIELDS = ("outcome", "category", "action", "source_ip", "event_time")


def _linked_conclusions(definitions: dict[str, Any], conclusion: dict[str, Any]) -> None:
    """Offer four coherent shapes without conditional JSON Schema keywords.

    Factor repeated fields to keep exact evidence and gap choices within the
    existing provider-schema budget. Controller coverage checks remain separate.
    """
    observations = conclusion["properties"]["observations"]
    if observations.get("maxItems") == 0:
        observations["items"] = {"type": "object"}
    else:
        # Whole-object constants preserve exact tuples with less repetition.
        observations["items"]["anyOf"] = [
            {"const": {name: field["const"] for name, field in claim["properties"].items()}}
            for claim in observations["items"]["anyOf"]
        ]
    common = {}
    for name, field in conclusion["properties"].items():
        if name not in {"hypotheses", "alternative_explanations", "evidence_requests"}:
            key = f"L{len(definitions)}"
            definitions[key] = field
            common[name] = {"$ref": f"#/$defs/{key}"}
    requests = conclusion["properties"]["evidence_requests"]
    # All gap candidates share these fields; only gap/source constants differ.
    request_fields = {}
    for name, field in requests["items"]["anyOf"][0]["properties"].items():
        if name not in {"gap_id", "evidence_source", "tests"}:
            key = f"L{len(definitions)}"
            definitions[key] = field
            request_fields[name] = {"$ref": f"#/$defs/{key}"}
    definitions["Ltext"] = {
        "type": "array", "minItems": 1, "maxItems": 1,
        "items": {"type": "string", "minLength": 1, "maxLength": 160},
    }
    definitions["Lempty"] = {"type": "array", "maxItems": 0, "items": {"type": "string"}}
    gap_fields = []
    for index, request in enumerate(requests["items"]["anyOf"]):
        fields = {}
        for prefix, name in (("g", "gap_id"), ("s", "evidence_source")):
            key = f"L{prefix}{index}"
            definitions[key] = request["properties"][name]
            fields[name] = {"$ref": f"#/$defs/{key}"}
        gap_fields.append(fields)
    branches = []
    for mask in range(4):
        branch: dict[str, Any] = {
            "type": "object",
            "additionalProperties": False,
            "required": list(conclusion["required"]),
            "properties": copy.deepcopy(common),
        }
        refs = []
        for bit, name in enumerate(("hypotheses", "alternative_explanations")):
            present = bool(mask & (1 << bit))
            branch["properties"][name] = {
                "$ref": "#/$defs/Ltext" if present else "#/$defs/Lempty",
            }
            if present:
                refs.append(f"{name}:0")
        tests: dict[str, Any] = {"type": "array", "maxItems": len(refs)}
        if refs:
            tests["items"] = {"type": "string", "enum": refs}
        else:
            tests["items"] = {"type": "string"}
        definitions[f"Lt{mask}"] = tests
        candidates = []
        for fields in gap_fields:
            properties: dict[str, Any] = dict(request_fields, **fields)
            properties["tests"] = {"$ref": f"#/$defs/Lt{mask}"}
            candidates.append({
                "type": "object", "additionalProperties": False,
                "required": list(requests["items"]["anyOf"][0]["required"]),
                "properties": properties,
            })
        branch["properties"]["evidence_requests"] = {
            "type": "array", "minItems": 1, "maxItems": 2,
            "items": {"anyOf": candidates},
        }
        branches.append(branch)
    definitions["Conclusion"] = {"anyOf": branches}
    # The linked branches replace this unconstrained request definition entirely.
    definitions.pop("EvidenceRequest", None)
    definitions.pop("ObservationClaim", None)


def grounded_schema(
    base: dict[str, object], context_json: str, *,
    linked_schema_order: SchemaOrder = "empty-first",
) -> dict[str, object]:
    context = json.loads(context_json)
    if not isinstance(context, dict):
        raise ValueError("Invalid controller context")
    validate_order(linked_schema_order, linked_tests=context.get("linked_tests") is True)
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
        if context.get("linked_tests") is True:
            request_schema["properties"]["tests"] = {
                "type": "array",
                "maxItems": 2,
                "uniqueItems": True,
                "items": {"type": "string", "enum": ["hypotheses:0", "alternative_explanations:0"]},
            }
            request_schema["required"].append("tests")
            request_schema["properties"]["evidence_needed"]["maxLength"] = 160
            for name in ("hypotheses", "alternative_explanations"):
                conclusion["properties"][name]["maxItems"] = 1
                conclusion["properties"][name]["items"] = {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 160,
                }
        else:
            request_schema["properties"].pop("tests", None)
        if context.get("shared_request_scope") is True:
            request_schema["properties"].pop("scope", None)
            request_schema["properties"]["scope_ref"] = {
                "type": "string",
                "const": scope_digest(scope_context(results)),
            }
            request_schema["required"].append("scope_ref")
        elif context.get("scoped_requests") is True:
            request_schema["properties"]["scope"] = {"$ref": "#/$defs/RequestScope"}
            request_schema["required"].append("scope")
            definitions["RequestScope"] = {"const": scope_context(results).model_dump(mode="json")}
        else:
            request_schema["properties"].pop("scope", None)
        if context.get("shared_request_scope") is not True:
            request_schema["properties"].pop("scope_ref", None)
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
    if context.get("scoped_requests") is not True or context.get("shared_request_scope") is True:
        for name in ("RequestScope", "EventReference", "CollectionInterval"):
            definitions.pop(name, None)
    if claims and context.get("linked_tests") is not True:
        conclusion["properties"]["alternative_explanations"]["minItems"] = 1
    if results and not claims:
        conclusion["properties"]["disposition"] = {"type": "string", "const": "inconclusive"}
    if context.get("linked_tests") is True and context.get("structured_requests") is True:
        _linked_conclusions(definitions, conclusion)
        if linked_schema_order == "populated-first":
            definitions["Conclusion"]["anyOf"].reverse()
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
    if context.get("linked_tests") is True and not any(
        "properties" in choice for choice in choices
    ):
        definitions.pop("LocalToolStep", None)
    if len(canonical(schema)) > 12 * 1024:
        raise RunStopped("budget_exhausted", "Grounded response schema exceeds 12 KiB")
    return schema
