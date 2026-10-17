"""Bounded presentation-only removal of catalog request suggestions."""

import copy
import json
from typing import Any, Literal

CatalogPresentation = Literal["suggestions", "descriptions-only"]


def validate_catalog(mode: str, *, linked_tests: bool = True) -> None:
    if mode not in ("suggestions", "descriptions-only"):
        raise ValueError("Unknown catalog presentation")
    if mode != "suggestions" and not linked_tests:
        raise ValueError("Catalog comparison requires linked tests")


def catalog_context(context_json: str, mode: CatalogPresentation) -> str:
    validate_catalog(mode)
    if mode == "suggestions":
        return context_json
    context = json.loads(context_json)
    if not isinstance(context, dict) or context.get("linked_tests") is not True:
        raise ValueError("Catalog comparison requires linked context")
    gaps = context.get("evidence_gaps")
    if not isinstance(gaps, list) or not all(isinstance(gap, dict) for gap in gaps):
        raise ValueError("Invalid context gap catalog")
    for gap in gaps:
        gap.pop("evidence_needed", None)
    return json.dumps(context, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def normalized_catalog_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(payload)
    for message in normalized["messages"]:
        if message["role"] == "user":
            message["content"] = catalog_context(message["content"], "descriptions-only")
    return normalized
