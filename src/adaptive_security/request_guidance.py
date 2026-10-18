"""Opt-in instruction-only guidance for proposed evidence-request questions."""

import copy
from typing import Any, Literal

RequestGuidance = Literal["baseline", "questions"]
QUESTION_GUIDANCE = (
    " Request-goal guidance: Write each evidence_needed as a concise investigation question. "
    "Identify the record or field to inspect and say which uncertainty it would resolve. "
    "Do not merely repeat a source category, supply a desired answer, or assert an unobserved "
    "health or availability state. Reference returned event IDs when available; otherwise ask "
    "how to establish source/time collection coverage. With no explanation, still ask a useful "
    "gap-resolution question and leave tests empty."
)


def validate_guidance(mode: str, *, linked_tests: bool = True) -> None:
    if mode not in ("baseline", "questions"):
        raise ValueError("Unknown request guidance")
    if mode != "baseline" and not linked_tests:
        raise ValueError("Question guidance requires linked tests")


def apply_guidance(system_prompt: str, mode: RequestGuidance) -> str:
    validate_guidance(mode)
    return system_prompt + QUESTION_GUIDANCE if mode == "questions" else system_prompt


def normalized_guidance_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(payload)
    for message in normalized["messages"]:
        if message["role"] == "system":
            message["content"] = message["content"].removesuffix(QUESTION_GUIDANCE)
    return normalized
