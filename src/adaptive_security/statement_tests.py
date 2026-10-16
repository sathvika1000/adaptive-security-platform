"""Structural links from proposed evidence requests to unverified explanations."""


def statement_inventory(hypotheses: list[str], alternatives: list[str]) -> dict[str, str]:
    return {
        f"{section}:{index}": text
        for section, values in (
            ("hypotheses", hypotheses),
            ("alternative_explanations", alternatives),
        )
        for index, text in enumerate(values)
    }


def validate_statement_tests(
    hypotheses: list[str],
    alternatives: list[str],
    request_tests: list[list[str]],
    *,
    required: bool = False,
    evidence_goals: list[str] | None = None,
) -> None:
    inventory = statement_inventory(hypotheses, alternatives)
    if required:
        if len(hypotheses) > 1 or len(alternatives) > 1:
            raise ValueError("Linked tests allow one hypothesis and one alternative")
        if any(not text.strip() or len(text) > 160 for text in inventory.values()):
            raise ValueError("Linked statements must be nonblank and at most 160 characters")
        if evidence_goals and any(len(text) > 160 for text in evidence_goals):
            raise ValueError("Linked evidence goals exceed 160 characters")
    linked = set()
    for references in request_tests:
        if len(references) != len(set(references)):
            raise ValueError("Duplicate statement test reference")
        if any(reference not in inventory for reference in references):
            raise ValueError("Statement test reference does not identify a supplied explanation")
        linked.update(references)
    if required and set(inventory) != linked:
        raise ValueError("Every supplied explanation needs a declared testing request")
