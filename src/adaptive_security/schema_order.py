"""Named presentation orders for the same four linked conclusion alternatives."""

from typing import Literal

SchemaOrder = Literal["empty-first", "populated-first"]


def validate_order(order: str, *, linked_tests: bool = True) -> None:
    if order not in ("empty-first", "populated-first"):
        raise ValueError("Unknown linked schema order")
    if order != "empty-first" and not linked_tests:
        raise ValueError("Nondefault schema order requires linked tests")
