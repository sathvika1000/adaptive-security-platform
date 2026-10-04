"""Evaluate one authentication signal on labeled canonical event cases."""

import argparse
from collections.abc import Iterator
from pathlib import Path

from pydantic import ValidationError

from adaptive_security.evaluation import EvaluationCase, evaluate, evaluate_report


def load_cases(path: Path) -> Iterator[EvaluationCase]:
    seen: set[str] = set()
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                case = EvaluationCase.model_validate_json(line)
            except ValidationError:
                raise ValueError(f"invalid case at line {line_number}") from None
            if case.case_id in seen:
                raise ValueError(f"duplicate case ID at line {line_number}")
            seen.add(case.case_id)
            yield case
    if not seen:
        raise ValueError("at least one labeled case is required")


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate an authentication signal")
    parser.add_argument("cases", type=Path, help="JSONL file of labeled canonical event cases")
    parser.add_argument("--rule", choices=("auth.failures_then_success", "auth.novel_source_ip",
                                       "auth.password_spray", "auth.rc4_service_ticket_burst"),
                        default="auth.failures_then_success")
    parser.add_argument("--details", action="store_true",
                        help="include case IDs, labels, predictions, and verdicts; no event data")
    args = parser.parse_args()
    try:
        result = (evaluate_report(load_cases(args.cases), rule_id=args.rule) if args.details else
                  evaluate(load_cases(args.cases), rule_id=args.rule))
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(result.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
