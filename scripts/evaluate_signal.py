"""Evaluate the authentication sequence signal on labeled canonical event cases."""

import argparse
from pathlib import Path

from pydantic import ValidationError

from adaptive_security.evaluation import EvaluationCase, evaluate


def load_cases(path: Path) -> list[EvaluationCase]:
    cases: list[EvaluationCase] = []
    seen: set[str] = set()
    with path.open() as source:
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
            cases.append(case)
    if not cases:
        raise ValueError("at least one labeled case is required")
    return cases


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the authentication sequence signal")
    parser.add_argument("cases", type=Path, help="JSONL file of labeled canonical event cases")
    args = parser.parse_args()
    try:
        cases = load_cases(args.cases)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(evaluate(cases).model_dump_json(indent=2))


if __name__ == "__main__":
    main()

