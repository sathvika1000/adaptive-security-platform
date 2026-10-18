"""Compare baseline and question-based request guidance with suggestions removed."""

from adaptive_security.schema_order_pair import main as pair_main


def main() -> int:
    return pair_main(guidance_comparison=True)


if __name__ == "__main__":
    raise SystemExit(main())
