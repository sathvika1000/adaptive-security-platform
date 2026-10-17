"""Compare supplied request suggestions with description-only gap catalogs."""

from adaptive_security.schema_order_pair import main as pair_main


def main() -> int:
    return pair_main(catalog_comparison=True)


if __name__ == "__main__":
    raise SystemExit(main())
