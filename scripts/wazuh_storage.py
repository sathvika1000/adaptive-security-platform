"""Measure Wazuh Docker storage paths without changing container data."""

import argparse
import json
import subprocess
from datetime import UTC, datetime


def path_bytes(container: str, path: str) -> int:
    result = subprocess.run(
        ["docker", "exec", container, "du", "-sk", path],
        check=True, capture_output=True, text=True,
    )
    try:
        kib, reported_path = result.stdout.strip().split(maxsplit=1)
        if reported_path != path:
            raise ValueError("unexpected path in du output")
        return int(kib) * 1024
    except (ValueError, TypeError) as error:
        raise ValueError(f"unexpected storage output from {container}") from error


def wazuh_storage(indexer: str, manager: str) -> dict[str, str | int]:
    return {
        "collected_at": datetime.now(UTC).isoformat(),
        "indexer_data_bytes": path_bytes(indexer, "/var/lib/wazuh-indexer"),
        "manager_logs_bytes": path_bytes(manager, "/var/ossec/logs"),
        "manager_alerts_bytes": path_bytes(manager, "/var/ossec/logs/alerts"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--indexer", default="asp-wazuh-wazuh.indexer-1")
    parser.add_argument("--manager", default="asp-wazuh-wazuh.manager-1")
    args = parser.parse_args()
    try:
        report = wazuh_storage(args.indexer, args.manager)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Wazuh storage check failed: {error}\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
