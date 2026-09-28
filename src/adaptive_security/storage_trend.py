"""Read-only growth report from verified platform database backups."""

import argparse
import json
import sqlite3
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path
from typing import Any

from adaptive_security.backup import verify_backup


def storage_trend(inputs: list[Path]) -> dict[str, Any]:
    paths: dict[Path, None] = {}
    for item in inputs:
        if item.is_dir():
            for path in item.rglob("security-*.db"):
                paths[path.resolve()] = None
        else:
            paths[item.resolve()] = None
    if len(paths) < 2:
        raise ValueError("at least two platform backup databases are required")

    snapshots = []
    for path in paths:
        manifest = verify_backup(path)
        created = datetime.fromisoformat(manifest["created_at"])
        if created.tzinfo is None or created.utcoffset() is None:
            raise ValueError(f"backup timestamp has no timezone: {path}")
        snapshots.append({
            "database": str(path),
            "created_at": created.astimezone(UTC).isoformat(),
            "events": manifest["counts"]["events"],
            "incidents": manifest["counts"]["incidents"],
            "size_bytes": manifest["size_bytes"],
        })
    snapshots.sort(key=lambda record: (record["created_at"], record["database"]))
    intervals = []
    for earlier, later in pairwise(snapshots):
        elapsed = (datetime.fromisoformat(later["created_at"]) -
                   datetime.fromisoformat(earlier["created_at"])).total_seconds()
        intervals.append({
            "from": earlier["database"],
            "to": later["database"],
            "elapsed_hours": round(elapsed / 3600, 2),
            "events_delta": later["events"] - earlier["events"],
            "incidents_delta": later["incidents"] - earlier["incidents"],
            "size_bytes_delta": later["size_bytes"] - earlier["size_bytes"],
        })
    return {"snapshots": snapshots, "intervals": intervals}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backups", nargs="+", type=Path,
                        help="backup databases or directories of timestamped backups")
    args = parser.parse_args()
    try:
        result = storage_trend(args.backups)
    except (OSError, sqlite3.Error, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Storage trend error: {error}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
