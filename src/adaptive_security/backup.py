"""Consistent, verifiable SQLite snapshots for the local platform."""

import argparse
import hashlib
import json
import os
import sqlite3
import tempfile
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

TABLES = (
    "events", "incidents", "incident_aliases", "incident_transitions",
    "auth_baselines", "event_signals",
)


def _manifest_path(destination: Path) -> Path:
    return destination.with_name(destination.name + ".manifest.json")


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _inspect(path: Path) -> dict[str, int]:
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as conn:
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("backup failed SQLite integrity check")
        return {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in TABLES}


def create_backup(source: Path, destination: Path) -> dict[str, Any]:
    source = source.resolve(strict=True)
    destination = destination.absolute()
    manifest_path = _manifest_path(destination)
    if destination.exists() or destination.is_symlink() or manifest_path.exists():
        raise FileExistsError("backup destination or manifest already exists")
    if not destination.parent.is_dir():
        raise FileNotFoundError("backup destination directory does not exist")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    manifest_temp: Path | None = None
    published = False
    try:
        with (closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True, timeout=10)) as live,
              closing(sqlite3.connect(temporary)) as copy):
            live.backup(copy)
        with temporary.open("rb") as stream:
            os.fsync(stream.fileno())
        result: dict[str, Any] = {
            "format_version": 1,
            "created_at": datetime.now(UTC).isoformat(),
            "database_file": destination.name,
            "sha256": _digest(temporary),
            "size_bytes": temporary.stat().st_size,
            "counts": _inspect(temporary),
        }
        descriptor, name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".manifest.tmp", dir=destination.parent
        )
        manifest_temp = Path(name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if manifest_path.exists() or manifest_path.is_symlink():
            raise FileExistsError("backup manifest already exists")
        os.link(temporary, destination)
        published = True
        os.link(manifest_temp, manifest_path)
        return result
    except Exception:
        if published:
            destination.unlink()
        raise
    finally:
        temporary.unlink(missing_ok=True)
        if manifest_temp is not None:
            manifest_temp.unlink(missing_ok=True)


def verify_backup(destination: Path) -> dict[str, Any]:
    with _manifest_path(destination).open(encoding="utf-8") as stream:
        manifest: dict[str, Any] = json.load(stream)
    if manifest.get("format_version") != 1 or manifest.get("database_file") != destination.name:
        raise ValueError("backup manifest does not match the database file")
    if _digest(destination) != manifest.get("sha256"):
        raise ValueError("backup SHA256 does not match the manifest")
    if destination.stat().st_size != manifest.get("size_bytes"):
        raise ValueError("backup size does not match the manifest")
    if _inspect(destination) != manifest.get("counts"):
        raise ValueError("backup table counts do not match the manifest")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Create or verify a platform SQLite backup")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("source", type=Path)
    create.add_argument("destination", type=Path)
    verify = commands.add_parser("verify")
    verify.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        result = (create_backup(args.source, args.destination) if args.command == "create"
                  else verify_backup(args.destination))
    except (OSError, sqlite3.Error, ValueError) as error:
        parser.exit(1, f"Backup error: {error}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
