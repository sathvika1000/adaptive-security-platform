"""Export and reconcile older unlinked events from a verified SQLite snapshot."""

import argparse
import hashlib
import json
import os
import sqlite3
import tempfile
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from adaptive_security.backup import verify_backup
from adaptive_security.domain.events import SecurityEvent
from adaptive_security.store import SQLiteStore

CLASSIFICATION = "unlinked_other_v1"


def _manifest_path(archive: Path) -> Path:
    return archive.with_name(archive.name + ".manifest.json")


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _before(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("cutoff must include a timezone")
    return value.astimezone(UTC).isoformat()


def _candidates(snapshot: Path, cutoff: str) -> Iterator[str]:
    with closing(sqlite3.connect(snapshot.resolve().as_uri() + "?mode=ro", uri=True)) as conn:
        cursor = conn.execute(
            """SELECT e.body FROM events AS e
               WHERE e.event_time < ? AND e.incident_id IS NULL
                 AND e.correlation_key IS NULL
                 AND NOT EXISTS (
                   SELECT 1 FROM event_signals AS s
                   WHERE s.source = e.source AND s.event_id = e.event_id
                 )
               ORDER BY e.event_time, e.source, e.event_id""",
            (cutoff,),
        )
        for (body,) in cursor:
            yield body


def create_archive(snapshot: Path, archive: Path, before: datetime) -> dict[str, Any]:
    source_manifest = verify_backup(snapshot)
    cutoff = _before(before)
    archive = archive.absolute()
    manifest_path = _manifest_path(archive)
    if (archive.exists() or archive.is_symlink() or
            manifest_path.exists() or manifest_path.is_symlink()):
        raise FileExistsError("archive destination or manifest already exists")
    if not archive.parent.is_dir():
        raise FileNotFoundError("archive destination directory does not exist")

    descriptor, name = tempfile.mkstemp(prefix=f".{archive.name}.", dir=archive.parent)
    temporary = Path(name)
    manifest_temp: Path | None = None
    published = False
    try:
        count = 0
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            for body in _candidates(snapshot, cutoff):
                stream.write(body + "\n")
                count += 1
            stream.flush()
            os.fsync(stream.fileno())
        result: dict[str, Any] = {
            "format_version": 1,
            "classification": CLASSIFICATION,
            "archive_file": archive.name,
            "before": cutoff,
            "count": count,
            "sha256": _digest(temporary),
            "source_backup_sha256": source_manifest["sha256"],
        }
        descriptor, name = tempfile.mkstemp(
            prefix=f".{archive.name}.", suffix=".manifest.tmp", dir=archive.parent
        )
        manifest_temp = Path(name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if manifest_path.exists() or manifest_path.is_symlink():
            raise FileExistsError("archive manifest already exists")
        os.link(temporary, archive)
        published = True
        os.link(manifest_temp, manifest_path)
        return result
    except Exception:
        if published:
            archive.unlink()
        raise
    finally:
        temporary.unlink(missing_ok=True)
        if manifest_temp is not None:
            manifest_temp.unlink(missing_ok=True)


def verify_archive(snapshot: Path, archive: Path) -> dict[str, Any]:
    source_manifest = verify_backup(snapshot)
    with _manifest_path(archive).open(encoding="utf-8") as stream:
        manifest: dict[str, Any] = json.load(stream)
    if (manifest.get("format_version") != 1 or
            manifest.get("classification") != CLASSIFICATION or
            manifest.get("archive_file") != archive.name or
            manifest.get("source_backup_sha256") != source_manifest["sha256"]):
        raise ValueError("archive manifest does not match the verified source backup")
    cutoff = _before(datetime.fromisoformat(manifest["before"]))
    if cutoff != manifest["before"] or _digest(archive) != manifest.get("sha256"):
        raise ValueError("archive cutoff or SHA256 does not match the manifest")
    count = 0
    with archive.open(encoding="utf-8") as stream:
        for body in _candidates(snapshot, cutoff):
            if stream.readline() != body + "\n":
                raise ValueError("archive records do not match the verified source backup")
            count += 1
        if stream.readline() or count != manifest.get("count"):
            raise ValueError("archive count does not match the verified source backup")
    return manifest


def _standalone_manifest(archive: Path) -> tuple[dict[str, Any], datetime]:
    with _manifest_path(archive).open(encoding="utf-8") as stream:
        manifest: dict[str, Any] = json.load(stream)
    if (manifest.get("format_version") != 1 or
            manifest.get("classification") != CLASSIFICATION or
            manifest.get("archive_file") != archive.name or
            not isinstance(manifest.get("count"), int) or
            isinstance(manifest.get("count"), bool) or manifest["count"] < 0 or
            not isinstance(manifest.get("source_backup_sha256"), str) or
            len(manifest["source_backup_sha256"]) != 64):
        raise ValueError("unsupported archive manifest")
    cutoff = datetime.fromisoformat(manifest["before"])
    if _before(cutoff) != manifest["before"]:
        raise ValueError("archive cutoff is not canonical UTC")
    if _digest(archive) != manifest.get("sha256"):
        raise ValueError("archive SHA256 does not match the manifest")
    return manifest, cutoff


def restore_archive(archive: Path, destination: Path) -> dict[str, Any]:
    """Restore verified archive bytes to a new, isolated SQLite database."""
    archive = archive.absolute()
    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("restore destination already exists")
    if not destination.parent.is_dir():
        raise FileNotFoundError("restore destination directory does not exist")
    manifest, cutoff = _standalone_manifest(archive)
    descriptor, name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    temporary = Path(name)
    os.close(descriptor)
    try:
        store = SQLiteStore(str(temporary))
        count = 0
        previous: tuple[str, str, str] | None = None
        with store.transaction() as conn, archive.open("r", encoding="utf-8") as stream:
            for line in stream:
                if not line.endswith("\n"):
                    raise ValueError("archive record is not newline terminated")
                body = line[:-1]
                event = SecurityEvent.model_validate_json(body)
                event_time = event.event_time.astimezone(UTC)
                key = (event_time.isoformat(), event.source, event.event_id)
                if event_time >= cutoff or (previous is not None and key <= previous):
                    raise ValueError("archive records are out of order or beyond the cutoff")
                conn.execute(
                    """INSERT INTO events (source, event_id, body, event_time)
                       VALUES (?, ?, ?, ?)""",
                    (event.source, event.event_id, body, key[0]),
                )
                previous = key
                count += 1
            if count != manifest["count"]:
                raise ValueError("archive record count does not match the manifest")
        with closing(sqlite3.connect(temporary)) as conn:
            if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("restored database integrity check failed")
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("restore destination already exists")
        os.link(temporary, destination)
        return {"destination": str(destination), "restored_events": count,
                "archive_sha256": manifest["sha256"]}
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("snapshot", type=Path)
    create.add_argument("archive", type=Path)
    create.add_argument("--before", required=True, type=datetime.fromisoformat)
    verify = commands.add_parser("verify")
    verify.add_argument("snapshot", type=Path)
    verify.add_argument("archive", type=Path)
    restore = commands.add_parser("restore")
    restore.add_argument("archive", type=Path)
    restore.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "create":
            result = create_archive(args.snapshot, args.archive, args.before)
        elif args.command == "verify":
            result = verify_archive(args.snapshot, args.archive)
        else:
            result = restore_archive(args.archive, args.destination)
    except (OSError, sqlite3.Error, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Archive error: {error}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
