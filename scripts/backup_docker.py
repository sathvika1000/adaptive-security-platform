"""Copy a verified platform snapshot from Docker to a private host directory."""

import argparse
import hashlib
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

TABLES = (
    "events", "incidents", "incident_aliases", "incident_transitions",
    "auth_baselines", "event_signals",
)


def verify_host_copy(database: Path) -> None:
    manifest = json.loads(Path(f"{database}.manifest.json").read_text(encoding="utf-8"))
    if manifest.get("format_version") != 1 or manifest.get("database_file") != database.name:
        raise ValueError("backup manifest does not match the database")
    digest = hashlib.sha256()
    with database.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != manifest.get("sha256"):
        raise ValueError("copied backup checksum does not match")
    if database.stat().st_size != manifest.get("size_bytes"):
        raise ValueError("copied backup size does not match")
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as copy:
        if copy.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("copied backup failed SQLite integrity check")
        counts = {table: copy.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                  for table in TABLES}
    if counts != manifest.get("counts"):
        raise ValueError("copied backup table counts do not match")


def backup_docker(container: str, output_dir: Path) -> Path:
    os.umask(0o077)
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = f"security-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{secrets.token_hex(4)}.db"
    remote = f"/data/{name}"
    final = output_dir / name.removesuffix(".db")
    if final.exists():
        raise FileExistsError(final)

    subprocess.run(["docker", "exec", container, "python", "-m", "adaptive_security.backup",
                    "create", "/data/security.db", remote], check=True)
    subprocess.run(["docker", "exec", container, "python", "-m", "adaptive_security.backup",
                    "verify", remote], check=True)

    staging = Path(tempfile.mkdtemp(prefix=f".{name}.", dir=output_dir))
    try:
        for filename in (name, f"{name}.manifest.json"):
            subprocess.run(["docker", "cp", f"{container}:/data/{filename}",
                            str(staging / filename)], check=True)
            (staging / filename).chmod(0o600)
        verify_host_copy(staging / name)
        # The name has a random suffix; never replace an existing destination.
        if final.exists():
            raise FileExistsError(final)
        staging.rename(final)
        return final / name
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", default="adaptive-security-platform-platform-1")
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    args = parser.parse_args()
    try:
        result = backup_docker(args.container, args.output_dir)
    except (OSError, sqlite3.Error, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Backup failed: {error}\n")
    print(f"Verified host backup: {result}")
    print(f"Manifest: {result}.manifest.json")


if __name__ == "__main__":
    main()
