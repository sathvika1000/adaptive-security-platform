import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from adaptive_security.domain.events import SecurityEvent
from adaptive_security.domain.incidents import Incident


class SQLiteStore:
    def __init__(self, path: str) -> None:
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.transaction() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    source TEXT NOT NULL, event_id TEXT NOT NULL, body TEXT NOT NULL,
                    PRIMARY KEY (source, event_id)
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY, body TEXT NOT NULL
                );
                """
            )

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def put_event(self, conn: sqlite3.Connection, event: SecurityEvent) -> SecurityEvent:
        row = conn.execute(
            "SELECT body FROM events WHERE source = ? AND event_id = ?",
            (event.source, event.event_id),
        ).fetchone()
        if row:
            return SecurityEvent.model_validate_json(row[0])
        conn.execute(
            "INSERT INTO events (source, event_id, body) VALUES (?, ?, ?)",
            (event.source, event.event_id, event.model_dump_json()),
        )
        return event

    def events(self, conn: sqlite3.Connection) -> list[SecurityEvent]:
        rows = conn.execute("SELECT body FROM events")
        return [SecurityEvent.model_validate_json(row[0]) for row in rows]

    def replace_incidents(self, conn: sqlite3.Connection, incidents: list[Incident]) -> None:
        conn.execute("DELETE FROM incidents")
        conn.executemany(
            "INSERT INTO incidents (incident_id, body) VALUES (?, ?)",
            [(incident.incident_id, incident.model_dump_json()) for incident in incidents],
        )

    def incident(self, incident_id: str) -> Incident | None:
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT body FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
        return Incident.model_validate_json(row[0]) if row else None

    def incidents(self) -> list[Incident]:
        with self.transaction() as conn:
            rows = conn.execute("SELECT body FROM incidents ORDER BY incident_id").fetchall()
        return [Incident.model_validate_json(row[0]) for row in rows]
