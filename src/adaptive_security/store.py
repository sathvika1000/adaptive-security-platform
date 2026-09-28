import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from adaptive_security.correlation.policy import WINDOW, identity
from adaptive_security.domain.detections import DetectionSignal
from adaptive_security.domain.events import SecurityEvent
from adaptive_security.domain.incidents import Incident, IncidentStatus, IncidentTransition

NEIGHBOR_PAGE_SIZE = 128


class RetentionPreview(BaseModel):
    before: datetime
    total_events: int
    before_cutoff: int
    incident_evidence: int
    signal_evidence: int
    unlinked_correlatable: int
    unlinked_other: int


def correlation_key(event: SecurityEvent) -> str | None:
    key = identity(event)
    return json.dumps(key, separators=(",", ":")) if key else None


class SQLiteStore:
    def __init__(self, path: str) -> None:
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.transaction() as conn:
            self._prepare(conn)

    def _prepare(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS events (
                source TEXT NOT NULL, event_id TEXT NOT NULL, body TEXT NOT NULL,
                event_time TEXT, correlation_key TEXT, incident_id TEXT,
                PRIMARY KEY (source, event_id)
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY, body TEXT NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS incident_aliases (
                retired_id TEXT PRIMARY KEY, current_id TEXT NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS incident_transitions (
                transition_id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL, action TEXT NOT NULL,
                occurred_at TEXT NOT NULL, request_id TEXT,
                event_source TEXT, event_id TEXT, merged_into TEXT
            )"""
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS transitions_by_incident "
            "ON incident_transitions(incident_id, transition_id)"
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS auth_baselines (
                correlation_key TEXT PRIMARY KEY, success_count INTEGER NOT NULL,
                source_ips TEXT NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS event_signals (
                source TEXT NOT NULL, event_id TEXT NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY (source, event_id)
            )"""
        )
        columns = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
        for name in ("event_time", "correlation_key", "incident_id"):
            if name not in columns:
                conn.execute(f"ALTER TABLE events ADD COLUMN {name} TEXT")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS events_by_identity "
            "ON events(correlation_key, event_time, source, event_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS events_by_incident "
            "ON events(incident_id, event_time, source, event_id)"
        )
        for source, event_id, body in conn.execute(
            "SELECT source, event_id, body FROM events WHERE event_time IS NULL"
        ):
            event = SecurityEvent.model_validate_json(body)
            conn.execute(
                """UPDATE events SET event_time = ?, correlation_key = ?
                   WHERE source = ? AND event_id = ?""",
                (event.event_time.astimezone(UTC).isoformat(), correlation_key(event),
                 source, event_id),
            )
        if "incident_id" not in columns:
            for incident in self.stored_incidents(conn):
                for event_id in incident.event_ids:
                    matches = conn.execute(
                        "SELECT source FROM events WHERE event_id = ?", (event_id,)
                    ).fetchall()
                    if len(matches) != 1:
                        raise ValueError(f"cannot migrate ambiguous incident event {event_id!r}")
                    conn.execute(
                        "UPDATE events SET incident_id = ? WHERE source = ? AND event_id = ?",
                        (incident.incident_id, matches[0][0], event_id),
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

    def ready(self) -> bool:
        try:
            conn = sqlite3.connect(self.path, timeout=1)
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("SELECT 1 FROM incidents LIMIT 1")
                conn.rollback()
            finally:
                conn.close()
        except sqlite3.Error:
            return False
        return True

    def put_event(
        self, conn: sqlite3.Connection, event: SecurityEvent
    ) -> tuple[SecurityEvent, bool, str | None]:
        row = conn.execute(
            "SELECT body, incident_id FROM events WHERE source = ? AND event_id = ?",
            (event.source, event.event_id),
        ).fetchone()
        if row:
            return SecurityEvent.model_validate_json(row[0]), False, row[1]
        conn.execute(
            """INSERT INTO events
               (source, event_id, body, event_time, correlation_key)
               VALUES (?, ?, ?, ?, ?)""",
            (event.source, event.event_id, event.model_dump_json(),
             event.event_time.astimezone(UTC).isoformat(), correlation_key(event)),
        )
        return event, True, None

    def connected_events(
        self, conn: sqlite3.Connection, event: SecurityEvent
    ) -> list[tuple[SecurityEvent, str | None]]:
        encoded = correlation_key(event)
        if encoded is None:
            return []

        def neighbors(before: bool) -> list[tuple[SecurityEvent, str | None]]:
            comparison = "<" if before else ">"
            ordering = "DESC" if before else "ASC"
            query = (
                "SELECT event_time, body, incident_id FROM events "
                f"WHERE correlation_key = ? AND (event_time, source, event_id) {comparison} "
                f"(?, ?, ?) ORDER BY event_time {ordering}, source {ordering}, "
                f"event_id {ordering} LIMIT ?"
            )
            found: list[tuple[SecurityEvent, str | None]] = []
            cursor = event
            while True:
                rows = conn.execute(
                    query,
                    (encoded, cursor.event_time.astimezone(UTC).isoformat(),
                     cursor.source, cursor.event_id, NEIGHBOR_PAGE_SIZE),
                ).fetchall()
                for row in rows:
                    neighbor_time = datetime.fromisoformat(row[0])
                    gap = (
                        cursor.event_time - neighbor_time if before
                        else neighbor_time - cursor.event_time
                    )
                    if gap > WINDOW:
                        return found
                    cursor = SecurityEvent.model_validate_json(row[1])
                    found.append((cursor, row[2]))
                if len(rows) < NEIGHBOR_PAGE_SIZE:
                    break
            return found

        return [*reversed(neighbors(True)), (event, None), *neighbors(False)]

    def source_baseline(
        self, conn: sqlite3.Connection, key: str
    ) -> tuple[int, set[str]]:
        row = conn.execute(
            "SELECT success_count, source_ips FROM auth_baselines WHERE correlation_key = ?", (key,)
        ).fetchone()
        return (row[0], set(json.loads(row[1]))) if row else (0, set())

    def save_source_baseline(
        self, conn: sqlite3.Connection, key: str, count: int, ips: set[str]
    ) -> None:
        conn.execute(
            """INSERT INTO auth_baselines (correlation_key, success_count, source_ips)
               VALUES (?, ?, ?) ON CONFLICT(correlation_key) DO UPDATE SET
               success_count = excluded.success_count, source_ips = excluded.source_ips""",
            (key, count, json.dumps(sorted(ips))),
        )

    def save_event_signal(
        self, conn: sqlite3.Connection, event: SecurityEvent, signal: DetectionSignal
    ) -> None:
        conn.execute(
            "INSERT INTO event_signals (source, event_id, body) VALUES (?, ?, ?)",
            (event.source, event.event_id, signal.model_dump_json()),
        )

    def signals_for_events(
        self, conn: sqlite3.Connection, events: list[SecurityEvent]
    ) -> tuple[DetectionSignal, ...]:
        signals = []
        for event in events:
            row = conn.execute(
                "SELECT body FROM event_signals WHERE source = ? AND event_id = ?",
                (event.source, event.event_id),
            ).fetchone()
            if row:
                signals.append(DetectionSignal.model_validate_json(row[0]))
        return tuple(signals)

    def event_signals(self) -> list[DetectionSignal]:
        with self.transaction() as conn:
            rows = conn.execute(
                "SELECT body FROM event_signals ORDER BY source, event_id"
            ).fetchall()
        return [DetectionSignal.model_validate_json(row[0]) for row in rows]

    def save_incident(
        self, conn: sqlite3.Connection, incident: Incident,
        events: list[SecurityEvent], retired_ids: set[str], trigger_event: SecurityEvent,
    ) -> None:
        conn.execute(
            """INSERT INTO incidents (incident_id, body) VALUES (?, ?)
               ON CONFLICT(incident_id) DO UPDATE SET body = excluded.body""",
            (incident.incident_id, incident.model_dump_json()),
        )
        conn.executemany(
            "UPDATE events SET incident_id = ? WHERE source = ? AND event_id = ?",
            [(incident.incident_id, event.source, event.event_id) for event in events],
        )
        for retired_id in sorted(retired_ids):
            conn.execute(
                "UPDATE incident_aliases SET current_id = ? WHERE current_id = ?",
                (incident.incident_id, retired_id),
            )
            conn.execute(
                """INSERT INTO incident_aliases (retired_id, current_id) VALUES (?, ?)
                   ON CONFLICT(retired_id) DO UPDATE SET current_id = excluded.current_id""",
                (retired_id, incident.incident_id),
            )
            self.record_transition(
                conn, retired_id, "merged", event=trigger_event,
                merged_into=incident.incident_id,
            )
        conn.executemany(
            "DELETE FROM incidents WHERE incident_id = ?",
            [(incident_id,) for incident_id in retired_ids],
        )

    def stored_incident(self, conn: sqlite3.Connection, incident_id: str) -> Incident | None:
        row = conn.execute(
            "SELECT body FROM incidents WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        if row is None:
            row = conn.execute(
                """SELECT incidents.body FROM incident_aliases
                   JOIN incidents ON incidents.incident_id = incident_aliases.current_id
                   WHERE incident_aliases.retired_id = ?""",
                (incident_id,),
            ).fetchone()
        return Incident.model_validate_json(row[0]) if row else None

    def record_transition(
        self, conn: sqlite3.Connection, incident_id: str, action: str,
        request_id: str | None = None, event: SecurityEvent | None = None,
        merged_into: str | None = None,
    ) -> None:
        conn.execute(
            """INSERT INTO incident_transitions
               (incident_id, action, occurred_at, request_id, event_source, event_id, merged_into)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (incident_id, action, datetime.now(UTC).isoformat(), request_id,
             event.source if event else None, event.event_id if event else None, merged_into),
        )

    def incident_history(
        self, incident_id: str, limit: int = 100, offset: int = 0
    ) -> list[IncidentTransition] | None:
        with self.transaction() as conn:
            incident = self.stored_incident(conn, incident_id)
            if incident is None:
                return None
            rows = conn.execute(
                """SELECT transition_id, incident_id, action, occurred_at,
                          request_id, event_source, event_id, merged_into
                   FROM incident_transitions
                   WHERE incident_id = ? OR incident_id IN
                       (SELECT retired_id FROM incident_aliases WHERE current_id = ?)
                   ORDER BY transition_id LIMIT ? OFFSET ?""",
                (incident.incident_id, incident.incident_id, limit, offset),
            ).fetchall()
        return [IncidentTransition(
            transition_id=row[0], incident_id=row[1], action=row[2],
            occurred_at=row[3], request_id=row[4], event_source=row[5], event_id=row[6],
            merged_into=row[7],
        ) for row in rows]

    def event(self, source: str, event_id: str) -> SecurityEvent | None:
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT body FROM events WHERE source = ? AND event_id = ?",
                (source, event_id),
            ).fetchone()
        return SecurityEvent.model_validate_json(row[0]) if row else None

    def retention_preview(self, before: datetime) -> RetentionPreview:
        cutoff = before.astimezone(UTC).isoformat()
        with self.transaction() as conn:
            total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            row = conn.execute(
                """SELECT
                    COUNT(*),
                    SUM(CASE WHEN e.incident_id IS NOT NULL THEN 1 ELSE 0 END),
                    SUM(CASE WHEN e.incident_id IS NULL AND EXISTS (
                        SELECT 1 FROM event_signals AS s
                        WHERE s.source = e.source AND s.event_id = e.event_id
                    ) THEN 1 ELSE 0 END),
                    SUM(CASE WHEN e.incident_id IS NULL AND e.correlation_key IS NOT NULL
                        AND NOT EXISTS (
                            SELECT 1 FROM event_signals AS s
                            WHERE s.source = e.source AND s.event_id = e.event_id
                        ) THEN 1 ELSE 0 END),
                    SUM(CASE WHEN e.incident_id IS NULL AND e.correlation_key IS NULL
                        AND NOT EXISTS (
                            SELECT 1 FROM event_signals AS s
                            WHERE s.source = e.source AND s.event_id = e.event_id
                        ) THEN 1 ELSE 0 END)
                   FROM events AS e WHERE e.event_time < ?""",
                (cutoff,),
            ).fetchone()
        return RetentionPreview(
            before=before, total_events=total, before_cutoff=row[0],
            incident_evidence=row[1] or 0, signal_evidence=row[2] or 0,
            unlinked_correlatable=row[3] or 0, unlinked_other=row[4] or 0,
        )

    def incident(self, incident_id: str) -> Incident | None:
        with self.transaction() as conn:
            return self.stored_incident(conn, incident_id)

    def incident_events(
        self, incident_id: str, limit: int = 100, offset: int = 0
    ) -> list[SecurityEvent] | None:
        with self.transaction() as conn:
            incident = self.stored_incident(conn, incident_id)
            if incident is None:
                return None
            rows = conn.execute(
                """SELECT body FROM events WHERE incident_id = ?
                   ORDER BY event_time, source, event_id LIMIT ? OFFSET ?""",
                (incident.incident_id, limit, offset),
            ).fetchall()
        return [SecurityEvent.model_validate_json(row[0]) for row in rows]

    def close_incident(self, incident_id: str, request_id: str | None = None) -> Incident | None:
        with self.transaction() as conn:
            incident = self.stored_incident(conn, incident_id)
            if incident is None:
                return None
            if incident.status is IncidentStatus.CLOSED:
                return incident
            closed = incident.model_copy(update={"status": IncidentStatus.CLOSED})
            conn.execute(
                "UPDATE incidents SET body = ? WHERE incident_id = ?",
                (closed.model_dump_json(), closed.incident_id),
            )
            self.record_transition(conn, closed.incident_id, "closed", request_id=request_id)
            return closed

    def stored_incidents(self, conn: sqlite3.Connection) -> list[Incident]:
        rows = conn.execute("SELECT body FROM incidents ORDER BY incident_id").fetchall()
        return [Incident.model_validate_json(row[0]) for row in rows]

    def incidents(self) -> list[Incident]:
        with self.transaction() as conn:
            return self.stored_incidents(conn)

    def incidents_page(self, limit: int, offset: int) -> list[Incident]:
        with self.transaction() as conn:
            rows = conn.execute(
                "SELECT body FROM incidents ORDER BY incident_id LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [Incident.model_validate_json(row[0]) for row in rows]
