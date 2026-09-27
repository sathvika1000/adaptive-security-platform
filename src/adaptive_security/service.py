from datetime import timedelta

from adaptive_security.correlation.engine import CorrelationEngine
from adaptive_security.domain.events import EventCategory, SecurityEvent
from adaptive_security.domain.incidents import Incident
from adaptive_security.store import SQLiteStore

WINDOW = timedelta(minutes=15)


def identity(event: SecurityEvent) -> tuple[str, str] | None:
    if event.category is not EventCategory.AUTHENTICATION:
        return None
    users = sorted(entity.value for entity in event.entities if entity.type == "user")
    hosts = sorted(entity.value for entity in event.entities if entity.type == "host")
    return (users[0], hosts[0]) if users and hosts else None


def correlate(events: list[SecurityEvent]) -> list[Incident]:
    groups: dict[tuple[str, str], list[SecurityEvent]] = {}
    for event in events:
        key = identity(event)
        if key is not None:
            groups.setdefault(key, []).append(event)

    incidents: list[Incident] = []
    engine = CorrelationEngine()
    for group in groups.values():
        ordered = sorted(group, key=lambda e: (e.event_time, e.source, e.event_id))
        segment: list[SecurityEvent] = []
        for event in ordered:
            if segment and event.event_time - segment[-1].event_time > WINDOW:
                if len(segment) >= 2:
                    incidents.append(engine.correlate(segment))
                segment = []
            segment.append(event)
        if len(segment) >= 2:
            incidents.append(engine.correlate(segment))
    return incidents


class IngestionService:
    def __init__(self, store: SQLiteStore) -> None:
        self.store = store

    def ingest(self, event: SecurityEvent) -> tuple[SecurityEvent, Incident | None]:
        with self.store.transaction() as conn:
            persisted = self.store.put_event(conn, event)
            incidents = correlate(self.store.events(conn))
            self.store.replace_incidents(conn, incidents)
            incident = next(
                (item for item in incidents if persisted.event_id in item.event_ids), None
            )
            return persisted, incident

