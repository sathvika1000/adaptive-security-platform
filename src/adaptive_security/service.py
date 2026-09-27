from adaptive_security.correlation.engine import CorrelationEngine
from adaptive_security.correlation.policy import WINDOW, identity
from adaptive_security.detection.auth_sequence import detect_auth_sequence
from adaptive_security.detection.novel_source import detect_novel_source
from adaptive_security.domain.events import SecurityEvent
from adaptive_security.domain.incidents import Incident, IncidentStatus
from adaptive_security.store import SQLiteStore, correlation_key


class IngestionService:
    def __init__(self, store: SQLiteStore) -> None:
        self.store = store

    def ingest(self, event: SecurityEvent) -> tuple[SecurityEvent, Incident | None]:
        with self.store.transaction() as conn:
            persisted, inserted, existing_id = self.store.put_event(conn, event)
            if not inserted:
                existing = self.store.stored_incident(conn, existing_id) if existing_id else None
                return persisted, existing

            key = identity(persisted)
            if key is None:
                return persisted, None
            if persisted.outcome == "success" and persisted.source_ip is not None:
                encoded_key = correlation_key(persisted)
                assert encoded_key is not None
                count, ips = self.store.source_baseline(conn, encoded_key)
                signal = detect_novel_source(persisted, count, ips)
                if signal is not None:
                    self.store.save_event_signal(conn, persisted, signal)
                self.store.save_source_baseline(conn, encoded_key, count + 1,
                                                ips | {persisted.source_ip})
            candidates = self.store.events_for_identity(conn, key)
            position = next(
                i for i, (candidate, _) in enumerate(candidates)
                if (candidate.source, candidate.event_id) == (persisted.source, persisted.event_id)
            )
            start = position
            end = position
            while start and (
                candidates[start][0].event_time - candidates[start - 1][0].event_time <= WINDOW
            ):
                start -= 1
            while end + 1 < len(candidates) and (
                candidates[end + 1][0].event_time - candidates[end][0].event_time <= WINDOW
            ):
                end += 1
            segment = candidates[start : end + 1]
            events = [candidate for candidate, _ in segment]
            if len(events) < 2 or not any(candidate.outcome == "failure" for candidate in events):
                return persisted, None

            incident = CorrelationEngine().correlate(events).model_copy(
                update={"signals": (*detect_auth_sequence(events),
                                    *self.store.signals_for_events(conn, events))}
            )
            old_ids = {incident_id for _, incident_id in segment if incident_id}
            previous = [
                old for incident_id in old_ids
                if (old := self.store.stored_incident(conn, incident_id)) is not None
            ]
            if previous:
                oldest = min(previous, key=lambda old: (old.first_seen, old.incident_id))
                status = oldest.status
                if (
                    status is IncidentStatus.CLOSED
                    and persisted.outcome == "failure"
                    and persisted.event_time > oldest.last_seen
                ):
                    status = IncidentStatus.OPEN
                incident = incident.model_copy(
                    update={"incident_id": oldest.incident_id, "status": status}
                )
            self.store.save_incident(conn, incident, events, old_ids - {incident.incident_id})
            return persisted, incident
