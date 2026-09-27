from collections.abc import Iterable
from hashlib import sha256

from adaptive_security.domain.events import EntityRef, SecurityEvent
from adaptive_security.domain.incidents import Incident


class CorrelationEngine:
    def correlate(self, events: Iterable[SecurityEvent]) -> Incident:
        ordered = sorted(events, key=lambda event: event.event_time)
        if not ordered:
            raise ValueError("at least one event is required")

        event_ids = tuple(event.event_id for event in ordered)
        entities = self._unique_entities(ordered)
        digest = sha256("\0".join(event_ids).encode()).hexdigest()[:16]

        return Incident(
            incident_id=f"inc-{digest}",
            title=self._title(ordered),
            first_seen=ordered[0].event_time,
            last_seen=ordered[-1].event_time,
            severity=max(event.severity for event in ordered),
            event_ids=event_ids,
            entities=entities,
        )

    @staticmethod
    def _unique_entities(events: Iterable[SecurityEvent]) -> tuple[EntityRef, ...]:
        seen: set[tuple[str, str]] = set()
        entities: list[EntityRef] = []
        for event in events:
            for entity in event.entities:
                key = (entity.type, entity.value)
                if key not in seen:
                    seen.add(key)
                    entities.append(entity)
        return tuple(entities)

    @staticmethod
    def _title(events: list[SecurityEvent]) -> str:
        categories = {event.category.value for event in events}
        if len(categories) == 1:
            return f"Correlated {next(iter(categories))} activity"
        return "Correlated security activity"
