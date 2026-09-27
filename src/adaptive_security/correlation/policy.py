from datetime import timedelta

from adaptive_security.domain.events import EventCategory, SecurityEvent

WINDOW = timedelta(minutes=15)


def identity(event: SecurityEvent) -> tuple[str, str] | None:
    if event.category is not EventCategory.AUTHENTICATION:
        return None
    users = sorted(entity.value for entity in event.entities if entity.type == "user")
    hosts = sorted(entity.value for entity in event.entities if entity.type == "host")
    return (users[0], hosts[0]) if users and hosts else None

