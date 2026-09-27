from typing import Any, Protocol

from adaptive_security.domain.events import SecurityEvent


class EventConnector(Protocol):
    def normalize(self, payload: dict[str, Any]) -> SecurityEvent: ...
