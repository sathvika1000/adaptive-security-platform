from collections import deque
from datetime import timedelta

from adaptive_security.domain.detections import DetectionSignal
from adaptive_security.domain.events import SecurityEvent

WINDOW = timedelta(minutes=15)
SEQUENCE_RULE_ID = "auth.failures_then_success"


def detect_auth_sequence(events: list[SecurityEvent]) -> tuple[DetectionSignal, ...]:
    failures: deque[SecurityEvent] = deque()
    signals: list[DetectionSignal] = []
    for event in events:
        while failures and event.event_time - failures[0].event_time > WINDOW:
            failures.popleft()
        if event.outcome == "failure":
            failures.append(event)
        elif event.outcome == "success" and len(failures) >= 3:
            evidence = (*list(failures)[-3:], event)
            signals.append(
                DetectionSignal(
                    rule_id=SEQUENCE_RULE_ID,
                    rule_version=1,
                    title="Repeated authentication failures followed by success",
                    evidence_event_ids=tuple(item.event_id for item in evidence),
                    priority=7,
                )
            )
    return tuple(signals)
