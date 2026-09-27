from adaptive_security.domain.detections import DetectionSignal
from adaptive_security.domain.events import SecurityEvent

MIN_BASELINE_SUCCESSES = 5


def detect_novel_source(
    event: SecurityEvent, success_count: int, known_ips: set[str]
) -> DetectionSignal | None:
    if event.outcome != "success" or event.source_ip is None:
        return None
    if success_count < MIN_BASELINE_SUCCESSES or event.source_ip in known_ips:
        return None
    return DetectionSignal(
        rule_id="auth.novel_source_ip",
        rule_version=1,
        title="First-seen source IP after established baseline",
        evidence_event_ids=(event.event_id,),
        priority=4,
        mode="shadow",
    )
