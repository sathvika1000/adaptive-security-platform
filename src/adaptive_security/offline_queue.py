"""Current-bundle analyst workload, independent of evaluation labels and metrics."""

from typing import get_args

from pydantic import AwareDatetime, BaseModel

from adaptive_security.offline_annotations import Disposition, ReviewEntry
from adaptive_security.offline_review import ReviewSnapshot


class QueueCounts(BaseModel):
    total: int = 0
    assessed: int = 0
    needs_review: int = 0
    unassessed: int = 0
    dispositions: dict[str, int]


class QueueItem(BaseModel):
    capture_id: str
    finding_id: str
    title: str
    evidence_records: int
    partition: str
    label: str
    disposition: Disposition
    revision: int
    actor: str | None
    assessed_at: AwareDatetime | None


class QueuePage(BaseModel):
    configured: bool
    counts: QueueCounts
    capture_counts: dict[str, QueueCounts]
    matching: int
    entries: list[QueueItem]


def empty_counts() -> QueueCounts:
    return QueueCounts(dispositions=dict.fromkeys(get_args(Disposition), 0))


def add_count(counts: QueueCounts, item: QueueItem) -> None:
    counts.total += 1
    counts.dispositions[item.disposition] += 1
    counts.needs_review += item.disposition == "needs_review"
    counts.assessed += item.disposition != "needs_review"
    counts.unassessed += item.revision == 0


def build_queue(
    snapshot: ReviewSnapshot | None,
    latest: dict[str, ReviewEntry],
    disposition: Disposition | None,
    capture_id: str | None,
    limit: int,
    offset: int,
) -> QueuePage:
    counts = empty_counts()
    captures = {}
    items = []
    if snapshot is not None:
        for identifier, capture in sorted(snapshot.captures.items()):
            capture_counts = empty_counts()
            captures[identifier] = capture_counts
            for finding in sorted(capture.findings, key=lambda finding: finding.incident_id):
                assessment = latest.get(snapshot.finding_keys[(identifier, finding.incident_id)])
                item = QueueItem(
                    capture_id=identifier,
                    finding_id=finding.incident_id,
                    title=finding.title,
                    evidence_records=len(finding.event_ids),
                    partition=capture.summary.partition,
                    label=capture.summary.label,
                    disposition=assessment.disposition if assessment else "needs_review",
                    revision=assessment.revision if assessment else 0,
                    actor=assessment.actor if assessment else None,
                    assessed_at=assessment.occurred_at if assessment else None,
                )
                add_count(counts, item)
                add_count(capture_counts, item)
                if (capture_id is None or identifier == capture_id) and (
                    disposition is None or item.disposition == disposition
                ):
                    items.append(item)
    # Pending first, then capture/finding ID: stable pagination for an unchanged journal.
    items.sort(
        key=lambda item: (item.disposition != "needs_review", item.capture_id, item.finding_id)
    )
    return QueuePage(
        configured=snapshot is not None,
        counts=counts,
        capture_counts=captures,
        matching=len(items),
        entries=items[offset : offset + limit],
    )
