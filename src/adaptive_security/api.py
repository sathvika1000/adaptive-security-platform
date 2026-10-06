import hashlib
import hmac
import json
import logging
import os
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from time import perf_counter
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import AwareDatetime, BaseModel
from starlette.responses import Response

from adaptive_security.connectors.wazuh import WazuhAlert, WazuhConnector
from adaptive_security.domain.events import SecurityEvent
from adaptive_security.domain.incidents import Incident, IncidentTransition
from adaptive_security.http import AlertBodyLimit
from adaptive_security.offline_annotations import (
    Disposition,
    ReviewConflict,
    ReviewEdit,
    ReviewEntry,
    ReviewPage,
)
from adaptive_security.offline_queue import QueuePage, build_queue
from adaptive_security.offline_report import REPORT_CSP, readable_report
from adaptive_security.offline_review import (
    CaptureSnapshot,
    ReviewSnapshot,
    ReviewSource,
    finding_review_binding,
    finding_review_key,
)
from adaptive_security.service import IngestionService
from adaptive_security.store import RetentionPreview, SQLiteStore


class IngestionResult(BaseModel):
    event: SecurityEvent
    incident: Incident | None


class AnalystIdentity(BaseModel):
    mode: Literal["shared", "analyst"]
    actor: str | None
    permissions: list[str]


logger = logging.getLogger("uvicorn.error")
DEFAULT_RETENTION_DAYS = 90
_ACTOR_NAME = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")


def _analyst_digests(
    config: object, shared_key: str | None
) -> tuple[tuple[str, str, frozenset[str]], ...]:
    if not isinstance(config, dict):
        raise ValueError("analyst keys must be a JSON object")
    result = []
    seen = set()
    for actor, entry in config.items():
        if not isinstance(actor, str) or not _ACTOR_NAME.fullmatch(actor):
            raise ValueError("invalid analyst name; use 1-64 letters, digits, . _ or -")
        if isinstance(entry, dict):
            if set(entry) != {"key", "permissions"}:
                raise ValueError("analyst entry must contain key and permissions only")
            token = entry["key"]
            raw_permissions = entry["permissions"]
            if (not isinstance(raw_permissions, list) or
                any(permission not in ("close", "review") for permission in raw_permissions) or
                len(raw_permissions) != len(set(raw_permissions))):
                raise ValueError("analyst permissions must be a unique list "
                                 "containing only close or review")
            permissions = frozenset(raw_permissions)
        else:
            token = entry
            permissions = frozenset({"close"})
        if not isinstance(token, str) or len(token) < 32 or token == shared_key:
            raise ValueError("each analyst key must be distinct and at least 32 characters")
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        if digest in seen:
            raise ValueError("analyst keys must be unique")
        seen.add(digest)
        result.append((actor, digest, permissions))
    return tuple(result)
_UI_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
}


def create_app(
    db_path: str | None = None, api_key: str | None = None,
    analyst_keys: dict[str, str | dict[str, object]] | None = None,
    offline_review_path: str | None = None,
) -> FastAPI:
    app = FastAPI(title="Adaptive Security Platform", version="0.1.0")
    app.add_middleware(AlertBodyLimit)
    store = SQLiteStore(db_path or os.environ.get("ASP_DB_PATH", "./security.db"))
    service = IngestionService(store)
    review_source = ReviewSource(offline_review_path or os.environ.get("ASP_OFFLINE_REVIEW_PATH"))
    key = api_key if api_key is not None else os.environ.get("ASP_API_KEY")
    configured = (analyst_keys if analyst_keys is not None else
                  json.loads(os.environ.get("ASP_ANALYST_KEYS_JSON") or "{}"))
    analyst_digests = _analyst_digests(configured, key)

    @app.middleware("http")
    async def trace_request(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = uuid4().hex
        request.state.request_id = request_id
        started = perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers["X-Request-ID"] = request_id
            if request.url.path.startswith("/v1/offline-review"):
                response.headers["Cache-Control"] = "no-store"
            return response
        finally:
            logger.info(
                json.dumps(
                    {
                        "request_id": request_id,
                        "method": request.method,
                        "path": getattr(request.scope.get("route"), "path", "<unmatched>"),
                        "status": status_code,
                        "duration_ms": round((perf_counter() - started) * 1000, 2),
                    }
                )
            )

    def authorize(x_api_key: str | None = Header(default=None)) -> None:
        if not key:
            raise HTTPException(status_code=503, detail="API key is not configured")
        if not x_api_key or not hmac.compare_digest(x_api_key, key):
            raise HTTPException(status_code=401, detail="Unauthorized")

    def authorize_analyst(x_analyst_key: str | None = Header(default=None)) -> str | None:
        if not analyst_digests:
            return None
        if not x_analyst_key:
            raise HTTPException(status_code=401, detail="Analyst key required")
        provided = hashlib.sha256(x_analyst_key.encode("utf-8")).hexdigest()
        actor = None
        for name, digest, _permissions in analyst_digests:
            if hmac.compare_digest(provided, digest):
                actor = name
        if actor is None:
            raise HTTPException(status_code=401, detail="Unauthorized")
        return actor

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready")
    def ready() -> dict[str, str]:
        if not key or not store.ready():
            raise HTTPException(status_code=503, detail="Service unavailable")
        return {"status": "ready"}

    @app.get(
        "/v1/auth/identity", response_model=AnalystIdentity,
        dependencies=[Depends(authorize)],
    )
    def analyst_identity(
        actor: Annotated[str | None, Depends(authorize_analyst)],
    ) -> AnalystIdentity:
        permissions = (["close", "review"] if actor is None else
                       sorted(next(rights for name, _, rights in analyst_digests if name == actor)))
        return AnalystIdentity(
            mode="analyst" if analyst_digests else "shared",
            actor=actor, permissions=permissions,
        )

    @app.get("/ui", include_in_schema=False)
    def incident_view() -> HTMLResponse:
        page = files("adaptive_security").joinpath("ui", "index.html").read_text()
        return HTMLResponse(page, headers=_UI_HEADERS)

    @app.get("/ui/{asset}", include_in_schema=False)
    def incident_view_asset(asset: str) -> Response:
        media_type = {"app.js": "text/javascript", "style.css": "text/css"}.get(asset)
        if media_type is None:
            raise HTTPException(status_code=404, detail="Not found")
        body = files("adaptive_security").joinpath("ui", asset).read_bytes()
        return Response(body, media_type=media_type, headers=_UI_HEADERS)

    def review_snapshot() -> ReviewSnapshot | None:
        try:
            return review_source.snapshot()
        except (OSError, ValueError, KeyError, TypeError):
            raise HTTPException(status_code=503, detail="Offline review bundle unavailable; "
                                "check configured output files") from None

    def review_capture(capture_id: str) -> CaptureSnapshot:
        snapshot = review_snapshot()
        if snapshot is None or capture_id not in snapshot.captures:
            raise HTTPException(status_code=404, detail="Offline capture not found")
        return snapshot.captures[capture_id]

    @app.get("/v1/offline-review", dependencies=[Depends(authorize)])
    def offline_index() -> dict[str, object]:
        snapshot = review_snapshot()
        if snapshot is None:
            return {"configured": False, "captures": []}
        return {"configured": True, "rule_id": snapshot.rule_id,
                "provenance": snapshot.provenance,
                "captures": [c.summary.model_dump() for c in snapshot.captures.values()]}

    @app.get("/v1/offline-review/queue", response_model=QueuePage,
             dependencies=[Depends(authorize)])
    def offline_queue(
        disposition: Disposition | None = None, capture_id: str | None = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> QueuePage:
        snapshot = review_snapshot()
        if snapshot is not None and capture_id is not None and capture_id not in snapshot.captures:
            raise HTTPException(status_code=404, detail="Offline capture not found")
        latest = (store.latest_offline_reviews(list(snapshot.finding_keys.values()))
                  if snapshot is not None else {})
        return build_queue(snapshot, latest, disposition, capture_id, limit, offset)

    @app.get("/v1/offline-review/captures/{capture_id}", dependencies=[Depends(authorize)])
    def offline_capture(capture_id: str) -> dict[str, object]:
        capture = review_capture(capture_id)
        return {"summary": capture.summary.model_dump(), "metadata": capture.metadata,
                "findings": [i.model_dump(mode="json") for i in capture.findings]}

    @app.get("/v1/offline-review/captures/{capture_id}/events",
             response_model=list[SecurityEvent], dependencies=[Depends(authorize)])
    def offline_events(
        capture_id: str, finding_id: str | None = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> list[SecurityEvent]:
        capture = review_capture(capture_id)
        events = capture.events
        if finding_id is not None:
            finding = next((i for i in capture.findings if i.incident_id == finding_id), None)
            if finding is None:
                raise HTTPException(status_code=404, detail="Offline finding not found")
            references = set(finding.event_ids)
            events = tuple(e for e in events if e.event_id in references)
        return list(events[offset:offset + limit])

    def offline_finding_key(capture_id: str, finding_id: str) -> str:
        snapshot = review_snapshot()
        capture = review_capture(capture_id)
        finding = next((i for i in capture.findings if i.incident_id == finding_id), None)
        if finding is None or snapshot is None:
            raise HTTPException(status_code=404, detail="Offline finding not found")
        return finding_review_key(snapshot, capture, finding)

    @app.get("/v1/offline-review/captures/{capture_id}/findings/{finding_id}/reviews",
             response_model=ReviewPage, dependencies=[Depends(authorize)])
    def offline_reviews(
        capture_id: str, finding_id: str,
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> ReviewPage:
        return store.offline_reviews(offline_finding_key(capture_id, finding_id), limit, offset)

    @app.post("/v1/offline-review/captures/{capture_id}/findings/{finding_id}/reviews",
              response_model=ReviewEntry, status_code=201, dependencies=[Depends(authorize)])
    def save_offline_review(
        capture_id: str, finding_id: str, edit: ReviewEdit, request: Request,
        actor: Annotated[str | None, Depends(authorize_analyst)],
    ) -> ReviewEntry:
        if actor is not None and "review" not in next(
            rights for name, _, rights in analyst_digests if name == actor
        ):
            raise HTTPException(status_code=403, detail="Review permission required")
        review_key = offline_finding_key(capture_id, finding_id)
        if edit.review_key != review_key:
            raise HTTPException(status_code=409, detail="Finding changed; reload before saving")
        try:
            return store.append_offline_review(review_key, edit, actor, request.state.request_id)
        except ReviewConflict:
            raise HTTPException(status_code=409,
                                detail="Review changed; reload before saving") from None

    @app.get("/v1/offline-review/captures/{capture_id}/findings/{finding_id}/export",
             dependencies=[Depends(authorize)])
    def export_offline_finding(
        capture_id: str, finding_id: str,
        review_key: Annotated[str, Query(pattern=r"^[0-9a-f]{64}$")],
        expected_revision: Annotated[int, Query(ge=0)],
        format: Literal["json", "html"] = "json",
    ) -> Response:
        key = offline_finding_key(capture_id, finding_id)
        history = store.offline_reviews(key, 100, 0)
        if key != review_key or history.revision != expected_revision:
            raise HTTPException(status_code=409,
                                detail="Finding or review changed; reload to export")
        snapshot = review_snapshot()
        capture = review_capture(capture_id)
        assert snapshot is not None
        finding = next(i for i in capture.findings if i.incident_id == finding_id)
        payload = {
            "format": "asp.offline-finding-review", "format_version": 1,
            "exported_at": datetime.now(UTC).isoformat(),
            "review_key": key,
            "binding": finding_review_binding(snapshot, capture, finding),
            "assessment_history": {
                "latest_revision": history.revision,
                "included_revisions": len(history.entries),
                "history_truncated": history.revision > len(history.entries),
                "entries": [entry.model_dump(mode="json") for entry in history.entries],
            },
            "scope": {
                "evidence_records": len(finding.event_ids),
                "capture_records": capture.summary.records,
                "original_evtx_included": False,
                "limitations": [
                    "Selected finding evidence only; other capture records are omitted.",
                    "Original EVTX binary is referenced by checksum, not embedded.",
                    "Latest 100 assessment revisions only; history_truncated indicates omissions.",
                    "Labels, provenance and analyst judgments are declarations, "
                    "not independent proof.",
                    "This export does not establish held-out accuracy or enable live detection.",
                    "SHA-256 checks detect content changes; they do not authenticate an author.",
                ],
            },
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        artifact = {**payload, "payload_sha256": hashlib.sha256(canonical).hexdigest()}
        html = format == "html"
        return Response(readable_report(artifact) if html else json.dumps(artifact, indent=2),
                        media_type="text/html" if html else "application/json", headers={
            "Content-Disposition": (
                f'attachment; filename="{capture_id}-{key[:12]}-review.{format}"'),
            "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
            "X-Review-History-Truncated": str(history.revision > len(history.entries)).lower(),
            "Content-Security-Policy": REPORT_CSP if html else "default-src 'none'",
        })

    @app.post("/v1/events/wazuh", response_model=IngestionResult, dependencies=[Depends(authorize)])
    def ingest_wazuh_event(payload: WazuhAlert) -> IngestionResult:
        event = WazuhConnector().normalize(payload.model_dump())
        persisted, incident = service.ingest(event)
        return IngestionResult(event=persisted, incident=incident)

    @app.get(
        "/v1/events/{source}/{event_id}",
        response_model=SecurityEvent,
        dependencies=[Depends(authorize)],
    )
    def get_event(source: str, event_id: str) -> SecurityEvent:
        event = store.event(source, event_id)
        if event is None:
            raise HTTPException(status_code=404, detail="Event not found")
        return event

    @app.get("/v1/incidents", response_model=list[Incident], dependencies=[Depends(authorize)])
    def list_incidents(
        limit: Annotated[int, Query(ge=1, le=100)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> list[Incident]:
        return store.incidents_page(limit, offset)

    @app.get(
        "/v1/storage/retention-preview", response_model=RetentionPreview,
        dependencies=[Depends(authorize)],
    )
    def retention_preview(
        before: Annotated[AwareDatetime | None, Query()] = None,
        days: Annotated[int | None, Query(ge=1, le=3650)] = None,
    ) -> RetentionPreview:
        if before is not None and days is not None:
            raise HTTPException(status_code=400, detail="Use either before or days")
        if before is not None:
            return store.retention_preview(before)
        window_days = days if days is not None else DEFAULT_RETENTION_DAYS
        cutoff = datetime.now(UTC) - timedelta(days=window_days)
        return store.retention_preview(cutoff).model_copy(update={"window_days": window_days})

    @app.get(
        "/v1/incidents/{incident_id}", response_model=Incident, dependencies=[Depends(authorize)]
    )
    def get_incident(incident_id: str) -> Incident:
        incident = store.incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident

    @app.get(
        "/v1/incidents/{incident_id}/context",
        response_model=list[SecurityEvent], dependencies=[Depends(authorize)],
    )
    def get_incident_context(
        incident_id: str,
        limit: Annotated[int, Query(ge=1, le=100)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> list[SecurityEvent]:
        context = store.incident_context(incident_id, limit, offset)
        if context is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return context

    @app.get(
        "/v1/incidents/{incident_id}/events",
        response_model=list[SecurityEvent],
        dependencies=[Depends(authorize)],
    )
    def get_incident_events(
        incident_id: str,
        limit: Annotated[int, Query(ge=1, le=100)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> list[SecurityEvent]:
        events = store.incident_events(incident_id, limit, offset)
        if events is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return events

    @app.get(
        "/v1/incidents/{incident_id}/history",
        response_model=list[IncidentTransition],
        dependencies=[Depends(authorize)],
    )
    def get_incident_history(
        incident_id: str,
        limit: Annotated[int, Query(ge=1, le=100)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> list[IncidentTransition]:
        history = store.incident_history(incident_id, limit, offset)
        if history is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return history

    @app.post(
        "/v1/incidents/{incident_id}/close",
        response_model=Incident,
        dependencies=[Depends(authorize)],
    )
    def close_incident(
        incident_id: str, request: Request,
        actor: Annotated[str | None, Depends(authorize_analyst)],
    ) -> Incident:
        if actor is not None and "close" not in next(
            rights for name, _, rights in analyst_digests if name == actor
        ):
            raise HTTPException(status_code=403, detail="Close permission required")
        incident = store.close_incident(
            incident_id, request_id=request.state.request_id, actor=actor
        )
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident

    return app


app = create_app()
