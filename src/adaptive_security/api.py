import hmac
import json
import logging
import os
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from time import perf_counter
from typing import Annotated
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import AwareDatetime, BaseModel
from starlette.responses import Response

from adaptive_security.connectors.wazuh import WazuhAlert, WazuhConnector
from adaptive_security.domain.events import SecurityEvent
from adaptive_security.domain.incidents import Incident, IncidentTransition
from adaptive_security.http import AlertBodyLimit
from adaptive_security.service import IngestionService
from adaptive_security.store import RetentionPreview, SQLiteStore


class IngestionResult(BaseModel):
    event: SecurityEvent
    incident: Incident | None


logger = logging.getLogger("uvicorn.error")
DEFAULT_RETENTION_DAYS = 90
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


def create_app(db_path: str | None = None, api_key: str | None = None) -> FastAPI:
    app = FastAPI(title="Adaptive Security Platform", version="0.1.0")
    app.add_middleware(AlertBodyLimit)
    store = SQLiteStore(db_path or os.environ.get("ASP_DB_PATH", "./security.db"))
    service = IngestionService(store)
    key = api_key if api_key is not None else os.environ.get("ASP_API_KEY")

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

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready")
    def ready() -> dict[str, str]:
        if not key or not store.ready():
            raise HTTPException(status_code=503, detail="Service unavailable")
        return {"status": "ready"}

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
    def close_incident(incident_id: str, request: Request) -> Incident:
        incident = store.close_incident(incident_id, request_id=request.state.request_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident

    return app


app = create_app()
