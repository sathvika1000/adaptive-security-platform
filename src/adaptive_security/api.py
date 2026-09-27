import hmac
import json
import logging
import os
from collections.abc import Awaitable, Callable
from time import perf_counter
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
from starlette.responses import Response

from adaptive_security.connectors.wazuh import WazuhAlert, WazuhConnector
from adaptive_security.domain.events import SecurityEvent
from adaptive_security.domain.incidents import Incident
from adaptive_security.http import AlertBodyLimit
from adaptive_security.service import IngestionService
from adaptive_security.store import SQLiteStore


class IngestionResult(BaseModel):
    event: SecurityEvent
    incident: Incident | None


logger = logging.getLogger("adaptive_security.api")


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

    @app.post("/v1/events/wazuh", response_model=IngestionResult, dependencies=[Depends(authorize)])
    def ingest_wazuh_event(payload: WazuhAlert) -> IngestionResult:
        event = WazuhConnector().normalize(payload.model_dump())
        persisted, incident = service.ingest(event)
        return IngestionResult(event=persisted, incident=incident)

    @app.get("/v1/incidents", response_model=list[Incident], dependencies=[Depends(authorize)])
    def list_incidents() -> list[Incident]:
        return store.incidents()

    @app.get(
        "/v1/incidents/{incident_id}", response_model=Incident, dependencies=[Depends(authorize)]
    )
    def get_incident(incident_id: str) -> Incident:
        incident = store.incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident

    @app.post(
        "/v1/incidents/{incident_id}/close",
        response_model=Incident,
        dependencies=[Depends(authorize)],
    )
    def close_incident(incident_id: str) -> Incident:
        incident = store.close_incident(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return incident

    return app


app = create_app()
