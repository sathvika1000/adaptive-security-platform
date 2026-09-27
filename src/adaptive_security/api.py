from typing import Any

from fastapi import FastAPI

from adaptive_security.connectors.wazuh import WazuhConnector
from adaptive_security.domain.events import SecurityEvent

app = FastAPI(title="Adaptive Security Platform", version="0.1.0")
_wazuh = WazuhConnector()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/events/wazuh", response_model=SecurityEvent)
def ingest_wazuh_event(payload: dict[str, Any]) -> SecurityEvent:
    return _wazuh.normalize(payload)
