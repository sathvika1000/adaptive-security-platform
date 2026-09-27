# Adaptive Security Platform

A Wazuh-first, source-independent security event and incident POC.

## Run locally

Python 3.12 is required. Set an API key before exposing the service. SQLite stores
events and incidents in the configured path; keep the database and key outside
source control.

```sh
python -m pip install -e '.[dev]'
export ASP_API_KEY='replace-with-a-long-random-value'
export ASP_DB_PATH='./security.db'
uvicorn adaptive_security.api:app --host 127.0.0.1 --port 8000
```

POST one Wazuh alert JSON to `/v1/events/wazuh` with `X-API-Key`.
The response includes the canonical event and an incident when correlated.
GET `/v1/incidents` or `/v1/incidents/{incident_id}` with the same header.
`/health` is unauthenticated. OpenAPI is available at `/docs`.

For a reproducible demonstration, send two authentication alerts with distinct
IDs, the same `data.srcuser` and `agent.name`, and timestamps within 15 minutes.
The second response contains an incident; restart the API and retrieve it.
See `tests/test_pipeline.py` for exact payloads.

## Correlation contract and limits

Only canonical authentication events with both user and host are eligible.
A run of at least two events for the same user and host, with no gap greater
than 15 minutes between adjacent event times, forms one incident. Severity is
the maximum event severity. Events are ordered by time, source and ID.
Duplicate source/ID ingestion returns the originally stored event.

The POC recomputes incidents transactionally after each ingestion, so incident
IDs can change as a run grows or late events arrive. This is suitable for small
local datasets, not high-volume ingestion or analyst state. Incident status
updates, paginated retrieval, retention, payload size limits, and live Wazuh
transport are subsequent work. Deploy behind TLS and network controls; the
shared API key is a POC boundary, not a multi-user authorization system.

