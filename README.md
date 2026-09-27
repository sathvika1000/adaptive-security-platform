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
GET `/v1/events/{source}/{event_id}` retrieves stored canonical evidence;
for current Wazuh signals use `wazuh` as the source and each evidence ID.
`POST /v1/incidents/{incident_id}/close` closes an incident. A newly ingested
failure with an event time later than the incident's previous last-seen time
reopens it; older evidence leaves it closed. Repeated closes are idempotent.
`/health` is unauthenticated. OpenAPI is available at `/docs`.
Responses carry an `X-Request-ID`; structured request logs contain that ID,
route, status, and duration without alert bodies or API keys. The Wazuh
ingestion endpoint rejects bodies larger than 1 MiB with HTTP 413, including
requests that understate their `Content-Length`.

For a reproducible demonstration, send two authentication alerts with distinct
IDs, the same `data.srcuser` and `agent.name`, and timestamps within 15 minutes.
The second response contains an incident; restart the API and retrieve it.
See `tests/test_pipeline.py` for exact payloads.

With Docker Desktop, the application-only Compose stack uses a single
Python 3.12 container and a named SQLite volume:

```sh
export ASP_API_KEY='replace-with-a-long-random-value'
docker compose up --build -d
python scripts/replay_demo.py
docker compose down
```

The replay prints the incident ID and confirms retrieval. Compose binds only
to localhost. The named volume survives `docker compose down`; use a fresh
volume to reset the demonstration. No Wazuh server is bundled.

## Forward Wazuh alerts

Wazuh writes JSON alerts to `/var/ossec/logs/alerts/alerts.json` on the
manager when JSON output is enabled. Run the forwarder on that host with
read-only access to the alert file and a writable checkpoint directory:

```sh
export ASP_API_KEY='same-key-as-the-platform'
python -m adaptive_security.forwarder /var/ossec/logs/alerts/alerts.json \
  --checkpoint /var/lib/adaptive-security/alerts.cursor --follow \
  --url https://platform.example.internal
```

It sends each complete JSON line to the API and checkpoints only after a
successful response. A failed delivery or malformed alert stops at that line
for diagnosis. Supervise and restart the command; duplicate deliveries are
idempotent by source/event ID. Use HTTPS for a remote platform and keep the
key outside source control. Run without `--follow` for a one-time replay.
Rotation or truncation resets the cursor; alerts removed before reading
cannot be recovered by this adapter. Live manager validation remains.

Wazuh references: [alert management](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html)
and [server-side forwarding](https://documentation.wazuh.com/current/integrations-guide/index.html).

## Correlation contract and limits

Only canonical authentication events with both user and host are eligible.
A run of at least two events for the same user and host, including a failure,
with no gap greater than 15 minutes between adjacent event times, forms one
incident. Severity is the maximum event severity. Events are ordered by time,
source and ID.
Duplicate source/ID ingestion returns the originally stored event.

A versioned deterministic signal marks three or more failures followed by a
success for that user and host within 15 minutes. The incident returns the
three most recent failure IDs and the success ID as evidence, with a heuristic
priority of 7/10. This sequence is a triage lead, not proof of compromise;
ordinary password retries can match it. Incident severity remains the maximum
source severity and is separate from signal priority.

## Evaluate the sequence signal

Provide a JSONL file with one labeled case per line. Each line has a unique
`case_id`, a `label` of `malicious` or `benign`, and an `events` array of
canonical `SecurityEvent` objects (see `tests/test_evaluation.py` for
examples). Run `python scripts/evaluate_signal.py cases.jsonl`.
Cases are isolated in separate temporary databases and processed through the
normal ingestion and incident path. The output counts case-level true/false
positives and negatives and computes precision and recall when defined.
It prints only aggregate counts; use deidentified, permissioned examples.
Synthetic cases test the evaluation contract, not real-world detection quality.

The POC indexes authentication events by user/host and event time. Each new
event updates only its connected correlation run while preserving the ID of a
matching incident as the run grows or late events arrive. Existing SQLite
databases are migrated on startup without discarding incidents or status.
If a late alert bridges two incidents, the older incident ID survives and the
other ID is retired. The lookup still scans the history for that user/host,
so high-volume retention and partitioning are future work. Merge retirement
does not provide an alias for the retired ID.
Closure has no actor identity or audit trail because this POC uses one shared
API key. Paginated retrieval and retention are subsequent work. Deploy behind
TLS and network controls; the shared API key is a POC boundary, not a multi-user
authorization system.
