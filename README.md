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
The incident list and each incident's `/history` endpoint accept `limit`
(1–100, default 100) and `offset` (zero or greater, default 0). Both return
arrays ordered by incident ID or transition ID respectively; request the next
page by increasing `offset`. Concurrent incident merges can shift list offsets.
GET `/v1/events/{source}/{event_id}` retrieves stored canonical evidence;
for current Wazuh signals use `wazuh` as the source and each evidence ID.
For newly ingested Wazuh SCA alerts, the canonical event retains a bounded
subset of policy, scan, check ID/title/result/status, and summary scores in
`attributes.sca`. Remediation text, commands, and raw check output are not
copied. Existing stored events are unchanged because duplicate alert IDs are
idempotent; use Wazuh for the original detailed SCA records.
`GET /v1/incidents/{incident_id}/events` returns the incident's canonical
events in event-time order, with source and event ID for each. It accepts
`limit` (1–100, default 100) and `offset` (zero or greater, default 0).
Retired incident aliases return the surviving incident's combined evidence;
a missing incident returns 404. This endpoint presents normalized events,
not raw Wazuh alert bodies.
`GET /v1/storage/retention-preview` returns an authenticated, read-only
inventory using a rolling 90-day window. Use `?days=30` to inspect a different
window (1–3650 days), or `?before=<UTC timestamp>` for an exact cutoff. Supply
only one of `days` and `before`. The response includes `before` (the actual UTC
cutoff) and `window_days` (null for an explicit cutoff). It reports total events,
older events linked to incidents,
older events carrying signals without incidents, older correlatable events
without either, and other older events. The categories do not overlap.
The cutoff must include a timezone and is exclusive. This is a planning
inventory, not a list of records safe to delete; even unlinked alerts may be
useful for later investigations or late correlation. No retention deletion
is enabled. The response also includes the 20 most frequent source/category/
rule combinations among older unlinked other events. This breakdown is
aggregate and may cover fewer events than the `unlinked_other` total when
there are more than 20 distinct combinations.

For this single-Mac proof of concept, the proposed policy keeps all events
searchable in the platform for at least 90 days by event time. After that,
only `unlinked_other` events become archive candidates. Incident evidence,
signal evidence, and correlatable events stay in the platform for the life of
the project. Keep verified archives and their manifests for at least one year,
with the full source backup needed to prove export eligibility. These periods
are project defaults, not a claim of regulatory compliance. Archiving and
verification remain manual; the API preview never archives or deletes events.
Wazuh manager alert files and indexer data have separate storage policies;
measure their growth before enabling any index retention rule.
`POST /v1/incidents/{incident_id}/close` closes an incident. A newly ingested
failure with an event time later than the incident's previous last-seen time
reopens it; older evidence leaves it closed. Repeated closes are idempotent.
For attributed close actions, optionally configure `ASP_ANALYST_KEYS_JSON` as
a JSON object mapping analyst names to distinct random keys of at least 32
characters. Compose passes this variable to the platform when set. Generate
each key with `openssl rand -hex 32`; keep the JSON and keys out of source
control. Once configured, close requests require both the normal `X-API-Key`
and an `X-Analyst-Key` matching one configured analyst. Invalid or missing
analyst keys return 401 without closing the incident. Without this mode, the
existing shared-key close flow continues with no actor attribution.
String entries retain `close` permission for compatibility. To restrict an
analyst key, use an object with exactly `key` and `permissions`, where the
permissions list is either `["close"]` or `[]`:

```json
{"sathvika":{"key":"<64-character-random-key>","permissions":["close"]},
 "reviewer":{"key":"<another-random-key>","permissions":[]}}
```

A valid key with no close permission receives 403 and leaves the incident
open. Unknown permissions or malformed entries fail startup. Update the
private configuration and recreate the platform container to change or
remove a key; the platform does not offer a live role-management interface.
The shared platform API key continues to allow reading and ingestion, so
these permissions govern only the close action, not data access.
`GET /v1/auth/identity` checks the same keys without changing an incident.
With analyst mode enabled it requires both headers and returns
`{"mode":"analyst","actor":"<configured name>","permissions":["close"]}`
or an empty permissions list. In shared mode it accepts the platform API key
and returns `{"mode":"shared","actor":null,"permissions":["close"]}`. It never
returns a key. Use this endpoint to check which mode is active before
offering an analyst action.
`GET /v1/incidents/{incident_id}/history` returns durable close/reopen/merge
transitions in processing order. Close entries include the API request ID;
in analyst-key mode, they also include the matching `actor` name. Existing
close transitions and automated reopen/merge transitions have a null actor;
previous actions cannot be attributed retrospectively. Analyst keys are not
recorded in the database or request logs. Reopen and
merge entries name the triggering source and event ID. Merge entries
also name the surviving ID. A retired incident alias retrieves the surviving
incident's combined history while each entry retains the incident ID it had
when recorded. Existing databases start with an empty history; earlier actions
cannot be reconstructed.
`/health` is unauthenticated liveness. `/ready` is unauthenticated readiness:
it returns 200 only when the API key is configured and the SQLite incident
store is accessible, or 503 with a generic detail otherwise. The container
health check uses `/ready`. OpenAPI is available at `/docs`.
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
volume to reset the demonstration. No Wazuh server is bundled. For Docker
Desktop and the official Wazuh single-node stack, follow
[the Wazuh setup guide](docs/WAZUH_DOCKER_DESKTOP.md).

## Back up the platform database

Create a consistent SQLite snapshot while the API runs with
`python -m adaptive_security.backup create SOURCE DESTINATION`. The command
refuses to overwrite a destination and writes a 0600 database copy plus a
`DESTINATION.manifest.json` containing SHA256, size, and table counts. Check a
copy with `python -m adaptive_security.backup verify DESTINATION`; verification
checks its digest, SQLite integrity, and counts. Keep both files together and
store the copied database privately because it contains security evidence.
For the Docker Desktop volume and host copy-out procedure, see
[the Wazuh setup guide](docs/WAZUH_DOCKER_DESKTOP.md#back-up-the-platform-database).
From the repository root on the Docker Desktop host, the same create, copy,
and host verification sequence can be run in one command:

```sh
python3 scripts/backup_docker.py
```

It writes a private timestamped directory beneath ignored `artifacts/` and
prints the verified database and manifest paths. Keep the pair together when
copying it to protected storage. Each invocation leaves a snapshot in the
platform's Docker volume too; review storage usage before scheduling repeated
runs. The command does not rotate or delete any backup.
This is a full database snapshot, not a retention deletion or a backup of
Wazuh's own volumes.

To inspect observed platform growth across two or more verified host backups:

```sh
python -m adaptive_security.storage_trend artifacts
```

The read-only report sorts snapshots by creation time and shows event and
incident counts, database bytes, and changes between consecutive backups.
It verifies each database, checksum, and table counts before reporting; it
does not forecast long-term usage from a short interval. You can also pass
individual `.db` paths. The report covers only platform SQLite backups, not
Wazuh indexer or manager volumes.

For the Docker Desktop Wazuh stack, measure the separate indexer data and
manager logs without changing them:

```sh
python3 scripts/wazuh_storage.py
```

The output is a point-in-time count of allocated bytes inside the running
containers. `manager_alerts_bytes` is included in `manager_logs_bytes`; do not
add those figures together. Repeat on later days to observe Wazuh growth.
Container names can be overridden with `--indexer` and `--manager`.

## Archive retention candidates

From a verified platform database snapshot and its manifest, export the older
`unlinked_other` partition as canonical JSONL without changing the live store:

```sh
python -m adaptive_security.archive create SNAPSHOT.db older.jsonl \
  --before 2026-09-28T00:00:00Z
python -m adaptive_security.archive verify SNAPSHOT.db older.jsonl
python -m adaptive_security.archive restore older.jsonl recovered.db
python -m adaptive_security.archive reconcile SNAPSHOT.db older.jsonl NEW_SNAPSHOT.db
```

The command requires the source snapshot's `.manifest.json`. It writes a
private 0600 archive and `.manifest.json` with the cutoff, record count,
digest, source backup digest, and classification version. Verification checks
the source backup, archive digest, and every archived record against the
snapshot's eligible rows. The exclusive UTC cutoff and partition match
`/v1/storage/retention-preview`; archive output includes events of any category
that lack an incident, correlation identity, and signal. This is a candidate
inventory, not a safe-to-delete decision: older unlinked alerts may still
matter to later investigation. Keep the full snapshot and archive together.
No event deletion or automatic rotation is enabled.

`restore` creates a separate 0600 SQLite database at a path that must not
already exist. It checks the archive digest, record count, canonical event
shape, order, and exclusive cutoff before publishing the restored database.
It needs only the JSONL and its manifest, so it can recover the exported
events if the source snapshot is unavailable. It cannot independently prove
which rows qualified for export: use `verify` with the source snapshot for
that reconciliation. The restored database contains the archived events only,
with no incidents, signals, baselines, or live platform state. Never use the
live database path as a restore destination.

`reconcile` verifies both complete snapshots and the original archive, then
compares each archived event with a newer snapshot at the same cutoff. It
reports unchanged eligible events, missing events, events whose body or
incident/signal/correlation status changed, and newly eligible events absent
from the original archive. `reconciled: true` means those counts match, not
that deletion is safe or authorized. Run a new verified backup before this
check; it reads snapshots only. Incident evidence, signal evidence, and
correlatable events remain protected regardless of age. The provisional
window is 90 days, and no command deletes platform events.

## Incident workspace

Open `http://127.0.0.1:8000/ui` on the Docker Desktop host and enter the
platform API key. The page lists incidents, normalized event evidence,
signals, and lifecycle transitions, including the analyst name on attributed
close actions. For an open incident, review its evidence, enter your analyst
key, and choose **Close incident**. Confirm the incident ID in the prompt.
The close request requires both keys in analyst mode; it clears the analyst
key field after submission and refreshes the incident and its history. It calls
the same authenticated API; the platform
key stays only in page memory and is cleared when you leave or choose **Forget
key**. It is never placed in a URL or browser storage. Keep the loopback bind
and do not share the key. The page shows 20 incidents or events at a time and
the first 100 lifecycle transitions for a selected incident. Refresh to see
new alerts. Enable analyst-key mode before using the close control so actions
are attributed; the shared API key alone does not identify an individual.

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
successful response. It logs a structured delivered count after each successful
batch, without alert bodies or API keys. A failed delivery or malformed alert
stops at that line
for diagnosis. Supervise and restart the command; duplicate deliveries are
idempotent by source/event ID. Use HTTPS for a remote platform and keep the
key outside source control. Run without `--follow` for a one-time replay.
Rotation or truncation resets the cursor; alerts removed before reading
cannot be recovered by this adapter. A Wazuh 4.14.8 manager and the
forwarder were validated on Apple Silicon Docker Desktop with live SCA alerts
and manager-decoded synthetic SSH authentication alerts; see the setup guide.
The checkpoint records a digest of the last delivered line, so truncation
followed by rapid regrowth past the old offset normally resets safely. Older
checkpoints are replayed once on upgrade; duplicate IDs are ignored by the API.
If a rewritten file has the same inode, size, and final checkpoint line at the
same offset, the adapter cannot distinguish it from an append-only file.

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

A separate `auth.novel_source_ip` signal learns successful Wazuh authentication
source IPs (`data.srcip`) for each user and host. After five successful events
with a valid source IP, a success from an IP not previously seen for that pair
records a versioned shadow signal with that event ID as evidence and priority
4/10. Shadow signals appear on an incident if its correlation run also contains
a failure; success-only activity never opens an incident. They do not change
severity, close/reopen behavior, or trigger a response. Duplicate events do not
train the baseline twice. The baseline and observations persist across restarts.
The rule uses ingestion order for learning, including late events. On upgrade,
existing event history is not retrospectively trained or signaled: each pair
starts with a cold baseline. Known VPN rotation, travel, shared IPs, and
attacker-influenced history can produce false positives or suppress a signal.
It does not infer geography or establish compromise.

## Evaluate the sequence signal

Provide a JSONL file with one labeled case per line. Each line has a unique
`case_id`, a `label` of `malicious` or `benign`, and an `events` array of
canonical `SecurityEvent` objects (see `tests/test_evaluation.py` for
examples). Run `python scripts/evaluate_signal.py cases.jsonl`.
Cases are isolated in separate temporary databases and processed through the
normal ingestion and incident path. The output counts case-level true/false
positives and negatives and computes precision and recall when defined.
It prints only aggregate counts by default; use deidentified, permissioned examples.
Synthetic cases test the evaluation contract, not real-world detection quality.
Pass `--rule auth.novel_source_ip` to evaluate the shadow rule. Its case-level
counts include persisted shadow observations even if success-only cases never
formed an incident. Labels must account for benign first-seen IPs and the
five-success cold start; synthetic fixtures alone cannot justify promotion.

Add `--details` to include one result per case: its ID, label, detected flag,
and true/false positive/negative verdict. The report also identifies the selected
rule and includes the same aggregate summary. It omits event bodies, users,
hosts, IPs, and evidence IDs; use non-sensitive case IDs because they appear
in detailed output. Duplicate case IDs are rejected to avoid ambiguous results.
Evaluation creates isolated temporary databases and does not use the live store.

Runnable synthetic examples cover a detected attack, a benign lookalike, a
benign non-match, and a missed attack for each rule:

```sh
python scripts/evaluate_signal.py examples/evaluation/auth-sequence.synthetic.jsonl --details
python scripts/evaluate_signal.py examples/evaluation/auth-novel-source.synthetic.jsonl \
  --rule auth.novel_source_ip --details
```

Each example deliberately yields one case in each verdict category. The
resulting 0.5 precision and recall illustrate known limitations, not measured
production performance. Replace these fixtures with permissioned, labeled
samples before deciding whether a signal should be promoted.

The POC indexes authentication events by user/host and event time. Each new
event walks indexed neighbors in pages of 128 only within its connected
correlation run, then updates that run while preserving the ID of a matching
incident as it grows or late events arrive. Rebuilding a long run for a late
arrival, merge, or success still reads all its members. Event row
assignments are written only for new or reassigned members, so ordinary
incident growth does not rewrite every existing event row. Persisted signal
lookups use batches of 128 event identities while keeping signal order aligned
with the incident timeline. An authentication event appended at the tail of
an existing incident reuses the stored aggregate. For a success, the platform
reads at most the three most recent failures within 15 minutes to preserve the
sequence signal, and retains persisted shadow signals in timeline order.
Late arrivals and merges still rebuild the connected run.
The incident record itself still grows with its evidence IDs, so this is not
a fixed-size incident design. Existing SQLite databases are migrated on startup
without discarding incidents or status.
If a late alert bridges two incidents, the older incident ID survives and the
other ID is retired. High-volume retention and partitioning are future work.
Merge retirement keeps a persistent alias for the retired ID. GET and close
through an old ID return the surviving incident with its current ID, including
after subsequent merges. The incident list contains only current IDs. Aliases
are created for merges after this upgrade; previously retired IDs cannot be
reconstructed.
Close transition history identifies an analyst when analyst-key mode is enabled;
older and automated transitions have no actor. Event retention remains future
work. Deploy behind TLS and network controls; the shared API key plus optional
analyst keys are a POC boundary, not a multi-user authorization system.

### OTRF captured attack replay

Import and replay the checksum-pinned PurpleSharp Windows host capture in isolation:

```sh
python -m adaptive_security.otrf_replay artifacts/otrf-playbook-1
```

This preserves all raw records and produces an inventory, production replay database,
separate UI-compatible password-spray findings database, evidence timeline, and a narrow
publisher-documented attack case. The `auth.password_spray` detector is offline batch
only; no live detection settings change. See [the OTRF evaluation guide](docs/OTRF_EVALUATION.md)
for Mac commands, UI inspection on port 8001, labels, and coverage limits.

Paired network metadata and exact host connection/time links are available with
`--with-network`. The incident UI separates supporting context from detection evidence
and shows accounts and origins before expandable raw records. See the guide for
parser coverage, matching limits, and commands to inspect the combined replay.

Replay also builds a separate five-event RC4 service-ticket investigation with requester,
service accounts, client IP, and issuing domain controller. The offline
`auth.rc4_service_ticket_burst` rule flags a narrow Kerberoasting candidate; legitimate
legacy applications can trigger it. Ticket issuance does not prove cracking or compromise.
Provenance-aware suites distinguish development captures from synthetic controls and
leave performance metrics null for single-label captured cases. Live ingestion is unchanged.

Two independent, reserved password-spray EVTX cases now provide a reproducible check of
v1 coverage: both are missed because they contain explicit-credential or Kerberos
preauthentication telemetry rather than the supported failed-logon records. Their
original evidence is preserved, and the detector remains frozen. See
[captured validation](docs/CAPTURED_VALIDATION.md) for results, optional dependencies,
label limitations, and the remaining representative benign testing requirement.
