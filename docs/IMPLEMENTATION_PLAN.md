# Implementation plan

## Completed
- Canonical event and Wazuh alert normalizer.
- Deterministic incident model and builder (PR #2).
- SQLite event/incident persistence, authenticated ingestion and retrieval,
  and a tested two-alert authentication correlation path.
- Application-only Compose topology and a replayable HTTP demonstration.
- JSON-line Wazuh alert-file forwarder with retry-safe checkpointing.
- Stable incident ID reconciliation for late and appended alerts, plus close
  and reopen lifecycle behavior.
- Indexed event identity/time lookup and affected-run incident updates, with
  migration of existing SQLite databases.
- Versioned, evidence-backed authentication sequence signal for analyst triage.
- Bounded Wazuh request bodies and structured request metadata with correlation IDs.
- Case-level evaluation harness using the production ingestion path and labeled
  canonical event sequences.
- Authenticated canonical event retrieval by source and event ID for signal evidence.
- Persisted user/host source IP baseline and first-seen success shadow signal,
  with isolated case-level evaluation and cold-start behavior.
- Persistent aliases for incident IDs retired by late-alert merges.
- Indexed neighbor lookup limited to the connected correlation run.
- Durable close/reopen/merge transition history, including request or event evidence
  and lookup through retired incident aliases.
- Bounded, offset-based API pagination for incident listings and transition history.
- Separate liveness and readiness endpoints; container health checks key and database readiness.
- Forwarder checkpoints verify the last delivered line to detect fast truncate/regrow cycles.
- Forwarder reports delivered batch counts without alert content and no longer
  inherits the API health check as a misleading sidecar health signal.
- Paginated incident evidence retrieval returns time-ordered canonical events,
  including through retired incident aliases and across event sources.
- Read-only local incident workspace with paginated queue and event timeline,
  signals, lifecycle history, and an in-memory API key.
- Indexed correlation neighbors are read in pages of 128, reducing query
  round trips on long connected authentication runs.
- Incident growth updates event assignments only for new or reassigned
  members; late merges still move all members of retired incidents.
- Persisted signal lookups use bounded batches of event identities instead of
  one query per incident member.
- Tail-appended authentication failures and successes reuse the incident
  aggregate; successes read up to three recent failures for sequence evidence.
  Late arrivals and merges retain the full rebuild.
- Authenticated retention preview counts older incident evidence, shadow-signal
  evidence, unlinked correlatable activity, and other unlinked events without
  modifying stored records; its top-rule breakdown helps inspect the unlinked
  remainder before choosing a policy.
- Newly ingested Wazuh SCA alerts retain bounded policy, check, and summary
  metadata in canonical attributes while omitting remediation and raw commands.
- Consistent SQLite backup and verification utility writes a private snapshot
  with SHA256, table counts, and integrity checks before retention work.
- Host-side Docker backup command copies a snapshot and manifest into a private
  directory only after verifying the host copy's digest, integrity, and counts.
- Snapshot-based JSONL archive exports older unlinked, noncorrelatable,
  unsignaled events and reconciles each record with the verified backup;
  the live store remains untouched.
- Isolated archive restore verifies the manifest and event stream, then creates
  a new private SQLite database containing only exported events; it refuses
  existing destinations and does not modify the live store.
- Read-only archive reconciliation compares a verified archive with a fresh
  verified snapshot to expose relinked, changed, missing, and newly eligible
  events before any retention decision.
- Authenticated retention preview defaults to a rolling 90-day window and
  accepts a bounded days override or an explicit timezone-aware cutoff;
  it reports the chosen window and leaves all stored evidence untouched.
- Verified-backup storage trend reports observed platform event, incident,
  and database-size changes across snapshots without touching the live store
  or extrapolating from short observation windows.
- Read-only Wazuh Docker measurement reports indexer data and manager/alert
  log allocation separately from the platform database, without touching
  the running volumes or printing alert content.
- Optional analyst-key mode requires a separate key for incident close actions,
  records the matched actor in durable history, and migrates existing history
  with null actors while leaving the current shared-key mode available.
- Read-only identity endpoint validates configured analyst credentials and
  reports the recognized actor or legacy shared mode without changing state.
- Incident workspace history shows the analyst name on attributed actions.
- Incident workspace allows a confirmed close of an open incident with a
  per-request analyst key, clears that field, and refreshes visible history.
- Analyst keys can explicitly grant or withhold close permission while legacy
  string keys retain that permission; identity reports the allowed action.
- Optional detailed evaluation reports identify detected, missed, and benign
  lookalike cases without event telemetry; runnable synthetic examples cover
  both authentication signals and preserve aggregate-only default output.
- Wazuh 4.14.8 single-node manager, indexer, and dashboard run on Apple Silicon Docker
  Desktop with loopback-only ports. SCA and manager-decoded synthetic SSH alerts
  reached the API; two SSH failures produced a durable incident.

## Current limits
- Correlation remains a user/host authentication rule, not cross-category
  detection. The stateful novelty observation is shadow-only and has no
  measured real-world precision. Late arrivals and merges in long connected
  runs still rebuild full incidents; incident bodies grow with evidence IDs.
  Unbounded event retention and per-identity known-IP sets limit throughput.
- The sequence signal is deterministic. Its priority is a heuristic; precision
  on representative real benign and malicious samples has not yet been measured.
- Merges preserve old links through aliases for newly retired IDs. Without
  analyst-key mode, the shared API key cannot attribute close actions;
  automated reopen and merge transitions have no human actor.
- The Apple Silicon Mac agent is enrolled and Active; a real rootcheck alert from
  agent 001 reached the API. Authentication correlation was tested with
  manager-decoded synthetic SSH logs, not a real login sequence.
- Older SCA events do not gain check metadata retrospectively on upgrade;
  the original Wazuh alerts remain the detailed source for those records.

## Next
1. Measure platform and Wazuh storage growth under the provisional 90-day
   active and one-year archive policy. Decide whether unlinked archived
   records may ever be deleted; require fresh backup, archive verification, and zero-drift
   reconciliation first. Bound incident update work for long correlation runs.
2. Evaluate stronger per-analyst authentication and read/ingest permissions before
   adding further UI response controls. The optional analyst keys govern close
   actions only; there is no live role-management or revocation interface.
3. Run both signal evaluations on permissioned benign lookalikes and malicious
   samples before considering shadow signal promotion.

Keep deterministic detection and evidence traceability through each slice.

## Captured OTRF telemetry milestone

- Checksum-pinned PurpleSharp host import preserves all 25,993 inspected records,
  provider-scoped mappings, timestamps, endpoint identities, and raw evidence references.
- Isolated production replay plus an offline cross-account password-spray detector
  produced one seven-event candidate on the inspected capture. A separate findings
  database supports UI evidence inspection without changing live per-user assignments.
- Publisher-documented spray case and per-case evaluator support are available;
  background remains unlabeled. Synthetic regressions test boundaries and isolation.
- Paired network capture import now preserves the original PCAP, reports parser
  coverage, and links 45 metadata buckets to nearby endpoint Sysmon connections.
  The authenticated UI separates paged network context from the seven spray events;
  readable accounts/origins, explanations, and expandable provenance support review.
- Next: held-out attack captures and benign lookalikes;
  ticket/share/remote-execution detection and cross-category relationships. Live spray
  ingestion and real-world accuracy remain unimplemented/unmeasured.
- Provenance-aware evaluation suites now pin labeled case files, keep synthetic
  controls and captured development/held-out results separate, reject capture or
  event overlap across partitions, and suppress performance metrics on single-label
  captures. Replay emits a development suite. No new held-out capture or representative
  benign measurement has been completed by this infrastructure change.
- Offline RC4 service-ticket burst detection adds a five-event investigation tied to
  the publisher-documented T1558.003 development simulation. Ticket status remains
  separate from logon outcome, and the UI distinguishes requester, service account,
  client IP, and issuing DC. Six synthetic controls expose a legacy-app false positive
  and a slow-attack miss. Shared network buckets preserve both investigations' host
  anchors (45 spray, 39 ticket buckets; 52 in their union).
  Live deployment, AES/slow/single-service detection, held-out
  evaluation, and representative benign measurements remain open.
- Independent captured-case evaluation now reserves two publisher-designated EVTX
  password-spray samples against frozen v1 detector digests. All 307 records are
  preserved; both cases are misses due to unsupported 4648/4771 telemetry rather than
  4625 logon failures. Positive-only metrics remain null. The reproducible optional
  EVTX workflow and historical results are in `CAPTURED_VALIDATION.md`. Fresh captures
  are required after using these results for development; representative benign and
  RC4-ticket held-out validation remain open.

Offline Windows authentication extension: separate explicit-credential fan-out (4648) and Kerberos
bad-password fan-out (4771/0x18) rules now preserve their evidence and enforce independent telemetry
families. Original baseline mappings and detector files stay unchanged. Reused captures are forced
into development partitions; fresh validation and representative benign testing are still pending.
See [Windows authentication development](WINDOWS_AUTH_DEVELOPMENT.md) for reproduction and scope.

Reviewed local capture validation now supports frozen Windows authentication implementations,
complete local EVTX exports and explicit malicious/benign/unlabeled review declarations. Known
inspected captures cannot be declared held out; unknown activity is excluded from accuracy metrics.
Representative benign exports and fresh labeled attack captures are still needed; the workflow does
not imply production accuracy or enable live rules. See [local validation](LOCAL_CAPTURE_VALIDATION.md).

Windows input collection now has a bounded read-only Security-log exporter, metadata/checksum sidecar,
and private EVTX preparation command. No auditing changes, generated attacks or automatic benign
labels are included. Native Windows CI exports existing logs and verifies Python record preservation;
this integration check does not complete representative benign or fresh labeled attack validation.
See [Windows collection](WINDOWS_CAPTURE_COLLECTION.md) for the Windows-to-Mac workflow.

Offline EVTX review is available in the investigation UI through authenticated read-only
endpoints. It validates bounded stored bundles, displays labels/partitions/checksums and
finding evidence separately from all capture records, and leaves live incident state untouched.
See [offline review](OFFLINE_REVIEW.md) for the Mac workflow. Fresh attack and representative
benign validation remain open.

Offline analyst assessment now appends disposition/note revisions in SQLite, bound to
capture metadata, run provenance, finding, and evidence. Named review permission, request
attribution, pagination, restart/backup persistence, and revision conflict checks are covered.
Analyst judgments do not change evaluation labels or scores.

Reviewed findings now have authenticated JSON export with complete selected evidence,
provenance, latest 100 saved review revisions, explicit history truncation/record omissions,
and content checksums. Stale fingerprints/revisions require reloading before download.
Original EVTX bytes and other capture records are referenced/omitted explicitly.

Real Chromium browser regression checks now run in CI against disposable synthetic
review servers: authentication, evidence, analyst saves and conflicts, downloads/hashes,
key cleanup and narrow layout. Reports/screenshots/failure traces are Actions artifacts.
This verifies UI behavior independently of the earlier DOM harness and does not change
detection-validation requirements.

Offline assessment queue implemented: current-fingerprint latest dispositions, pending-first
pagination, capture/disposition filters, global/per-capture workload counts, exact-finding
navigation and automatic refresh after saves. Latest revisions are read consistently in
SQLite; old/different-context journals are excluded. Browser coverage checks the queue flow.

Readable investigation reports now download as self-contained HTML using the existing
export authentication and revision checks. Summary, saved assessments, evidence overview,
provenance and complete selected JSON/XML remain distinct; print output explicitly omits
digital raw-data sections. Escaped notes, full evidence preservation, bounded overview and
real Chromium download/mobile/print behavior are covered.

Windows authentication validation now reports eligible telemetry using the detector's
shared grouping/record checks, disjoint exclusion counts and per-capture coverage status.
A missing-telemetry quiet result remains separate from usable inputs below threshold.
Both local validation and public development evaluation include this diagnostic; labels,
metrics, five-account thresholds and live enablement remain unchanged. Fresh attack and
representative benign exports are still required.

The first investigation tool slice now exposes three authenticated read-only operations over
validated offline snapshots with strict inputs, current-fingerprint checks, capture/time/entity
scope, original event references, explicit coverage and request/response budgets. Security
boundary tests cover scope escape, extra executable/query inputs, streamed bodies, oversized
responses and unchanged live/assessment state. The standards mapping and ordered MCP,
dedicated authorization, bounded reasoning, source-adapter and pilot gates are recorded in
[INVESTIGATION_ARCHITECTURE.md](INVESTIGATION_ARCHITECTURE.md). No model, MCP transport,
tenant isolation or autonomous response is enabled by this slice.

Dedicated investigation identities now enforce server-owned finding/fingerprint/tool grants,
separate credentials from platform/analyst keys, and reject other protected read/write routes.
Paginated scope discovery replaces the earlier incorrect queue-fingerprint setup instruction;
restricted callers see only configured grants, including stale status without replacement hashes.
Configuration and restart-based revocation are documented in INVESTIGATION_ACCESS.md. Remote
MCP authentication, tenant isolation, execution budgets and model reasoning remain separate gates.

Local stdio MCP transport now reuses the strict investigation contracts and server-owned grants
with SDK 2.3.0 pinned in an optional extra. One owner-private identity file and one validated
snapshot are loaded per process; broader platform credentials are rejected. The wrapper bounds
incoming frames, argument/result bytes and tool-call attempts, and returns metadata-only errors
and logs. Protocol integration tests include an actual stdio child and the Mac smoke command.
MCP_STDIO.md documents scope semantics and local trust. Remote authentication, hard execution
deadlines, tenant isolation and controlled model reasoning remain future gates.

The investigation controller foundation now fixes scope outside replaceable adapter decisions,
bounds decisions/tools/bytes/cooperative deadlines, validates exact observation references and
values, and saves private non-overwriting execution journals with response hashes. A deterministic
adapter and real MCP CLI verify the workflow without model API calls, score/label changes or
platform writes. INVESTIGATION_RUNNER.md documents the narrow citation guarantee and remaining
live model, provider token/cost, hard isolation, independent evaluation and durable audit gates.
