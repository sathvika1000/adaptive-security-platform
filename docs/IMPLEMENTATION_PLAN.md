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
