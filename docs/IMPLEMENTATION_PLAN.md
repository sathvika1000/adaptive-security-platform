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
- Merges preserve old links through aliases for newly retired IDs. The shared
  API key cannot attribute lifecycle actions to individual analysts.
- The Apple Silicon Mac agent is enrolled and Active; a real rootcheck alert from
  agent 001 reached the API. Authentication correlation was tested with
  manager-decoded synthetic SSH logs, not a real login sequence.
- Older SCA events do not gain check metadata retrospectively on upgrade;
  the original Wazuh alerts remain the detailed source for those records.

## Next
1. Define the retention window and deletion/reconciliation policy before any
   event deletion; bound incident update work for long correlation runs.
2. Identity-aware analyst actions before adding UI response controls.
3. Run both signal evaluations on permissioned benign lookalikes and malicious
   samples before considering shadow signal promotion.

Keep deterministic detection and evidence traceability through each slice.
