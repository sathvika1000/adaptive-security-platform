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

## Current limits
- Correlation remains a user/host authentication rule, not cross-category
  detection. The stateful novelty observation is shadow-only and has no
  measured real-world precision. Long connected runs, unbounded event retention,
  and unbounded per-identity known-IP sets limit throughput.
- The sequence signal is deterministic. Its priority is a heuristic; precision
  on representative real benign and malicious samples has not yet been measured.
- Merges preserve old links through aliases for newly retired IDs. The shared
  API key cannot attribute lifecycle actions to individual analysts.
- Live Wazuh manager forwarding and ARM64 development topology are not yet validated.

## Next
1. Event retention, long-run handling, and identity-aware analyst actions.
2. Validate forwarding against a real Wazuh manager and document host access.
3. Validate the Compose topology and readiness on Docker Desktop.
4. Run both signal evaluations on permissioned benign lookalikes and malicious
   samples before considering shadow signal promotion.

Keep deterministic detection and evidence traceability through each slice.
