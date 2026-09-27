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

## Current limits
- Correlation is a precise user/host authentication rule, not behavioral or
  cross-category detection. Per-identity history scans and unbounded retention
  still limit throughput.
- The sequence signal is deterministic. Its priority is a heuristic; precision
  on representative real benign and malicious samples has not yet been measured.
- Incident IDs survive membership growth, but merging two incident runs retires
  one ID. Aliases for retired IDs and audited per-analyst lifecycle actions
  are still pending.
- Live Wazuh manager forwarding and ARM64 development topology are not yet validated.

## Next
1. Bounded history/retention, incident merge aliases, and auditable analyst actions.
2. Validate forwarding against a real Wazuh manager and document host access.
3. Validate the Compose topology on Docker Desktop and add operational signals.
4. Run the evaluation harness on permissioned benign lookalikes and malicious
   samples, then measure an adaptive capability before promotion.

Keep deterministic detection and evidence traceability through each slice.
