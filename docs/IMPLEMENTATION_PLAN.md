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

## Current limits
- Correlation is a precise user/host authentication rule, not behavioral or
  cross-category detection. Rebuilding all incidents per write is bounded
  only by available memory and work per request.
- Incident IDs survive membership growth, but merging two incident runs retires
  one ID. Full recomputation remains expensive; indexed event association and
  audited per-analyst lifecycle actions are still pending.
- Live Wazuh manager forwarding and ARM64 development topology are not yet validated.

## Next
1. Incremental, indexed event association and auditable analyst actions.
2. Validate forwarding against a real Wazuh manager and document host access.
3. Validate the Compose topology on Docker Desktop and add operational signals.
4. Measure a specific adaptive capability against benign lookalikes before promotion.

Keep deterministic detection and evidence traceability through each slice.
