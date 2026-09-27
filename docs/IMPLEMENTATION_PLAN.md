# Implementation plan

## Completed
- Canonical event and Wazuh alert normalizer.
- Deterministic incident model and builder (PR #2).
- SQLite event/incident persistence, authenticated ingestion and retrieval,
  and a tested two-alert authentication correlation path.

## Current limits
- Correlation is a precise user/host authentication rule, not behavioral or
  cross-category detection. Rebuilding all incidents per write is bounded
  only by available memory and work per request.
- Incident IDs are content-derived and change when membership changes;
  lifecycle updates require a stable identifier and incremental state model.
- Live Wazuh forwarding and ARM64 development topology are not yet validated.

## Next
1. Stable incident lifecycle and incremental, indexed event association.
2. Resource-conscious Wazuh forwarding adapter with real alert validation.
3. Container startup, replayable scenario, and operational signals.
4. Measure a specific adaptive capability against benign lookalikes before promotion.

Keep deterministic detection and evidence traceability through each slice.

