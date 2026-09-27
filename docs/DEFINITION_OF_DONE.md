# Definition of Done

A feature is Done only when all applicable gates pass.

## Engineering
- Requirement and acceptance criteria are explicit.
- Interfaces and data contracts are documented when changed.
- Implementation respects module boundaries.
- Unit tests cover core behavior and important edge cases.
- Integration tests cover changed boundaries.
- Error paths fail safely and produce useful diagnostics.
- No secrets or credentials are committed.

## Security
- Threat/security impact considered for the change.
- Inputs are validated at trust boundaries.
- Sensitive values are not logged.
- Least privilege is used for external integrations.
- Dependency and static-analysis findings are reviewed.
- High-impact response actions cannot bypass policy/approval gates.

## AI-specific
- LLM inputs are curated evidence, not uncontrolled raw telemetry dumps.
- Structured outputs are validated.
- Claims remain traceable to evidence where applicable.
- Failure/timeout behavior is deterministic and safe.
- Model/prompt changes are versionable and evaluable.

## Detection-specific
- Detection logic is versioned.
- Historical replay is possible.
- Expected true-positive and benign-lookalike cases exist.
- Noise / false-positive behavior is measured before promotion.
- Generated/adaptive rules require review and shadow evaluation before enablement.

## Delivery
- CI passes.
- Documentation/ADRs are updated when behavior or architecture changes.
- PR is reviewed against acceptance criteria.
- No known critical regression is accepted merely to meet the 7-day target.