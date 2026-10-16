# Shared scope for compact evidence-request proposals

The first inline-scope development run completed four of five tasks; the mixed-outcome task
was blocked by the adapter's truncation/context check. Repeating full scope in two requests
increases output size. Aggregate usage suggests output truncation, but does not supply a
per-request provider trace. Existing failed and completed results must be preserved.

`task_session --shared-request-scope` is a new opt-in protocol. It implies structured and scoped
requests. The controller derives `request_scope` from accepted tool results and computes its
SHA-256 using sorted, compact UTF-8 JSON. The context contains this object and `request_scope_ref`.
The provider returns `scope_ref` in each request, without an inline `scope` object.

At completion the controller checks every reference against its current derived context,
validates exact source/event/timestamp anchors, and stores the context once as run `shared_scope`.
Old references stop matching after a read changes the context. Missing, unbound or forged
references, inline-only requests and requests with both forms are rejected. Scope objects are
controller-derived metadata, not model-discovered facts. A digest binds bytes, not provenance,
source authorization or semantic quality. Original grant boundaries do not change.

The five-record context bound, unknown account/resource/collector fields, unresolved collection
interval and exact citation checks remain. No request is executed. Provider generation stays
at 512 output tokens and 4096 context tokens; per-task token, tool and time budgets are unchanged.
Old default, structured and inline-scope provider protocols remain available unchanged.

Audit independently resolves shared references against accepted journal results and reports
`validated_shared_context` or `missing_or_invalid_shared_scope`. The human review sheet includes
one `shared_scopes` entry per run; copied scopes and exact requests must remain unchanged.
Summary generation checks both. Absent optional fields are omitted from canonical request hashes
so existing legacy and inline request reviews continue to load without changing their pins.
The shared scope is available in diagnostics and audit output for inspection.

## Run on the Mac

Use a fresh directory; do not overwrite `artifacts/qwen25-scoped-requests-v1`:

```bash
cd ~/adaptive-security-platform
git fetch origin
git switch investigation/shared-request-scope
source .venv/bin/activate
python -m pip install -e '.[mcp]'
python -m adaptive_security.task_session \
  artifacts/qwen25-shared-scope-v1 \
  --suite-version neutral --shared-request-scope \
  --ollama-model qwen2.5-coder:7b --slow-local
python -m adaptive_security.task_diagnostics \
  artifacts/qwen25-shared-scope-v1
```

Inspect statuses and usage before preparing reviews. Then generate the offline audit:

```bash
python -m adaptive_security.task_audit \
  artifacts/qwen25-shared-scope-v1 \
  artifacts/qwen25-shared-scope-v1/audit-v1.json
cat artifacts/qwen25-shared-scope-v1/audit-v1.json
```

Use `request_review prepare` as described in `EVIDENCE_REQUEST_REVIEW.md` with the new folder.
Inspect the shared scopes together with request wording. Do not transfer prior human ratings
automatically. Hypothesis semantics still need separate task review: compact scope does not
address unsupported vulnerability or causal claims. This protocol changes response format,
so it is a development iteration rather than a controlled quality comparison. Automated tests
use mocks and deterministic adapters; actual model completion and quality remain to be measured.
