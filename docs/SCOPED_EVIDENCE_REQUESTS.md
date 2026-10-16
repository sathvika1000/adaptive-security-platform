# Evidence requests with explicit returned context

`task_session --scoped-requests` enables structured requests plus a required scope object.
It is opt-in; default and earlier structured-request provider inputs remain unchanged.
Original sessions and edited review sheets must be preserved.

Each scope contains:

- `event_references`: exact source, event ID and normalized timestamp for each unique record
  returned so far, sorted by source/ID in schema guidance. Empty pages yield an empty list.
  These are context anchors, not proof that events share identity or causal relationships.
- `collection_interval`: `status: requires_analyst_scope`, `start: null`, `end: null`.
  Observed event timestamps are not a collection interval, source coverage or permission.
- `account_scope`, `resource_scope`, `collector_scope`: `not_established`. Returned entity
  references, if any, do not establish ownership, authorization or connector access.

The controller derives this context from accepted tool results. Provider guidance requires a
copy; controller validation independently checks every supplied scope, including when the
profile is off. References must cover the returned context exactly, with no duplicates or
fabricated timestamps. Harmless reference reordering is allowed by the controller. More than
five unique records fails closed rather than silently truncating scope. Existing context,
response-schema, token, response-size, tool and deadline limits remain enforced.

This increment deliberately leaves the collection interval unresolved. Non-null interval
bounds and invented account/resource/collector identifiers are rejected. There is no support
for executing proposed collection queries or expanding tool grants. A future collection
workflow needs explicit source and time authorization; returned timestamps alone cannot
supply it. Identical timestamps do not establish order.

The offline audit distinguishes absent, validated, failed and missing-required scope. Human
request reviews bind the entire scope object. Legacy requests omit absent scope when computing
canonical request hashes, so old edited reviews remain compatible. Old report bytes are not
rewritten. The copied context improves explicitness, but it is controller guidance and is not
an independent model discovery or evidence of better reasoning. Request wording and relevance
still need human judgment. Updated review source hashes identify the new review implementation.

## Run on the Mac

Use a new directory; leave `artifacts/qwen25-structured-requests-v1` unchanged:

```bash
cd ~/adaptive-security-platform
git fetch origin
git switch investigation/explicit-request-scope
source .venv/bin/activate
python -m pip install -e '.[mcp]'
python -m adaptive_security.task_session \
  artifacts/qwen25-scoped-requests-v1 \
  --suite-version neutral --scoped-requests \
  --ollama-model qwen2.5-coder:7b --slow-local
python -m adaptive_security.task_diagnostics \
  artifacts/qwen25-scoped-requests-v1
python -m adaptive_security.task_audit \
  artifacts/qwen25-scoped-requests-v1 \
  artifacts/qwen25-scoped-requests-v1/audit-v1.json
cat artifacts/qwen25-scoped-requests-v1/audit-v1.json
```

The same frozen neutral suite and inference budgets are used, but provider schema and context
change. This is a development iteration, not a controlled quality comparison with the older
run. Automated validation uses mocks and deterministic adapters; actual model behavior remains
unmeasured until the local run. No accuracy, injection-resistance or readiness score is assigned.

To prepare a separate review after inspecting the new output:

```bash
python -m adaptive_security.request_review prepare \
  artifacts/qwen25-scoped-requests-v1 \
  artifacts/qwen25-scoped-requests-v1/request-review-v1.json
open -a TextEdit artifacts/qwen25-scoped-requests-v1/request-review-v1.json
```

Follow `EVIDENCE_REQUEST_REVIEW.md`. Consider the complete scope alongside the wording when
rating specificity. Do not automatically carry over prior ratings or treat copied constants
as a semantic quality pass. Any assistant-suggested assessment is assisted development review.
