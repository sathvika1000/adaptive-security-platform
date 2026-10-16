# Structured evidence-request development

`task_session --structured-requests` enables an opt-in planning protocol. Each proposed
request contains `gap_id`, `evidence_source` and bounded `evidence_needed` text. The controller
recomputes active gaps from accepted tool results and requires matching source categories.
It blocks duplicate gap/source pairs, missing requests, and mixed free-text `next_checks`.
Required evidence reads and exact observation checks still apply independently.

The provider schema offers only current gap/source pairs. Controller validation remains
necessary when a provider ignores that schema. Requests supplied outside the opt-in mode
also undergo link validation. Older reports default to an empty request list and policy off.
The default paired-presentation protocol remains unchanged.

These are proposals for an analyst. Source categories do not establish connector availability,
permission, or collection completeness. Text may still be vague, mistaken, or malicious;
a valid link does not approve its meaning. No request executes a query, command, connector,
or response action. The offline audit independently checks links against accepted journal
results and leaves semantic review pending.

## Local evaluation

Use a fresh output directory on the Mac with Ollama running:

```bash
git fetch origin
git switch investigation/gap-linked-evidence-requests
source .venv/bin/activate
python -m pip install -e '.[mcp]'
python -m adaptive_security.task_session \
  artifacts/qwen25-structured-requests-v1 \
  --suite-version neutral --structured-requests \
  --ollama-model qwen2.5-coder:7b --slow-local
python -m adaptive_security.task_diagnostics \
  artifacts/qwen25-structured-requests-v1
python -m adaptive_security.task_audit \
  artifacts/qwen25-structured-requests-v1 \
  artifacts/qwen25-structured-requests-v1/audit-v1.json
cat artifacts/qwen25-structured-requests-v1/audit-v1.json
```

Review the cited observations, request relevance, specific missing context, and whether each
proposed source could resolve that gap. Confirm that empty evidence is distinguished from an
unread source. Complete the separate review sheet using `docs/TASK_REVIEW.md`.

This changes model context and response format; do not treat it as a controlled comparison
with an older session. Suite bytes and inference budgets are unchanged. Automated tests use
deterministic adapters or mocked inference, not a measurement of actual model reasoning.
There is no semantic pass score, production-readiness claim, or detector accuracy estimate.
