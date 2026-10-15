# Local-model investigation tasks (draft)

These three synthetic tasks evaluate whether an adapter retrieves finding evidence,
cites requested observations and produces a disposition consistent with a draft rubric.
They cover a failed logon, no available evidence, and an instruction embedded in an
event's action field. The tasks and rubrics need independent security-analyst review.
They are development fixtures, not a held-out model benchmark or customer validation.

The adapter sees the investigation objective, permitted tool names and returned evidence.
It never receives rubric claims, review notes or expected dispositions. The fixture channel
answers requests by tool and requested page, rather than assuming a scripted call order.
The controller retains its existing fixed scope, citation checks and budgets.

## Run on your Mac

No Windows capture or platform API key is required. From the repository root:

```bash
source .venv/bin/activate
python -m pip install -e '.[mcp]'
python -m adaptive_security.investigation_tasks \
  examples/evaluation/analyst-tasks.json \
  artifacts/analyst-tasks-smoke-v1.json \
  --suite-sha256 SUITE_DIGEST \
  --smoke
```

Published file SHA-256:

`0d7d919ead8f04304204fa3e4fd821b2afb3cd19a767f6d1a6f8ad98a003ad12`

Replace `SUITE_DIGEST` with that value. Smoke mode uses the
existing deterministic demo adapter. It checks the execution/report path only: that
adapter cites category fields and will miss the task's requested outcome observations.
This deliberate mismatch remains visible in the report.

For an actual model run, ensure your trusted local Ollama daemon is running and your
chosen model is available. Then run with a different output path:

```bash
python -m adaptive_security.investigation_tasks \
  examples/evaluation/analyst-tasks.json \
  artifacts/analyst-tasks-gemma3-v1.json \
  --suite-sha256 SUITE_DIGEST \
  --ollama-model gemma3:4b
```

This uses the existing bounded loopback Ollama adapter. Each task gets at most three
decisions, two tool calls, 90 seconds total, 30 seconds per operation and 13,824 charged
tokens. All three tasks run sequentially, so the configured total is at most 270 seconds
and 41,472 charged tokens. These are ceilings, not expected performance or memory estimates.
There is no inference result bundled with this change; mocked adapter tests are not
measurements of Gemma or your Mac. Do not pass cloud-model names.

## Review the report

The report includes the original and canonical suite hashes, relevant source hashes,
per-task journals, effective budgets and model usage/metadata when available. POSIX
reports are owner-only and existing paths are never overwritten. Use a new filename
for each run. Source hashes are identifiers, not a complete reproducible environment.

Checks show completion, required distinct observations cited, and disposition match.
They do not produce an overall accuracy score. Every task remains marked
`pending-human-review`, including when all automatic checks match. In particular:

- A failed logon alone does not prove password spraying or compromise.
- Empty evidence does not establish benign activity or collection completeness.
- Citing the right outcome does not prove that injected instructions were ignored.

Review each hypothesis for unsupported attribution, omitted alternative explanations,
missing collection context and instructions followed from event text. Record independent
review separately before promoting these draft tasks into a frozen assessment set.

CLI exit 0 means a report was generated, not that the model passed. Invalid inputs or
output-write failures exit 2. Inspect per-task statuses for blocked, timeout, exhausted
or failed runs; these remain in the report and denominator. The controller replay suite
in `REASONING_EVALUATION.md` remains a separate enforcement regression check. Neither
suite measures detector precision/recall or exercises live MCP/SIEM/EDR systems.

Use [the task review workflow](TASK_REVIEW.md) to create a separate content-bound
human assessment, record rationale and summarize explicit ratings without changing the run.

For automatic input pinning, result collection and blank review creation, use the
[single-command task session](TASK_SESSION.md).
