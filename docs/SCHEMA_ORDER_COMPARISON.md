# Linked conclusion schema order comparison

The first consistent-links Mac run completed all five tasks with no citation rejections.
Every accepted answer supplied empty hypothesis and alternative arrays and empty test links.
Requests mostly repeated collection-health and identity templates. This is operational progress,
not evidence of useful linked reasoning. The run is development evidence, not a control arm
with recorded request-level schema provenance.

One possible explanation is sensitivity to the ordering of the four provider-schema branches.
Other explanations include the prompt, task information, model capabilities and grammar
implementation. This experiment probes order sensitivity; it does not assume the cause or
promote a schema order as a product improvement.

## What changes

`python -m adaptive_security.schema_order_pair` collects two fresh neutral, linked-test sessions:

| Arm | Conclusion branch order |
| --- | --- |
| `empty-first` | neither, hypothesis only, alternative only, both |
| `populated-first` | both, alternative only, hypothesis only, neither |

Only `Conclusion.anyOf` is reversed in provider guidance. Definitions, property order, prompts,
objectives, facts, tool grants, required evidence reads and accepted-answer validation remain
identical. Either explanation array can still be empty. The controller still blocks dangling,
duplicate and uncovered explanation references. There are no answer repairs or forced theories.

Each task keeps its existing three-step/two-tool-call and 13,824-token budget. Generation stays
at 512 output tokens and 4096 context tokens. The slow-local profile retains its existing
request, operation and total deadlines. Each arm receives its own budgets; collecting both
arms doubles the number of task runs. No live SIEM calls or response actions are introduced.

## Recorded checks

Session started records, reports and manifests record `linked_schema_order`. Local adapter
usage additionally records the actual order and hashes for every constructed linked-protocol
chat request, including requests that subsequently fail or time out after dispatch begins:

- `non_format_payload_sha256`: the constructed chat payload with `format` removed, including
  system/user messages, model, generation options, stream setting and keep-alive setting.
- `format_sha256`: the actual constructed provider schema.
- `order_normalized_format_sha256`: the same schema with only `Conclusion.anyOf` sorted by
  canonical branch contents. Other mapping and array order is retained.

These digests use compact UTF-8 JSON without ASCII escaping and retain mapping insertion order.
They identify constructed payload values, not authenticated wire captures or server execution.
The normalized digest is a presentation check, not a general schema-equivalence solver.
Old runs lacking traces remain unrecorded; no historic schema provenance is reconstructed.

The pair summary pins both saved reports, records execution order and orchestrator source
hash, and compares suite hashes, source hashes, modes, model metadata, budgets and read policy.
It compares ordinal request payloads and schemas separately for each task. A model choosing a
different tool page can change later contexts; such requests are flagged as unmatched rather
than treated as a controlled comparison. Dependency/environment versions are not locked by
source hashes. Independently edited source or changed model metadata invalidates matching.

The summary reports accepted explanation, request and link counts alongside run status and
existing citation checks. A blocked conclusion has null counts, not zero accepted explanations.
No count measures semantic quality, injection resistance, detection accuracy or product readiness.
An arm with more explanations can simply contain more speculation.

## Run on the Mac

Preserve `artifacts/qwen25-consistent-links-v1` unchanged. Both comparison arms must be fresh:

```bash
cd ~/adaptive-security-platform
git fetch origin
git switch evaluation/schema-order-comparison
source .venv/bin/activate
python -m pip install -e '.[mcp]'
python -m adaptive_security.schema_order_pair \
  artifacts/qwen25-schema-order-pair-v1 \
  --ollama-model qwen2.5-coder:7b --slow-local
```

The command prints and saves `pair-summary.json`. It runs ten tasks across two sessions: five
per arm. Exit code 1 means one or more comparison/completion checks failed; the saved summary
and partial results remain inspectable. Exit code 2 means collection could not finish. Do not
rerun into the same directory or edit report/manifests to make checks pass.

To inspect answers, use existing diagnostics and worksheets:

```bash
python -m adaptive_security.task_diagnostics \
  artifacts/qwen25-schema-order-pair-v1/empty-first
python -m adaptive_security.task_diagnostics \
  artifacts/qwen25-schema-order-pair-v1/populated-first
python -m adaptive_security.reasoning_audit \
  artifacts/qwen25-schema-order-pair-v1/empty-first \
  artifacts/qwen25-schema-order-pair-v1/empty-first/reasoning-review-v1
python -m adaptive_security.reasoning_audit \
  artifacts/qwen25-schema-order-pair-v1/populated-first \
  artifacts/qwen25-schema-order-pair-v1/populated-first/reasoning-review-v1
```

Review each arm's answers independently using its own blank `review.json`. Check whether
explanations go beyond restating observations, proposed tests distinguish explanations,
missing identity/authorization context remains explicit, and equal timestamps are not treated
as event order. The prompt-injection fixture alone cannot establish injection resistance.

A later independent repetition can use `--reverse-run-order` and another fresh directory.
This reverses arm execution order, not the named schema orders. Sequential warm-up effects,
model nondeterminism and five synthetic cases limit causal interpretation even with matched
request hashes. One pair cannot prove an order effect or identify the best production format.
No winner or semantic score is assigned automatically. `--smoke` exercises file plumbing and
checks only; it bypasses model/schema sampling and cannot test order sensitivity.


## Follow-up on supplied catalog wording

The initial Mac pair completed all tasks in both arms with identical accepted conclusions and
no explanations or test links. Request goals repeated ready-written catalog suggestions. See
[the catalog-suggestion probe](CATALOG_SUGGESTION_COMPARISON.md) for a fresh comparison that
removes only those model-facing suggestion fields while holding schema order fixed. The
initial pair remains an unchanged development observation, not proof of order insensitivity.
