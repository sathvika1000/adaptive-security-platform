# Evidence-request question guidance comparison

The catalog-removal development pair completed all tasks with matched inputs. Without supplied
request sentences, goals were often only source-category labels, or status shorthand such as
collector_health:unhealthy. Some chosen categories were more relevant to their cases, but the
requests did not reliably explain what evidence to inspect or which uncertainty it would resolve.
No health or availability status in those proposed requests is an established observation.

This experiment tests clearer request instructions. It does not force explanations, change
response fields, add content rejection rules, repair answers or promote a new production default.

| Arm | Catalog | Schema order | System instructions |
| --- | --- | --- | --- |
| `baseline` | Descriptions only | Empty-first | Existing instructions |
| `questions` | Descriptions only | Empty-first | Existing instructions plus question guidance |

The added segment asks each evidence_needed goal to be a concise investigation question,
identify the record/field to inspect, and explain the uncertainty it could resolve. It discourages
merely repeating source categories, supplying a desired answer, or asserting unobserved health
or availability. It refers to event IDs when available and source/time coverage when no events
are available. It allows useful requests with empty explanations and empty test lists.

The exact text is versioned in `src/adaptive_security/request_guidance.py`. It provides no
case-specific examples, desired dispositions or rubric answers. This is instruction guidance,
not a requirement for question marks, keyword matching, longer text or invented theories.

## Fixed controls and provenance

Both arms use the same frozen neutral suite, objectives, returned evidence, catalog descriptions,
gap IDs, source categories, read policy, grants, response schema, citation checks and shared
scope. Catalog request suggestions remain removed in both arms. Existing generation limits,
tool budgets and deadlines remain unchanged. Additional prompt text changes prompt length
and can change token use or timing; this pair cannot isolate wording from length effects.

`request_guidance` is recorded in started records, reports, manifests and actual local adapter
usage. It is not exposed as an experimental label in the model's user context. Defaults remain
baseline, and older records default to unrecorded provenance rather than inferred baseline use.
The existing catalog and schema-order comparisons remain available, with this new profile held
fixed. Selecting two comparison changes together is rejected before creating output.

Each constructed linked chat request records `guidance_normalized_payload_sha256`, the digest
of the non-format payload after removing only the exact known guidance suffix from the system
message. User evidence, settings, other instructions, catalog content and mapping order remain
untouched. The existing original payload and schema digests are also retained.

The guidance pair expects different original payload digests, equal guidance-normalized payload
digests, and equal schema digests. Extra instruction changes, altered evidence or model-selected
pages can invalidate matching; the collector records these mismatches instead of silently
normalizing them away. Missing old traces cannot satisfy matching. Hashes identify constructed
request values, not authenticated server execution or locked environment dependencies.

The summary pins both reports, records execution order and source hashes, checks recorded
profiles and model metadata, and includes both complete accepted answers. Counts and exact
catalog wording overlap remain structural diagnostics; no automatic semantic winner or score
is assigned. Blocked runs retain status/reason and null accepted conclusions.

## Run on the Mac

Keep all existing sessions, especially `artifacts/qwen25-catalog-pair-v1`, unchanged.

```bash
cd ~/adaptive-security-platform
git fetch origin
git switch evaluation/request-question-guidance
source .venv/bin/activate
python -m pip install -e '.[mcp]'
python -m adaptive_security.request_guidance_pair \
  artifacts/qwen25-request-guidance-pair-v1 \
  --ollama-model qwen2.5-coder:7b --slow-local
```

The command collects five tasks per arm in separate fresh sessions and prints/saves a summary
including accepted answers. To display the saved summary without rerunning inference:

```bash
cat artifacts/qwen25-request-guidance-pair-v1/pair-summary.json
```

Exit 1 means a comparison/completion check failed; inspect saved outputs. Exit 2 means collection
could not finish; partial sessions remain. Use a fresh directory for retries. A later repetition
can use `--reverse-run-order`, which changes execution order rather than profile names. Each
arm has its own report, manifest and blank review sheet for separate human review.

Review the actual goals: would an analyst know what to inspect, which returned records are
relevant, and what the proposed evidence could resolve? Does a goal ask a question rather than
presuppose collector failure or unavailable data? Does it respect missing identity, authorization,
collection scope and event relationship information? Empty hypotheses can be appropriate when
facts do not support a useful explanation. More questions, more text, fewer copied labels or
more explanations are not themselves improvements.

Automated tests exercise exact prompt changes, input matching, schema equality and file plumbing
with mocked replies; they do not establish that the prompt helps a real model. Smoke mode bypasses
model sampling entirely. This small, sequential synthetic development pair does not establish
held-out performance, production readiness or prompt-injection resistance. Human judgment,
model variability, prompt-length effects and execution-order effects remain limitations.
