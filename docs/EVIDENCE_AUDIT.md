# Deterministic evidence brief and advisory next-check audit

This offline command audits existing saved task reports without calling a model, changing
provider context or rescoring a run. It creates a separate owner-only JSON artifact bound
to the original report hash. Original reports, pair summaries, reviews, task pins and
prompts remain unchanged.

## Run on the Mac

```bash
git fetch origin
git switch investigation/evidence-brief-audit
source .venv/bin/activate

python -m adaptive_security.task_audit \
  artifacts/qwen25-presentation-pair-v1/labelled \
  artifacts/qwen25-presentation-pair-v1/labelled/audit-v1.json

python -m adaptive_security.task_audit \
  artifacts/qwen25-presentation-pair-v1/neutral \
  artifacts/qwen25-presentation-pair-v1/neutral/audit-v1.json
```

Each command verifies the session report against its manifest pin. Use a fresh output
filename for revisions; existing files are never overwritten. Audit artifacts do not alter
the original manifest inventory. The command also accepts an individual report instead
of a session directory when `--report-sha256 DIGEST` is supplied. It verifies that exact
file before loading. Reports are capped at 8 MiB, accepted response payloads at 64 KiB,
and journals at 100 entries per task. A handled input/write failure exits 2; exit 0 means
an artifact was generated, not that an answer passed a quality assessment.

## Three separate parts

| Audit section | Meaning |
|---|---|
| `evidence_brief` | Application-generated descriptions of accepted returned fields and schema limits. |
| `model_draft` | The original conclusion, including unverified hypotheses and proposed checks. |
| `next_check_flags` | Narrow literal-pattern advisories for specific next-check problems. |

The brief distinguishes no accepted query, empty returned event pages, returned records
and coverage-only results. Empty pages do not prove an empty environment or complete
collection. Duplicate identical events are counted once; conflicting accepted versions
fail the audit. Accepted scope/tool/source bindings are checked. The bounded fact catalog
contains up to 40 exact returned field assertions with source/event references; oversized
values or identifiers are omitted, never shortened into apparent exact citations. Counts
still include all accepted records and omission is indicated. These are untrusted returned
assertions, not authenticated ground truth.

The gap catalog provides stable IDs, a rule basis, an analyst evidence-source category
and evidence needed. Rules identify collection completeness, unread event evidence,
missing user/account/principal references, absent authorization decisions in the tool
schema, unexplained failure outcomes and unestablished relationships between records.
A present identity reference does not prove account ownership or authorization. Multiple
records or shared timestamps alone do not establish a causal sequence or an attack.

These gaps describe the returned schema and records, not everything collected elsewhere.
Source categories are suggested evidence an analyst could consult, not assertions that
such a connector is installed or permission to call it. No live read or response action
is triggered. This catalog is a foundation for later typed gap-linked requests; the
existing model's free-text next checks are not silently converted into structured plans.
The artifact explicitly records that gap linkage is not encoded in the legacy text.

## Advisory flags

- `empty_or_placeholder`: exact normalized placeholders such as `None` or `None available`.
- `duplicate_suggestion`: suggestions equal after case/whitespace/punctuation normalization.
- `bare_tool_without_evidence_goal`: a recognized tool name without an investigation purpose.
- `repeats_completed_read`: a bare tool or narrowly recognized finding-read phrase referring
  to an exhausted accepted page (or an already returned coverage response).

The repeat check uses the latest accepted page. A non-exhausted page can still need
pagination. More specific free-text requests are deliberately not guessed to be repeats;
flags are advisory and cannot certify semantic equivalence. No flags is not evidence of
useful planning, supported hypotheses or injection resistance. The audit does not detect
all unsupported threat attribution, does not automatically approve conclusions and does
not assign model accuracy. Semantic review remains pending for every task.

## What to review next

Compare each proposed check with a specific gap and the evidence needed to resolve it.
Ask whether it adds information, whether the source actually exists and is authorized,
and whether it merely repeats a completed read. Keep speculative hypotheses separate
from returned facts. Future structured request selection must name an active gap and
an appropriate read-only evidence source and retain independent permission enforcement.
This change does not feed new context into the model or alter the saved evaluation baseline.
