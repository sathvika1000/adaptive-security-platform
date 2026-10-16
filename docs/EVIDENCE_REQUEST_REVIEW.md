# Human review of evidence requests

This separate review assesses accepted request proposals without another model run. It does
not change the original report, task review, frozen suite, or audit. It does not execute requests.

Each row includes the task objective, current deterministic gap basis, original request, task/run
IDs, zero-based request index and SHA-256 of its canonical JSON. The review is also bound to the
original report bytes and suite semantic digest. Summary generation reloads the pinned report,
reconstructs accepted journal evidence and checks current gap/source links. Every exact request
and its copied context must appear once; assessment rows may be reordered. Editing copied
request text or context invalidates the review. Hashes identify content, not authentic authorship.

Only completed conclusions supply requests. Tasks without accepted requests appear in the
summary inventory with zero requests; rejected model proposals are excluded. Preparation fails
when the report contains no accepted requests. This workflow can be used on existing sessions.

## Prepare and edit

```bash
git fetch origin
git switch evaluation/evidence-request-review
source .venv/bin/activate
python -m adaptive_security.request_review prepare \
  artifacts/qwen25-structured-requests-v1 \
  artifacts/qwen25-structured-requests-v1/request-review-v1.json
open -a TextEdit artifacts/qwen25-structured-requests-v1/request-review-v1.json
```

Fill `reviewer`, then all three ratings and `notes` for every assessment. Leave the copied IDs,
request, objective, gap basis and digests unchanged. Use these rating values:

| Dimension | Question |
| --- | --- |
| `relevance` | Does this request address the task objective and a material uncertainty? |
| `specificity` | Does it identify evidence and scope precisely enough for an analyst to pursue? |
| `gap_resolution` | Could the requested evidence distinguish explanations or resolve the named gap? |

For each dimension, choose `supported`, `concern`, or `not_assessable`. `supported` means your
judgment supports that dimension, not that the evidence exists or source access is authorized.
Use `not_assessable` when available context cannot support the judgment; explain why in notes.
A valid gap/source link alone is insufficient for a supported rating. Do not fill ratings merely
to make a summary command succeed.

For example, collector health and time coverage can help interpret an empty returned page.
An authorization-policy request may be relevant later, yet less immediately useful before
collection coverage is understood. For mixed outcomes, identity context may help, while a
separate session-correlation request could address an unresolved relationship. This review
does not score omitted requests: record such concerns in notes and inspect the complete audit.
Evaluate model hypotheses separately using the existing task review.

## Summarize after saving the completed review

```bash
REQUEST_REVIEW_SHA=$(shasum -a 256 \
  artifacts/qwen25-structured-requests-v1/request-review-v1.json | awk '{print $1}')
python -m adaptive_security.request_review summarize \
  artifacts/qwen25-structured-requests-v1 \
  artifacts/qwen25-structured-requests-v1/request-review-summary-v1.json \
  --review artifacts/qwen25-structured-requests-v1/request-review-v1.json \
  --review-sha256 "$REQUEST_REVIEW_SHA"
cat artifacts/qwen25-structured-requests-v1/request-review-summary-v1.json
```

The session manifest supplies the report digest. To review a standalone report file, replace
the session-directory argument with that file and supply `--report-sha256` to either command.
Outputs use owner-only permissions and refuse overwrites. Use fresh versioned output names
for another preparation or summary; preserve earlier versions. File inputs are bounded.

Summaries retain all rating counts including not-assessable entries, exact assessments,
per-task request counts, review source hashes, and the edited review-file digest. There is no
aggregate pass score, model accuracy, injection-resistance claim or production approval.
Attribution is self-declared; assisted development review is not independent validation.
