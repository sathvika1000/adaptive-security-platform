# Run and collect a local-model evaluation session

This command bundles the three draft analyst tasks, executes them and prepares a blank
human-review sheet. It works without Windows, an API key or a running platform container.
Actual model inference runs on your own trusted loopback Ollama daemon.

Install this branch's code in your existing environment:

```bash
git fetch origin
git switch validation/single-command-task-session
source .venv/bin/activate
python -m pip install -e '.[mcp]'
```

The branch includes the earlier task, controller and review changes; a plain pull of
main will not fetch unmerged functionality into your working tree. Git may refuse to
switch with conflicting local changes; preserve your work before switching.

With your Ollama daemon running and `gemma3:4b` already installed:

```bash
python -m adaptive_security.task_session \
  artifacts/gemma3-session-v1 --ollama-model gemma3:4b
```

To verify the collection path without inference:

```bash
python -m adaptive_security.task_session \
  artifacts/smoke-session-v1 --smoke
```

Choose a new output folder for every attempt. Existing directories and symlinks are
rejected before inference. The folder is owner-only on POSIX; its files are also
owner-only. Keep these files private when they contain model answers or reviewer notes.
The built-in task bytes are hash-pinned and included in the installed package, so the
command can also run outside the repository. Changing tasks requires updating the
versioned example, bundled copy and pin together.

## Files created

| File | Purpose |
|---|---|
| `started.json` | Records start mode, model name and bundled input hash; does not assert completion. |
| `suite.json` | Exact bytes of the bundled synthetic development tasks. |
| `report.json` | Objectives, rubrics, controller journals, conclusions, automatic checks and model usage. |
| `review.json` | Blank assessments bound to the original report hash and task/run IDs. |
| `manifest.json` | Final inventory with file hashes, mode, run statuses and review-pending state. |
| `failure.json` | Present on handled session-generation failure; partial files are retained. |

Exit 0 means every task run completed, not that the model answered correctly. Exit 1
means a valid session was saved with one or more incomplete runs. Inspect `report.json`
for blocked, timeout, budget-exhausted or failed statuses. Exit 2 indicates a setup or
file-generation failure. A process interruption may leave only partial artifacts with
`started.json`; absence of `manifest.json` means session generation did not finish.
Retry with a new folder rather than deleting or overwriting diagnostic files.

## Review next

Read `report.json`, then fill `review.json` following [the review guide](TASK_REVIEW.md).
The manifest records the report hash for the `--report-sha256` option. After editing
the review, compute its new hash with `shasum -a 256` and use it when summarizing the review.
The manifest's review hash identifies the original blank sheet, not your later assessment.
Never include the manifest itself as proof of authenticated provenance.

The deterministic smoke adapter deliberately misses some requested observations; a
completed smoke run supplies no evidence about Gemma. Local-model runs use the existing
per-task ceilings: three decisions, two tool calls, 90 seconds and 13,824 charged tokens.
The three tasks run sequentially. No real model results are shipped with this command.
The tasks and their rubrics remain draft synthetic development material requiring
independent review. No held-out accuracy, production readiness or live response is inferred.

## When local inference times out

A report with some confirmed prompt/generated tokens, `status: timeout` and an
`unconfirmed_requests` count indicates that some responses were processed but at least
one request did not reach confirmed usage accounting before a deadline. It does not
establish why that request was slow or whether the resulting answer would be valid.
Do not treat a timeout as a wrong security conclusion or return its token reservation.

For a slower local evaluation, preserve the first session and run in a new directory:

```bash
python -m adaptive_security.task_session \
  artifacts/gemma3-session-slow-v1 --ollama-model gemma3:4b --slow-local
```

The default profile is unchanged: HTTP timeout 25 seconds, controller operation deadline
30 seconds and total task deadline 90 seconds. The opt-in slow profile uses 85 seconds
for the HTTP timeout, 90 seconds per controller operation and 270 seconds per task.
The three-task suite may therefore take up to 810 seconds (13.5 minutes). Controller
bounds remain finite: operation deadlines cannot exceed 120 seconds and task deadlines
cannot exceed 360 seconds. HTTP client timeouts are phase timeouts; the controller
provides the overall operation deadline.

Both profiles retain three decisions, two tool calls, 13,824 charged tokens per task,
512 maximum generated tokens per request and the same evidence/citation checks. The
actual controller deadlines are included in every task's report; the session's start
record and manifest also record the slow-profile selection. `--slow-local` requires
`--ollama-model` and cannot be used for smoke mode. The lower-level
`investigation_tasks` CLI accepts the same option.

If the slower run also times out, inspect its task journals before changing other
limits. More time does not repair an invalid decision, repeated read or unsupported
citation. Do not overwrite the original run or infer model accuracy from completion.

## Inspect rejected proposals

After a session, inspect it without making any model requests:

```bash
python -m adaptive_security.task_diagnostics artifacts/gemma3-session-slow-v1
```

The command verifies `report.json` against the manifest's recorded file hash and prints
per-task status, usage, schema-valid proposals and citation rejection comparisons.
New reports retain proposals separately from accepted conclusions. Each proposal is
explicitly untrusted, bounded by the existing 8 KiB decision cap and step limit, and
cannot trigger an extra tool call. Rejected citations record whether the event had not
been returned or the requested field value differed, including the observed value.
No citation is repaired, inferred or accepted by this logging path.

A tool-call budget stop alone does not prove a repeated page; inspect the proposed tool,
limit and offset to identify the requested reads. A citation rejection alone does not
prove prompt injection succeeded. These outcomes show missing valid conclusions, not
security verdicts or a model-quality pass.

Older reports contain no saved proposals and the inspector reports them unavailable;
it cannot reconstruct discarded model answers. Preserve those original runs. To collect
new diagnostics, use a fresh folder:

```bash
python -m adaptive_security.task_session \
  artifacts/gemma3-session-diagnostic-v1 --ollama-model gemma3:4b --slow-local
python -m adaptive_security.task_diagnostics artifacts/gemma3-session-diagnostic-v1
```

Only decisions that satisfy the decision schema and size checks are logged. Invalid raw
provider text, commands in unknown fields and arbitrary exceptions are not retained.
Proposal text and comparison values can still contain sensitive or malicious strings;
keep diagnostic output private and treat it as data. This change adds observability,
not a prompt correction or model-quality improvement. Token, tool, deadline and citation
acceptance policies are unchanged.
