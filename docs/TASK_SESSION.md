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
