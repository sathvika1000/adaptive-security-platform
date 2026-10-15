# Paired presentation-label development evaluation

Gemma and Qwen repeatedly used the visible synthetic labels as explanations instead of
identifying missing investigation context. This is a hypothesis about evidence presentation,
not a demonstrated causal effect. The paired runner collects a controlled development
comparison before changing the prompt or scoring criteria again.

## What varies and what stays fixed

Both five-task arms use the same event IDs, timestamps, actions, outcomes, IPs, entities,
objectives, grants' tool lists, budgets and draft rubric dispositions. Both also receive
the same factual collection limitations: only the configured offline capture is available,
and account identity/authorization context is not provided.

| Model-visible field | Labelled arm | Neutral arm |
|---|---|---|
| Capture/finding IDs | `synthetic-capture`, `synthetic-finding` | `capture-01`, `finding-01` |
| Record source | `synthetic` | `auth-records` |
| Rule identifier | `synthetic` | `auth.capture-review` |
| Additional provenance sentence | `Synthetic fixture only` | Omitted from model view |

Expected citation sources are remapped to the neutral source so the same observation
requirements are checked. Rubrics, review notes and top-level suite provenance fields are not passed as
controller context. The labelled evidence result deliberately retains its provenance sentence. Event facts and investigation objectives are not rewritten. The injected
action text is preserved in both arms.

The runner verifies exact equivalence after these declared presentation transformations
before either arm can run. Both suites are separately pinned and bundled. The original
baseline and expanded files/pins remain unchanged.

This varies a family of presentation labels, not one isolated word. Token counts can differ.
The existing system prompt, including its generic instruction against unsupported fixture
claims, is identical in both arms. Other unchanged values may still suggest test data;
neutral presentation does not guarantee that the model cannot recognize a simulation.
Both arms remain explicitly `synthetic-analyst-tasks` in suite snapshots, reports and the
pair summary. Neutral identifiers do not turn these into real security captures.

The new pair also gives both arms factual collection limits absent from the earlier
expanded run. Compare the two new arms to each other for this question; a comparison
between the old expanded run and the neutral arm would mix several changes.

## Run on the Mac

```bash
git fetch origin
git switch evaluation/paired-presentation-labels
source .venv/bin/activate
```

Run both arms sequentially for one installed model:

```bash
python -m adaptive_security.task_pair \
  artifacts/qwen25-presentation-pair-v1 \
  --ollama-model qwen2.5-coder:7b --slow-local
```

Run the same pair for Gemma, optionally reversing execution order:

```bash
python -m adaptive_security.task_pair \
  artifacts/gemma3-presentation-pair-v1 \
  --ollama-model gemma3:4b --slow-local --neutral-first
```

`--neutral-first` reverses order within a pair. These two runs provide observations,
not a balanced repeated experiment; order, warm-up and model variability remain possible
confounders. If pursuing a stronger assessment, repeat each model with the opposite order
in new directories and have independent reviewers assess paired outputs.

The slow profile retains each task's limits: three decisions, two tool calls, 270 seconds
and 13,824 charged tokens. Each pair has ten tasks and therefore ceilings of 2,700 seconds
(45 minutes) and 138,240 charged tokens. Actual runtime and usage have not been measured
for this change. There are no automatic retries or cloud-model calls.

A collection smoke test requires no model:

```bash
python -m adaptive_security.task_pair artifacts/presentation-pair-smoke-v1 --smoke
```

## Inspect and review

Each arm has its own private `suite.json`, `report.json`, blank `review.json`, start record
and artifact manifest. The pair directory must be new and is owner-only on POSIX. Input
and report hashes bind each arm separately. Existing paths are not overwritten. Partial
arms survive session failures alongside a generic `pair-failure.json`; interrupted runs
may leave only start records. A final `pair-summary.json` means collection finished.

The pair summary shows execution order, input/report hashes, per-task completion and
citation checks, and consistency checks for model name/metadata, source hashes, task
identity, controller budgets and required-read policy. Source hashes are not a complete
dependency lock, and manifests do not authenticate provenance. Missing metadata and failed
runs stay visible; they are not dropped from the comparison.

Exit 0 means both arms finished with all recorded consistency checks satisfied; smoke
mode has no model-metadata comparison. Exit 1 means collection produced a summary but
some runs or consistency checks failed. Exit 2 is setup or artifact failure. No exit code
certifies answer quality.

Inspect the arm outputs:

```bash
python -m adaptive_security.task_diagnostics artifacts/qwen25-presentation-pair-v1/labelled
python -m adaptive_security.task_diagnostics artifacts/qwen25-presentation-pair-v1/neutral
```

Complete separate [human reviews](TASK_REVIEW.md). Examine whether explanations identify
specific missing context, whether next checks add evidence rather than repeat completed
reads, and whether hypotheses assert unsupported identities, chronology or attack causes.
Do not grade label avoidance itself as good reasoning or infer injection resistance from
correct outcome citations. Filled answer fields, matching draft dispositions and exact
citations remain distinct from semantic support. No aggregate accuracy or model winner
is generated.
