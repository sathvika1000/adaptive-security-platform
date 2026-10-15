# Answer-quality development after the first assisted review

The first grounded Gemma development run completed all three tasks, but the assisted
review recorded missing collection explanations, weak alternatives and an unsupported
fixture-behavior hypothesis. This change provides places to express those concepts and
adds two development cases. It does not claim that the model's answers have improved.

## Answer fields

Conclusions can now include three explicit arrays:

| Field | Intended content |
|---|---|
| `alternative_explanations` | Plausible interpretations expressed as uncertain possibilities. |
| `collection_limits` | Specific absent evidence and the inference that absence prevents. |
| `next_checks` | Evidence an analyst could review to distinguish those possibilities. |

Each contains at most three entries of 1–512 characters. For local structured generation,
the provider schema requires collection limits and next checks, and requires at least
one alternative when citable observations exist. Empty evidence can have no assessable
alternatives. The prompt asks for concise entries, relevant objective-directed citations,
no unsupported fixture or false-positive assertions, and no executable commands.

The core conclusion schema keeps defaults of empty arrays for old adapters and reports.
Provider instructions can still be ignored. The controller checks structure, citations,
permissions and budgets; it does not certify the truth or usefulness of free-text fields.
Proposed checks are inert text and cannot cause tool execution. No live actions are added.

Per-task `checks.answer_structure` records whether these fields contain nonblank text.
This is presence only: generic, misleading or irrelevant entries can still be present.
Every answer remains `pending-human-review`; no semantic score or automatic approval is
assigned. Use the existing four review dimensions to assess the complete answer, including
these fields. New reports include them in proposals and accepted conclusions.

## Versioned development cases

The default `baseline` suite remains the original three tasks with the original byte pin
and draft rubric. Its previously reviewed artifacts are never modified or rescored.
The opt-in `expanded` suite includes those exact three tasks plus:

- Successful authentication without authorization context: a success is not proof of
  authorized access, benign behavior or compromise.
- Mixed authentication outcomes: cite both observations without assuming a causal
  sequence from event IDs, and identify missing account/timing/session context.

Both suites are synthetic development material. The new cases and draft triage expectations
need independent analyst review. Adding cases after observing model behavior does not
make them held-out evidence. In particular, the original failed-logon `needs_review`
expectation remains a draft; an inconclusive disposition can be defensible. No expected
disposition was changed to make a model pass.

## Run on your Mac

Switch to the branch containing this change, retaining earlier artifacts:

```bash
git fetch origin
git switch investigation/explicit-answer-context
source .venv/bin/activate
```

First compare the revised answer format on the same three baseline tasks:

```bash
python -m adaptive_security.task_session \
  artifacts/gemma3-answer-context-baseline-v1 --ollama-model gemma3:4b --slow-local
python -m adaptive_security.task_diagnostics artifacts/gemma3-answer-context-baseline-v1
```

Then use new development cases without overwriting either baseline:

```bash
python -m adaptive_security.task_session \
  artifacts/gemma3-answer-context-expanded-v1 \
  --ollama-model gemma3:4b --slow-local --suite-version expanded
python -m adaptive_security.task_diagnostics artifacts/gemma3-answer-context-expanded-v1
```

`--suite-version baseline` is the default. The expanded suite's exact bytes are pinned
and copied into each session. The start record and manifest identify the suite version;
reports and review sheets bind the selected input digests. Existing files are not reused.

Per-task ceilings remain three decisions, two tool calls, 13,824 charged tokens and
512 generated tokens per response. With the slow profile, the baseline has a configured
ceiling of 810 seconds and 41,472 charged tokens, and expanded has 1,350 seconds (22.5
minutes) and 69,120 charged tokens. These are ceilings, not measured runtimes or usage.

A deterministic smoke run can test collection with `--smoke --suite-version expanded`;
it does not supply the new explanations or measure model quality. Review actual local
outputs in new review sheets, recording whether collection limits are specific, alternatives
are defensible, and proposed checks would resolve the stated uncertainty. Preserve the
original assisted review as its own baseline, not an independent validation result.
