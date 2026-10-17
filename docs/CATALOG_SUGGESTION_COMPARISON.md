# Catalog request-suggestion comparison

The schema-order development pair completed five tasks per arm with matched inputs. Both
orders produced empty explanation arrays and the same accepted conclusions. Their nine
requests per arm exactly repeated collection-health or identity suggestions supplied by the
controller's gap catalog. That wording overlap does not establish why the model chose them,
nor does it demonstrate independent request planning.

This probe compares two fresh sessions to test the influence of the supplied request text.
It is an experiment, not a replacement product default or a claimed quality improvement.

| Arm | Catalog presented to the model |
| --- | --- |
| `suggestions` | Existing catalog, including `evidence_needed` suggestions |
| `descriptions-only` | Same catalog with only each suggestion field removed |

Gap IDs, source categories, factual gap descriptions, entry order, objective, evidence records,
system instructions, source/time scope, inference limits and controller checks remain fixed.
Both arms use the empty-first linked conclusion schema. There are no new examples or target
answers. Hypotheses and alternatives may remain empty when evidence does not support a useful
explanation. The experiment does not require requesting every possible gap.

## Provider-only transformation

The controller continues to derive the full gap catalog and validate requests independently.
The local adapter removes `evidence_needed` only from entries in the top-level `evidence_gaps`
list of the model's user-context message. It does not recursively remove matching field names
from evidence or modify any accepted tool result. Response schemas are built from unchanged
controller context; IDs, exact citations, scope digests and explanation-test checks are intact.

Both arms keep the same system prompt. The description-only prompt is shorter by design;
possible effects include changed token counts and loss of ready-written examples. This probe
cannot isolate semantic copying from prompt-length or model-attention effects. Factual gap
labels/descriptions still guide both arms, so neither arm is unguided planning.

`catalog_presentation` is recorded in session started records, reports, manifests and local
adapter usage. It is not added as an experimental label in the model context. Defaults retain
the original catalog. Historic records lacking the field remain unrecorded; no presentation
provenance is reconstructed for them.

## Matched-request checks

The shared paired-session collector retains the previous schema-order experiment and adds a
catalog comparison path. For each constructed linked chat request, it records:

- The complete non-format payload digest, including both messages and generation settings.
- The schema digest, preserving mapping and array order.
- `catalog_normalized_payload_sha256`: the non-format payload digest after removing only
  catalog suggestion fields from the user-context message and serializing that context with
  sorted keys. Other payload values and mapping order are retained.

A catalog pair expects different original non-format payload digests, equal normalized payload
digests and equal schema digests. Comparisons are ordinal within a task. Different model-selected
tool pages can change later contexts; such mismatches are flagged rather than silently treated
as matched inputs. Missing old trace fields cannot satisfy the comparison.

The summary also checks suite hashes, source hashes, model metadata, budgets, read policy and
recorded presentation settings. It pins both saved reports and records execution order and
collector/entrypoint source digests. Hashes identify constructed data, not authenticated wire
captures, server execution, locked dependency versions or verified provenance.

Each arm's accepted answer is included in the summary alongside structural counts and status.
`exact_suggestion_matches` counts request goals that exactly equal the original suggestion for
their active gap. It is a wording-overlap diagnostic, not a quality score or causal copying
claim. Paraphrasing alone does not improve reasoning. Blocked conclusions have null accepted
answer/count fields. Private output and fresh-directory requirements remain enforced.

## Run on the Mac

Preserve all existing directories, including `artifacts/qwen25-schema-order-pair-v1`.

```bash
cd ~/adaptive-security-platform
git fetch origin
git switch evaluation/catalog-suggestion-comparison
source .venv/bin/activate
python -m pip install -e '.[mcp]'
python -m adaptive_security.catalog_pair \
  artifacts/qwen25-catalog-pair-v1 \
  --ollama-model qwen2.5-coder:7b --slow-local
```

The command runs five tasks per arm and prints/saves `pair-summary.json`, including the
accepted answers. Each arm has its own report, manifest and blank human-review sheet. If
needed, display the saved summary without rerunning inference:

```bash
cat artifacts/qwen25-catalog-pair-v1/pair-summary.json
```

Exit code 1 means a completion or comparison check failed; inspect the saved summary. Exit
code 2 means collection did not finish; partial sessions remain. Never overwrite an existing
session or edit report/manifest pins to force a pass. A later independent repetition can use
`--reverse-run-order` and a new directory, reversing arm execution without renaming them.

Judge answers independently: is the requested evidence relevant to the objective, specific to
the returned records, and clear about what it could resolve? For mixed outcomes, does it help
establish whether events share an identity/session without inventing sequence? For successful
authentication, does it preserve the distinction between success and authorization? An empty
capture calls for collection/context checks, not an invented event explanation.

Complete each arm's separate review only after inspecting its report. This small synthetic
pair does not provide held-out detection performance, production readiness or prompt-injection
resistance. Completion, more hypotheses, changed wording or fewer suggestion matches do not
establish semantic improvement. `--smoke` bypasses local inference and tests plumbing only.
