# Explanations linked to proposed evidence tests

The shared-scope development run completed all five tasks, but the offline worksheet exposed
weak reasoning: speculative causes were not consistently paired with requests that could test
them, and mixed outcomes with equal timestamps were described as a possible sequence without
requesting session correlation. Existing reports and assisted reviews remain development data.

`task_session --linked-tests` is an opt-in protocol that implies shared scope and structured
requests. Each request has a `tests` list naming explanations in the same conclusion, such as
`hypotheses:0` or `alternative_explanations:0`. Its existing `evidence_needed` field describes
what evidence to inspect and a possible result that could distinguish or weaken the linked
explanation. One request can test both explanations; supplementary requests can use `tests: []`.

For example, a proposed credential-error explanation and a service-fault alternative could
both link to a request for failure details, whose result would distinguish those possibilities.
That is a proposed test, not evidence that either explanation is true or that the source exists.

## Bounded response and controller checks

This profile allows at most one hypothesis and one alternative, each nonblank and at most
160 characters. Evidence goals are also capped at 160 characters. Either or both explanation
arrays may be empty when the model has no useful testable explanation. The profile does not
require an alternative merely because observations exist. Models should not restate an
observation as an explanatory hypothesis or invent a theory just to populate a field.

Every supplied explanation must have at least one declared testing request. References must
identify actual supplied explanations; duplicates within one request and missing coverage are
blocked independently of provider schema guidance. References supplied outside this profile
also undergo existence/duplicate checks. No cross-statement semantic interpretation is implied.

Exact observation citations, active gap/source links, shared scope digests, required evidence
reads and all existing grant boundaries remain enforced. Generation stays at 512 output tokens
and 4096 context tokens. Tool, token and deadline budgets are unchanged. The explanation caps
and response format change the protocol: this is not a controlled comparison with old runs.
No request executes queries or actions; current data do not establish new source authorization.

## Audit and review

The audit reports `statement_test_linkage` separately from gap/source and scope validation.
`structural_links_validated` means references exist and declared coverage satisfies the profile;
it does not mean the evidence goal actually tests an explanation. A graph can be well formed
and still semantically wrong. There is no automatic test-quality or hypothesis-support score.

The offline reasoning worksheet shows model-declared request links under each explanation.
These are testing intentions, not citations. Actual observation citations remain attached to
the whole conclusion; no per-statement evidence-support link is invented. Old reports show
that test links were not recorded rather than being marked as failures. Invalid links receive
a distinct state and are not rendered as accepted associations.

Request-review sheets include `statement_contexts` keyed by run ID. Exact request hashes bind
nonempty `tests`; copied explanation context is checked during summarization. Editing that
context invalidates the review. Older requests omit empty test lists when calculating hashes,
so archived request reviews remain compatible. Rating relevance still requires human judgment.

## Run on the Mac

Keep `artifacts/qwen25-shared-scope-v1` and its worksheet unchanged. Use a fresh directory:

```bash
cd ~/adaptive-security-platform
git fetch origin
git switch investigation/linked-explanation-tests
source .venv/bin/activate
python -m pip install -e '.[mcp]'
python -m adaptive_security.task_session \
  artifacts/qwen25-linked-tests-v1 \
  --suite-version neutral --linked-tests \
  --ollama-model qwen2.5-coder:7b --slow-local
python -m adaptive_security.task_diagnostics \
  artifacts/qwen25-linked-tests-v1
```

Inspect completion, citations, requests and model usage first. Then open the worksheet:

```bash
python -m adaptive_security.reasoning_audit \
  artifacts/qwen25-linked-tests-v1 \
  artifacts/qwen25-linked-tests-v1/reasoning-review-v1
open artifacts/qwen25-linked-tests-v1/reasoning-review-v1/index.html
```

For each declared test, judge whether the requested evidence could distinguish the explanation
from its alternative, whether unknown context remains explicit, and whether unsupported event
order or causation is still being suggested. Successful completion is not semantic approval.
Automated checks use mocks/deterministic adapters; actual local-model quality needs this fresh
run and human review. Assisted review is not independent validation or production readiness.
