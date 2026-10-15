# Bounded investigation controller

The controller foundation runs a read-only investigation through the local MCP boundary, checks
exact observation citations and saves a private execution journal. It includes a deterministic
review adapter to verify the workflow. No language model is connected in this slice; this is
not an evaluation of autonomous reasoning or detection accuracy.

## Try the deterministic workflow on a Mac

Use a checkout containing this change and its MCP/scoped-identity prerequisites. Install
`.[evtx,mcp]` and complete [MCP setup](MCP_STDIO.md), including the private grant file.
The file's grants must already identify the finding you deliberately selected.

```bash
source .venv/bin/activate
python -m pip install -e '.[evtx,mcp]'
python -m adaptive_security.investigation_run \
  artifacts/investigation-access.json \
  artifacts/explicit-credentials-dev-v1 \
  artifacts/investigation-run-01.json
```

The default selects grant index zero. For a file containing multiple explicit grants, use
`--grant-index N` to select the intended scope. A real MCP child is launched with a minimal
environment; a running API server or Windows machine is not required. The demo reads up to five
finding records, candidate related events and capture-wide coverage where those tools are
granted, then proposes `needs_review` or `inconclusive`. It cites event categories and keeps
independent-context explanations under unverified hypotheses. These demo choices do not prove
an attack or resolve benign explanations.

The journal is created with owner-only permissions and will not overwrite an existing path.
Use a new filename for another run. It contains selected evidence and should stay private.
Failed/blocked runs are also saved after the controller starts; CLI exit code is 2 for those
runs or startup/save failures. Startup failures cannot produce a scoped journal.

## Controller and adapter contracts

`ReasoningAdapter.next_step(context_json)` receives an immutable JSON string containing the
controller's fixed scope, allowed tools, accepted result pages and an evidence trust notice.
It returns a strict decision object. The adapter never supplies capture/finding/fingerprint
arguments for tool calls; the controller constructs those from the operator-owned grant.

- Tool decision: `{kind: "tool", tool, limit, offset}`. No URL, path, command, credentials or
  arbitrary query is accepted. The tool must appear in this particular finding's grant.
- Finish decision: `{kind: "finish", disposition, observations, hypotheses}`. Dispositions are
  restricted to `needs_review` and `inconclusive`; no automatic malicious/benign classification.
- Observation: `{source, event_id, field, value}`. Fields are limited to action, outcome,
  source IP, category and event time. The reference must have been returned in an accepted page
  and the value must equal its normalized typed field. Free-form factual claims are not accepted.
- Hypotheses remain unverified text, explicitly separate from observations; their content never
  changes policy, invokes tools or writes platform state.

Citation checks establish membership/value consistency. They do not verify publisher honesty,
causality, semantic truth, capture completeness or a security verdict. Source data can still be
wrong. Future richer claims need a separate support/entailment design and independent evaluation.

Each response is checked against the requested scope, tool, pagination/relationship metadata,
and stable source checksum/rule binding. Conflicting versions of a returned record stop the run.
The runner uses the same MCP server authorization; it does not substitute for those checks.

## Budgets and execution history

Defaults are eight decisions, five tool calls, 128 KiB accumulated response data, 30 seconds
overall and five seconds per adapter/tool operation. Adapter output is limited to 8 KiB and
individual tool payloads to 64 KiB. Constructor budget bounds cap configured values. Model
context is derived only from accepted bounded results plus small controller metadata.

Async cancellation requires a cooperative adapter; arbitrary Python adapters are trusted code,
not sandboxed plugins. Blocking CPU work or an adapter that ignores cancellation requires process
isolation to enforce hard deadlines. The demo uses no model tokens or billed API calls. A live
model adapter must add provider token/output limits and usage/cost accounting before release.

The versioned journal includes run ID, adapter name, configured budgets, scope, status,
step/call/byte counts, accepted requests and projected responses, and a reviewed proposal only
after citation checks succeed. Invalid adapter output is summarized rather than reflected.
Checksums separately identify the received canonical JSON payload and the stored normalized
response; they are not signatures or proof of authorship. Stopped runs retain prior accepted
evidence and a terminal reason. The whole file is limited to 1 MiB and created without overwrite.

These local files are an execution history, not an append-only or tamper-proof audit service.
The runner does not modify analyst assessments, detector labels/scores or live incidents.
Durable audit integration, UI review and lifecycle controls remain separate work.

## Verification and next milestone

`tests/test_investigation_runner.py` checks exact citations, non-returned/invented references,
scope/action/classification escalation, immutable context, untrusted hypotheses, step/call/byte
budgets, cooperative deadlines, inconsistent responses, stable source binding, journal permissions
and hashes, overwrite rejection and a real MCP CLI execution without credential disclosure.

Next connect an opt-in local model adapter, keep controller policy outside its prompts, add
provider output/token accounting, and evaluate adversarial/contradictory/missing-data cases.
The deterministic adapter currently verifies plumbing and constraints, not model reliability.
