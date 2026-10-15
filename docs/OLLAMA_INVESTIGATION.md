# Opt-in local model investigation

The bounded runner can now use a local Ollama model to propose its next read-only tool call
or review conclusion. It uses the official [chat API](https://docs.ollama.com/api/chat) and
[structured JSON schema output](https://docs.ollama.com/capabilities/structured-outputs).
The controller still owns scope, permissions, deadlines, output validation and exact citations.
Provider schema constraints and system prompts are not authorization controls.

## Try it on your Mac

Use a checkout containing this change and its runner/MCP/identity prerequisites. Complete the
[private grant setup](INVESTIGATION_ACCESS.md) and the [MCP smoke test](MCP_STDIO.md) first.
Your complete offline bundle must match the grant's current evidence fingerprint.

For a local-only Ollama installation, disable cloud features in the **daemon**, not just the
Python client's terminal. The official [FAQ](https://docs.ollama.com/faq#how-do-i-disable-ollamas-cloud-features)
documents `OLLAMA_NO_CLOUD=1` and the `disable_ollama_cloud` server setting. For the macOS app:

```bash
launchctl setenv OLLAMA_NO_CLOUD 1
```

Quit and reopen Ollama so it picks up that setting. Its logs should say cloud is disabled.
If you run `ollama serve` manually, stop that server and restart it with `OLLAMA_NO_CLOUD=1`.
Do not expose its port or route it through an external proxy for this workflow.

Check your already installed models:

```bash
ollama list
```

If `gemma3:4b` is still in your installed list, you can use it as a first integration trial.
That is an example model, not a validated security recommendation or accuracy claim. You may
select another installed local GGUF model using its exact name. This adapter does not download
models. Simple lowercase names/tags of at most 48 characters are supported; cloud names and
registry/URL syntax are rejected. The local daemon and the selected model remain trusted inputs.

```bash
source .venv/bin/activate
python -m pip install -e '.[evtx,mcp]'
python -m adaptive_security.investigation_run \
  artifacts/investigation-access.json \
  artifacts/explicit-credentials-dev-v1 \
  artifacts/ollama-investigation-01.json \
  --ollama-model gemma3:4b
```

Use a fresh journal filename per run. Add `--grant-index N` if your private file has multiple
grants. Omitting `--ollama-model` retains the deterministic demo; there is no automatic model
selection, hosted-provider fallback or model installation. Existing platform API keys are not
sent to Ollama, placed in prompts or passed to the MCP child.

The command prints run status and usage metadata. `completed` means the controller accepted a
review proposal; it does not mean an attack was confirmed. A model may abstain without requesting
evidence, so inspect `tool_calls`, observations, hypotheses and the journal. Invalid proposals,
unsupported citations, errors or exhausted budgets stop the run. Exit code 2 is used for stopped
runs and setup/save failures. The private journal preserves prior accepted evidence and limits.

## Network and data boundary

The provider endpoint is fixed at `http://127.0.0.1:11434`; neither CLI arguments nor model
decisions can replace it. The HTTP client ignores environment proxies, does not follow redirects,
requests identity encoding and rejects encoded responses. Before every generation, `/api/show`
must indicate local GGUF metadata with an architecture and no remote host/model. A metadata
fingerprint must remain stable throughout the adapter's lifetime. Metadata requests contain
only the model name. Evidence is sent only after these checks.

These checks reject known remote models; they do not attest the daemon, authenticate model
weights or prevent a compromised/local proxy daemon from forwarding data. Metadata can be
misreported and names can change. Keep Ollama's cloud features disabled and trust the machine
and daemon. The fingerprint is metadata identity, not a weight-file digest or signed provenance.

Generation prompts contain the fixed policy/schema, finding scope and returned projected event
pages. They omit platform credentials, raw XML, local access-file paths and arbitrary attributes.
Evidence still may contain sensitive entity values. Its text is treated as untrusted data, but
prompts alone do not eliminate injection. The controller independently rejects tool/scope/action
expansion and restricts conclusions to `needs_review` or `inconclusive`.

## Model and controller budgets

Model mode uses 120 seconds for the controller and 30 seconds per operation. Individual HTTP
I/O timeouts are 25 seconds; no automatic retry is made. Local model loading may exceed these
limits. A timed-out run is not a benign verdict; inspect Ollama and the journal before rerunning.
Async cancellation does not certify immediate termination of GPU/server computation.

Each generation requests `num_ctx=4096`, `num_predict=512`, `temperature=0`, non-streaming JSON
and a five-minute model keep-alive. Model tool decisions are restricted to pages of at most five
records (default five), while the general controller API supports larger bounded pages.
The adapter caps incoming model context at 16 KiB, generation
HTTP responses at 64 KiB and metadata at 128 KiB. JSON decision content is limited to 8 KiB.
Output truncation, missing/invalid usage, incorrect model identity and a nearly full reported
context window are rejected. These byte/token checks do not prove a tokenizer preserved every
input token; long inputs can still be truncated by a provider. Small evidence pages are preferred.

The default model token quota is 36,864. Before sending a generation request, the adapter reserves
4,608 tokens (context plus generation cap). It refunds the difference only after usable identity,
completion and bounded token counts are received. Failed/cancelled/unaccounted calls keep the full
reservation. `--model-token-limit N` can set 4,608–73,728; eight decisions/five tools and the other
controller limits still apply. A small remaining quota may prevent another call even if its
eventual actual usage would fit. This conservative charge is intentional.

`adapter_usage` in the journal records model name, generation attempts, reported prompt/generated
tokens, charged tokens, quota, uncertain requests and metadata fingerprint. Counts depend on the
trusted daemon honoring options and reporting usage correctly; they are not billing verification.
No hosted model API or dollar-cost estimator is integrated. Prompts, raw invalid model outputs and
separate thinking fields are not added to the journal. Accepted observations/hypotheses and tool
evidence remain recorded under the controller's rules.

## What was tested and what remains

Automated tests use controlled Ollama-compatible HTTP responses and the actual MCP/controller
path. They exercise structured decisions, successful exact citations, scope/action/classification
attacks, invented references, cloud metadata, model changes, byte/token budgets, redirects, HTTP
errors and cancellation accounting. This tests enforcement when such responses occur; it does
not measure how frequently a real model behaves that way. No real Ollama model was executed in
the development environment or on your Mac by this change.

Next collect real local run artifacts, assess citation correctness and useful abstention, then
use frozen independent cases containing benign explanations, missing/contradictory evidence and
instructions embedded in telemetry. Keep that reasoning evaluation separate from detector
precision/recall and label partitions. Live detection and autonomous response remain disabled.
