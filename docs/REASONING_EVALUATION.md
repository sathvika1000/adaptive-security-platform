# Reproducible controller checks

This suite exercises the investigation controller with eight synthetic cases and
supplied adapter decisions. It runs on macOS without Windows, Ollama, EVTX downloads
or an MCP server. It does not evaluate a language model or detection accuracy.

The cases cover an exact supported citation, an invented event reference, a changed
observed value, an ungranted tool, a tool response from another capture, an explicitly
inconclusive conclusion, an unsupported action proposal and a repeated-read loop.
Expectations check the terminal status, disposition and exact controller reason;
an unrelated failure cannot satisfy a citation-rejection expectation.

From the repository root, after installing the project:

```bash
source .venv/bin/activate
python -m adaptive_security.reasoning_evaluation \
  examples/evaluation/reasoning-controls.json \
  artifacts/reasoning-controls-v1.json \
  --suite-sha256 SUITE_DIGEST
```

Replace `SUITE_DIGEST` with this published SHA-256:

`3db792a735864f93d10cda06e0cf712fb55262553b665b012605bd3e4b3128c7`

 The evaluator checks the
original file bytes before parsing. JSON whitespace changes also require a new pin.
Review and version any intended changes to fixtures and expectations before running;
recomputing a hash after an unexpected change defeats this check.

The report records the file digest, canonical parsed-suite digest, SHA-256 values
of the evaluator/controller/tool-schema source modules, all effective per-case budgets,
expectations and execution journals. These hashes identify inputs and key source files;
they are not a complete dependency lock or a signature proving trusted provenance.
Run IDs and elapsed execution are not promised to be byte-identical between runs.

The CLI prints status/disposition counts and expectation matches over the explicit
case denominator. It exits 0 if every expectation matches, 1 for mismatches, and 2
for invalid inputs or an output-write failure. Reports are created with owner-only
permissions on POSIX and existing report paths are never overwritten. Use a new path
for each run. Reports include evidence and should be treated as private.

An inconclusive outcome is counted, not assumed to be a useful abstention. A matching
replay demonstrates a controller check against the scripted proposal; it says nothing
about how often a real model proposes that action. The existing MCP integration tests
and Ollama adapter checks remain separate. There is no live response or rule enablement.

Next: define independently reviewed analyst tasks and expected evidence before running
Ollama against them. Keep that model-quality report separate from these regression
counts and from held-out detector performance.
