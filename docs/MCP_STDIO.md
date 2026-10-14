# Local read-only MCP investigation

This implementation uses the [official MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk),
pinned to [2.3.0](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.3.0).
It wraps the existing investigation policy and schemas with the SDK's
[low-level server](https://py.sdk.modelcontextprotocol.io/advanced/low-level-server/), which requires
application-owned argument validation. Strict Pydantic validation is applied on every tool call.

The first transport is local stdio on Mac/Linux. There is no listening socket, HTTP proxy,
model invocation, sampling callback, shell tool, write tool or live-source query. The operator
and local MCP host are trusted to launch the reviewed server with the intended grant file.
This is a local process boundary, not OAuth authentication or protection from a compromised host
with access to the same account's files. See
[MCP security guidance](https://modelcontextprotocol.io/specification/latest/basic/security_best_practices)
for the additional remote/transport-specific requirements.

## Prepare and verify on a Mac

Use a checkout containing the MCP change and its scoped-identity prerequisite. Install the
optional SDK alongside the existing EVTX support:

```bash
source .venv/bin/activate
python -m pip install -e '.[evtx,mcp]'
```

Complete [the read-only access setup](INVESTIGATION_ACCESS.md) to generate
`artifacts/investigation-access.json`. Select the finding deliberately before creating the
grant. The file must contain exactly one identity, be a regular file owned by your account,
and have no group/other permissions. Symlinks and oversized files are rejected. Keep the
file private; neither its key nor its pathname belongs in model tool arguments.

```bash
chmod 600 artifacts/investigation-access.json
python -m adaptive_security.mcp_smoke \
  artifacts/investigation-access.json \
  artifacts/explicit-credentials-dev-v1
```

The smoke command launches a real child process using your current virtualenv interpreter,
negotiates MCP with the official client, discovers only its granted tools/scopes and performs
one permitted read. It passes a minimal MCP-specific environment without platform/analyst keys.
It prints a small JSON report with `successful: true`, actor, tool and finding identifiers;
it does not print credentials, fingerprints or raw evidence. It requires no running API server
and no Windows installation. A failure means inspect private-file permissions, the original
complete bundle and grant staleness; it does not measure detection accuracy.

## Local host launch configuration

Configure your local MCP host to run your virtualenv's absolute Python path with arguments:

```text
-m adaptive_security.mcp_server
```

Supply only these application environment variables, using absolute local paths:

| Variable | Value |
| --- | --- |
| `ASP_MCP_ACCESS_FILE` | Path to the private single-identity grant file |
| `ASP_OFFLINE_REVIEW_PATH` | Path to the complete validated offline review output |

Host configuration format varies. The built-in smoke client is the verified launcher example.
Do not run the server through an HTTP/stdio gateway or expose its pipes to untrusted remote users.
Do not set `ASP_API_KEY`, `ASP_ANALYST_KEYS_JSON` or `ASP_INVESTIGATION_KEYS_JSON` in its process;
startup rejects those broader credentials/configuration. For a direct terminal launch, remove
them from that process environment:

```bash
env -u ASP_API_KEY -u ASP_ANALYST_KEYS_JSON -u ASP_INVESTIGATION_KEYS_JSON \
  ASP_MCP_ACCESS_FILE="$PWD/artifacts/investigation-access.json" \
  ASP_OFFLINE_REVIEW_PATH="$PWD/artifacts/explicit-credentials-dev-v1" \
  python -m adaptive_security.mcp_server
```

This waits for MCP JSON-RPC on stdin; it is not an interactive chat. Normal operational logs go
to stderr. The server disables SDK telemetry and suppresses SDK parser logs that could reflect
untrusted inputs. Application logs contain only a server-generated request ID, actor, allowlisted
tool name (or an unsupported placeholder), outcome code and call count.

## Exposed contracts and limits

`tools/list` advertises `get_investigation_scopes` plus the union of this identity's explicitly
granted evidence tools. A listed tool does not authorize every finding: each call still must
match the exact capture/finding/fingerprint/tool grant. Tool annotations declare read-only,
non-destructive, idempotent reads over a closed offline source; enforcement is in code, not hints.

- `get_investigation_scopes`: strict `{limit, offset}` pagination, 20 by default; returns the
  same restricted catalog as HTTP. Stale entries retain the old hash and never renew access.
- Evidence tools: the unchanged flat `ToolRequest` schema and version 1 `ToolResult`, including
  original references, evidence trust marker, pagination and collection limitations.
- Incoming stdio JSON-RPC lines: 64 KiB maximum, checked before decoding/parsing. Oversized or
  invalid UTF-8 frames terminate the local process with a generic diagnostic.
- Tool arguments: 32 KiB serialized JSON maximum; unknown fields and scalar coercion rejected.
- Serialized MCP `CallToolResult`: 64 KiB maximum, including structured content, text and metadata.
  The SDK's outer JSON-RPC wrapper is additional. Oversized results return a generic 413 tool
  error rather than silently truncating fields.
- Per process: 100 `tools/call` attempts, including discovery, invalid and denied calls.
  Further attempts return 429; tool arguments cannot reset the budget. Lightweight protocol
  methods such as ping/list are not counted. Only an operator-controlled process restart resets it.

Success is returned in `structured_content`; text identifies it as untrusted read-only data.
Tool errors use MCP `is_error: true` and a small text JSON `{status, detail}`; HTTP-like status
numbers describe application outcomes and are not HTTP responses. Error details do not echo
arguments, secrets or filesystem paths. Metadata has a server-generated correlation ID.

Snapshot and grant state are loaded once per process. Restart after changing evidence or policy;
changed fingerprints still require explicit operator reissuance. The SDK dispatches concurrent
requests, but these handlers perform synchronous bounded snapshot reads without yielding during
policy/call-counter updates. There is no per-call hard CPU deadline, durable execution journal
or multi-tenant isolation. A future controller must bound total reasoning, wall time, costs and
protocol requests; remote deployment still requires its own auth, rate and concurrency controls.

## Verification and next gate

Install `.[dev,evtx,mcp]` for full checks. `tests/test_mcp_server.py` exercises the actual official
client, in-process and real stdio negotiation, schema discovery, allowed reads, scope/tool/key
escalation, stale grants, private-file validation, frame/argument/result limits, call exhaustion,
metadata-only logs and the Mac smoke command. CI installs the pinned SDK for this suite.

Next build the bounded single-agent controller, replaceable model adapter and independent
citation validator described in [the architecture](INVESTIGATION_ARCHITECTURE.md). The transport
does not itself make this an agent or validate a model's reasoning.
