# Evidence-grounded security investigation

Status: first offline tool slice implemented; model reasoning, MCP transport and live
investigation connectors are not implemented. Reference review: 2026-10-10.

## Product goal and first use case

Help an analyst investigate an authentication finding with traceable evidence, explicit
collection limits and a reviewable explanation. The initial workflow is Windows authentication
fan-out investigation using already validated offline captures on a Mac. The long-term product
should use customer-owned SIEM/EDR/identity sources through replaceable adapters; a customer
does not have to adopt Wazuh or our development lab.

Success means fewer unsupported claims and less analyst investigation time, measured against
the same cases reviewed manually. A richer explanation is not evidence of better detection.
The current public captures have been inspected during development. Fresh attack captures and
representative benign activity remain necessary before performance claims or live enablement.

## References and control decisions

These references guide design and tests. This table is our engineering mapping, not a claim of
certification, complete framework coverage or a third party assessment.

| Official reference | Checks we implement now | Remaining acceptance gate |
| --- | --- | --- |
| [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/), API1/API2/API5 | Authenticate the HTTP entry point; resolve finding inside its capture; allow only three read operations; reject stale evidence fingerprints | Tenant and object grants bound to a dedicated read-only service identity; the existing shared platform key is not tenant isolation |
| Same reference, API3/API4/API7/API10 | Project selected fields; reject unknown inputs and coercion; bound request bytes, response bytes and page size; accept no caller-supplied URL/path/query/command; reuse validated snapshots | Rate/concurrency limits, adapter timeouts and total execution budgets; connector-specific egress policy and sensitive-field policy |
| [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), ASI01/ASI02/ASI03/ASI05/ASI06 | Treat tool data as untrusted observations; expose no executable tool; bind the finding and enforce scope in application code | Adversarial model tests, server-controlled grants and secret separation, session isolation, bounded reasoning and validated citations |
| [MCP security best practices](https://modelcontextprotocol.io/specification/latest/basic/security_best_practices) and [official Python SDK](https://github.com/modelcontextprotocol/python-sdk) | Keep policy and evidence access independent of any model or transport; no arbitrary remote fetches | Pin a reviewed SDK release; implement transport authentication, audience/scope checks, consent where applicable, no token passthrough and transport-specific tests before remote use |
| [NIST SSDF SP 800-218 v1.1](https://csrc.nist.gov/pubs/sp/800/218/final) | Define a threat boundary and security acceptance tests; run lint, types and regression tests in CI | Dependency/release provenance, vulnerability management, deployment hardening and reproducible release checks |
| [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) | Record intended use, uncertainty, limitations and validation partitions | Evaluate the model separately from the detector; measure unsupported claims, citation validity, abstention, analyst usefulness, latency and cost |

Use the SDK as a transport implementation reference, not as a replacement for our authorization
or evidence policy. Its API evolves; this slice adds no MCP dependency. Future source adapters
must translate fixed tool requests into provider-specific queries on the server. A model must
never supply unrestricted SQL, SIEM query language, credentials or destination addresses.

## Trust boundary implemented in this slice

1. An operator configures `ASP_OFFLINE_REVIEW_PATH`. Existing bundle validation checks hashes,
   finding membership and capture provenance before creating the cached snapshot.
2. The HTTP caller authenticates with the existing `X-API-Key` read boundary. That platform
   credential grants access to the entire configured offline run and other platform endpoints;
   do not hand it to a model or treat it as a dedicated agent credential.
3. A strict request names a capture, finding and current `review_key`. The fingerprint binds
   evidence/context, including rule and provenance. It is an integrity check, not a permission
   grant or author signature. Unknown capture/finding requests fail closed.
4. A server-selected tool reads only that capture. It cannot ingest events, alter labels,
   modify saved analyst assessments or execute a response action.
5. The result includes source/event references, capture checksum, selection scope, pagination
   and limitations. Text fields remain untrusted even though raw attributes/XML are omitted.

No model runs in this slice. A `data_trust` label does not by itself prevent prompt injection.
Later reasoning must enforce policy outside the prompt and reject unsupported tool calls.
The existing offline API/export retains original records for analyst inspection; projection
does not delete or sanitize those originals.

## Version 1 tool contract

`POST /v1/investigation-tools/{tool}` requires `X-API-Key` and JSON:

```json
{
  "capture_id": "sample",
  "finding_id": "win-auth-...",
  "review_key": "<current 64-character lowercase SHA-256 fingerprint>",
  "limit": 20,
  "offset": 0
}
```

Obtain real identifiers/fingerprints from the authenticated offline queue at
`GET /v1/offline-review/queue`; do not use the example placeholders. `/docs` exposes
the request and result schemas. See [offline review](OFFLINE_REVIEW.md) for launch and
API-key setup. Existing running processes must restart after pulling to register new routes.

| Tool | Selection | Meaning of an empty result |
| --- | --- | --- |
| `get_finding_evidence` | Original records referenced by this finding, in snapshot time/ID order | No records in the requested page; consult matched count and offset |
| `get_related_events` | Same capture; exact overlap with at least one finding entity; from five minutes before `first_seen` to five minutes after `last_seen`, inclusive; exclude finding evidence | No stored records meet that particular relationship/time selection; no conclusion about other sources |
| `get_telemetry_coverage` | All stored records in this capture, using the existing detector's eligibility/grouping checks | Coverage reports explicit eligibility and exclusion counts; no events page is returned |

A shared entity is a candidate relationship, not proof of the same actor/session or causality.
An empty related-events page can occur even with extensive capture data. Coverage is capture-wide,
not a finding-window query; `limit` and `offset` apply only to the two event tools. Distinct
account counts are not detector threshold windows and do not establish complete collection.

Requests forbid extra fields and scalar coercion. IDs are limited to 128 characters, `limit`
to 1–100 and `offset` to 0–10,000. The middleware checks actual streamed body bytes as well as
Content-Length: 32 KiB maximum. Serialized results are limited to 64 KiB; oversized pages fail
with 413 rather than silently truncating values. A single oversized record may require inspection
through the original offline evidence view instead of a smaller page.

Results carry `schema_version: 1`, `tool`, `scope`, `relationship`,
`data_trust: untrusted_observations`, `events`, `page`, `coverage` and `limitations`.
Event projections include source, event ID, time, category, action, outcome, source IP and
entities. They omit arbitrary attributes/XML. `page.exhausted` describes the stored selection,
not completeness of telemetry collection. Responses use `Cache-Control: no-store` and the
existing request-ID metadata logs; logs are not a durable investigation execution journal.

Errors: 401 unauthenticated, 404 missing/unconfigured finding, 409 stale fingerprint,
413 byte budget exceeded, 422 invalid input/tool, 503 invalid configured bundle. Messages do
not reveal filesystem paths. Tool calls are independent reads, not a mutable investigation
session. Server restart is needed to load changed bundle files.

## Security acceptance checks

`tests/test_investigation_tools.py` exercises:

- All tools require authentication; unknown tool names and extra inputs fail.
- Missing capture/finding and stale fingerprints cannot return evidence.
- Boolean/string pagination, out-of-range values and oversized IDs are rejected.
- Streamed oversized bodies fail even with a misleading Content-Length.
- Related selections exclude other captures, out-of-window events, nonmatching entities and
  finding evidence; boundary times are explicit.
- Pages keep original references and expose exhaustion/remaining offsets.
- Raw XML stays in the snapshot and is absent from projected tool output.
- Hostile text remains inert data; oversized responses fail without truncating evidence.
- Calls leave live incidents and offline assessment queue state unchanged.
- Coverage uses the shared detector checks; no precision/recall is manufactured.
- Unconfigured/invalid bundles fail closed with generic messages.

These tests establish tool behavior, not adversarial resilience of a future model. Existing
detector, evidence export, API and browser regression suites remain release gates.

## Ordered next milestones

### 1. Transport and authorization

Wrap these exact contracts with the reviewed official MCP SDK. Add a dedicated read-only
identity and server-controlled capture/finding grants before attaching an agent. Test invalid
audiences/scopes, attempted cross-scope reads, credential separation and denied write actions.
Start locally; remote deployment requires the applicable MCP transport/auth controls. Add
rate/concurrency limits and time budgets rather than relying on page limits alone.

### 2. Bounded single-agent investigation

Add one replaceable model adapter and a deterministic controller. The controller sets allowed
tools and scope; caps steps, tool calls, wall time, response bytes and model token/cost budget;
and records an execution journal. The model proposes hypotheses and citations. A separate
validator checks every cited source/event against returned evidence and requires unsupported
claims to be removed or marked inconclusive. Preserve analyst review and leave detector scores
and capture labels separate from the model's proposed conclusion.

Test benign explanations, missing/contradictory data, timeout/retry behavior, invented IDs,
instructions embedded in telemetry, secret-exfiltration requests and attempts to expand scope.
Evaluate citation correctness, unsupported-claim rate, useful abstention and analyst time saved
on frozen independent cases. This becomes agentic security only when controlled reasoning
actually chooses and uses tools; the current deterministic layer alone is not an agent.

### 3. One customer-source adapter

Choose a design partner's existing SIEM/identity source and implement the same contracts with
fixed server-owned queries, least-privilege credentials, tenant scoping, bounded timeouts and
explicit result truncation/freshness. Keep ingestion event normalization distinct from evidence
retrieval. Validate against source fixtures and source-of-truth records before adding further
vendors. Supporting every enterprise stack is a direction, not a near-term release criterion.

### 4. Production pilot and response gate

Require fresh attacks and representative benign operation, observed collection coverage,
reliability/load checks, authentication/RBAC tests, dependency/image review, backup/restore,
retention/privacy controls and reproducible releases. Define success thresholds with the pilot
analysts before evaluation. Any containment capability is a later product decision with a
separate human approval, audit and recovery design; investigation tools remain read-only.
