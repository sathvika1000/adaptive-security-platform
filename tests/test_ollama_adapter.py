import asyncio
import json

import pytest

pytest.importorskip("httpx2")

import httpx2
from mcp import Client
from test_mcp_server import mcp_fixture as _mcp_fixture

from adaptive_security.investigation_run import MCPChannel, run_demo
from adaptive_security.investigation_runner import InvestigationRunner, RunBudget, RunStopped
from adaptive_security.ollama_adapter import CALL_RESERVATION, OllamaAdapter

mcp_fixture = _mcp_fixture

LOCAL_INFO = {
    "details": {"format": "gguf", "family": "gemma3"},
    "model_info": {"general.architecture": "gemma3"},
    "modified_at": "2026-01-01T00:00:00Z",
}


def wire(data, status=200, headers=None):
    raw = json.dumps(data).encode() if not isinstance(data, bytes) else data
    return httpx2.Response(status, stream=httpx2.ByteStream(raw), headers=headers or {})


def reply(decision, **changes):
    return {
        "model": "gemma3:4b",
        "done": True,
        "done_reason": "stop",
        "message": {"role": "assistant", "content": json.dumps({"decision": decision})},
        "prompt_eval_count": 100,
        "eval_count": 50,
    } | changes


FINISH = {"kind": "finish", "disposition": "inconclusive"}


def test_real_mcp_reads_followed_by_model_proposal_and_exact_citations(mcp_fixture):
    service, _, _, _ = mcp_fixture
    sent = []

    def handler(request):
        assert request.url.host == "127.0.0.1" and request.url.port == 11434
        assert "authorization" not in request.headers and "x-api-key" not in request.headers
        body = json.loads(request.content)
        if request.url.path == "/api/show":
            assert "messages" not in body
            return wire(LOCAL_INFO)
        sent.append(body)
        assert body["stream"] is False and body["format"]["additionalProperties"] is False
        assert body["options"]["num_predict"] == 512 and body["options"]["num_ctx"] == 4096
        context = json.loads(body["messages"][1]["content"])
        if not context["results"]:
            decision = {"kind": "tool", "tool": "get_finding_evidence", "limit": 1}
        else:
            record = context["results"][0]["events"][0]
            decision = {
                "kind": "finish",
                "disposition": "needs_review",
                "observations": [
                    {
                        "source": record["source"],
                        "event_id": record["event_id"],
                        "field": "category",
                        "value": record["category"],
                    },
                ],
            }
        return wire(reply(decision))

    adapter = OllamaAdapter("gemma3:4b", transport=httpx2.MockTransport(handler))

    async def exercise():
        async with Client(service.server()) as client:
            return await InvestigationRunner(
                service.identity.grants[0],
                MCPChannel(client),
                adapter,
                adapter_name="ollama-local:gemma3:4b",
            ).run()

    report = asyncio.run(exercise())
    assert report.status == "completed" and report.tool_calls == 1 and len(sent) == 2
    assert report.conclusion.observations[0].event_id == "event-000"
    assert report.adapter_usage.requests == 2 and report.adapter_usage.charged_tokens == 300
    assert (
        report.adapter_usage.prompt_tokens == 200 and report.adapter_usage.generated_tokens == 100
    )
    assert report.adapter_usage.unconfirmed_requests == 0 and report.adapter_usage.metadata_sha256


@pytest.mark.parametrize(
    "decision",
    [
        {"kind": "tool", "tool": "execute", "command": "steal-private-key"},
        {"kind": "tool", "tool": "get_finding_evidence", "capture_id": "other"},
        {"kind": "tool", "tool": "get_finding_evidence", "limit": 100},
        {"kind": "tool", "tool": "get_finding_evidence", "url": "https://attacker.example/"},
        {"kind": "finish", "disposition": "benign"},
        {"kind": "finish", "disposition": "malicious"},
        {
            "kind": "finish",
            "disposition": "needs_review",
            "observations": [
                {
                    "source": "evtx",
                    "event_id": "invented",
                    "field": "category",
                    "value": "authentication",
                },
            ],
        },
    ],
)
def test_hostile_model_proposals_cannot_override_controller(mcp_fixture, decision):
    service, _, _, _ = mcp_fixture

    def handler(request):
        return wire(LOCAL_INFO if request.url.path == "/api/show" else reply(decision))

    adapter = OllamaAdapter("gemma3:4b", transport=httpx2.MockTransport(handler))

    async def exercise():
        async with Client(service.server()) as client:
            return await InvestigationRunner(
                service.identity.grants[0], MCPChannel(client), adapter
            ).run()

    report = asyncio.run(exercise())
    assert report.status == "blocked" and report.conclusion is None and report.tool_calls == 0
    assert report.adapter_usage.requests == 1
    assert "steal-private-key" not in report.model_dump_json()


@pytest.mark.parametrize(
    "info",
    [
        LOCAL_INFO | {"remote_host": "https://ollama.com"},
        LOCAL_INFO | {"remote_model": "gemma3-cloud"},
        LOCAL_INFO | {"details": {"format": "remote"}},
        LOCAL_INFO | {"model_info": {}},
    ],
)
def test_remote_or_unknown_metadata_blocks_before_evidence_is_sent(info):
    paths = []

    def handler(request):
        paths.append(request.url.path)
        return wire(info)

    adapter = OllamaAdapter("gemma3:4b", transport=httpx2.MockTransport(handler))
    with pytest.raises(RunStopped):
        asyncio.run(adapter.next_step("{}"))
    assert paths == ["/api/show"] and adapter.usage().requests == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"done": False},
        {"done_reason": "length"},
        {"model": "other:4b"},
        {"prompt_eval_count": 4000},
        {"eval_count": 513},
        {"eval_count": True},
        {"message": {"role": "system", "content": "private-server-data"}},
        {"message": {"role": "assistant", "content": "not json private-server-data"}},
    ],
)
def test_incomplete_wrong_model_invalid_counts_and_bad_json_are_not_accepted(mcp_fixture, changes):
    service, _, _, _ = mcp_fixture

    def handler(request):
        return wire(LOCAL_INFO if request.url.path == "/api/show" else reply(FINISH, **changes))

    adapter = OllamaAdapter("gemma3:4b", transport=httpx2.MockTransport(handler))

    async def exercise():
        async with Client(service.server()) as client:
            return await InvestigationRunner(
                service.identity.grants[0], MCPChannel(client), adapter
            ).run()

    report = asyncio.run(exercise())
    assert report.status == "blocked" and report.conclusion is None
    assert report.adapter_usage.requests == 1 and report.adapter_usage.charged_tokens > 0
    assert "private-server-data" not in report.model_dump_json()


def test_token_reservations_failures_and_context_limit():
    paths = []

    def handler(request):
        paths.append(request.url.path)
        return wire(LOCAL_INFO) if request.url.path == "/api/show" else wire({}, status=500)

    adapter = OllamaAdapter(
        "gemma3:4b", token_limit=CALL_RESERVATION, transport=httpx2.MockTransport(handler)
    )
    with pytest.raises(RunStopped):
        asyncio.run(adapter.next_step("{}"))
    assert adapter.usage().charged_tokens == CALL_RESERVATION
    assert adapter.usage().unconfirmed_requests == 1
    with pytest.raises(RunStopped, match="reservation"):
        asyncio.run(adapter.next_step("{}"))
    assert len(paths) == 2
    with pytest.raises(RunStopped, match="16 KiB"):
        asyncio.run(adapter.next_step("x" * 17_000))


def test_redirects_and_oversized_generation_are_rejected(mcp_fixture):
    service, _, _, _ = mcp_fixture
    for bad in (
        wire(b"", status=302, headers={"Location": "https://attacker.example"}),
        wire(b"x" * 70_000),
    ):

        def handler(request, bad=bad):
            return wire(LOCAL_INFO) if request.url.path == "/api/show" else bad

        adapter = OllamaAdapter("gemma3:4b", transport=httpx2.MockTransport(handler))

        async def exercise(adapter=adapter):
            async with Client(service.server()) as client:
                return await InvestigationRunner(
                    service.identity.grants[0], MCPChannel(client), adapter
                ).run()

        report = asyncio.run(exercise())
        assert report.status in ("blocked", "budget_exhausted")
        assert report.adapter_usage.charged_tokens == CALL_RESERVATION
        assert report.adapter_usage.unconfirmed_requests == 1


def test_cancelled_generation_retains_reservation(mcp_fixture):
    service, _, _, _ = mcp_fixture

    async def handler(request):
        if request.url.path == "/api/show":
            return wire(LOCAL_INFO)
        await asyncio.sleep(1)
        return wire(reply(FINISH))

    adapter = OllamaAdapter("gemma3:4b", transport=httpx2.MockTransport(handler))

    async def exercise():
        async with Client(service.server()) as client:
            return await InvestigationRunner(
                service.identity.grants[0],
                MCPChannel(client),
                adapter,
                RunBudget(operation_seconds=0.05),
            ).run()

    report = asyncio.run(exercise())
    assert report.status == "timeout"
    assert report.adapter_usage.unconfirmed_requests == 1
    assert report.adapter_usage.charged_tokens == CALL_RESERVATION


def test_model_changes_cannot_continue_same_run():
    shows = 0
    chats = 0

    def handler(request):
        nonlocal shows, chats
        if request.url.path == "/api/show":
            shows += 1
            return wire(LOCAL_INFO | {"modified_at": str(shows)})
        chats += 1
        return wire(reply(FINISH))

    adapter = OllamaAdapter("gemma3:4b", transport=httpx2.MockTransport(handler))
    asyncio.run(adapter.next_step("{}"))
    with pytest.raises(RunStopped, match="metadata changed"):
        asyncio.run(adapter.next_step("{}"))
    assert chats == 1


@pytest.mark.parametrize("failure", ["timeout", "connect"])
def test_http_errors_are_generic_and_generation_reservations_are_retained(failure):
    def handler(request):
        if request.url.path == "/api/show":
            return wire(LOCAL_INFO)
        error = httpx2.ReadTimeout if failure == "timeout" else httpx2.ConnectError
        raise error("private-error-detail", request=request)

    adapter = OllamaAdapter("gemma3:4b", transport=httpx2.MockTransport(handler))
    with pytest.raises((TimeoutError, RunStopped)) as exc:
        asyncio.run(adapter.next_step("{}"))
    assert "private-error-detail" not in str(exc.value)
    assert adapter.usage().charged_tokens == CALL_RESERVATION
    assert adapter.usage().unconfirmed_requests == 1


def test_hidden_thinking_is_not_saved_in_the_execution_journal(mcp_fixture):
    service, _, _, _ = mcp_fixture
    response = reply(FINISH)
    response["message"]["thinking"] = "sensitive-internal-thought"

    def handler(request):
        return wire(LOCAL_INFO if request.url.path == "/api/show" else response)

    adapter = OllamaAdapter("gemma3:4b", transport=httpx2.MockTransport(handler))

    async def exercise():
        async with Client(service.server()) as client:
            return await InvestigationRunner(
                service.identity.grants[0], MCPChannel(client), adapter
            ).run()

    report = asyncio.run(exercise())
    assert report.status == "completed" and report.adapter_usage.charged_tokens == 150
    assert "sensitive-internal-thought" not in report.model_dump_json()


def test_opt_in_launcher_selects_model_adapter_over_real_stdio(mcp_fixture, monkeypatch):
    import adaptive_security.ollama_adapter as module

    _, _, path, output = mcp_fixture

    def handler(request):
        return wire(LOCAL_INFO if request.url.path == "/api/show" else reply(FINISH))

    adapter = OllamaAdapter("gemma3:4b", transport=httpx2.MockTransport(handler))

    def factory(model, token_limit):
        assert model == "gemma3:4b" and token_limit == 36_864
        return adapter

    monkeypatch.setattr(module, "OllamaAdapter", factory)
    report = asyncio.run(run_demo(path, output, 0, ollama_model="gemma3:4b"))
    assert report.status == "completed" and report.adapter_name == "ollama-local:gemma3:4b"
    assert report.budget.total_seconds == 120 and report.budget.operation_seconds == 30
    assert report.adapter_usage.requests == 1


@pytest.mark.parametrize(
    "model,limit",
    [
        ("gemma3:cloud", 36_864),
        ("https://other/model", 36_864),
        ("model; shell", 36_864),
        ("gemma3:4b", True),
        ("gemma3:4b", 1),
    ],
)
def test_bad_operator_settings_are_rejected(model, limit):
    with pytest.raises(ValueError):
        OllamaAdapter(model, limit)


@pytest.mark.parametrize("timeout", [0, -1, 91, float("inf"), float("nan"), True, "85"])
def test_local_timeout_configuration_is_bounded(timeout):
    with pytest.raises(ValueError):
        OllamaAdapter("gemma3:4b", request_timeout_seconds=timeout)


def test_slow_http_timeout_reaches_client_without_changing_token_options():
    def handler(request):
        assert request.extensions["timeout"]["read"] == 85.0
        if request.url.path == "/api/show":
            return wire(LOCAL_INFO)
        body = json.loads(request.content)
        assert body["options"]["num_predict"] == 512
        assert body["options"]["num_ctx"] == 4096
        return wire(reply(FINISH))

    adapter = OllamaAdapter(
        "gemma3:4b", transport=httpx2.MockTransport(handler), request_timeout_seconds=85.0
    )
    assert asyncio.run(adapter.next_step("{}")) == {
        **FINISH, "observations": [], "hypotheses": [],
    }
