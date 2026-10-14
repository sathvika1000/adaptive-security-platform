import asyncio
import io
import json
import os
import subprocess
import sys
from dataclasses import replace

import pytest
from test_offline_review import bundle

pytest.importorskip("mcp")

from mcp import Client
from mcp.client.stdio import StdioServerParameters

from adaptive_security.investigation_access import investigation_identities
from adaptive_security.mcp_server import (
    MAX_FRAME_BYTES,
    MAX_SESSION_CALLS,
    BoundedInput,
    MCPInvestigation,
    from_environment,
    load_identity,
)
from adaptive_security.offline_review import load_review

TOKEN = "mcp-private-test-credential-" + "x" * 32


@pytest.fixture
def mcp_fixture(tmp_path, monkeypatch):
    output = bundle(tmp_path, monkeypatch)
    snapshot = load_review(output)
    finding = snapshot.captures["sample"].findings[0]
    invocation = {
        "capture_id": "sample",
        "finding_id": finding.incident_id,
        "review_key": snapshot.finding_keys[("sample", finding.incident_id)],
    }
    config = {
        "local-reader": {
            "key": TOKEN,
            "grants": [
                invocation | {"tools": ["get_finding_evidence", "get_related_events"]},
            ],
        }
    }
    path = tmp_path / "private-access.json"
    path.write_text(json.dumps(config))
    path.chmod(0o600)
    identity = load_identity(path)
    return MCPInvestigation(snapshot, identity), invocation, path, output


def failure_status(result):
    assert result.is_error and result.structured_content is None
    return json.loads(result.content[0].text)["status"]


@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_official_client_negotiates_lists_exact_schemas_and_reads_scoped_evidence(
    mcp_fixture, mode,
):
    service, invocation, _, _ = mcp_fixture

    async def exercise():
        async with Client(service.server(), mode=mode) as client:
            listed = await client.list_tools()
            assert {tool.name for tool in listed.tools} == {
                "get_investigation_scopes",
                "get_finding_evidence",
                "get_related_events",
            }
            for tool in listed.tools:
                assert tool.annotations.read_only_hint
                assert not tool.annotations.open_world_hint
                assert tool.input_schema["additionalProperties"] is False
                assert tool.output_schema
            scopes = await client.call_tool("get_investigation_scopes", {})
            assert not scopes.is_error and scopes.structured_content["matching"] == 1
            assert scopes.structured_content["entries"][0]["review_key"] == invocation["review_key"]
            result = await client.call_tool("get_finding_evidence", invocation | {"limit": 7})
            assert not result.is_error
            assert result.structured_content["page"]["returned_records"] == 7
            assert result.structured_content["page"]["next_offset"] == 7
            assert result.structured_content["data_trust"] == "untrusted_observations"
            assert (
                "raw_xml" not in result.model_dump_json() and TOKEN not in result.model_dump_json()
            )
            assert result.meta["request_id"]
            related = await client.call_tool("get_related_events", invocation)
            assert not related.is_error and related.structured_content["events"] == []

    asyncio.run(exercise())


def test_official_client_cannot_escape_scope_or_expand_capabilities(mcp_fixture):
    service, invocation, _, _ = mcp_fixture
    original = service.snapshot.captures["sample"].events[0].model_dump_json()

    async def exercise():
        async with Client(service.server()) as client:
            for tool in ("get_telemetry_coverage", "execute", "close_incident"):
                assert failure_status(await client.call_tool(tool, invocation)) == 403
            for change in (
                {"capture_id": "other"},
                {"finding_id": "other"},
                {"review_key": "0" * 64},
            ):
                assert (
                    failure_status(
                        await client.call_tool("get_finding_evidence", invocation | change)
                    )
                    == 403
                )
            for change in (
                {"limit": True},
                {"limit": "7"},
                {"limit": 101},
                {"command": "echo secret"},
                {"url": "http://169.254.169.254/"},
            ):
                assert (
                    failure_status(
                        await client.call_tool("get_finding_evidence", invocation | change)
                    )
                    == 422
                )
            assert (
                failure_status(
                    await client.call_tool("get_investigation_scopes", {"actor": "platform"})
                )
                == 422
            )
            oversized = await client.call_tool(
                "get_finding_evidence", invocation | {"sql": "x" * 33_000}
            )
            assert failure_status(oversized) == 413

    asyncio.run(exercise())
    assert service.snapshot.captures["sample"].events[0].model_dump_json() == original


def test_stale_grants_remain_stale_through_protocol(mcp_fixture):
    service, invocation, _, _ = mcp_fixture
    capture = service.snapshot.captures["sample"]
    service.snapshot = replace(
        service.snapshot,
        captures={
            "sample": replace(capture, metadata={"changed": True}),
        },
    )
    current = service.snapshot.finding_keys[("sample", invocation["finding_id"])]

    async def exercise():
        async with Client(service.server()) as client:
            scopes = await client.call_tool("get_investigation_scopes", {})
            assert scopes.structured_content["entries"][0]["stale"]
            assert current not in scopes.model_dump_json()
            assert failure_status(await client.call_tool("get_finding_evidence", invocation)) == 409
            assert (
                failure_status(
                    await client.call_tool(
                        "get_finding_evidence", invocation | {"review_key": current}
                    )
                )
                == 403
            )

    asyncio.run(exercise())


def test_total_session_calls_include_denials_and_cannot_be_reset_by_arguments(mcp_fixture):
    service, _, _, _ = mcp_fixture
    service.calls = MAX_SESSION_CALLS - 1

    async def exercise():
        async with Client(service.server()) as client:
            assert failure_status(await client.call_tool("execute", {})) == 403
            assert failure_status(await client.call_tool("get_investigation_scopes", {})) == 429
            assert (
                failure_status(await client.call_tool("get_investigation_scopes", {"reset": True}))
                == 429
            )
            assert service.calls == MAX_SESSION_CALLS

    asyncio.run(exercise())


def test_full_protocol_result_is_bounded_and_discovery_can_use_smaller_pages(mcp_fixture):
    service, _, _, _ = mcp_fixture
    config = {
        "large-reader": {
            "key": TOKEN,
            "grants": [
                {
                    "capture_id": "\U0001f512" * 128,
                    "finding_id": str(i) + "\U0001f512" * 120,
                    "review_key": "0" * 64,
                    "tools": ["get_finding_evidence"],
                }
                for i in range(100)
            ],
        }
    }
    service.identity = investigation_identities(config, set())[0]

    async def exercise():
        async with Client(service.server()) as client:
            too_large = await client.call_tool("get_investigation_scopes", {"limit": 100})
            assert failure_status(too_large) == 413
            page = await client.call_tool("get_investigation_scopes", {"limit": 10})
            assert not page.is_error and page.structured_content["next_offset"] == 10
            assert len(page.model_dump_json(by_alias=True).encode()) < 64 * 1024

    asyncio.run(exercise())


def test_real_stdio_subprocess_negotiates_and_applies_same_policy(mcp_fixture):
    _, invocation, path, output = mcp_fixture
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "adaptive_security.mcp_server"],
        env={"ASP_MCP_ACCESS_FILE": str(path), "ASP_OFFLINE_REVIEW_PATH": str(output)},
    )

    async def exercise():
        async with Client(params, read_timeout_seconds=10) as client:
            tools = await client.list_tools()
            assert len(tools.tools) == 3
            result = await client.call_tool("get_finding_evidence", invocation)
            assert not result.is_error
            assert result.structured_content["scope"]["review_key"] == invocation["review_key"]
            assert (
                failure_status(await client.call_tool("get_telemetry_coverage", invocation)) == 403
            )

    asyncio.run(exercise())


def test_mac_smoke_command_runs_through_real_child_without_inheriting_platform_key(mcp_fixture):
    _, _, path, output = mcp_fixture
    result = subprocess.run(
        [sys.executable, "-m", "adaptive_security.mcp_smoke", str(path), str(output)],
        env=os.environ | {"ASP_API_KEY": TOKEN}, capture_output=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr.decode()
    report = json.loads(result.stdout)
    assert report["successful"] and report["transport"] == "stdio"
    assert report["actor"] == "local-reader"
    assert TOKEN.encode() not in result.stdout + result.stderr
    assert b"private-record" not in result.stdout + result.stderr


@pytest.mark.parametrize(
    "problem", ["public", "symlink", "invalid_json", "extra_identity", "oversized", "fifo"]
)
def test_private_configuration_rejects_unsafe_files_without_echoing_secrets(mcp_fixture, problem):
    _, _, path, _ = mcp_fixture
    if problem == "public":
        path.chmod(0o644)
    elif problem == "symlink":
        linked = path.parent / "linked.json"
        linked.symlink_to(path)
        path = linked
    elif problem == "invalid_json":
        path.write_text('{"key":"' + TOKEN)
    elif problem == "extra_identity":
        data = json.loads(path.read_text())
        data["other"] = data["local-reader"]
        path.write_text(json.dumps(data))
    elif problem == "oversized":
        path.write_bytes(b" " * 140_000)
    elif problem == "fifo":
        path.unlink()
        os.mkfifo(path, mode=0o600)
    with pytest.raises(ValueError) as error:
        load_identity(path)
    assert TOKEN not in str(error.value) and str(path) not in str(error.value)


def test_environment_rejects_privileged_credentials_and_bad_bundle(mcp_fixture):
    _, _, path, output = mcp_fixture
    env = {"ASP_MCP_ACCESS_FILE": str(path), "ASP_OFFLINE_REVIEW_PATH": str(output)}
    assert from_environment(env).identity.actor == "local-reader"
    for name in ("ASP_API_KEY", "ASP_ANALYST_KEYS_JSON", "ASP_INVESTIGATION_KEYS_JSON"):
        with pytest.raises(ValueError, match="MCP-only") as error:
            from_environment(env | {name: TOKEN})
        assert TOKEN not in str(error.value)
    with pytest.raises(ValueError, match="Set ASP_MCP"):
        from_environment({})
    with pytest.raises(ValueError, match="bundle unavailable"):
        from_environment(env | {"ASP_OFFLINE_REVIEW_PATH": str(path.parent / "private-missing")})


def test_raw_frame_reader_caps_bytes_before_decode():
    assert BoundedInput(io.BytesIO(b"{}\n")).readline() == "{}\n"
    assert BoundedInput(io.BytesIO(b"{}\n")).readline(1) == "{"
    with pytest.raises(ValueError, match="frame"):
        BoundedInput(io.BytesIO(b"x" * (MAX_FRAME_BYTES + 1))).readline()
    with pytest.raises(UnicodeDecodeError):
        BoundedInput(io.BytesIO(b"\xff\n")).readline()


def test_oversized_wire_frame_terminates_without_reflecting_payload(mcp_fixture):
    _, _, path, output = mcp_fixture
    env = {name: value for name, value in os.environ.items() if not name.startswith("ASP_")}
    env.update(ASP_MCP_ACCESS_FILE=str(path), ASP_OFFLINE_REVIEW_PATH=str(output))
    result = subprocess.run(
        [sys.executable, "-m", "adaptive_security.mcp_server"],
        env=env,
        input=TOKEN.encode() + b"x" * MAX_FRAME_BYTES + b"\n",
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 2 and TOKEN.encode() not in result.stderr
    assert result.stdout == b"" and b"transport was rejected" in result.stderr


def test_protocol_errors_and_metadata_logs_do_not_echo_arguments(mcp_fixture, caplog):
    service, invocation, _, _ = mcp_fixture

    async def exercise():
        async with Client(service.server()) as client:
            result = await client.call_tool("get_finding_evidence", invocation | {"key": TOKEN})
            assert failure_status(result) == 422 and TOKEN not in result.model_dump_json()

    with caplog.at_level("INFO", logger="adaptive_security.mcp"):
        asyncio.run(exercise())
    logs = [json.loads(r.message) for r in caplog.records if r.name == "adaptive_security.mcp"]
    assert logs[0]["actor"] == "local-reader" and logs[0]["status"] == 422
    assert TOKEN not in caplog.text and invocation["review_key"] not in caplog.text
