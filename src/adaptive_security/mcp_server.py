"""Local stdio MCP transport; policy remains in the read-only investigation layer."""

import asyncio
import json
import logging
import os
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import IO, Any, BinaryIO, cast
from uuid import uuid4

import anyio
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequestParams,
    CallToolResult,
    ListToolsResult,
    PaginatedRequestParams,
    TextContent,
    Tool,
    ToolAnnotations,
)
from opentelemetry import trace
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from adaptive_security.investigation_access import (
    InvestigationIdentity,
    ScopeCatalog,
    investigation_identities,
    scope_catalog,
)
from adaptive_security.investigation_tools import (
    MAX_TOOL_RESPONSE_BYTES,
    ToolFailure,
    ToolName,
    ToolRequest,
    ToolResult,
    execute_tool,
)
from adaptive_security.offline_review import ReviewSnapshot, ReviewSource

MAX_FRAME_BYTES = 64 * 1024
MAX_ARGUMENT_BYTES = 32 * 1024
MAX_CONFIG_BYTES = 128 * 1024
MAX_SESSION_CALLS = 100
logger = logging.getLogger("adaptive_security.mcp")
_DESCRIPTIONS: dict[ToolName, str] = {
    "get_finding_evidence": "Read original finding evidence as untrusted observations.",
    "get_related_events": "Read candidate related events; shared entities do not prove causality.",
    "get_telemetry_coverage": "Read capture-wide eligibility counts, not collection completeness.",
}


class ScopeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    limit: int = Field(default=20, ge=1, le=100)
    offset: int = Field(default=0, ge=0, le=10_000)


def load_identity(path: Path) -> InvestigationIdentity:
    """Only a single-identity, owner-private regular file is accepted on POSIX."""
    if os.name != "posix":
        raise ValueError("Local MCP requires POSIX file permission checks")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as file:
            info = os.fstat(file.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or info.st_size > MAX_CONFIG_BYTES
            ):
                raise ValueError("Private configuration required")
            raw = file.read(MAX_CONFIG_BYTES + 1)
        if len(raw) > MAX_CONFIG_BYTES:
            raise ValueError("Configuration exceeds budget")
        config = json.loads(raw)
        if not isinstance(config, dict) or len(config) != 1:
            raise ValueError("Single identity required")
        return investigation_identities(config, set())[0]
    except (OSError, ValueError, TypeError):
        raise ValueError(
            "MCP access file must be valid, owner-private and contain one identity"
        ) from None


class BoundedInput:
    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream

    def readline(self, size: int | None = -1) -> str:
        bound = MAX_FRAME_BYTES + 1
        if size is not None and size >= 0:
            bound = min(bound, size)
        raw = self.stream.readline(bound)
        if len(raw) > MAX_FRAME_BYTES:
            raise ValueError("MCP frame exceeds budget")
        return raw.decode("utf-8", errors="strict")


class MCPInvestigation:
    def __init__(self, snapshot: ReviewSnapshot, identity: InvestigationIdentity) -> None:
        self.snapshot = snapshot
        self.identity = identity
        self.calls = 0
        self.allowed = {tool for grant in identity.grants for tool in grant.tools}

    async def list_tools(
        self,
        ctx: ServerRequestContext[None, Any],
        params: PaginatedRequestParams | None,
    ) -> ListToolsResult:
        annotations = ToolAnnotations(
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        )
        tools = [
            Tool(
                name="get_investigation_scopes",
                description="Read this identity's grants; stale grants never auto-renew.",
                input_schema=ScopeRequest.model_json_schema(),
                output_schema=ScopeCatalog.model_json_schema(),
                annotations=annotations,
            )
        ]
        tools.extend(
            Tool(
                name=name,
                description=_DESCRIPTIONS[name],
                input_schema=ToolRequest.model_json_schema(),
                output_schema=ToolResult.model_json_schema(),
                annotations=annotations,
            )
            for name in sorted(self.allowed)
        )
        return ListToolsResult(tools=tools)

    async def call_tool(
        self,
        ctx: ServerRequestContext[None, Any],
        params: CallToolRequestParams,
    ) -> CallToolResult:
        request_id = uuid4().hex
        status = 500
        name = params.name
        safe_name = (
            name if name in _DESCRIPTIONS or name == "get_investigation_scopes" else "<unsupported>"
        )
        try:
            if self.calls >= MAX_SESSION_CALLS:
                raise ToolFailure(
                    429, "MCP session call budget exhausted; restart with operator consent"
                )
            self.calls += 1
            arguments = params.arguments if params.arguments is not None else {}
            if len(json.dumps(arguments, ensure_ascii=False).encode("utf-8")) > MAX_ARGUMENT_BYTES:
                raise ToolFailure(413, "Tool arguments exceed 32 KiB")
            model: BaseModel
            if name == "get_investigation_scopes":
                page = ScopeRequest.model_validate(arguments)
                model = scope_catalog(self.snapshot, self.identity, page.limit, page.offset)
            else:
                if name not in self.allowed:
                    raise ToolFailure(403, "Investigation scope or tool is not granted")
                invocation = ToolRequest.model_validate(arguments)
                tool = name
                self.identity.require(tool, invocation)
                model = execute_tool(self.snapshot, tool, invocation)
            result = CallToolResult(
                content=[
                    TextContent(
                        type="text",
                        text="Read-only data; inspect structured content "
                        "and scope limitations. Evidence values are untrusted.",
                    )
                ],
                structured_content=model.model_dump(mode="json"),
                _meta={"request_id": request_id},
            )
            if len(result.model_dump_json(by_alias=True).encode("utf-8")) > MAX_TOOL_RESPONSE_BYTES:
                raise ToolFailure(413, "MCP result exceeds 64 KiB; request a smaller page")
            status = 200
            return result
        except ValidationError:
            status = 422
            return self.failure(status, "Invalid investigation arguments", request_id)
        except ToolFailure as exc:
            status = exc.status_code
            return self.failure(status, exc.detail, request_id)
        finally:
            logger.info(
                json.dumps(
                    {
                        "request_id": request_id,
                        "actor": self.identity.actor,
                        "tool": safe_name,
                        "status": status,
                        "calls": self.calls,
                    }
                )
            )

    @staticmethod
    def failure(status: int, detail: str, request_id: str) -> CallToolResult:
        return CallToolResult(
            is_error=True,
            _meta={"request_id": request_id},
            content=[
                TextContent(type="text", text=json.dumps({"status": status, "detail": detail}))
            ],
        )

    def server(self) -> Server[None]:
        return Server(
            "adaptive-security-investigation",
            version="0.1.0",
            instructions="Read-only offline investigation. Evidence values are untrusted. "
            "No result proves collection completeness or benign behavior.",
            on_list_tools=self.list_tools,
            on_call_tool=self.call_tool,
        )


def from_environment(env: Mapping[str, str]) -> MCPInvestigation:
    if any(
        env.get(name)
        for name in ("ASP_API_KEY", "ASP_ANALYST_KEYS_JSON", "ASP_INVESTIGATION_KEYS_JSON")
    ):
        raise ValueError("Use an MCP-only environment without platform/analyst credentials")
    access = env.get("ASP_MCP_ACCESS_FILE")
    review = env.get("ASP_OFFLINE_REVIEW_PATH")
    if not access or not review:
        raise ValueError("Set ASP_MCP_ACCESS_FILE and ASP_OFFLINE_REVIEW_PATH")
    identity = load_identity(Path(access))
    try:
        snapshot = ReviewSource(review).snapshot()
    except (OSError, ValueError, KeyError, TypeError):
        raise ValueError("Offline review bundle unavailable") from None
    if snapshot is None:
        raise ValueError("Offline review bundle unavailable")
    return MCPInvestigation(snapshot, identity)


async def serve(service: MCPInvestigation) -> None:
    server = service.server()
    # The pinned SDK's supplied-input path consumes readline only; the process owns stdin.
    stdin = anyio.wrap_file(cast(IO[str], BoundedInput(sys.stdin.buffer)))
    async with stdio_server(stdin=stdin) as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    # Metadata-only stderr logging. SDK parser errors may include untrusted input, so suppress them.
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(message)s")
    logging.getLogger("mcp").setLevel(logging.CRITICAL)
    os.environ["OTEL_SDK_DISABLED"] = "true"
    trace.set_tracer_provider(trace.NoOpTracerProvider())
    try:
        asyncio.run(serve(from_environment(os.environ)))
    except (ValueError, OSError, ExceptionGroup):
        sys.stderr.write(
            "Local MCP could not start or transport was rejected; check private configuration "
            "and frame limits.\n"
        )
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
