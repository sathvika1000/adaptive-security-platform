"""Run the deterministic controller demo through real local MCP and save a private journal."""

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

from mcp import Client
from mcp.client.stdio import StdioServerParameters
from opentelemetry import trace

from adaptive_security.investigation_runner import (
    EvidenceReviewAdapter,
    InvestigationRunner,
    ReasoningAdapter,
    RunBudget,
    RunReport,
    save_run,
)
from adaptive_security.investigation_tools import ToolName, ToolRequest
from adaptive_security.mcp_server import load_identity


class MCPChannel:
    def __init__(self, client: Client) -> None:
        self.client = client

    async def read(self, tool: ToolName, request: ToolRequest) -> object:
        result = await self.client.call_tool(tool, request.model_dump())
        if result.is_error:
            raise ValueError("MCP denied the tool invocation")
        return result.structured_content


async def run_demo(
    access: Path,
    review: Path,
    grant_index: int,
    *,
    ollama_model: str | None = None,
    token_limit: int = 36_864,
) -> RunReport:
    identity = load_identity(access)
    grant = identity.grants[grant_index]
    adapter: ReasoningAdapter = EvidenceReviewAdapter()
    budget = RunBudget()
    adapter_name = "deterministic-demo"
    if ollama_model is not None:
        from adaptive_security.ollama_adapter import OllamaAdapter

        adapter = OllamaAdapter(ollama_model, token_limit)
        budget = RunBudget(total_seconds=120.0, operation_seconds=30.0)
        adapter_name = "ollama-local:" + ollama_model
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "adaptive_security.mcp_server"],
        env={
            "ASP_MCP_ACCESS_FILE": str(access.resolve()),
            "ASP_OFFLINE_REVIEW_PATH": str(review.resolve()),
            "OTEL_SDK_DISABLED": "true",
        },
    )
    async with Client(params, read_timeout_seconds=5) as client:
        return await InvestigationRunner(
            grant, MCPChannel(client), adapter, budget, adapter_name=adapter_name
        ).run()


def main() -> None:
    os.environ["OTEL_SDK_DISABLED"] = "true"
    trace.set_tracer_provider(trace.NoOpTracerProvider())
    logging.getLogger("mcp").setLevel(logging.CRITICAL)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("access_file", type=Path)
    parser.add_argument("review_path", type=Path)
    parser.add_argument("journal_path", type=Path)
    parser.add_argument("--grant-index", type=int, default=0, choices=range(100))
    parser.add_argument(
        "--ollama-model", help="Opt in to a local model already installed in Ollama"
    )
    parser.add_argument("--model-token-limit", type=int, default=36_864)
    args = parser.parse_args()
    try:
        report = asyncio.run(
            run_demo(
                args.access_file,
                args.review_path,
                args.grant_index,
                ollama_model=args.ollama_model,
                token_limit=args.model_token_limit,
            )
        )
        save_run(report, args.journal_path)
    except Exception:
        sys.stderr.write(
            "Investigation demo failed; check private configuration and journal path.\n"
        )
        raise SystemExit(2) from None
    print(
        json.dumps(
            {
                "run_id": report.run_id,
                "status": report.status,
                "steps": report.steps,
                "tool_calls": report.tool_calls,
                "adapter": report.adapter_name,
                "adapter_usage": (
                    report.adapter_usage.model_dump() if report.adapter_usage else None
                ),
                "journal": str(args.journal_path),
            }
        )
    )
    if report.status != "completed":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
