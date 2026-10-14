"""Exercise the real local MCP transport without a model, API server or platform key."""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from mcp import Client
from mcp.client.stdio import StdioServerParameters


async def smoke(access_file: Path, review_path: Path) -> dict[str, Any]:
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "adaptive_security.mcp_server"],
        env={"ASP_MCP_ACCESS_FILE": str(access_file.resolve()),
             "ASP_OFFLINE_REVIEW_PATH": str(review_path.resolve()),
             "OTEL_SDK_DISABLED": "true"},
    )
    async with Client(params, read_timeout_seconds=10) as client:
        listed = await client.list_tools()
        offset = 0
        while True:
            response = await client.call_tool("get_investigation_scopes", {"offset": offset})
            if response.is_error:
                raise ValueError("Scope discovery failed")
            catalog = response.structured_content
            grant = next((entry for entry in catalog["entries"] if not entry["stale"]), None)
            if grant is not None:
                break
            offset = catalog["next_offset"]
            if offset is None:
                raise ValueError("No current investigation grant")
        tool = ("get_finding_evidence" if "get_finding_evidence" in grant["tools"]
                else grant["tools"][0])
        invocation = {name: grant[name] for name in ("capture_id", "finding_id", "review_key")}
        result = await client.call_tool(tool, invocation | {"limit": 1})
        if result.is_error:
            raise ValueError("Granted evidence read failed")
        return {
            "transport": "stdio", "actor": catalog["actor"],
            "available_tools": [entry.name for entry in listed.tools], "tool": tool,
            "capture_id": grant["capture_id"], "finding_id": grant["finding_id"],
            "successful": True,
            "limitation": "Local offline protocol check; no model or accuracy claim.",
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("access_file", type=Path)
    parser.add_argument("review_path", type=Path)
    args = parser.parse_args()
    try:
        report = asyncio.run(smoke(args.access_file, args.review_path))
    except Exception:
        sys.stderr.write("MCP smoke check failed; verify private access, "
                         "current grants and bundle.\n")
        raise SystemExit(2) from None
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
