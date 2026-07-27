"""End-to-end: a real MCP client session talks to a server built by any2mcp,
over the SDK's in-memory transport. Proves the tools are actually callable."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from any2mcp.build import build_server


@pytest.mark.anyio
async def test_client_lists_and_calls_tools(fixtures_dir: Path):
    server, _ = build_server(
        str(Path(__file__).parents[1] / "examples" / "calculator.py")
    )

    async with create_connected_server_and_client_session(
        server._mcp_server
    ) as client:
        tools = await client.list_tools()
        names = {t.name for t in tools.tools}
        assert {"add", "divide", "round_to", "summarize"} <= names

        add_result = await client.call_tool("add", {"a": 2, "b": 3})
        assert add_result.content[0].text == "5.0"

        summary = await client.call_tool(
            "summarize", {"numbers": [10, 20, 30], "label": "scores"}
        )
        parsed = json.loads(summary.content[0].text)
        assert parsed["mean"] == 20.0
        assert parsed["label"] == "scores"


@pytest.fixture
def anyio_backend():
    return "asyncio"
