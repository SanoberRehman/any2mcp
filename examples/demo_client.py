"""End-to-end proof: launch any2mcp as a real MCP server and call its tools.

    python examples/demo_client.py

This starts ``any2mcp examples/calculator.py`` as a stdio subprocess, performs
the MCP handshake, lists the auto-generated tools, and invokes two of them —
exactly what an agent (Claude Desktop, an IDE, your own client) would do.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

EXAMPLE = Path(__file__).with_name("calculator.py")


async def main() -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "any2mcp", str(EXAMPLE)],
    )

    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()

        tools = await session.list_tools()
        print("Tools exposed by calculator.py:")
        for tool in tools.tools:
            print(f"  - {tool.name}: {(tool.description or '').splitlines()[0]}")

        print("\nCalling add(a=2, b=3):")
        result = await session.call_tool("add", {"a": 2, "b": 3})
        print(f"  -> {result.content[0].text}")

        print("\nCalling summarize(numbers=[10, 20, 30], label='scores'):")
        result = await session.call_tool(
            "summarize", {"numbers": [10, 20, 30], "label": "scores"}
        )
        print(f"  -> {result.content[0].text}")


if __name__ == "__main__":
    asyncio.run(main())
