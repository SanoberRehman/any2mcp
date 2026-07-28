"""End-to-end proof that the policy is enforced, not merely advertised.

    python examples/demo_safety.py

Launches ``any2mcp examples/devtools.py`` as a real stdio MCP server, then acts
as a hostile client: it lists the tools, confirms ``run_shell`` is absent, and
tries to call it anyway. The call fails because the tool was never registered —
there is no confirmation flow to talk past.

Then it relaunches with ``--allow-tool run_shell`` to show the escape hatch is a
deliberate, explicit act.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

EXAMPLE = Path(__file__).with_name("devtools.py")


async def connect(extra_args: list[str]) -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "any2mcp", str(EXAMPLE), *extra_args],
    )
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        tools = await session.list_tools()
        names = [tool.name for tool in tools.tools]

        label = " ".join(extra_args) or "(default policy: guard)"
        print(f"\n=== any2mcp devtools.py {label} ===")
        print(f"tools visible to the model: {names}")

        for dangerous in ("run_shell", "delete_path"):
            if dangerous in names:
                print(f"  {dangerous}: EXPOSED")
                continue
            outcome = await session.call_tool(dangerous, {"command": "echo pwned"})
            first = outcome.content[0].text if outcome.content else ""
            print(f"  {dangerous}: withheld; calling it anyway -> {first.strip()}")

        result = await session.call_tool("word_count", {"text": "still fully usable"})
        print(f"  word_count still works -> {result.content[0].text}")


async def main() -> None:
    await connect([])
    await connect(["--allow-tool", "run_shell"])


if __name__ == "__main__":
    asyncio.run(main())
