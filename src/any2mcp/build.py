"""Assemble a :class:`FastMCP` server from a target module.

Schema generation is deliberately *not* implemented here. Each discovered
function is handed to ``FastMCP.add_tool``, which uses the MCP SDK's own
pydantic-based machinery to derive the tool's JSON schema from type hints,
defaults, and the docstring. That is the whole point: reuse the canonical
implementation instead of re-deriving type-to-schema rules that would drift.
"""

from __future__ import annotations

from types import ModuleType

from mcp.server.fastmcp import FastMCP

from .discover import Discovered, discover_functions
from .loader import load_module


def build_server(
    target: str,
    *,
    name: str | None = None,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
) -> tuple[FastMCP, list[Discovered]]:
    """Build an MCP server exposing the public functions of *target*.

    Returns the server and the list of functions that were registered.
    """
    module, selector = load_module(target)
    functions = discover_functions(
        module, selector=selector, include=include, exclude=exclude
    )

    server_name = name or _default_name(module)
    server = FastMCP(server_name)

    for item in functions:
        server.add_tool(item.func, name=item.name)

    return server, functions


def _default_name(module: ModuleType) -> str:
    raw = getattr(module, "__name__", "any2mcp")
    # File-loaded targets get an internal ``any2mcp_target_<stem>`` name; make
    # the advertised server name the friendly stem instead.
    prefix = "any2mcp_target_"
    if raw.startswith(prefix):
        return raw[len(prefix) :]
    return raw.rsplit(".", 1)[-1]
