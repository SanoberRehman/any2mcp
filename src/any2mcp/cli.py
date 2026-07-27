"""Command-line entry point: ``any2mcp TARGET [options]``."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .build import build_server
from .discover import DiscoveryError
from .loader import ModuleLoadError

_EPILOG = """\
examples:
  any2mcp ./tools/calc.py            expose every public function in calc.py
  any2mcp mypackage.tools            expose a dotted, importable module
  any2mcp calc.py:add                expose only the `add` function
  any2mcp calc.py --list             show the tools + JSON schemas, don't serve
  any2mcp calc.py --exclude '_*'     skip functions matching a glob
  any2mcp calc.py --transport sse    serve over SSE instead of stdio

security: importing a module runs its top-level code. Only point any2mcp at
code you trust, exactly as you would with `python -c "import that_module"`.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="any2mcp",
        description="Turn any Python module into an MCP server. No decorators.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "target",
        help="a .py file, an importable module, or either with a ':name' selector",
    )
    parser.add_argument(
        "--name",
        help="server name advertised to clients (default: the module name)",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "sse", "streamable-http"),
        default="stdio",
        help="transport to serve on (default: stdio)",
    )
    parser.add_argument(
        "--include",
        action="append",
        metavar="GLOB",
        help="only expose functions matching this glob (repeatable)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        metavar="GLOB",
        help="skip functions matching this glob (repeatable)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="print the discovered tools and their schemas, then exit",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        result = build_server(
            args.target,
            name=args.name,
            include=args.include,
            exclude=args.exclude,
        )
    except (ModuleLoadError, DiscoveryError) as exc:
        print(f"any2mcp: {exc}", file=sys.stderr)
        return 2

    for skip in result.skipped:
        print(
            f"any2mcp: skipping {skip.name!r} (unsupported signature: {skip.reason})",
            file=sys.stderr,
        )

    if not result.registered:
        print(
            f"any2mcp: no exposable functions found in {args.target!r}.\n"
            "  Hint: functions must be public (no leading underscore) and defined\n"
            "  in the target module. Use --include to widen the search.",
            file=sys.stderr,
        )
        return 1

    if args.list:
        _print_tool_list(result.server)
        return 0

    print(
        f"any2mcp: serving {len(result.registered)} tool(s) from {args.target!r} "
        f"over {args.transport}",
        file=sys.stderr,
    )
    result.server.run(transport=args.transport)
    return 0


def _print_tool_list(server) -> None:
    tools = server._tool_manager.list_tools()
    payload = [
        {
            "name": tool.name,
            "description": (tool.description or "").strip().splitlines()[0]
            if tool.description
            else "",
            "input_schema": tool.parameters,
        }
        for tool in tools
    ]
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    raise SystemExit(main())
