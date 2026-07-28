"""Command-line entry point: ``any2mcp TARGET [options]``."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

from . import __version__
from .audit import AuditLog
from .build import build_server
from .discover import DiscoveryError
from .loader import ModuleLoadError
from .policy import Policy, PolicyMode, remediation_hint
from .report import render_table, startup_summary, to_json
from .risk import Capability, RiskAnalysisError, analyze_path

_EPILOG = """\
examples:
  any2mcp ./tools/calc.py            expose every public function in calc.py
  any2mcp mypackage.tools            expose a dotted, importable module
  any2mcp calc.py:add                expose only the `add` function
  any2mcp calc.py --list             show the tools + JSON schemas, don't serve
  any2mcp calc.py --risk-report      audit what each function can reach
  any2mcp calc.py --policy readonly  refuse to expose anything that writes
  any2mcp calc.py --allow-tool run   expose a high-risk tool on purpose

policy: by default (--policy guard) functions that reach subprocesses, dynamic
execution, or recursive deletion are NOT exposed. Blocked tools are absent from
tools/list entirely, so a model cannot call them. Run --risk-report to see why.

security: any2mcp is not a sandbox. Capability analysis is a static heuristic
and indirection (getattr, eval) defeats it; a function reported 'safe' is one
where nothing risky was *found*. Importing a module also runs its top-level
code, so --risk-report on a file path deliberately does not import it.
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
        help="print the exposed tools and their schemas, then exit",
    )

    safety = parser.add_argument_group("safety")
    safety.add_argument(
        "--policy",
        choices=tuple(m.value for m in PolicyMode),
        default=PolicyMode.GUARD.value,
        help=(
            "how much risk to expose: open (all), guard (default: no high risk), "
            "readonly (no writes/network), strict (no side effects at all)"
        ),
    )
    safety.add_argument(
        "--allow-tool",
        action="append",
        metavar="GLOB",
        default=[],
        help="expose this tool even if the policy would block it (repeatable)",
    )
    safety.add_argument(
        "--deny-tool",
        action="append",
        metavar="GLOB",
        default=[],
        help="never expose this tool; overrides --allow-tool (repeatable)",
    )
    safety.add_argument(
        "--deny-capability",
        action="append",
        metavar="CAP",
        default=[],
        choices=tuple(c.value for c in Capability),
        help="block any tool reaching this capability (repeatable)",
    )
    safety.add_argument(
        "--risk-report",
        action="store_true",
        help="print the capability audit and exit (does not import a file target)",
    )
    safety.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format for --risk-report (default: table)",
    )
    safety.add_argument(
        "--audit-log",
        metavar="PATH",
        help="append a JSONL record of every tool call to PATH",
    )
    safety.add_argument(
        "--audit-values",
        action="store_true",
        help="include argument values in the audit log (default: types only)",
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
    policy = _policy_from_args(args)

    if args.risk_report:
        return _run_risk_report(args, policy)

    audit = AuditLog(args.audit_log, record_values=args.audit_values)

    try:
        result = build_server(
            args.target,
            name=args.name,
            include=args.include,
            exclude=args.exclude,
            policy=policy,
            audit=audit,
        )
    except (ModuleLoadError, DiscoveryError) as exc:
        print(f"any2mcp: {exc}", file=sys.stderr)
        return 2

    for skip in result.skipped:
        print(
            f"any2mcp: skipping {skip.name!r} (unsupported signature: {skip.reason})",
            file=sys.stderr,
        )

    for line in startup_summary(result.decisions, policy=policy):
        print(line, file=sys.stderr)

    if not result.registered:
        print(_nothing_exposed_message(args.target, result, policy), file=sys.stderr)
        return 1

    # Print before the --list early return: someone inspecting the tool list is
    # exactly who needs to know why a function is missing from it.
    hint = remediation_hint(result.decisions)
    if hint:
        print(f"any2mcp: {hint}", file=sys.stderr)

    if args.list:
        _print_tool_list(result.server)
        return 0

    audit.record_startup(
        {
            "target": args.target,
            "policy": policy.mode.value,
            "exposed": [item.name for item in result.registered],
        }
    )
    print(
        f"any2mcp: serving {len(result.registered)} tool(s) from {args.target!r} "
        f"over {args.transport}",
        file=sys.stderr,
    )
    result.server.run(transport=args.transport)
    return 0


def _run_risk_report(args: argparse.Namespace, policy: Policy) -> int:
    """Audit the target. For a file path this never imports it."""
    target, selector = _split_selector(args.target)
    source_path = _source_path_for(target)

    if source_path is None:
        print(
            f"any2mcp: cannot locate source for {target!r} to audit it.\n"
            "  --risk-report works on .py files and importable modules with "
            "source available.",
            file=sys.stderr,
        )
        return 2

    names = [selector] if selector else None
    try:
        risks = analyze_path(source_path, names)
    except RiskAnalysisError as exc:
        print(f"any2mcp: {exc}", file=sys.stderr)
        return 2

    if not risks:
        print(
            f"any2mcp: no public functions found in {target!r}.", file=sys.stderr
        )
        return 1

    decisions = [policy.decide(risk) for risk in risks.values()]

    if args.format == "json":
        print(json.dumps(to_json(decisions, target=target, policy=policy), indent=2))
    else:
        print(render_table(decisions, target=target, policy=policy))

    # Non-zero when something was blocked, so this is usable as a CI gate.
    return 3 if any(d.blocked for d in decisions) else 0


def _policy_from_args(args: argparse.Namespace) -> Policy:
    return Policy(
        mode=PolicyMode.parse(args.policy),
        allow_tools=tuple(args.allow_tool),
        deny_tools=tuple(args.deny_tool),
        deny_capabilities=frozenset(
            Capability(value) for value in args.deny_capability
        ),
    )


def _split_selector(target: str) -> tuple[str, str | None]:
    """Split ``mod.py:func`` into its parts, tolerating Windows drive letters."""
    head, sep, tail = target.rpartition(":")
    if not sep or not tail or not tail.isidentifier():
        return target, None
    return head, tail


def _source_path_for(target: str) -> str | None:
    """Resolve a target to a source file without importing the target itself."""
    if target.endswith(".py"):
        return target if Path(target).is_file() else None
    try:
        spec = importlib.util.find_spec(target)
    except (ImportError, ValueError, AttributeError, TypeError):
        return None
    if spec is None or not spec.origin or not spec.origin.endswith(".py"):
        return None
    return spec.origin


def _nothing_exposed_message(target: str, result, policy: Policy) -> str:
    if result.blocked:
        hint = remediation_hint(result.decisions) or ""
        return (
            f"any2mcp: every discovered function in {target!r} was blocked by "
            f"policy '{policy.mode.value}'.\n  {hint}"
        )
    return (
        f"any2mcp: no exposable functions found in {target!r}.\n"
        "  Hint: functions must be public (no leading underscore) and defined\n"
        "  in the target module. Use --include to widen the search."
    )


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
