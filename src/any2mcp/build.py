"""Assemble a :class:`FastMCP` server from a target module.

Schema generation is deliberately *not* implemented here. Each discovered
function is handed to ``FastMCP.add_tool``, which uses the MCP SDK's own
pydantic-based machinery to derive the tool's JSON schema from type hints,
defaults, and the docstring. That is the whole point: reuse the canonical
implementation instead of re-deriving type-to-schema rules that would drift.

A function whose signature cannot be turned into a JSON schema (e.g. a
parameter typed as a bare non-pydantic class, some ``**kwargs`` shapes, or an
unresolvable forward reference) is *skipped*, not fatal. One unsupported
function costs one tool — never the whole server.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import ModuleType

from mcp.server.fastmcp import FastMCP

from .audit import AuditLog
from .discover import Discovered, discover_functions
from .loader import load_module
from .policy import Decision, Policy
from .risk import FunctionRisk, analyze


@dataclass(frozen=True)
class Skipped:
    name: str
    reason: str


@dataclass(frozen=True)
class BuildResult:
    server: FastMCP
    registered: list[Discovered]
    skipped: list[Skipped]
    decisions: list[Decision] = field(default_factory=list)
    risks: dict[str, FunctionRisk] = field(default_factory=dict)

    @property
    def blocked(self) -> list[Decision]:
        return [d for d in self.decisions if d.blocked]

    # Preserve tuple-unpacking ergonomics: ``server, funcs = build_server(...)``.
    def __iter__(self):
        return iter((self.server, self.registered))


def build_server(
    target: str,
    *,
    name: str | None = None,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    policy: Policy | None = None,
    audit: AuditLog | None = None,
) -> BuildResult:
    """Build an MCP server exposing the permitted public functions of *target*.

    Functions the *policy* blocks are never registered, so they are absent from
    ``tools/list`` entirely — see :mod:`any2mcp.policy` for why that, rather
    than a call-time refusal, is the enforcement point.

    Returns a :class:`BuildResult`. It also unpacks as ``(server, registered)``
    for convenience.
    """
    policy = policy or Policy()
    audit = audit or AuditLog(None)

    module, selector = load_module(target)
    functions = discover_functions(
        module, selector=selector, include=include, exclude=exclude
    )

    risks = analyze(module, [item.name for item in functions])
    decisions = [policy.decide(risks[item.name]) for item in functions]
    verdict = {d.name: d for d in decisions}

    server_name = name or _default_name(module)
    server = FastMCP(server_name)

    registered: list[Discovered] = []
    skipped: list[Skipped] = []
    for item in functions:
        decision = verdict[item.name]
        if decision.blocked:
            audit.record_blocked(
                item.name, decision.reason, decision.risk.level.label
            )
            continue
        instrumented = audit.wrap(item.func, item.name, decision.risk.level.label)
        try:
            server.add_tool(instrumented, name=item.name)
        except Exception as exc:  # noqa: BLE001 - isolate one bad signature
            skipped.append(Skipped(name=item.name, reason=_short_reason(exc)))
        else:
            registered.append(item)

    return BuildResult(
        server=server,
        registered=registered,
        skipped=skipped,
        decisions=decisions,
        risks=risks,
    )


def _short_reason(exc: Exception) -> str:
    text = str(exc).splitlines()[0].strip() if str(exc) else exc.__class__.__name__
    return f"{exc.__class__.__name__}: {text}" if text else exc.__class__.__name__


def _default_name(module: ModuleType) -> str:
    raw = getattr(module, "__name__", "any2mcp")
    # File-loaded targets get an internal ``any2mcp_target_<stem>`` name; make
    # the advertised server name the friendly stem instead.
    prefix = "any2mcp_target_"
    if raw.startswith(prefix):
        return raw[len(prefix) :]
    return raw.rsplit(".", 1)[-1]
