"""Decide which discovered functions are allowed to become MCP tools.

Enforcement model — the important part, and the part that is actually sound:
**a blocked function is never registered as a tool.** It does not appear in
``tools/list``, so the model cannot see it, cannot call it, and cannot talk its
way past it. There is no confirmation token for an LLM to forge and no runtime
check to race. The capability analysis in :mod:`any2mcp.risk` is heuristic; this
gate is not.

Modes, in increasing strictness:

``open``
    Register everything. What any2mcp 0.1 did.
``guard`` (default)
    Register everything except ``high`` risk — subprocesses, dynamic
    execution, recursive deletes — and anything whose source could not be
    read. A calculator needs no flags; an ``os.system`` wrapper is not handed
    to a model by accident.
``readonly``
    Only ``safe`` and ``low``: reads and environment access, no writes, no
    network, no execution.
``strict``
    Only ``safe``: nothing that touched a known side-effecting symbol.

Precedence, highest first: ``--deny-tool`` beats ``--allow-tool`` beats
``--deny-capability`` beats the mode threshold. Naming a specific tool is
treated as a stronger statement of intent than a category rule, and an explicit
deny always wins over an explicit allow.
"""

from __future__ import annotations

import enum
import fnmatch
from dataclasses import dataclass, field

from .risk import Capability, FunctionRisk, RiskLevel


class PolicyMode(enum.Enum):
    OPEN = "open"
    GUARD = "guard"
    READONLY = "readonly"
    STRICT = "strict"

    @property
    def ceiling(self) -> RiskLevel | None:
        """Highest risk level this mode admits; None means no limit."""
        return _MODE_CEILING[self]

    @classmethod
    def parse(cls, text: str) -> PolicyMode:
        for member in cls:
            if member.value == text:
                return member
        valid = ", ".join(m.value for m in cls)
        raise ValueError(f"unknown policy {text!r} (expected one of: {valid})")


_MODE_CEILING: dict[PolicyMode, RiskLevel | None] = {
    PolicyMode.OPEN: None,
    PolicyMode.GUARD: RiskLevel.MODERATE,
    PolicyMode.READONLY: RiskLevel.LOW,
    PolicyMode.STRICT: RiskLevel.SAFE,
}


@dataclass(frozen=True)
class Decision:
    """Whether one function may be registered, and why."""

    name: str
    allowed: bool
    reason: str
    risk: FunctionRisk

    @property
    def blocked(self) -> bool:
        return not self.allowed


@dataclass(frozen=True)
class Policy:
    mode: PolicyMode = PolicyMode.GUARD
    allow_tools: tuple[str, ...] = ()
    deny_tools: tuple[str, ...] = ()
    deny_capabilities: frozenset[Capability] = field(default_factory=frozenset)

    def decide(self, risk: FunctionRisk) -> Decision:
        name = risk.name

        if _matches(name, self.deny_tools):
            return Decision(name, False, "denied explicitly by --deny-tool", risk)

        if _matches(name, self.allow_tools):
            return Decision(name, True, "allowed explicitly by --allow-tool", risk)

        forbidden = self.deny_capabilities & risk.capabilities
        if forbidden:
            listed = ", ".join(sorted(c.value for c in forbidden))
            return Decision(name, False, f"uses denied capability: {listed}", risk)

        ceiling = self.mode.ceiling
        if ceiling is None:
            return Decision(name, True, "policy 'open' allows all tools", risk)

        if risk.level > ceiling:
            if risk.level is RiskLevel.UNKNOWN:
                detail = "source could not be analyzed"
            else:
                caps = ", ".join(sorted(c.value for c in risk.capabilities))
                detail = f"risk '{risk.level.label}' ({caps})"
            return Decision(
                name,
                False,
                f"{detail} exceeds policy '{self.mode.value}' "
                f"(max '{ceiling.label}')",
                risk,
            )

        return Decision(
            name, True, f"risk '{risk.level.label}' within '{self.mode.value}'", risk
        )

    def apply(self, risks: dict[str, FunctionRisk]) -> list[Decision]:
        """Decide every function, preserving the input ordering."""
        return [self.decide(risk) for risk in risks.values()]


def _matches(name: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


def remediation_hint(decisions: list[Decision]) -> str | None:
    """A copy-pasteable next step when tools were blocked, else None."""
    blocked = [d for d in decisions if d.blocked]
    if not blocked:
        return None
    names = " ".join(f"--allow-tool {d.name}" for d in blocked[:3])
    more = "" if len(blocked) <= 3 else f" (and {len(blocked) - 3} more)"
    return (
        f"To expose {'it' if len(blocked) == 1 else 'them'} anyway, re-run with: "
        f"{names}{more}\n"
        "  Or relax the policy with --policy open. Review the code first: "
        "these tools become callable by a model."
    )
