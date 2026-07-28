"""Human- and machine-readable renderings of the risk analysis.

Output is deliberately ASCII-only. Box-drawing characters and em dashes raise
``UnicodeEncodeError`` on a default Windows ``cp1252`` console, and a safety
report that crashes the tool is worse than a plain one.
"""

from __future__ import annotations

from typing import Any

from .policy import Decision, Policy
from .risk import FunctionRisk

_HEADER = ("RISK", "TOOL", "CAPABILITIES", "STATUS")


def render_table(
    decisions: list[Decision],
    *,
    target: str,
    policy: Policy,
    show_findings: bool = True,
) -> str:
    """A fixed-width table of every function, its capabilities, and its fate."""
    lines: list[str] = [
        f"any2mcp risk report: {target}",
        f"policy: {policy.mode.value}{_ceiling_note(policy)}",
        "",
    ]

    rows = [
        (
            d.risk.level.label,
            d.name,
            ", ".join(sorted(c.value for c in d.risk.capabilities)) or "-",
            "exposed" if d.allowed else "BLOCKED",
        )
        for d in decisions
    ]

    widths = [
        max(len(_HEADER[i]), *(len(r[i]) for r in rows)) if rows else len(_HEADER[i])
        for i in range(4)
    ]
    lines.append("  " + _row(_HEADER, widths))
    lines.append("  " + "  ".join("-" * w for w in widths))

    for decision, row in zip(decisions, rows, strict=True):
        lines.append("  " + _row(row, widths))
        if show_findings:
            for finding in decision.risk.findings:
                lines.append(f"      - {finding.render()}")
            if decision.risk.note:
                lines.append(f"      ! {decision.risk.note}")
            if decision.blocked:
                lines.append(f"      ! blocked: {decision.reason}")

    exposed = sum(1 for d in decisions if d.allowed)
    blocked = len(decisions) - exposed
    lines.extend(["", f"{exposed} exposed, {blocked} blocked."])
    return "\n".join(lines)


def to_json(decisions: list[Decision], *, target: str, policy: Policy) -> dict[str, Any]:
    """Machine-readable form, for CI gates and editor integrations."""
    return {
        "target": target,
        "policy": policy.mode.value,
        "summary": {
            "exposed": sum(1 for d in decisions if d.allowed),
            "blocked": sum(1 for d in decisions if d.blocked),
        },
        "tools": [
            {
                "name": d.name,
                "risk": d.risk.level.label,
                "capabilities": sorted(c.value for c in d.risk.capabilities),
                "exposed": d.allowed,
                "reason": d.reason,
                "analyzed": d.risk.analyzed,
                "note": d.risk.note,
                "findings": [
                    {
                        "capability": f.capability.value,
                        "symbol": f.symbol,
                        "line": f.lineno,
                        "heuristic": f.heuristic,
                        "via": f.via,
                    }
                    for f in d.risk.findings
                ],
            }
            for d in decisions
        ],
    }


def startup_summary(decisions: list[Decision], *, policy: Policy) -> list[str]:
    """Short stderr banner: what was exposed, what was withheld, and why."""
    exposed = [d for d in decisions if d.allowed]
    blocked = [d for d in decisions if d.blocked]

    notable = [d for d in exposed if d.risk.capabilities]
    lines: list[str] = []
    if notable:
        detail = ", ".join(
            f"{d.name} [{d.risk.level.label}]"
            for d in sorted(notable, key=lambda d: -d.risk.level.order)[:5]
        )
        lines.append(f"any2mcp: exposed tools with side effects: {detail}")
    for decision in blocked:
        lines.append(f"any2mcp: BLOCKED {decision.name} - {decision.reason}")
    return lines


def _ceiling_note(policy: Policy) -> str:
    ceiling = policy.mode.ceiling
    if ceiling is None:
        return " (no restrictions)"
    return f" (allows up to '{ceiling.label}')"


def _row(cells: tuple[str, ...], widths: list[int]) -> str:
    return "  ".join(cell.ljust(width) for cell, width in zip(cells, widths, strict=True))


def risks_only_table(risks: dict[str, FunctionRisk], *, target: str) -> str:
    """Render without policy context, for `--risk-report` on an unloaded file."""
    from .policy import Policy as _Policy

    default = _Policy()
    return render_table(
        [default.decide(r) for r in risks.values()], target=target, policy=default
    )
