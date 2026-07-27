"""A plain, decorator-free Python module.

Run ``any2mcp examples/calculator.py`` and every public function below becomes
an MCP tool — schemas, validation, and descriptions derived automatically from
the type hints and docstrings. Nothing in this file knows MCP exists.
"""

from __future__ import annotations

from enum import Enum


def add(a: float, b: float) -> float:
    """Add two numbers and return the sum."""
    return a + b


def divide(a: float, b: float) -> float:
    """Divide ``a`` by ``b``. Raises if ``b`` is zero."""
    if b == 0:
        raise ValueError("cannot divide by zero")
    return a / b


class Rounding(str, Enum):
    up = "up"
    down = "down"
    nearest = "nearest"


def round_to(value: float, ndigits: int = 2, mode: Rounding = Rounding.nearest) -> float:
    """Round ``value`` to ``ndigits`` decimal places using the given mode."""
    factor = 10**ndigits
    if mode is Rounding.up:
        import math

        return math.ceil(value * factor) / factor
    if mode is Rounding.down:
        import math

        return math.floor(value * factor) / factor
    return round(value, ndigits)


def summarize(numbers: list[float], label: str | None = None) -> dict[str, float | str]:
    """Return count, sum, and mean of ``numbers``, with an optional label."""
    total = sum(numbers)
    result: dict[str, float | str] = {
        "count": len(numbers),
        "sum": total,
        "mean": total / len(numbers) if numbers else 0.0,
    }
    if label is not None:
        result["label"] = label
    return result


# Private helper — never exposed as a tool (leading underscore).
def _internal_precision_hint() -> int:
    return 12
