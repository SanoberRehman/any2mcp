"""Signatures the SDK's schema generator cannot handle.

These must be *skipped* individually — never crash the whole build. ``good``
proves the healthy functions still get through.
"""

from __future__ import annotations


class Weird:
    """A bare, non-pydantic class used as a parameter type."""


def uses_bare_class(x: Weird) -> int:
    """Parameter typed as a bare class -> no JSON schema."""
    return 1


def good(a: int, b: int) -> int:
    """A perfectly ordinary function that must survive."""
    return a + b
