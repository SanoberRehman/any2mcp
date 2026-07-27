"""A module of deliberately messy signatures — the schema-quality test matrix.

Also exercises discovery rules: it imports a function from the stdlib (which
must NOT be exposed) and defines a private helper (also not exposed).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import Enum
from os.path import join  # imported symbol: must not be exposed as a tool
from typing import Literal, Optional, Union

from pydantic import BaseModel

# Re-export the imported symbol to prove it is filtered out by __module__ check.
_ = join


class Color(str, Enum):
    red = "red"
    green = "green"
    blue = "blue"


class Point(BaseModel):
    x: int
    y: int
    label: str = "origin"


@dataclass
class Box:
    width: float
    height: float


def with_optional(name: str, nickname: Optional[str] = None) -> str:
    """Optional / None-union parameter."""
    return nickname or name


def with_union(value: Union[int, str]) -> str:
    """A plain union parameter."""
    return str(value)


def with_literal(mode: Literal["fast", "slow"] = "fast") -> str:
    """A Literal-typed parameter with a default."""
    return mode


def with_enum(color: Color) -> str:
    """An Enum-typed parameter."""
    return color.value


def with_pydantic_model(point: Point) -> int:
    """A pydantic BaseModel as a parameter (nested object schema)."""
    return point.x + point.y


def with_dataclass(box: Box) -> float:
    """A dataclass as a parameter."""
    return box.width * box.height


def with_containers(
    tags: list[str], meta: dict[str, int], pair: tuple[int, int]
) -> int:
    """Container types: list, dict, tuple."""
    return len(tags) + len(meta) + sum(pair)


def with_defaults(a: int, b: int = 10, c: str = "x") -> str:
    """Mixed required and defaulted parameters."""
    return f"{a}{b}{c}"


def no_annotations(a, b=5):
    """No type hints at all — must still be exposable (schema falls back)."""
    return a


async def async_tool(x: int) -> int:
    """An async function must be exposable as a tool."""
    await asyncio.sleep(0)
    return x * 2


def _private(x: int) -> int:
    """Leading underscore — must never be exposed."""
    return x
