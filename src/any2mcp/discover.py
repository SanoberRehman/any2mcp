"""Decide which functions in a module should become MCP tools.

Selection rules, in order:

1. If a ``selector`` is given (``mymod:foo``), only that function is exposed.
2. Otherwise, if the module defines ``__all__``, that list is the allow-list.
3. Otherwise, every module-level function that is (a) not underscore-prefixed
   and (b) actually *defined* in this module (not imported from elsewhere) is
   exposed.

``--include`` / ``--exclude`` glob patterns are applied on top of the above.
"""

from __future__ import annotations

import fnmatch
import inspect
from collections.abc import Callable
from dataclasses import dataclass
from types import ModuleType


@dataclass(frozen=True)
class Discovered:
    name: str
    func: Callable[..., object]


def discover_functions(
    module: ModuleType,
    *,
    selector: str | None = None,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
) -> list[Discovered]:
    """Return the ordered list of functions to expose from *module*."""
    if selector is not None:
        func = getattr(module, selector, None)
        if not _is_exposable(func):
            raise DiscoveryError(
                f"{selector!r} is not a callable function in "
                f"{getattr(module, '__name__', module)!r}"
            )
        return [Discovered(name=selector, func=func)]

    names = _candidate_names(module)
    names = _apply_patterns(names, include=include, exclude=exclude)

    found: list[Discovered] = []
    for name in names:
        func = getattr(module, name, None)
        if _is_exposable(func):
            found.append(Discovered(name=name, func=func))
    return found


def _candidate_names(module: ModuleType) -> list[str]:
    explicit = getattr(module, "__all__", None)
    if explicit is not None:
        return [str(n) for n in explicit]

    module_name = getattr(module, "__name__", None)
    names: list[str] = []
    for name, obj in vars(module).items():
        if name.startswith("_"):
            continue
        if not _is_exposable(obj):
            continue
        # Skip functions merely imported into this module's namespace.
        if getattr(obj, "__module__", None) != module_name:
            continue
        names.append(name)
    return names


def _apply_patterns(
    names: list[str],
    *,
    include: list[str] | None,
    exclude: list[str] | None,
) -> list[str]:
    result = names
    if include:
        result = [n for n in result if any(fnmatch.fnmatch(n, p) for p in include)]
    if exclude:
        result = [n for n in result if not any(fnmatch.fnmatch(n, p) for p in exclude)]
    return result


def _is_exposable(obj: object) -> bool:
    """A plain function or coroutine function, callable and introspectable."""
    if obj is None:
        return False
    if not (inspect.isfunction(obj) or inspect.iscoroutinefunction(obj)):
        return False
    try:
        inspect.signature(obj)
    except (ValueError, TypeError):
        return False
    return True


class DiscoveryError(Exception):
    """Raised when a requested function cannot be found or exposed."""
