"""Resolve a user-supplied target string into an importable Python module.

A *target* is one of:

* a path to a file            ``./tools/calc.py``  or  ``tools/calc.py``
* a dotted, importable module ``mypackage.tools``
* either of the above with an explicit selector suffix ``…:public_name``

.. warning::
   Importing a module runs its top-level code. ``any2mcp`` never sandboxes the
   target — only point it at code you trust, exactly as you would with
   ``python -c "import that_module"``.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType


@dataclass(frozen=True)
class Target:
    """A parsed target: the module to import plus an optional name selector."""

    module: str
    selector: str | None = None


def parse_target(raw: str) -> Target:
    """Split a raw target string into its module part and optional ``:selector``.

    A leading Windows drive letter (``C:\\...``) is not mistaken for a selector.
    """
    module, sep, selector = raw.rpartition(":")
    if not sep:
        return Target(module=raw, selector=None)
    # Guard against Windows drive letters, e.g. ``C:\path`` or a bare ``C:``.
    if len(module) == 1 and module.isalpha():
        return Target(module=raw, selector=None)
    return Target(module=module, selector=selector or None)


def load_module(target: str) -> tuple[ModuleType, str | None]:
    """Import the module named by *target* and return ``(module, selector)``.

    Raises :class:`ModuleLoadError` with an actionable message on failure.
    """
    parsed = parse_target(target)
    candidate = Path(parsed.module)

    try:
        if candidate.suffix == ".py" or candidate.exists():
            module = _load_from_path(candidate)
        else:
            module = importlib.import_module(parsed.module)
    except ModuleLoadError:
        raise
    except Exception as exc:
        raise ModuleLoadError(
            f"Could not import {parsed.module!r}: {type(exc).__name__}: {exc}"
        ) from exc

    return module, parsed.selector


def _load_from_path(path: Path) -> ModuleType:
    if not path.exists():
        raise ModuleLoadError(f"File not found: {path}")
    if path.suffix != ".py":
        raise ModuleLoadError(f"Not a Python file: {path}")

    resolved = path.resolve()
    module_name = f"any2mcp_target_{resolved.stem}"

    spec = importlib.util.spec_from_file_location(module_name, resolved)
    if spec is None or spec.loader is None:
        raise ModuleLoadError(f"Could not build an import spec for {path}")

    module = importlib.util.module_from_spec(spec)
    # Register before executing so dataclasses / pickling inside the target work.
    sys.modules[module_name] = module
    # Let the target import sibling modules from its own directory.
    sys.path.insert(0, str(resolved.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


class ModuleLoadError(Exception):
    """Raised when a target module cannot be located or imported."""
