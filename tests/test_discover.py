from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from any2mcp.discover import DiscoveryError, discover_functions
from any2mcp.loader import load_module


def _load(fixtures_dir: Path, name: str):
    module, selector = load_module(str(fixtures_dir / name))
    return module, selector


def test_excludes_private_and_imported(fixtures_dir):
    module, _ = _load(fixtures_dir, "messy.py")
    names = {d.name for d in discover_functions(module)}
    assert "_private" not in names
    # `join` was imported from os.path; it must not leak in as a tool.
    assert "join" not in names
    assert "add" not in names  # not present here, sanity
    assert "with_optional" in names
    assert "async_tool" in names


def test_selector_returns_single(fixtures_dir):
    module, _ = _load(fixtures_dir, "messy.py")
    found = discover_functions(module, selector="with_enum")
    assert [d.name for d in found] == ["with_enum"]


def test_selector_rejects_non_function(fixtures_dir):
    module, _ = _load(fixtures_dir, "messy.py")
    with pytest.raises(DiscoveryError):
        discover_functions(module, selector="Color")  # a class, not a function


def test_selector_can_override_privacy(fixtures_dir):
    # An explicit selector is intentional: picking a private function is allowed.
    module, _ = _load(fixtures_dir, "messy.py")
    found = discover_functions(module, selector="_private")
    assert [d.name for d in found] == ["_private"]


def test_include_exclude_globs(fixtures_dir):
    module, _ = _load(fixtures_dir, "messy.py")
    only_with = {d.name for d in discover_functions(module, include=["with_*"])}
    assert all(n.startswith("with_") for n in only_with)
    assert "async_tool" not in only_with

    no_with = {d.name for d in discover_functions(module, exclude=["with_*"])}
    assert not any(n.startswith("with_") for n in no_with)
    assert "async_tool" in no_with


def test_dunder_all_is_respected(tmp_path):
    src = textwrap.dedent(
        '''
        __all__ = ["exposed"]

        def exposed(x: int) -> int:
            return x

        def hidden(x: int) -> int:
            return x
        '''
    )
    path = tmp_path / "explicit.py"
    path.write_text(src)
    module, _ = load_module(str(path))
    names = {d.name for d in discover_functions(module)}
    assert names == {"exposed"}
