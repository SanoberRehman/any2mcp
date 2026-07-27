from __future__ import annotations

import pytest

from any2mcp.loader import ModuleLoadError, load_module, parse_target


def test_parse_plain_module():
    t = parse_target("package.module")
    assert t.module == "package.module"
    assert t.selector is None


def test_parse_selector():
    t = parse_target("package.module:func")
    assert t.module == "package.module"
    assert t.selector == "func"


def test_parse_file_with_selector():
    t = parse_target("tools/calc.py:add")
    assert t.module == "tools/calc.py"
    assert t.selector == "add"


def test_windows_drive_is_not_a_selector():
    t = parse_target(r"C:\tools\calc.py")
    assert t.module == r"C:\tools\calc.py"
    assert t.selector is None


def test_load_dotted_stdlib_module():
    module, selector = load_module("json")
    assert hasattr(module, "dumps")
    assert selector is None


def test_load_missing_file_raises():
    with pytest.raises(ModuleLoadError):
        load_module("does_not_exist.py")


def test_load_missing_module_raises():
    with pytest.raises(ModuleLoadError):
        load_module("definitely.not.a.real.module.xyz")


def test_load_file_with_selector(fixtures_dir):
    module, selector = load_module(str(fixtures_dir / "messy.py") + ":with_enum")
    assert selector == "with_enum"
    assert hasattr(module, "with_enum")
