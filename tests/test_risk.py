"""Capability analysis: what it catches, and what it provably does not."""

from __future__ import annotations

from pathlib import Path

import pytest

from any2mcp.risk import (
    Capability,
    RiskAnalysisError,
    RiskLevel,
    analyze_path,
    analyze_source,
)


def caps(source: str, name: str) -> set[Capability]:
    return set(analyze_source(source, [name])[name].capabilities)


def level(source: str, name: str) -> RiskLevel:
    return analyze_source(source, [name])[name].level


class TestImportAliasResolution:
    """Surface text is not enough; aliases must be resolved to real symbols."""

    def test_plain_dotted_call(self):
        src = "import subprocess\ndef f(c):\n    subprocess.run(c)\n"
        assert caps(src, "f") == {Capability.SUBPROCESS}

    def test_module_aliased_with_as(self):
        src = "import subprocess as sp\ndef f(c):\n    sp.run(c)\n"
        assert caps(src, "f") == {Capability.SUBPROCESS}

    def test_from_import(self):
        src = "from os import system\ndef f(c):\n    system(c)\n"
        assert caps(src, "f") == {Capability.SUBPROCESS}

    def test_from_import_aliased(self):
        src = "from os import system as sh\ndef f(c):\n    sh(c)\n"
        assert caps(src, "f") == {Capability.SUBPROCESS}

    def test_submodule_import(self):
        src = "import urllib.request\ndef f(u):\n    urllib.request.urlopen(u)\n"
        assert caps(src, "f") == {Capability.NETWORK}

    def test_unrelated_module_named_like_a_risky_one(self):
        """A local `sp.run` where `sp` is not subprocess must not match."""
        src = "import statistics as sp\ndef f(xs):\n    return sp.mean(xs)\n"
        assert caps(src, "f") == set()


class TestOpenMode:
    def test_default_mode_is_read(self):
        src = "def f(p):\n    return open(p).read()\n"
        assert caps(src, "f") == {Capability.FS_READ}

    def test_explicit_read_mode(self):
        src = "def f(p):\n    return open(p, 'r').read()\n"
        assert caps(src, "f") == {Capability.FS_READ}

    @pytest.mark.parametrize("mode", ["w", "a", "x", "r+", "wb"])
    def test_write_modes(self, mode: str):
        src = f"def f(p):\n    return open(p, {mode!r})\n"
        assert caps(src, "f") == {Capability.FS_WRITE}

    def test_keyword_mode(self):
        src = "def f(p):\n    return open(p, mode='w')\n"
        assert caps(src, "f") == {Capability.FS_WRITE}

    def test_computed_mode_is_conservatively_write(self):
        src = "def f(p, m):\n    return open(p, m)\n"
        assert caps(src, "f") == {Capability.FS_WRITE}


class TestTransitiveCalls:
    def test_capability_inherited_from_local_helper(self):
        src = (
            "import shutil\n"
            "def _wipe(p):\n"
            "    shutil.rmtree(p)\n"
            "def public(p):\n"
            "    _wipe(p)\n"
        )
        result = analyze_source(src, ["public"])["public"]
        assert result.capabilities == {Capability.FS_DELETE}
        assert result.findings[0].via == "_wipe"

    def test_two_hops(self):
        src = (
            "import subprocess\n"
            "def _c(x):\n    subprocess.run(x)\n"
            "def _b(x):\n    _c(x)\n"
            "def a(x):\n    _b(x)\n"
        )
        assert caps(src, "a") == {Capability.SUBPROCESS}

    def test_mutual_recursion_terminates(self):
        src = (
            "import os\n"
            "def a(n):\n    return b(n) if n else os.system('x')\n"
            "def b(n):\n    return a(n - 1)\n"
        )
        assert caps(src, "a") == {Capability.SUBPROCESS}

    def test_local_shadow_is_not_treated_as_builtin(self):
        """A module defining its own `open` must not be flagged as file I/O."""
        src = "def open(x):\n    return x\ndef f(p):\n    return open(p)\n"
        assert caps(src, "f") == set()


class TestMisclassificationGuards:
    def test_webbrowser_open_is_network_not_file_read(self):
        src = "import webbrowser\ndef f(u):\n    webbrowser.open(u)\n"
        assert caps(src, "f") == {Capability.NETWORK}

    def test_path_open_write_is_a_file_write(self):
        src = (
            "from pathlib import Path\ndef f(p):\n    return Path(p).open('w')\n"
        )
        assert caps(src, "f") == {Capability.FS_WRITE}

    def test_method_matches_are_flagged_heuristic(self):
        src = "def f(obj):\n    obj.write_text('x')\n"
        result = analyze_source(src, ["f"])["f"]
        assert result.capabilities == {Capability.FS_WRITE}
        assert result.findings[0].heuristic is True

    def test_resolved_symbols_are_not_heuristic(self):
        src = "import os\ndef f(p):\n    os.remove(p)\n"
        assert analyze_source(src, ["f"])["f"].findings[0].heuristic is False


class TestRiskLevels:
    @pytest.mark.parametrize(
        ("source", "expected"),
        [
            ("def f(a, b):\n    return a + b\n", RiskLevel.SAFE),
            ("def f(p):\n    return open(p).read()\n", RiskLevel.LOW),
            ("def f(p):\n    return open(p, 'w')\n", RiskLevel.MODERATE),
            ("import os\ndef f(p):\n    os.system(p)\n", RiskLevel.HIGH),
        ],
    )
    def test_level_is_the_worst_capability(self, source: str, expected: RiskLevel):
        assert level(source, "f") is expected

    def test_unanalyzable_is_not_called_safe(self):
        result = analyze_source("x = 1\n", ["missing"])["missing"]
        assert result.analyzed is False
        assert result.level is RiskLevel.UNKNOWN

    def test_unknown_ranks_with_high(self):
        assert RiskLevel.UNKNOWN >= RiskLevel.HIGH
        assert RiskLevel.UNKNOWN > RiskLevel.MODERATE


class TestImportlessAnalysis:
    """The report must never require importing the target."""

    def test_analyzes_a_module_whose_dependencies_are_missing(
        self, fixtures_dir: Path
    ):
        # risky.py imports `requests`, which is deliberately not a dependency
        # of this project. Importing it would fail; analyzing it must not.
        with pytest.raises(ImportError):
            import requests  # noqa: F401

        result = analyze_path(str(fixtures_dir / "risky.py"))
        assert result["fetch"].capabilities == {Capability.NETWORK}
        assert result["nuke"].level is RiskLevel.HIGH

    def test_discovers_names_statically(self, fixtures_dir: Path):
        result = analyze_path(str(fixtures_dir / "risky.py"))
        assert "pure_add" in result
        assert "_upload" not in result  # private, not exposable

    def test_honours_literal_dunder_all(self):
        src = "__all__ = ['b']\ndef a():\n    pass\ndef b():\n    pass\n"
        assert list(analyze_source(src)) == ["b"]

    def test_falls_back_when_dunder_all_is_computed(self):
        src = "__all__ = [x for x in ('a',)]\ndef a():\n    pass\n"
        assert list(analyze_source(src)) == ["a"]

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(RiskAnalysisError, match="could not read"):
            analyze_path(str(tmp_path / "nope.py"))

    def test_syntax_error_raises(self, tmp_path: Path):
        bad = tmp_path / "bad.py"
        bad.write_text("def (:\n", encoding="utf-8")
        with pytest.raises(RiskAnalysisError, match="failed to parse"):
            analyze_path(str(bad))


class TestDocumentedBlindSpots:
    """These assert the *limits* we publish. If one starts failing we have
    become stronger than advertised and the README should be updated; if the
    wording is ever softened to imply soundness, these are the counterexamples.
    """

    def test_getattr_indirection_is_not_detected(self):
        src = "import os\ndef f(c):\n    getattr(os, 'system')(c)\n"
        assert caps(src, "f") == set()
        assert level(src, "f") is RiskLevel.SAFE

    def test_dispatch_table_is_not_detected(self):
        src = (
            "import os\n"
            "TABLE = {'go': os.system}\n"
            "def f(c):\n    TABLE['go'](c)\n"
        )
        assert caps(src, "f") == set()

    def test_string_built_call_is_not_detected(self):
        src = "import os\ndef f(c):\n    fn = os.__dict__['system']\n    fn(c)\n"
        assert caps(src, "f") == set()

    def test_third_party_wrapper_is_not_followed(self):
        """We classify by call name, not by analyzing the dependency's body."""
        src = "import some_lib\ndef f(c):\n    some_lib.helpfully_runs(c)\n"
        assert caps(src, "f") == set()

    def test_star_import_is_noted_as_unresolvable(self):
        src = "from os import *\ndef f(c):\n    system(c)\n"
        result = analyze_source(src, ["f"])["f"]
        assert result.capabilities == set()
        assert result.note is not None
        assert "import *" in result.note
