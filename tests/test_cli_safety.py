"""CLI surface for the safety features, including exit codes for CI gating."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from any2mcp.cli import main


@pytest.fixture
def risky(fixtures_dir: Path) -> str:
    """A module that cannot be imported here (its deps are absent)."""
    return str(fixtures_dir / "risky.py")


@pytest.fixture
def sideeffects(fixtures_dir: Path) -> str:
    return str(fixtures_dir / "sideeffects.py")


class TestRiskReport:
    def test_exit_3_when_something_is_blocked(self, sideeffects: str, capsys):
        assert main([sideeffects, "--risk-report"]) == 3
        out = capsys.readouterr().out
        assert "BLOCKED" in out
        assert "run_command" in out

    def test_exit_0_when_nothing_is_blocked(self, sideeffects: str):
        code = main([sideeffects, "--risk-report", "--policy", "open"])
        assert code == 0

    def test_does_not_import_the_target(self, risky: str, capsys):
        """risky.py imports `requests`, which is not installed. A report that
        needed to import would crash; this must succeed."""
        code = main([risky, "--risk-report"])
        assert code == 3
        out = capsys.readouterr().out
        assert "fetch" in out
        assert "network" in out

    def test_json_format_is_machine_readable(self, sideeffects: str, capsys):
        main([sideeffects, "--risk-report", "--format", "json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["policy"] == "guard"
        assert payload["summary"]["blocked"] == 3
        by_name = {t["name"]: t for t in payload["tools"]}
        assert by_name["run_command"]["exposed"] is False
        assert by_name["run_command"]["risk"] == "high"
        assert by_name["add"]["exposed"] is True
        assert by_name["delete_tree"]["capabilities"] == ["fs-delete"]

    def test_findings_include_line_numbers(self, sideeffects: str, capsys):
        main([sideeffects, "--risk-report", "--format", "json"])
        payload = json.loads(capsys.readouterr().out)
        finding = next(
            t for t in payload["tools"] if t["name"] == "run_command"
        )["findings"][0]
        assert finding["symbol"] == "subprocess.check_output"
        assert finding["line"] > 0
        assert finding["heuristic"] is False

    def test_selector_narrows_the_report(self, sideeffects: str, capsys):
        main([f"{sideeffects}:add", "--risk-report", "--format", "json"])
        payload = json.loads(capsys.readouterr().out)
        assert [t["name"] for t in payload["tools"]] == ["add"]

    def test_missing_file_is_reported(self, tmp_path: Path, capsys):
        code = main([str(tmp_path / "nope.py"), "--risk-report"])
        assert code == 2
        assert "cannot locate source" in capsys.readouterr().err


class TestPolicyFlags:
    def test_blocked_tools_absent_from_list(self, sideeffects: str, capsys):
        assert main([sideeffects, "--list"]) == 0
        names = {t["name"] for t in json.loads(capsys.readouterr().out)}
        assert "add" in names
        assert "run_command" not in names

    def test_policy_open_exposes_everything(self, sideeffects: str, capsys):
        main([sideeffects, "--list", "--policy", "open"])
        names = {t["name"] for t in json.loads(capsys.readouterr().out)}
        assert "run_command" in names

    def test_allow_tool_flag(self, sideeffects: str, capsys):
        main([sideeffects, "--list", "--allow-tool", "run_command"])
        names = {t["name"] for t in json.loads(capsys.readouterr().out)}
        assert "run_command" in names
        assert "delete_tree" not in names

    def test_deny_capability_flag(self, sideeffects: str, capsys):
        main([sideeffects, "--list", "--deny-capability", "fs-write"])
        names = {t["name"] for t in json.loads(capsys.readouterr().out)}
        assert "write_file" not in names
        assert "add" in names

    def test_invalid_capability_is_rejected(self, sideeffects: str):
        with pytest.raises(SystemExit):
            main([sideeffects, "--deny-capability", "not-a-capability"])

    def test_blocked_tools_are_announced_on_stderr(self, sideeffects: str, capsys):
        main([sideeffects, "--list"])
        err = capsys.readouterr().err
        assert "BLOCKED run_command" in err
        assert "--allow-tool" in err  # remediation is offered

    def test_strict_policy_blocking_everything_exits_1(
        self, sideeffects: str, capsys
    ):
        code = main([sideeffects, "--list", "--policy", "strict", "--deny-tool", "*"])
        assert code == 1
        assert "blocked by policy" in capsys.readouterr().err
