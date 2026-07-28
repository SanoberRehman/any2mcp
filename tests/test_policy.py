"""Policy decisions, and the enforcement that a blocked tool is unreachable."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from any2mcp.audit import AuditLog
from any2mcp.build import build_server
from any2mcp.policy import Policy, PolicyMode, remediation_hint
from any2mcp.risk import Capability, FunctionRisk, analyze_source

from .conftest import tool_names


def risk_of(source: str, name: str = "f") -> FunctionRisk:
    return analyze_source(source, [name])[name]


PURE = "def f(a, b):\n    return a + b\n"
READS = "def f(p):\n    return open(p).read()\n"
WRITES = "def f(p):\n    return open(p, 'w')\n"
SHELLS = "import os\ndef f(c):\n    os.system(c)\n"


class TestModeThresholds:
    @pytest.mark.parametrize(
        ("mode", "source", "allowed"),
        [
            (PolicyMode.OPEN, SHELLS, True),
            (PolicyMode.OPEN, PURE, True),
            (PolicyMode.GUARD, PURE, True),
            (PolicyMode.GUARD, READS, True),
            (PolicyMode.GUARD, WRITES, True),
            (PolicyMode.GUARD, SHELLS, False),
            (PolicyMode.READONLY, PURE, True),
            (PolicyMode.READONLY, READS, True),
            (PolicyMode.READONLY, WRITES, False),
            (PolicyMode.READONLY, SHELLS, False),
            (PolicyMode.STRICT, PURE, True),
            (PolicyMode.STRICT, READS, False),
            (PolicyMode.STRICT, SHELLS, False),
        ],
    )
    def test_threshold(self, mode: PolicyMode, source: str, allowed: bool):
        decision = Policy(mode=mode).decide(risk_of(source))
        assert decision.allowed is allowed

    def test_default_mode_is_guard(self):
        assert Policy().mode is PolicyMode.GUARD

    def test_unanalyzable_is_blocked_by_guard(self):
        unknown = FunctionRisk(name="f", analyzed=False, note="no source")
        decision = Policy().decide(unknown)
        assert decision.blocked
        assert "could not be analyzed" in decision.reason

    def test_parse_rejects_unknown_mode(self):
        with pytest.raises(ValueError, match="unknown policy"):
            PolicyMode.parse("yolo")


class TestPrecedence:
    def test_allow_tool_overrides_mode(self):
        policy = Policy(allow_tools=("f",))
        assert policy.decide(risk_of(SHELLS)).allowed

    def test_deny_tool_overrides_allow_tool(self):
        policy = Policy(allow_tools=("f",), deny_tools=("f",))
        decision = policy.decide(risk_of(PURE))
        assert decision.blocked
        assert "--deny-tool" in decision.reason

    def test_deny_capability_blocks_otherwise_allowed(self):
        policy = Policy(deny_capabilities=frozenset({Capability.FS_READ}))
        decision = policy.decide(risk_of(READS))
        assert decision.blocked
        assert "fs-read" in decision.reason

    def test_allow_tool_beats_deny_capability(self):
        policy = Policy(
            allow_tools=("f",), deny_capabilities=frozenset({Capability.FS_READ})
        )
        assert policy.decide(risk_of(READS)).allowed

    def test_globs_are_supported(self):
        policy = Policy(deny_tools=("admin_*",))
        risk = FunctionRisk(name="admin_reset")
        assert policy.decide(risk).blocked


class TestEnforcement:
    """A blocked function must not reach the tool list at all."""

    def test_high_risk_absent_by_default(self, fixtures_dir: Path):
        result = build_server(str(fixtures_dir / "sideeffects.py"))
        names = tool_names(result.server)
        assert {"add", "read_file", "write_file", "list_env"} <= names
        assert {"run_command", "delete_tree", "evaluate"}.isdisjoint(names)

    def test_open_policy_exposes_everything(self, fixtures_dir: Path):
        result = build_server(
            str(fixtures_dir / "sideeffects.py"),
            policy=Policy(mode=PolicyMode.OPEN),
        )
        assert {"run_command", "delete_tree", "evaluate"} <= tool_names(result.server)

    def test_readonly_drops_writes(self, fixtures_dir: Path):
        result = build_server(
            str(fixtures_dir / "sideeffects.py"),
            policy=Policy(mode=PolicyMode.READONLY),
        )
        names = tool_names(result.server)
        assert "read_file" in names
        assert "write_file" not in names

    def test_explicit_allow_restores_one_tool_only(self, fixtures_dir: Path):
        result = build_server(
            str(fixtures_dir / "sideeffects.py"),
            policy=Policy(allow_tools=("run_command",)),
        )
        names = tool_names(result.server)
        assert "run_command" in names
        assert "delete_tree" not in names

    @pytest.mark.anyio
    async def test_blocked_tool_is_uncallable_by_a_real_client(
        self, fixtures_dir: Path
    ):
        """The end-to-end guarantee: the model cannot invoke what was withheld."""
        result = build_server(str(fixtures_dir / "sideeffects.py"))
        async with create_connected_server_and_client_session(
            result.server._mcp_server
        ) as client:
            listed = {t.name for t in (await client.list_tools()).tools}
            assert "run_command" not in listed

            outcome = await client.call_tool("run_command", {"cmd": "echo pwned"})
            assert outcome.isError
            assert "unknown tool" in outcome.content[0].text.lower()

    def test_decisions_are_reported(self, fixtures_dir: Path):
        result = build_server(str(fixtures_dir / "sideeffects.py"))
        blocked = {d.name for d in result.blocked}
        assert blocked == {"run_command", "delete_tree", "evaluate"}
        assert all(d.reason for d in result.decisions)


class TestRemediationHint:
    def test_none_when_nothing_blocked(self):
        policy = Policy()
        assert remediation_hint([policy.decide(risk_of(PURE))]) is None

    def test_names_the_blocked_tool(self):
        hint = remediation_hint([Policy().decide(risk_of(SHELLS))])
        assert hint is not None
        assert "--allow-tool f" in hint


class TestAuditLog:
    @pytest.mark.anyio
    async def test_records_calls_without_argument_values(
        self, fixtures_dir: Path, tmp_path: Path
    ):
        log_path = tmp_path / "audit.jsonl"
        result = build_server(
            str(fixtures_dir / "sideeffects.py"), audit=AuditLog(log_path)
        )
        async with create_connected_server_and_client_session(
            result.server._mcp_server
        ) as client:
            await client.call_tool("add", {"a": 2, "b": 40})

        events = [json.loads(line) for line in log_path.read_text().splitlines()]
        call = next(e for e in events if e["event"] == "call")
        assert call["tool"] == "add"
        assert call["ok"] is True
        assert call["risk"] == "safe"
        assert "duration_ms" in call
        # Values must be absent by default: types only. (The annotations are
        # `float`, so the SDK coerces the ints before the call reaches us.)
        assert call["args"] == {"a": "float", "b": "float"}
        assert "40" not in json.dumps(call["args"])

    @pytest.mark.anyio
    async def test_records_values_when_opted_in(
        self, fixtures_dir: Path, tmp_path: Path
    ):
        log_path = tmp_path / "audit.jsonl"
        result = build_server(
            str(fixtures_dir / "sideeffects.py"),
            audit=AuditLog(log_path, record_values=True),
        )
        async with create_connected_server_and_client_session(
            result.server._mcp_server
        ) as client:
            await client.call_tool("add", {"a": 2, "b": 40})

        text = log_path.read_text()
        assert "40" in text

    @pytest.mark.anyio
    async def test_records_failures(self, fixtures_dir: Path, tmp_path: Path):
        log_path = tmp_path / "audit.jsonl"
        result = build_server(
            str(fixtures_dir / "sideeffects.py"), audit=AuditLog(log_path)
        )
        async with create_connected_server_and_client_session(
            result.server._mcp_server
        ) as client:
            await client.call_tool("read_file", {"path": "definitely-missing.txt"})

        events = [json.loads(line) for line in log_path.read_text().splitlines()]
        call = next(e for e in events if e["event"] == "call")
        assert call["ok"] is False
        assert "error" in call

    def test_blocked_tools_are_logged(self, fixtures_dir: Path, tmp_path: Path):
        log_path = tmp_path / "audit.jsonl"
        build_server(str(fixtures_dir / "sideeffects.py"), audit=AuditLog(log_path))
        events = [json.loads(line) for line in log_path.read_text().splitlines()]
        blocked = {e["tool"] for e in events if e["event"] == "blocked"}
        assert blocked == {"run_command", "delete_tree", "evaluate"}

    def test_disabled_log_is_a_noop(self, fixtures_dir: Path):
        log = AuditLog(None)
        assert log.enabled is False
        sentinel = object()

        def func():
            return sentinel

        assert log.wrap(func, "func", "safe") is func

    def test_unwritable_path_does_not_break_the_server(
        self, fixtures_dir: Path, tmp_path: Path
    ):
        # A directory where a file is expected: writing must fail silently.
        bad = tmp_path / "dir-not-file"
        bad.mkdir()
        log = AuditLog(bad)
        log.write({"event": "test"})
        assert log._broken is True

        result = build_server(str(fixtures_dir / "sideeffects.py"), audit=log)
        assert "add" in tool_names(result.server)


class TestWrappingPreservesSchema:
    """Instrumentation must not disturb the SDK's schema generation."""

    def test_schemas_identical_with_and_without_audit(
        self, fixtures_dir: Path, tmp_path: Path
    ):
        target = str(fixtures_dir / "sideeffects.py")
        plain = build_server(target)
        wrapped = build_server(target, audit=AuditLog(tmp_path / "a.jsonl"))

        def schemas(result):
            return {
                t.name: t.parameters
                for t in result.server._tool_manager.list_tools()
            }

        assert schemas(plain) == schemas(wrapped)

    @pytest.mark.anyio
    async def test_async_tool_still_works_when_wrapped(
        self, fixtures_dir: Path, tmp_path: Path
    ):
        result = build_server(
            str(fixtures_dir / "sideeffects.py"),
            audit=AuditLog(tmp_path / "a.jsonl"),
        )
        async with create_connected_server_and_client_session(
            result.server._mcp_server
        ) as client:
            outcome = await client.call_tool("slow_double", {"value": 21})
            assert outcome.content[0].text == "42.0"


@pytest.fixture
def anyio_backend():
    return "asyncio"
