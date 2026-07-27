"""One unschematizable function must not take down the whole server."""

from __future__ import annotations

import json
from pathlib import Path

from any2mcp.build import build_server
from any2mcp.cli import main
from tests.conftest import tool_names


def test_bad_signature_is_skipped_not_fatal(fixtures_dir: Path):
    result = build_server(str(fixtures_dir / "hostile.py"))
    names = tool_names(result.server)

    # The healthy function survives...
    assert "good" in names
    # ...and the unsupported one is reported as skipped, not raised.
    assert "uses_bare_class" not in names
    assert [s.name for s in result.skipped] == ["uses_bare_class"]
    assert result.skipped[0].reason  # carries a human-readable reason


def test_cli_reports_skip_and_still_lists(fixtures_dir: Path, capsys):
    code = main([str(fixtures_dir / "hostile.py"), "--list"])
    assert code == 0
    captured = capsys.readouterr()
    assert "skipping 'uses_bare_class'" in captured.err
    payload = json.loads(captured.out)
    assert [e["name"] for e in payload] == ["good"]


def test_all_unsupported_yields_empty_exit(tmp_path: Path, capsys):
    src = "class C: pass\n\ndef f(x: C) -> int:\n    return 1\n"
    (tmp_path / "allbad.py").write_text(src)
    code = main([str(tmp_path / "allbad.py"), "--list"])
    assert code == 1
    assert "no exposable functions" in capsys.readouterr().err
