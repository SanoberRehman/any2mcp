from __future__ import annotations

import json
from pathlib import Path

import pytest

from any2mcp.cli import main


def test_list_outputs_json(fixtures_dir: Path, capsys):
    code = main([str(fixtures_dir / "messy.py"), "--list"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    names = {entry["name"] for entry in payload}
    assert "with_enum" in names
    # Every entry carries a JSON-schema-shaped input_schema.
    for entry in payload:
        assert entry["input_schema"]["type"] == "object"


def test_list_with_selector(fixtures_dir: Path, capsys):
    code = main([str(fixtures_dir / "messy.py") + ":with_enum", "--list"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert [e["name"] for e in payload] == ["with_enum"]


def test_missing_target_is_error(capsys):
    code = main(["does_not_exist.py", "--list"])
    assert code == 2
    assert "any2mcp:" in capsys.readouterr().err


def test_no_functions_found(tmp_path: Path, capsys):
    empty = tmp_path / "empty.py"
    empty.write_text("x = 1\n")
    code = main([str(empty), "--list"])
    assert code == 1
    assert "no exposable functions" in capsys.readouterr().err


def test_include_narrows(fixtures_dir: Path, capsys):
    code = main([str(fixtures_dir / "messy.py"), "--list", "--include", "with_*"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert all(e["name"].startswith("with_") for e in payload)


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "any2mcp" in capsys.readouterr().out
