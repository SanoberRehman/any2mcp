from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


def schema_of(server, tool_name: str) -> dict:
    """Return the input JSON schema for a named tool on a built server."""
    for tool in server._tool_manager.list_tools():
        if tool.name == tool_name:
            return tool.parameters
    raise KeyError(tool_name)


def tool_names(server) -> set[str]:
    return {tool.name for tool in server._tool_manager.list_tools()}
