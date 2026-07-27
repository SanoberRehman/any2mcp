"""The schema-quality matrix: build a server from messy.py and assert that the
SDK-generated JSON schema is correct for each tricky signature shape."""

from __future__ import annotations

from pathlib import Path

import pytest

from any2mcp.build import build_server
from tests.conftest import schema_of, tool_names


@pytest.fixture
def server(fixtures_dir: Path):
    srv, _ = build_server(str(fixtures_dir / "messy.py"))
    return srv


def test_all_expected_tools_present(server):
    names = tool_names(server)
    expected = {
        "with_optional",
        "with_union",
        "with_literal",
        "with_enum",
        "with_pydantic_model",
        "with_dataclass",
        "with_containers",
        "with_defaults",
        "no_annotations",
        "async_tool",
    }
    assert expected <= names
    assert "_private" not in names


def test_optional_becomes_nullable(server):
    props = schema_of(server, "with_optional")["properties"]
    assert props["name"]["type"] == "string"
    # Optional[str] with default None -> nullable, defaulted, not required.
    assert props["nickname"].get("default", "MISSING") is None
    assert "nickname" not in schema_of(server, "with_optional").get("required", [])


def test_union_has_anyof(server):
    prop = schema_of(server, "with_union")["properties"]["value"]
    types = {sub.get("type") for sub in prop.get("anyOf", [])}
    assert {"integer", "string"} <= types


def test_literal_becomes_enum(server):
    prop = schema_of(server, "with_literal")["properties"]["mode"]
    assert set(prop["enum"]) == {"fast", "slow"}
    assert prop["default"] == "fast"


def test_enum_reference(server):
    schema = schema_of(server, "with_enum")
    prop = schema["properties"]["color"]
    assert "$ref" in prop
    assert "Color" in schema["$defs"]
    assert set(schema["$defs"]["Color"]["enum"]) == {"red", "green", "blue"}


def test_pydantic_model_nested_object(server):
    schema = schema_of(server, "with_pydantic_model")
    prop = schema["properties"]["point"]
    assert "$ref" in prop
    point_def = schema["$defs"]["Point"]
    assert point_def["type"] == "object"
    assert {"x", "y"} <= set(point_def["properties"])
    assert point_def["properties"]["label"]["default"] == "origin"


def test_dataclass_nested_object(server):
    schema = schema_of(server, "with_dataclass")
    prop = schema["properties"]["box"]
    assert "$ref" in prop
    box_def = schema["$defs"]["Box"]
    assert {"width", "height"} <= set(box_def["properties"])


def test_container_types(server):
    props = schema_of(server, "with_containers")["properties"]
    assert props["tags"]["type"] == "array"
    assert props["tags"]["items"]["type"] == "string"
    assert props["meta"]["type"] == "object"  # dict[str, int]
    assert props["pair"]["type"] == "array"  # tuple


def test_defaults_and_required(server):
    schema = schema_of(server, "with_defaults")
    assert schema["required"] == ["a"]
    props = schema["properties"]
    assert props["b"]["default"] == 10
    assert props["c"]["default"] == "x"


def test_unannotated_function_still_builds(server):
    # Must not raise; parameter with no hint is permissive.
    schema = schema_of(server, "no_annotations")
    assert "a" in schema["properties"]


def test_default_server_name_is_stem(fixtures_dir):
    srv, _ = build_server(str(fixtures_dir / "messy.py"))
    assert srv.name == "messy"


def test_explicit_name_override(fixtures_dir):
    srv, _ = build_server(str(fixtures_dir / "messy.py"), name="custom")
    assert srv.name == "custom"
