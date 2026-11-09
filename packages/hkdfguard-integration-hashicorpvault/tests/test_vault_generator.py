"""scripts/generate-vault-client.py: what it generates from a spec, and its command line."""

from __future__ import annotations

import ast
import importlib.util
import io
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_PACKAGE = Path(__file__).resolve().parents[1]
_WORKSPACE = _PACKAGE.parents[1]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("generate_vault_client", _WORKSPACE / "scripts" / "generate-vault-client.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up
    spec.loader.exec_module(module)
    return module


generator = _load()


def spec(paths: dict[str, Any], schemas: dict[str, Any] | None = None) -> str:
    return json.dumps({"openapi": "3.0.2", "info": {"title": "test", "version": "9.9.9"}, "paths": paths, "components": {"schemas": schemas or {}}})


def operation(operation_id: str, tag: str = "secrets", **more: Any) -> dict[str, Any]:
    return {"operationId": operation_id, "tags": [tag], "responses": {"200": {"description": "OK"}}, **more}


def ref(name: str) -> dict[str, str]:
    return {"$ref": f"#/components/schemas/{name}"}


def json_body(name: str) -> dict[str, Any]:
    return {"content": {"application/json": {"schema": ref(name)}}}


_MOUNT = {"name": "kv_mount_path", "in": "path", "required": True, "schema": {"type": "string", "default": "secret"}}


def test_the_generated_code_is_what_the_spec_generates() -> None:
    files = generator.generate((_PACKAGE / "openapi.json").read_text(encoding="utf-8"), (_PACKAGE / "generator.json").read_text(encoding="utf-8"))
    output = _PACKAGE / "src" / "hkdfguard" / "integration" / "hashicorpvault" / "_generated"
    on_disk = {p.relative_to(output).as_posix(): p.read_text(encoding="utf-8").replace("\r\n", "\n") for p in output.rglob("*.py")}
    assert on_disk == files, "Regenerate: uv run python scripts/generate-vault-client.py"


def test_the_generated_api_is_the_subset_generator_json_names() -> None:
    files = generator.generate((_PACKAGE / "openapi.json").read_text(encoding="utf-8"), (_PACKAGE / "generator.json").read_text(encoding="utf-8"))
    assert sorted(files) == ["__init__.py", "_apis.py", "_auth_api.py", "_secrets_api.py", "_system_api.py", "schema.py"]
    secrets = files["_secrets_api.py"]
    assert "def kv_v2_read(" in secrets and "def transit_encrypt(" in secrets and "def kv_v1_read(" in secrets
    assert "def pki_" not in secrets


def test_every_generated_file_is_python() -> None:
    files = generator.generate((_PACKAGE / "openapi.json").read_text(encoding="utf-8"), None)
    for name, content in files.items():
        ast.parse(content, name)
    assert "identity" in "".join(files)


def test_duplicates_and_enterprise_stubs_are_left_out_with_their_schemas() -> None:
    files = generator.generate(spec({
        "/a": {"post": operation("thing-write", requestBody=json_body("ThingWriteRequest"))},
        "/b": {"post": operation("thing-write2", requestBody=json_body("ThingWrite2Request"))},
        "/c": {"get": operation("enterprise-stub-read")},
    }, {"ThingWriteRequest": {"type": "object", "properties": {"a": {"type": "string"}}},
        "ThingWrite2Request": {"type": "object", "properties": {"a": {"type": "string"}}}}), None)
    assert "def thing_write(" in files["_secrets_api.py"]
    assert "thing_write2" not in files["_secrets_api.py"] and "enterprise_stub" not in files["_secrets_api.py"]
    assert "class ThingWriteRequest" in files["schema.py"] and "ThingWrite2Request" not in files["schema.py"]


def test_prose_cant_break_out_of_its_docstring() -> None:
    nasty = 'Ends """ here \\ and "quoted" ’smart’ — dash'
    files = generator.generate(spec({"/a": {"get": operation("evil-read", summary=nasty, description=nasty)}}), None)
    tree = ast.parse(files["_secrets_api.py"])
    method = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "evil_read")
    docstring = ast.get_docstring(method) or ""
    assert docstring.startswith('Ends """ here \\ and "quoted" \'smart\' - dash')
    assert files["_secrets_api.py"].isascii()


def test_an_operation_overrides_a_path_parameter_and_its_first_2xx_response_types_it() -> None:
    shared = {"name": "name", "in": "path", "description": "shared", "schema": {"type": "string"}}
    own = {"name": "name", "in": "path", "description": "its own", "schema": {"type": "string"}}
    files = generator.generate(spec({"/{kv_mount_path}/things/{name}": {
        "parameters": [_MOUNT, shared],
        "get": operation("thing-read", parameters=[own], responses={"default": {"description": "error"},
                                                                  "200": {"content": {"application/json": {"schema": ref("ThingReadResponse")}}},
                                                                  "204": {"description": "none"}}),
    }}, {"ThingReadResponse": {"type": "object", "properties": {"when": {"type": "string", "format": "date-time"}, "n": {"type": "integer"},
                                                               "tags": {"type": "array", "items": {"type": "string"}},
                                                               "extra": {"type": "object"}}}}), None)
    api = files["_secrets_api.py"]
    assert ":param name: its own" in api
    assert "VaultResponse[ThingReadResponse]" in api and "ThingReadResponse.from_json" in api
    # Long, the expression is wrapped: compare it without its layout.
    flat = " ".join(api.split()).replace("( ", "(").replace(" )", ")")
    assert ('request_path = ("/v1/" + _client.escape_path_segment(_client.mount_path_or(options, "secret")) + "/things/" + '
            "_client.escape_path_segment(name))") in flat
    schema = files["schema.py"]
    assert "when: datetime | None = None" in schema and "tags: list[str] | None = None" in schema
    assert "extra: dict[str, JsonValue] | None = None" in schema
    assert 'when=json.member("when").read_datetime()' in schema and 'tags=json.member("tags").read_list(JsonValue.read_str)' in schema


def test_names_are_python_and_kept_clear_of_each_other() -> None:
    query = [{"name": n, "in": "query", "schema": {"type": "boolean"}} for n in ("options", "class", "list")]
    files = generator.generate(spec({"/x": {"get": operation("odd-names", parameters=query)}},
                                    {"OddRequest": {"type": "object", "properties": {"from": {"type": "string"}, "write_json": {"type": "string"},
                                                                                     "a-b": {"type": "string"}, "a_b": {"type": "string"}}}}), None)
    api = files["_secrets_api.py"]
    assert "options_parameter: bool | None = None" in api and "class_: bool | None = None" in api
    assert 'query.append(("list", "true"))' in api
    schema = files["schema.py"]
    for field in ("from_: str | None", "write_json_value: str | None", "a_b: str | None", "a_b2: str | None"):
        assert field in schema
    ast.parse(schema)


def test_an_include_list_keeps_only_its_operations_the_schemas_they_use_and_their_classes() -> None:
    document = spec({
        "/a": {"post": operation("kv-write", requestBody=json_body("KvWriteRequest"))},
        "/b": {"post": operation("app-login", tag="auth", requestBody=json_body("AppLoginRequest"))},
    }, {"KvWriteRequest": {"type": "object", "properties": {"nested": ref("Nested")}}, "Nested": {"type": "object", "properties": {}},
        "AppLoginRequest": {"type": "object", "properties": {}}, "Unused": {"type": "object", "properties": {}}})
    files = generator.generate(document, json.dumps({"description": "d", "include": ["^Kv"]}))
    assert sorted(files) == ["__init__.py", "_apis.py", "_secrets_api.py", "schema.py"]
    assert "class KvWriteRequest" in files["schema.py"] and "class Nested" in files["schema.py"]
    assert "AppLoginRequest" not in files["schema.py"] and "Unused" not in files["schema.py"]
    everything = generator.generate(document, None)
    assert "_auth_api.py" in everything and "class Unused" in everything["schema.py"]


@pytest.mark.parametrize(("settings", "message"), [
    ("not json", "aren't JSON"), ("[]", "JSON object"), ('{"exclude": []}', "Unknown generator setting"), ('{"include": []}', "non-empty"),
    ('{"include": ["("]}', "isn't a regular expression"), ('{"include": ["^Nothing"]}', "matches no operation"),
])
def test_bad_settings_are_refused(settings: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        generator.generate(spec({"/a": {"get": operation("a-read")}}), settings)


def test_an_included_operations_missing_schema_is_refused() -> None:
    with pytest.raises(ValueError, match="Missing is used by a generated operation"):
        generator.generate(spec({"/a": {"post": operation("a-write", requestBody=json_body("Missing"))}}), None)


def test_literal_escapes_what_a_python_string_cant_hold_as_it_is() -> None:
    for value in ('quote " back \\ nl \n tab \t nul \0', "é"):
        assert ast.literal_eval(generator.literal(value)) == value


def test_the_command_refuses_an_output_holding_files_it_didnt_write(tmp_path: Path) -> None:
    # A mistyped --output, such as the package's own source folder: nothing written, nothing deleted.
    document = tmp_path / "openapi.json"
    document.write_text(spec({"/a": {"get": operation("a-read")}}), encoding="utf-8")
    output = tmp_path / "src"
    output.mkdir()
    hand_written = output / "_client.py"
    hand_written.write_text('"""Hand-written."""\n', encoding="utf-8")
    error = io.StringIO()

    assert generator.run(["--spec", str(document), "--output", str(output)], tmp_path, io.StringIO(), error) == 2
    assert "didn't write" in error.getvalue() and "_client.py" in error.getvalue()
    assert hand_written.read_text(encoding="utf-8") == '"""Hand-written."""\n'
    assert sorted(path.name for path in output.iterdir()) == ["_client.py"]


def test_the_command_writes_only_changed_files_and_deletes_stale_ones(tmp_path: Path) -> None:
    document = tmp_path / "openapi.json"
    document.write_text(spec({"/a": {"get": operation("a-read")}}), encoding="utf-8")
    (tmp_path / "generator.json").write_text('{"include": ["^A"]}', encoding="utf-8")
    output = tmp_path / "out"
    output.mkdir()
    (output / "stale.py").write_text("# Generated by scripts/generate-vault-client.py from openapi.json (old).\n", encoding="utf-8")
    out = io.StringIO()
    assert generator.run(["--spec", str(document), "--output", str(output)], tmp_path, out, io.StringIO()) == 0
    assert "4 written, 0 unchanged, 1 stale deleted" in out.getvalue() and "with" in out.getvalue()
    assert not (output / "stale.py").exists()
    out = io.StringIO()
    generator.run(["--spec", str(document), "--output", str(output), "--settings", str(tmp_path / "none.json")], tmp_path, out, io.StringIO())
    assert "0 written, 4 unchanged, 0 stale deleted" in out.getvalue() and " with " not in out.getvalue()


def test_the_command_refuses_unknown_arguments_and_needs_the_workspace(tmp_path: Path) -> None:
    error = io.StringIO()
    assert generator.run(["--bogus"], tmp_path, io.StringIO(), error) == 2
    assert "Usage" in error.getvalue()
    error = io.StringIO()
    assert generator.run([], tmp_path, io.StringIO(), error) == 2
    assert "workspace root" in error.getvalue()


def test_the_command_defaults_to_the_librarys_spec_and_output_from_the_workspace_root() -> None:
    assert generator.workspace_root(_PACKAGE / "tests") == _WORKSPACE
