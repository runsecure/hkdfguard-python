"""Generates hkdfguard-integration-hashicorpvault's typed API from Vault's OpenAPI document: what
vault-client-go's generate/templates produce through openapi-generator, in Python - and what the
.NET and Java generators produce in C# and Java. One class per tag (AuthApi, IdentityApi,
SecretsApi, SystemApi) with one method per operation and its ``_async`` counterpart, the VaultApis
mixin whose properties reach them from a VaultClient, and one model per schema in ``schema.py``.

As vault-client-go, operations whose id ends in 2, 3 or 4 (duplicates Vault's spec lists for
alternative paths) or starts EnterpriseStub are left out, and so are their schemas.

Settings can narrow that further: an "include" list of regular expressions, matched against each
operation's name in PascalCase (KvV2Read, AppRoleLogin - the .NET method name without Async). Only
operations one of them matches are generated, only the schemas those operations use (directly, or
through another schema), and only the classes that still have an operation. Each expression must
match at least one operation, so a typo or an operation the spec has dropped is noticed rather than
silently generating less.

The command line: [--spec <openapi.json>] [--settings <generator.json>] [--output <directory>]. The
spec and output default to the library's own, found from the workspace root - the directory holding
hkdfguard-python's pyproject.toml, at or above the current one - and the settings to generator.json
beside the spec, if there is one. Files are only rewritten when they change, and .py files under the
output that the spec no longer produces are deleted. Run it from hkdfguard-python:

    uv run python scripts/generate-vault-client.py

The spec isn't fetched: pull a newer openapi.json from Vault yourself (``vault read sys/internal/specs/openapi``
on the Vault version to target) and regenerate.
"""

from __future__ import annotations

import json
import keyword
import re
import sys
import textwrap
import unicodedata
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, TextIO

LIBRARY: Final = "hkdfguard-integration-hashicorpvault"
"""The library's directory under packages/."""

SETTINGS_FILE_NAME: Final = "generator.json"
"""The settings file looked for beside the spec."""

PACKAGE: Final = "hkdfguard.integration.hashicorpvault"
GENERATED: Final = PACKAGE + "._generated"

# The tags in the order vault-client-go lists them, and what each class holds.
KNOWN_TAGS: Final = {
    "auth": "Vault's auth methods and tokens.",
    "identity": "Vault's identity store: entities, groups, aliases, OIDC and MFA.",
    "secrets": "Vault's secrets engines.",
    "system": "Vault's system backend (sys/).",
}

# Names generated code uses itself, so a parameter can't take them.
_RESERVED_PARAMETER_NAMES: Final = frozenset({"self", "options", "request", "request_path", "query"})
# Names a model has already, so a property can't take them.
_RESERVED_FIELD_NAMES: Final = frozenset({"write_json", "from_json"})
# vault-client-go's .openapi-generator-ignore: model_*2_request.go, ..., model_enterprise_stub*.
_EXCLUDED_SCHEMA: Final = re.compile(r"^EnterpriseStub|[234](Request|Response)$")
_PLACEHOLDER: Final = re.compile(r"([^{]*)\{([^}]*)\}")
_NON_ALPHANUMERIC: Final = re.compile(r"[^A-Za-z0-9]+")
_CAMEL_BOUNDARY: Final = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_WHITESPACE: Final = re.compile(r"\s+")
_METHODS: Final = ("get", "put", "post", "delete", "patch")
_SCHEMA_PREFIX: Final = "#/components/schemas/"
_WIDTH: Final = 150
# Prose the spec writes with typographic characters, in ASCII.
_ASCII: Final = str.maketrans({0x2018: "'", 0x2019: "'", 0x201C: '"', 0x201D: '"', 0x2013: "-", 0x2014: "-", 0x2026: "...", 0x00A0: " ",
                               0x00B5: "u", 0x03BC: "u"})


# --- The spec ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Parameter:
    """A path or query parameter."""

    name: str
    location: str
    description: str | None
    schema: Any
    required: bool

    @property
    def is_mount_path(self) -> bool:
        """Whether this is the path parameter where the auth method or secrets engine is mounted."""
        return self.location == "path" and self.name.endswith("_mount_path")


@dataclass(frozen=True)
class Operation:
    """One endpoint and method; ``method`` upper case."""

    id: str
    tag: str
    method: str
    path: str
    summary: str | None
    description: str | None
    path_description: str | None
    deprecated: bool
    unauthenticated: bool
    sudo: bool
    parameters: list[Parameter]
    request_schema: Any
    response_schema: Any


@dataclass(frozen=True)
class OpenApiSpec:
    """What the generator needs from Vault's OpenAPI document, in document order."""

    api_version: str
    operations: list[Operation]
    schemas: dict[str, Any]

    @staticmethod
    def read(root: Any) -> OpenApiSpec:
        """Reads the document root.

        :raises ValueError: an operation lacks an id or tag, or uses something the generator doesn't handle
        """
        version = _string(_member(root, "info"), "version")
        operations: list[Operation] = []
        for path, item in _members(_member(root, "paths")).items():
            shared = _parameters(item)
            for method, operation in _members(item).items():
                if method not in _METHODS:
                    continue
                operation_id = _string(operation, "operationId")
                if operation_id is None:
                    raise ValueError(f"{method} {path} has no operationId.")
                tags = _member(operation, "tags")
                tags = tags if isinstance(tags, list) else []
                if len(tags) != 1:
                    raise ValueError(f"Operation {operation_id} has {len(tags)} tags; the generator expects exactly one.")
                # Operation parameters first, then the path's that it doesn't override - as openapi-generator orders them.
                own = _parameters(operation)
                every = own + [s for s in shared if not any(o.name == s.name and o.location == s.location for o in own)]
                operations.append(Operation(
                    operation_id, tags[0], method.upper(), path, _string(operation, "summary"), _string(operation, "description"),
                    _string(item, "description"), _bool(operation, "deprecated"),
                    _bool(operation, "x-vault-unauthenticated") or _bool(item, "x-vault-unauthenticated"),
                    _bool(operation, "x-vault-sudo") or _bool(item, "x-vault-sudo"),
                    every, _request_schema(operation_id, operation), _response_schema(operation)))
        schemas = _members(_member(_member(root, "components"), "schemas"))
        return OpenApiSpec(version or "", operations, schemas)


def ref_name(schema: Any) -> str | None:
    """The schema a $ref names, without its "#/components/schemas/" prefix; ``None`` if ``schema`` isn't a $ref.

    :raises ValueError: the $ref points anywhere else
    """
    reference = _string(schema, "$ref")
    if reference is None:
        return None
    if not reference.startswith(_SCHEMA_PREFIX):
        raise ValueError(f"Unsupported $ref '{reference}': only {_SCHEMA_PREFIX}... is handled.")
    return reference[len(_SCHEMA_PREFIX):]


def _member(element: Any, name: str) -> Any:
    return element.get(name) if isinstance(element, dict) else None


def _members(element: Any) -> dict[str, Any]:
    return element if isinstance(element, dict) else {}


def _string(element: Any, name: str) -> str | None:
    value = _member(element, name)
    return value if isinstance(value, str) else None


def _bool(element: Any, name: str) -> bool:
    return _member(element, name) is True


def _has(element: Any, name: str) -> bool:
    return isinstance(element, dict) and name in element


def _parameters(element: Any) -> list[Parameter]:
    parameters = _member(element, "parameters")
    if not isinstance(parameters, list):
        return []
    return [Parameter(_string(p, "name") or "", _string(p, "in") or "", _string(p, "description"), _member(p, "schema"), _bool(p, "required"))
            for p in parameters]


def _request_schema(operation_id: str, operation: Any) -> Any:
    if not _has(operation, "requestBody"):
        return None
    content = _members(_member(_member(operation, "requestBody"), "content"))
    if "application/json" not in content or len(content) != 1:
        raise ValueError(f"Operation {operation_id} has a request body that isn't only application/json.")
    return _member(content["application/json"], "schema")


def _response_schema(operation: Any) -> Any:
    # The first 2xx response's JSON schema, if it has one.
    for status, response in _members(_member(operation, "responses")).items():
        if not status.startswith("2"):
            continue
        content = _member(_member(response, "content"), "application/json")
        return _member(content, "schema") if _has(content, "schema") else None
    return None


# --- Names and prose -----------------------------------------------------------------------------


def pascal(name: str) -> str:
    """``name`` in PascalCase: split at anything but letters and digits, each part's first letter
    capitalized - "kv-v2-read" is KvV2Read, as openapi-generator (and the .NET generator) names it."""
    result = "".join(part[0].upper() + part[1:] for part in _NON_ALPHANUMERIC.split(name) if part)
    if not result:
        return "Value"
    # Letters and digits only: one can't start with a digit.
    return result if result[0].isalpha() else "_" + result


def snake(name: str) -> str:
    """``name`` in snake_case, with "_" appended if it's a keyword: "kv-v2-read" is kv_v2_read,
    "tokenTTL" is token_ttl."""
    parts = [p.lower() for part in _NON_ALPHANUMERIC.split(name) if part for p in _CAMEL_BOUNDARY.split(part)]
    result = "_".join(parts) or "value"
    if result[0].isdigit():
        result = "_" + result
    return result + "_" if keyword.iskeyword(result) or keyword.issoftkeyword(result) else result


def literal(value: str) -> str:
    """``value`` as a Python string literal."""
    return json.dumps(value, ensure_ascii=False)


def doc(text: str) -> str:
    """``text`` for a docstring: in ASCII, whitespace collapsed to single spaces, and backslashes and
    any triple quote escaped, so prose can never end the docstring or become an escape."""
    ascii_text = unicodedata.normalize("NFKD", text.translate(_ASCII)).encode("ascii", "ignore").decode("ascii")
    collapsed = _WHITESPACE.sub(" ", ascii_text).strip()
    return collapsed.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')


def docstring(text: str, indent: str) -> str:
    """``text`` (already :func:`doc`-escaped) as a docstring at ``indent``: paragraphs separated by
    "\\n\\n", each line of one wrapped on its own - a ":param" line with a hanging indent."""
    paragraphs = ["\n".join(textwrap.fill(line, width=100, initial_indent=indent, subsequent_indent=indent + ("    " if line.startswith(":") else ""),
                                          break_long_words=False, break_on_hyphens=False)
                            for line in p.split("\n"))
                  for p in text.split("\n\n") if p]
    body = "\n\n".join(paragraphs).strip()
    if body.endswith('"'):
        body += " "
    if "\n" not in body and len(indent) + len(body) + 6 <= _WIDTH:
        return f'{indent}"""{body}"""\n'
    return f'{indent}"""{body}\n{indent}"""\n'


# --- Generating ----------------------------------------------------------------------------------


def generate(open_api_json: str, settings_json: str | None) -> dict[str, str]:  # noqa: PLR0912 - one pass over the spec
    """The generated files for the OpenAPI document ``open_api_json``, by path relative to the output
    directory ('/'-separated), each with '\\n' line endings.

    :param settings_json: the generator's settings - {"include": ["^KvV2", ...]} - or ``None`` to
        generate every operation vault-client-go does
    :raises ValueError: the document uses something the generator doesn't handle, the settings
        aren't valid, or an include pattern matches no operation
    """
    include = _read_include(settings_json)
    try:
        root = json.loads(open_api_json)
    except json.JSONDecodeError as error:
        raise ValueError(f"The spec isn't JSON: {error}") from error
    spec = OpenApiSpec.read(root)
    operations = [o for o in spec.operations if not _is_excluded(pascal(o.id))]
    if include is not None:
        for pattern in include:
            if not any(pattern.search(pascal(o.id)) for o in operations):
                raise ValueError(f"The include pattern '{pattern.pattern}' matches no operation.")
        operations = [o for o in operations if any(p.search(pascal(o.id)) for p in include)]

    schema_names = {name for name in spec.schemas if not _EXCLUDED_SCHEMA.search(name)}
    # Which operations send or return each schema, for its summary and how it's typed.
    request_uses: dict[str, list[Operation]] = {}
    response_uses: dict[str, list[Operation]] = {}
    for operation in operations:
        request_name = None if operation.request_schema is None else ref_name(operation.request_schema)
        if request_name is not None:
            request_uses.setdefault(request_name, []).append(operation)
        response_name = None if operation.response_schema is None else ref_name(operation.response_schema)
        if response_name is not None:
            response_uses.setdefault(response_name, []).append(operation)
    used = [*request_uses, *response_uses]
    for name in used:
        if name not in schema_names:
            raise ValueError(f"Schema {name} is used by a generated operation but is missing or excluded.")
    # Narrowed, only the schemas the operations use are generated: those they send or return, and
    # those those refer to.
    if include is not None:
        schema_names = _referenced(spec, used)

    by_type: dict[str, list[str]] = {}
    for name in sorted(schema_names):
        by_type.setdefault(pascal(name), []).append(name)
    for type_name, names in by_type.items():
        if len(names) > 1:
            raise ValueError(f"Schemas {', '.join(names)} would all be named {type_name}.")

    tags = _order_tags(dict.fromkeys(o.tag for o in operations))
    files = {"__init__.py": _init_file(spec, tags), "_apis.py": _apis_file(spec, tags)}
    for tag in tags:
        files[f"_{snake(tag)}_api.py"] = _api_file(spec, tag, [o for o in operations if o.tag == tag])
    models = [_model(name, spec.schemas[name], request_uses.get(name, []), response_uses.get(name, [])) for name in sorted(schema_names, key=pascal)]
    files["schema.py"] = _schema_file(spec, models)
    # Prose from the spec can carry its own line endings.
    return {path: content.replace("\r\n", "\n").replace("\r", "\n") for path, content in sorted(files.items())}


def _read_include(settings_json: str | None) -> list[re.Pattern[str]] | None:
    # The settings' include patterns; None without settings or an include list.
    if settings_json is None:
        return None
    try:
        settings = json.loads(settings_json)
    except json.JSONDecodeError as error:
        raise ValueError(f"The generator's settings aren't JSON: {error}") from error
    if not isinstance(settings, dict):
        raise ValueError("The generator's settings must be a JSON object.")
    include: list[re.Pattern[str]] | None = None
    for name, value in settings.items():
        if name == "description":
            continue
        if name != "include":
            raise ValueError(f"Unknown generator setting '{name}': only \"include\" and \"description\" are.")
        if not isinstance(value, list) or not value or not all(isinstance(p, str) for p in value):
            raise ValueError("The generator's \"include\" setting must be a non-empty array of regular expressions.")
        try:
            include = [re.compile(p) for p in value]
        except re.error as error:
            raise ValueError(f"An include pattern isn't a regular expression: {error}") from error
    return include


def _referenced(spec: OpenApiSpec, roots: Iterable[str]) -> set[str]:
    # roots, and every schema they refer to, however indirectly.
    found: set[str] = set()
    pending = list(roots)
    while pending:
        name = pending.pop()
        if name in found:
            continue
        found.add(name)
        if name not in spec.schemas:
            raise ValueError(f"Schema {name} is referred to but missing.")
        _references(spec.schemas[name], pending)
    return found


def _references(element: Any, found: list[str]) -> None:
    if isinstance(element, dict):
        reference = ref_name(element)
        if reference is not None:
            found.append(reference)
            return
        for value in element.values():
            _references(value, found)
    elif isinstance(element, list):
        for value in element:
            _references(value, found)


def _is_excluded(operation_name: str) -> bool:
    # vault-client-go's partial_filter_operation.
    return operation_name.endswith(("2", "3", "4")) or operation_name.startswith("EnterpriseStub")


def _order_tags(tags: dict[str, None]) -> list[str]:
    return [t for t in KNOWN_TAGS if t in tags] + sorted(t for t in tags if t not in KNOWN_TAGS)


def api_class(tag: str) -> str:
    """The class holding ``tag``'s operations: AuthApi for "auth"."""
    return pascal(tag) + "Api"


def method_name(operation: Operation) -> str:
    """The method an operation is generated as: kv_v2_read for kv-v2-read."""
    return snake(operation.id)


def _tag_summary(tag: str) -> str:
    return KNOWN_TAGS.get(tag, f"Vault's \"{tag}\" endpoints.")


def _header(spec: OpenApiSpec) -> str:
    return (f"# Generated by scripts/generate-vault-client.py from openapi.json (HashiCorp Vault API {spec.api_version}).\n"
            "# Don't edit: change the generator or the spec, and regenerate (docs/how-to/use-hashicorp-vault-client.md).\n")


def _init_file(spec: OpenApiSpec, tags: list[str]) -> str:
    names = ["VaultApis", *(api_class(t) for t in tags)]
    code = [_header(spec), '"""The typed API generated from Vault\'s OpenAPI spec: the groups a VaultClient reaches, and their models."""\n\n']
    code.append(f"from {GENERATED}._apis import VaultApis\n")
    code += (f"from {GENERATED}._{snake(t)}_api import {api_class(t)}\n" for t in tags)
    code.append("\n__all__ = [\n")
    code += (f"    {literal(n)},\n" for n in _sorted_all(names))
    code.append("]\n")
    return "".join(code)


def _apis_file(spec: OpenApiSpec, tags: list[str]) -> str:
    code = [_header(spec), '"""The typed groups of Vault\'s API a VaultClient reaches."""\n\n', "from __future__ import annotations\n\n",
            "from typing import TYPE_CHECKING, cast\n\n"]
    code += (f"from {GENERATED}._{snake(t)}_api import {api_class(t)}\n" for t in tags)
    code.append(f"\nif TYPE_CHECKING:\n    from {PACKAGE}._client import VaultClient\n\n\n")
    code.append("class VaultApis:\n")
    code.append(docstring("The typed groups of Vault's API a VaultClient reaches, generated from Vault's OpenAPI spec.", "    "))
    code.append("\n    __slots__ = ()\n")
    for tag in tags:
        code.append(f"\n    @property\n    def {snake(tag)}(self) -> {api_class(tag)}:\n")
        code.append(docstring(f"{doc(_tag_summary(tag))} The {doc(tag)} endpoints, through this client.", "        "))
        code.append(f"        return {api_class(tag)}(cast(\"VaultClient\", self))\n")
    return "".join(code)


@dataclass
class _Param:
    parameter: Parameter
    name: str
    type: str


def _api_file(spec: OpenApiSpec, tag: str, operations: list[Operation]) -> str:
    schemas: set[str] = set()
    body = "".join("\n" + _method(operation, schemas) for operation in operations)
    code = [_header(spec), '"""', doc(_tag_summary(tag)), '"""\n\n', "from __future__ import annotations\n\n"]
    standard = ["from typing import TYPE_CHECKING\n"]
    if "Mapping[" in body:
        standard.insert(0, "from collections.abc import Mapping\n")
    code += standard
    code.append(f"\nfrom {PACKAGE} import _client\n")
    if schemas:
        code.append(_import_names(f"{GENERATED}.schema", sorted(schemas)))
    code.append(f"from {PACKAGE}._json import JsonValue\n")
    code.append(f"from {PACKAGE}._options import VaultRequestOptions\n")
    code.append(f"from {PACKAGE}._response import VaultResponse\n")
    code.append(f"\nif TYPE_CHECKING:\n    from {PACKAGE}._client import VaultClient\n\n\n")
    code.append(f"class {api_class(tag)}:\n")
    code.append(docstring(f"{doc(_tag_summary(tag))} Reached through ``VaultClient.{snake(tag)}``.", "    "))
    code.append('\n    __slots__ = ("_client",)\n\n')
    code.append("    def __init__(self, client: VaultClient) -> None:\n        self._client = client\n")
    code.append(body)
    text = "".join(code)
    return text if "JsonValue" in body else text.replace(f"from {PACKAGE}._json import JsonValue\n", "")


def _import_names(module: str, names: Sequence[str]) -> str:
    line = f"from {module} import {', '.join(names)}\n"
    if len(line) <= _WIDTH:
        return line
    return f"from {module} import (\n" + "".join(f"    {n},\n" for n in names) + ")\n"


def _method(operation: Operation, schemas: set[str]) -> str:  # noqa: PLR0912, PLR0915 - one operation, one method
    mount: Parameter | None = None
    path_parameters: list[Parameter] = []
    query_parameters: list[Parameter] = []
    lists = False
    for parameter in operation.parameters:
        if parameter.location == "path":
            if parameter.is_mount_path:
                mount = mount or parameter
            else:
                path_parameters.append(parameter)
        elif parameter.location == "query":
            if parameter.name == "list":
                lists = True
            else:
                query_parameters.append(parameter)
        else:
            raise ValueError(f"Operation {operation.id} has a {parameter.location} parameter, {parameter.name}; only path and query "
                             "parameters are handled.")

    # Python names for the parameters, kept clear of each other and of the generated code's own.
    names: set[str] = set()
    paths = [_param(operation, p, names) for p in path_parameters]
    queries = [_param(operation, p, names) for p in query_parameters]

    response_name = None if operation.response_schema is None else ref_name(operation.response_schema)
    if response_name is not None:
        response_type = pascal(response_name)
        reader = f"{response_type}.from_json"
        schemas.add(response_type)
    else:
        response_type = "dict[str, JsonValue]"
        reader = "JsonValue.read_json_dict"

    request_type = None
    if operation.request_schema is not None:
        request_name = ref_name(operation.request_schema)
        if request_name is not None:
            request_type = pascal(request_name)
            schemas.add(request_type)
        elif _is_free_form(operation.request_schema):
            request_type = "Mapping[str, object]"
        else:
            raise ValueError(f"Operation {operation.id}'s request body is neither a $ref nor a free-form object.")

    signature = ["self", *(f"{p.name}: {p.type}" for p in paths)]
    if request_type is not None:
        signature.append(f"request: {request_type}")
    signature.append("*")
    for q in queries:
        signature.append(f"{q.name}: {q.type}" if q.parameter.required else f"{q.name}: {q.type} | None = None")
    signature.append("options: VaultRequestOptions | None = None")

    description = operation.description
    summary = operation.summary or description or operation.path_description
    if operation.summary is None:
        description = None
    remarks = f"``{operation.method} /v1{operation.path}``" + (" with ``list=true``" if lists else "") + "."
    if description is not None:
        remarks += " " + doc(description)
    if operation.unauthenticated:
        remarks += " Needs no token."
    if operation.sudo:
        remarks += " Needs a token with sudo capability."
    if operation.deprecated:
        remarks += " Deprecated by Vault."
    parameter_docs = [f":param {p.name}: {_parameter_doc(p.parameter)}" for p in paths]
    if request_type is not None:
        parameter_docs.append(":param request: The request body.")
    parameter_docs += (f":param {q.name}: {_parameter_doc(q.parameter)}" for q in queries)
    if mount is not None:
        engine = "auth method" if operation.tag == "auth" else "secrets engine"
        parameter_docs.append(f":param options: Settings for this request; ``None`` for none. Its ``mount_path`` is where the {engine} is mounted, "
                              f"\"{doc(_mount_default(operation, mount))}\" by default.")
    else:
        parameter_docs.append(":param options: Settings for this request; ``None`` for none.")
    parameter_docs += [":returns: Vault's response; ``None`` if it has no body", ":raises VaultResponseError: Vault refuses the request"]

    name = method_name(operation)
    return_type = f"VaultResponse[{response_type}] | None"
    summary_doc = doc(summary) if summary else f"{operation.method} /v1{operation.path}."

    statements = []
    if request_type is not None:
        statements.append("if request is None:\n            raise TypeError(\"request must not be None.\")\n")
    statements.append(_assignment("request_path", _path_expression(operation, mount, paths)))
    statements.append("query = _client.query_parameters(options)\n")
    if lists:
        statements.append('query.append(("list", "true"))\n')
    for q in queries:
        append = f"query.append(({literal(q.parameter.name)}, _client.format_query_value({q.name})))\n"
        statements.append(append if q.parameter.required else f"if {q.name} is not None:\n            {append}")
    call = f"(self._client, {literal(operation.method)}, request_path, {'None' if request_type is None else 'request'}, query, options, {reader})"

    def method(is_async: bool) -> str:
        prefix = "async def" if is_async else "def"
        text = _def(f"    {prefix} {name}{'_async' if is_async else ''}", signature, return_type)
        if is_async:
            text += docstring(f"As :meth:`{name}`, without blocking the event loop.", "        ")
        else:
            text += docstring(summary_doc + "\n\n" + remarks + "\n\n" + "\n".join(parameter_docs), "        ")
        text += "".join(f"        {s}" for s in statements)
        send = f"await _client.send_async{call}" if is_async else f"_client.send{call}"
        return text + f"        return {send}\n"

    return method(is_async=False) + "\n" + method(is_async=True)


def _def(start: str, parameters: list[str], return_type: str) -> str:
    line = f"{start}({', '.join(parameters)}) -> {return_type}:\n"
    if len(line) <= _WIDTH:
        return line
    indent = " " * (len(start) - len(start.lstrip()) + 4)
    return f"{start}(\n" + "".join(f"{indent}{p},\n" for p in parameters) + f"{indent[:-4]}) -> {return_type}:\n"


def _assignment(target: str, parts: list[str]) -> str:
    line = f"{target} = {' + '.join(parts)}\n"
    if len(line) + 8 <= _WIDTH:
        return line
    return f"{target} = (\n" + "".join(f"            {'+ ' if i else ''}{p}\n" for i, p in enumerate(parts)) + "        )\n"


def _param(operation: Operation, parameter: Parameter, names: set[str]) -> _Param:
    name = snake(parameter.name)
    while name in _RESERVED_PARAMETER_NAMES or name in names:
        name += "_parameter"
    names.add(name)
    return _Param(parameter, name, _parameter_type(operation, parameter))


def _path_expression(operation: Operation, mount: Parameter | None, paths: list[_Param]) -> list[str]:
    # "/v1" + the path, its placeholders filled in - each escaped as one segment, the mount path
    # with options' or the default - as vault-client-go's strings.Replace(..., url.PathEscape(...)).
    parts: list[str] = []
    text = "/v1"
    for match in _PLACEHOLDER.finditer(operation.path + "{}"):
        text += match.group(1)
        placeholder = match.group(2)
        if not placeholder:
            break
        if text:
            parts.append(literal(text))
        text = ""
        if mount is not None and placeholder == mount.name:
            parts.append(f"_client.escape_path_segment(_client.mount_path_or(options, {literal(_mount_default(operation, mount))}))")
            continue
        parameter = next((p for p in paths if p.parameter.name == placeholder), None)
        if parameter is None:
            raise ValueError(f"Operation {operation.id}'s path {operation.path} has a placeholder {{{placeholder}}} with no parameter.")
        parts.append(f"_client.escape_path_segment({parameter.name})")
    if text:
        parts.append(literal(text))
    return parts


def _mount_default(operation: Operation, mount: Parameter) -> str:
    value = _string(mount.schema, "default")
    if not value:
        raise ValueError(f"Operation {operation.id}'s mount path parameter {mount.name} has no default.")
    return value


def _parameter_type(operation: Operation, parameter: Parameter) -> str:
    match _string(parameter.schema, "type"):
        case "string":
            return "str"
        case "integer":
            return "int"
        case "boolean":
            return "bool"
        case other:
            raise ValueError(f"Operation {operation.id}'s parameter {parameter.name} is a {other or 'typeless'}; only string, integer and "
                             "boolean are handled.")


def _parameter_doc(parameter: Parameter) -> str:
    text = doc(parameter.description or f"The {parameter.name} {parameter.location} parameter.")
    # _parameter_type has already refused a parameter without a schema.
    if _has(parameter.schema, "default"):
        text += f" Vault's default: {doc(json.dumps(_member(parameter.schema, 'default')))}."
    return text


def _is_free_form(schema: Any) -> bool:
    return _string(schema, "type") == "object" and not _has(schema, "properties")


# --- Models --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class PythonType:
    """A property's Python type, and how its value is read from a JsonValue.

    ``element`` is a function reading one, for read_list and read_dict (a method like
    ``JsonValue.read_str``, or a lambda); ``read`` the expression reading one from the JsonValue
    expression given, at the lambda depth given.
    """

    name: str
    element: Callable[[int], str]
    read: Callable[[str, int], str]


def _scalar(name: str, method: str) -> PythonType:
    return PythonType(name, lambda _: f"JsonValue.{method}", lambda e, _: f"{e}.{method}()")


def _whole(name: str, element: str, method: str) -> PythonType:
    # A type read whole with method, and as an element with element.
    return PythonType(name, lambda _: element, lambda e, _: f"{e}.{method}()")


def _container(name: str, method: str, item: PythonType) -> PythonType:
    def read(e: str, depth: int) -> str:
        return f"{e}.{method}({item.element(depth)})"

    def element(depth: int) -> str:
        v = f"v{depth}"
        return f"lambda {v}: {read(v, depth + 1)}"

    return PythonType(name, element, read)


def type_of(where: str, schema: Any, is_request: bool) -> PythonType:  # noqa: PLR0911, PLR0912 - one case per type
    """The Python type a property's schema maps to: vault-client-go's type mapping, but with
    free-form values as ``object`` (sent) or ``JsonValue`` (returned) where Go has interface{}."""
    reference = ref_name(schema)
    if reference is not None:
        model = pascal(reference)
        return PythonType(model, lambda _: f"{model}.from_json", lambda e, _: f"{e}.read_model({model}.from_json)")
    free = _whole("object", "JsonValue.read_object", "read_object") if is_request else _whole("JsonValue", "JsonValue.as_json", "read_json")
    match _string(schema, "type"):
        case None:
            return free
        case "string":
            return _scalar("datetime", "read_datetime") if _string(schema, "format") == "date-time" else _scalar("str", "read_str")
        case "integer":
            return _scalar("int", "read_int")
        case "number":
            return _scalar("float", "read_float")
        case "boolean":
            return _scalar("bool", "read_bool")
        case "array":
            items = type_of(where, _member(schema, "items"), is_request) if _has(schema, "items") else free
            if items.name == "JsonValue":
                return _whole("list[JsonValue]", "JsonValue.read_json_list", "read_json_list")
            if items.name == "object":
                return _whole("list[object]", "JsonValue.read_object_list", "read_object_list")
            return _container(f"list[{items.name}]", "read_list", items)
        case "object":
            if _has(schema, "properties"):
                raise ValueError(f"{where} is an object with properties of its own; only free-form objects are handled inline.")
            values = _member(schema, "additionalProperties")
            value = type_of(where, values, is_request) if isinstance(values, dict) else free
            if value.name == "JsonValue":
                return _whole("dict[str, JsonValue]", "JsonValue.read_json_dict", "read_json_dict")
            if value.name == "object":
                return _whole("dict[str, object]", "JsonValue.read_object_dict", "read_object_dict")
            return _container(f"dict[str, {value.name}]", "read_dict", value)
        case other:
            raise ValueError(f"{where} has type '{other}', which the generator doesn't handle.")


@dataclass
class _Property:
    json_name: str
    field: str
    type: PythonType
    required: bool
    deprecated: bool
    schema: Any


@dataclass
class _Model:
    name: str
    code: str
    uses_datetime: bool = field(default=False)


def _model(name: str, schema: Any, sent_by: list[Operation], returned_by: list[Operation]) -> _Model:
    if _string(schema, "type") != "object":
        raise ValueError(f"Schema {name} isn't an object; only object schemas are handled.")
    # Sent, it's written: free-form values are any object, and required members are required.
    # Returned, it's read: free-form values are JSON, and nothing is relied on being there.
    is_request = bool(sent_by) or (not returned_by and name.endswith("Request"))
    # As openapi-generator names models: Vault's spec has a few with underscores.
    type_name = pascal(name)
    required_list = _member(schema, "required")
    required = set(required_list) if isinstance(required_list, list) else set()

    properties: list[_Property] = []
    used: set[str] = set()
    for json_name, member in _members(_member(schema, "properties")).items():
        field_name = snake(json_name)
        if field_name in _RESERVED_FIELD_NAMES:
            field_name += "_value"
        unique = field_name
        i = 2
        while unique in used:
            unique = f"{field_name}{i}"
            i += 1
        used.add(unique)
        properties.append(_Property(json_name, unique, type_of(f"{name}.{json_name}", member, is_request), is_request and json_name in required,
                                    _bool(member, "deprecated"), member))

    code = [f"@dataclass(frozen=True, kw_only=True, slots=True)\nclass {type_name}(VaultModel):\n"]
    code.append(docstring(_model_summary(name, schema, sent_by, returned_by), "    "))
    if properties:
        code.append("\n")
    for p in properties:
        # object holds None already.
        annotation = p.type.name if p.type.name == "object" else f"{p.type.name} | None"
        code.append(f"    {p.field}: {annotation} = None\n")
        code.append(docstring(_property_doc(p), "    "))

    code.append("\n    def write_json(self, writer: JsonWriter) -> None:\n")
    for p in properties:
        if p.required:
            code.append(f"        if self.{p.field} is None:\n            raise ValueError({literal(f'{type_name} needs its {p.json_name}.')})\n")
    code.append("        writer.begin_object()\n")
    if properties:
        code.append("        for name, value in (\n")
        code += (f"            ({literal(p.json_name)}, self.{p.field}),\n" for p in properties)
        code.append("        ):\n            if value is not None:\n                writer.name(name).value(value)\n")
    code.append("        writer.end_object()\n")

    code.append(f"\n    @classmethod\n    def from_json(cls, json: JsonValue) -> {type_name}:\n")
    code.append(docstring("This model read from ``json``: a JSON object, its members read leniently (see :class:`JsonValue`).\n\n"
                          ":raises VaultJsonError: ``json`` isn't an object, or a member isn't what this model holds there", "        "))
    code.append(f"        json.require_object({literal(type_name)})\n")
    if not properties:
        code.append("        return cls()\n")
    else:
        code.append("        return cls(\n")
        for p in properties:
            line = f"            {p.field}={p.type.read(f'json.member({literal(p.json_name)})', 0)},\n"
            code.append(line)
        code.append("        )\n")
    text = "".join(code)
    return _Model(type_name, text, uses_datetime=any("datetime" in p.type.name for p in properties))


def _model_summary(name: str, schema: Any, sent_by: list[Operation], returned_by: list[Operation]) -> str:
    description = _string(schema, "description")
    if description:
        return doc(description)
    if sent_by:
        return f"The request body of {_methods(sent_by)}."
    if returned_by:
        return f"The data {_methods(returned_by)} return{'s' if len(returned_by) == 1 else ''}."
    return f"The {doc(name)} schema."


def _methods(operations: list[Operation]) -> str:
    return ", ".join(f":meth:`{api_class(o.tag)}.{method_name(o)}`" for o in operations)


def _property_doc(p: _Property) -> str:
    description = _string(p.schema, "description")
    text = doc(description or "Not described by Vault's spec.")
    remarks = []
    if _string(p.schema, "format") == "duration":
        remarks.append("A duration: seconds, or a Go duration such as \"24h\".")
    values = _member(p.schema, "enum")
    if isinstance(values, list):
        remarks.append("One of: " + ", ".join(json.dumps(v) for v in values) + ".")
    if _has(p.schema, "default"):
        remarks.append(f"Vault's default: {json.dumps(_member(p.schema, 'default'))}.")
    if p.required:
        remarks.append("Required.")
    if p.deprecated:
        remarks.append("Deprecated by Vault.")
    if remarks:
        text += "\n\n" + doc(" ".join(remarks))
    return text


def _schema_file(spec: OpenApiSpec, models: list[_Model]) -> str:
    code = [_header(spec), '"""The models of the request and response bodies the generated methods send and return."""\n\n',
            "from __future__ import annotations\n\n", "from dataclasses import dataclass\n"]
    if any(m.uses_datetime for m in models):
        code.append("from datetime import datetime\n")
    code.append(f"\nfrom {PACKAGE}._json import JsonValue, JsonWriter, VaultModel\n")
    code.append("\n__all__ = [\n")
    code += (f"    {literal(n)},\n" for n in _sorted_all([m.name for m in models]))
    code.append("]\n")
    code += ("\n\n" + m.code for m in models)
    return "".join(code)


def _sorted_all(names: list[str]) -> list[str]:
    # As ruff's RUF022 sorts __all__: SCREAMING_CASE, then CamelCase, then the rest, each in natural order.
    def key(name: str) -> tuple[int, list[object]]:
        kind = 0 if name.isupper() and len(name) > 1 else 1 if name[:1].isupper() else 2
        return kind, [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", name)]

    return sorted(names, key=key)


# --- The command line ----------------------------------------------------------------------------


def workspace_root(start: Path) -> Path | None:
    """The directory at or above ``start`` holding the workspace's pyproject.toml (project hkdfguard-workspace)."""
    for directory in [start.resolve(), *start.resolve().parents]:
        pyproject = directory / "pyproject.toml"
        if pyproject.is_file() and 'name = "hkdfguard-workspace"' in pyproject.read_text(encoding="utf-8"):
            return directory
    return None


def run(args: Sequence[str], current_directory: Path, output: TextIO, error: TextIO) -> int:
    """Runs the command.

    :returns: 0 on success, 2 for bad arguments or no workspace root
    :raises ValueError: the spec or settings are refused by the generator
    """
    options: dict[str, Path] = {}
    i = 0
    while i < len(args):
        argument = args[i]
        if argument not in {"--spec", "--settings", "--output"} or i + 1 >= len(args):
            print(f"Unknown argument '{argument}'. Usage: [--spec <openapi.json>] [--settings <generator.json>] [--output <directory>]", file=error)
            return 2
        options[argument[2:]] = current_directory / args[i + 1]
        i += 2

    spec = options.get("spec")
    output_directory = options.get("output")
    if spec is None or output_directory is None:
        root = workspace_root(current_directory)
        if root is None:
            print("Couldn't find the workspace root (hkdfguard-python's pyproject.toml) at or above the current directory; run from inside "
                  "it, or pass --spec and --output.", file=error)
            return 2
        library = root / "packages" / LIBRARY
        spec = spec or library / "openapi.json"
        output_directory = output_directory or library / "src" / "hkdfguard" / "integration" / "hashicorpvault" / "_generated"
    spec = spec.resolve()
    output_directory = output_directory.resolve()
    settings = (options.get("settings") or spec.with_name(SETTINGS_FILE_NAME)).resolve()

    has_settings = settings.is_file()
    files = generate(spec.read_text(encoding="utf-8"), settings.read_text(encoding="utf-8") if has_settings else None)
    written = 0
    expected: set[Path] = set()
    for relative, content in files.items():
        path = (output_directory / relative).resolve()
        expected.add(path)
        if path.is_file() and path.read_text(encoding="utf-8").replace("\r\n", "\n") == content:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
        written += 1
    deleted = 0
    if output_directory.is_dir():
        for path in sorted(output_directory.rglob("*.py")):
            if path.is_file() and path.resolve() not in expected:
                path.unlink()
                deleted += 1
    with_settings = f" with {settings}" if has_settings else ""
    print(f"{len(files)} files from {spec}{with_settings}: {written} written, {len(files) - written} unchanged, {deleted} stale deleted, "
          f"in {output_directory}.", file=output)
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:], Path.cwd(), sys.stdout, sys.stderr))
