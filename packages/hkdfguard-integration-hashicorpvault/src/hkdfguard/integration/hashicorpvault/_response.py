"""What Vault answers with, and how a VaultClient reads it: the response envelope, a login's token
and a wrapped response's - protected as they are read - and the errors a refusal lists."""

from __future__ import annotations

import http.client
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from email.message import Message
from types import TracebackType
from typing import Self

from hkdfguard.abstractions import ArrayUtility, CryptographicError, DataProtector, JsonReader, JsonToken, MalformedJsonError
from hkdfguard.integration.hashicorpvault._connection import is_valid_token
from hkdfguard.integration.hashicorpvault._errors import VaultJsonError, VaultResponseError
from hkdfguard.integration.hashicorpvault._json import JsonValue
from hkdfguard.integration.hashicorpvault._token_provider import StaticVaultToken


@dataclass(frozen=True, slots=True)
class VaultMfaMethod:
    """An MFA method."""

    type: str | None
    """The method's type: totp, duo, okta or pingid."""
    id: str | None
    """The method's id."""
    uses_passcode: bool
    """Whether it takes a passcode."""


@dataclass(frozen=True, slots=True)
class VaultMfaConstraint:
    """A constraint any one of whose methods satisfies it."""

    any: list[VaultMfaMethod] | None
    """The methods that satisfy it."""


@dataclass(frozen=True, slots=True)
class VaultMfaRequirement:
    """The multi-factor validation a login needs."""

    mfa_request_id: str | None
    """The id to validate against (sys/mfa/validate)."""
    mfa_constraints: dict[str, VaultMfaConstraint] | None
    """The constraints, by name: each satisfied by any one of its methods."""

    @staticmethod
    def from_json(json: JsonValue) -> VaultMfaRequirement:
        json.require_object("mfa_requirement")

        def method(m: JsonValue) -> VaultMfaMethod:
            m.require_object("any")
            return VaultMfaMethod(m.member("type").read_str(), m.member("id").read_str(), m.member("uses_passcode").read_bool() is True)

        def constraint(c: JsonValue) -> VaultMfaConstraint:
            c.require_object("mfa_constraints")
            return VaultMfaConstraint(c.member("any").read_list(lambda m: m.read_model(method)))

        return VaultMfaRequirement(json.member("mfa_request_id").read_str(),
                                   json.member("mfa_constraints").read_dict(lambda c: c.read_model(constraint)))


@dataclass(frozen=True, slots=True)
class VaultResponseAuth:
    """The token a login issued, and about it."""

    client_token: StaticVaultToken | None
    """The token, protected by the client's token protector as the response was read. Hand it to
    :meth:`VaultClient.set_token` or :attr:`VaultRequestOptions.token`."""
    accessor: str | None
    """The token's accessor: for looking it up or revoking it, not for making requests."""
    policies: list[str] | None
    """Every policy the token carries."""
    token_policies: list[str] | None
    """The policies attached to the token itself."""
    identity_policies: list[str] | None
    """The policies the token gets from its identity."""
    metadata: dict[str, str] | None
    """The auth method's metadata about the login."""
    orphan: bool
    """Whether the token has no parent."""
    entity_id: str | None
    """The identity entity the token belongs to."""
    lease_duration: int
    """How long the token lasts, in seconds."""
    renewable: bool
    """Whether the token can be renewed."""
    mfa_requirement: VaultMfaRequirement | None
    """Set when the login needs multi-factor validation before it issues a token."""


@dataclass(frozen=True, slots=True)
class VaultResponseWrapInfo:
    """A wrapped response: the token that unwraps it, and about it."""

    token: StaticVaultToken | None
    """The wrapping token, protected by the client's token protector as the response was read.
    Hand it to :meth:`VaultClient.unwrap`."""
    accessor: str | None
    """The wrapping token's accessor."""
    ttl: int
    """How long the wrapping token lasts, in seconds."""
    creation_time: datetime | None
    """When the response was wrapped."""
    creation_path: str | None
    """The path whose response was wrapped."""
    wrapped_accessor: str | None
    """When a token is wrapped, that token's accessor."""


@dataclass(frozen=True, slots=True)
class VaultResponse[T]:
    """What Vault answers most requests with. A response without a "data", "auth" or "wrap_info"
    member - sys/health, sys/leader and sys/seal-status, for instance - is read whole into :attr:`data`."""

    request_id: str | None = None
    """The id of the request this answers."""
    lease_id: str | None = None
    """The lease on a dynamic secret, for renewing or revoking it."""
    lease_duration: int = 0
    """How long the lease lasts, in seconds."""
    renewable: bool = False
    """Whether the lease can be renewed."""
    data: T | None = None
    """The response's contents, whose shape depends on the endpoint: a generated model, or a dict
    of JSON values."""
    warnings: list[str] | None = None
    """Things Vault wants noticed that didn't fail the request."""
    auth: VaultResponseAuth | None = None
    """The token a login issued, and about it; ``None`` for anything but a login."""
    wrap_info: VaultResponseWrapInfo | None = None
    """The wrapping token, when the response was wrapped (:attr:`VaultRequestOptions.response_wrapping_ttl`)."""


class VaultRawResponse:
    """Vault's response as it is, from :meth:`VaultClient.read_raw`: not parsed, not checked for an
    error status, its body to read and close. A context manager that closes. Unlike
    http.client's response, it gives no way back to the request, which carried the token."""

    __slots__ = ("_close", "_response")

    def __init__(self, response: http.client.HTTPResponse, close: Callable[[], None]) -> None:
        self._response = response
        self._close = close

    @property
    def status_code(self) -> int:
        """The status Vault answered with."""
        return self._response.status

    @property
    def headers(self) -> Message:
        """The response's headers."""
        return self._response.headers

    def read(self, amount: int | None = None) -> bytes:
        """Reads up to ``amount`` bytes of the body - all of it for ``None``."""
        return self._response.read(amount)

    def readinto(self, buffer: memoryview | bytearray) -> int:
        """Reads the body into ``buffer``; 0 at its end."""
        return self._response.readinto(buffer)

    def close(self) -> None:
        """Closes the body and its connection."""
        self._response.close()
        self._close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()


def read_response[T](body: memoryview, token_protector: DataProtector, reader: Callable[[JsonValue], T | None]) -> VaultResponse[T] | None:  # noqa: PLR0912 - one per member
    """``body`` as a response - the standard envelope when it has a "data" member (as
    vault-client-go decides), or "auth" or "wrap_info", so a token is never mistaken for data;
    otherwise the body whole as its data - its data read with ``reader``; ``None`` if it is empty.
    The tokens in auth.client_token and wrap_info.token are protected straight from the body's bytes.

    :raises VaultJsonError: the body isn't JSON, or not of the shape ``reader`` reads
    """
    if not len(body):
        return None
    if not _is_envelope(body):
        return VaultResponse(data=JsonValue.parse(body).read_model(reader))

    try:
        json = JsonReader(body)
        json.read()
        fields: dict[str, object] = {}
        while json.read() and json.token() is JsonToken.PROPERTY_NAME:
            name = json.get_string()
            json.read()
            if name == "auth":
                fields["auth"] = _read_auth(json, token_protector)
            elif name == "wrap_info":
                fields["wrap_info"] = _read_wrap_info(json, token_protector)
            else:
                value = JsonValue.read_from(json)
                match name:
                    case "request_id" | "lease_id":
                        fields[name] = value.read_str()
                    case "lease_duration":
                        fields[name] = value.read_int() or 0
                    case "renewable":
                        fields[name] = value.read_bool() is True
                    case "data":
                        fields[name] = value.read_model(reader)
                    case "warnings":
                        fields[name] = value.read_list(JsonValue.read_str)
                    case _:
                        pass  # Not part of the envelope.
        if json.read():
            raise VaultJsonError("Vault's response holds more than one JSON value.")
        return VaultResponse(**fields)  # type: ignore[arg-type]  # each read as its field's type
    except MalformedJsonError as error:
        raise VaultJsonError(f"Vault's response isn't JSON: {error}") from None


def response_error(status: int, body: memoryview, method: str, url: str) -> VaultResponseError:
    """The error a refusal is reported as: the errors ``body`` lists, as {"errors":[...]} or
    {"error":"..."}; failing those, the body itself."""
    reason = reason_phrase(status)
    errors = _read_errors(body)
    if errors:
        return VaultResponseError(f"{status}{reason}: {', '.join(errors)}", status, errors, None, method, url)
    raw = bytes(body) if len(body) else None
    message = f"{status}{reason}" if raw is None else f"{status}{reason}: {raw.decode('utf-8', 'replace')}"
    return VaultResponseError(message, status, [], raw, method, url)


def reason_phrase(status: int) -> str:
    """" Not Found" for 404: the space and the status's reason, as Go's http.StatusText; "" for one
    without a name."""
    try:
        return " " + http.HTTPStatus(status).phrase
    except ValueError:
        return ""


def _is_envelope(body: memoryview) -> bool:
    # Whether body is an object with a "data", "auth" or "wrap_info" member. Malformed, it isn't.
    try:
        reader = JsonReader(body)
        if not reader.read() or reader.token() is not JsonToken.START_OBJECT:
            return False
        while reader.read() and reader.token() is JsonToken.PROPERTY_NAME:
            if reader.value_text_equals("data") or reader.value_text_equals("auth") or reader.value_text_equals("wrap_info"):
                return True
            reader.read()
            reader.skip()
    except MalformedJsonError:
        pass
    return False


def _read_auth(json: JsonReader, token_protector: DataProtector) -> VaultResponseAuth | None:
    if json.token() is JsonToken.NULL:
        return None
    if json.token() is not JsonToken.START_OBJECT:
        raise VaultJsonError("Expected a JSON object for auth.")
    token, m = _read_members(json, "client_token", token_protector)

    def member(name: str) -> JsonValue:
        return m.get(name, JsonValue.NULL)

    return VaultResponseAuth(
        token,
        member("accessor").read_str(),
        member("policies").read_list(JsonValue.read_str),
        member("token_policies").read_list(JsonValue.read_str),
        member("identity_policies").read_list(JsonValue.read_str),
        member("metadata").read_dict(JsonValue.read_str),
        member("orphan").read_bool() is True,
        member("entity_id").read_str(),
        member("lease_duration").read_int() or 0,
        member("renewable").read_bool() is True,
        member("mfa_requirement").read_model(VaultMfaRequirement.from_json))


def _read_wrap_info(json: JsonReader, token_protector: DataProtector) -> VaultResponseWrapInfo | None:
    if json.token() is JsonToken.NULL:
        return None
    if json.token() is not JsonToken.START_OBJECT:
        raise VaultJsonError("Expected a JSON object for wrap_info.")
    token, m = _read_members(json, "token", token_protector)

    def member(name: str) -> JsonValue:
        return m.get(name, JsonValue.NULL)

    return VaultResponseWrapInfo(token, member("accessor").read_str(), member("ttl").read_int() or 0, member("creation_time").read_datetime(),
                                 member("creation_path").read_str(), member("wrapped_accessor").read_str())


def _read_members(json: JsonReader, token_name: str, token_protector: DataProtector) -> tuple[StaticVaultToken | None, dict[str, JsonValue]]:
    # The members of the object json has just started, the one named token_name protected rather than read.
    token: StaticVaultToken | None = None
    values: dict[str, JsonValue] = {}
    while json.read() and json.token() is JsonToken.PROPERTY_NAME:
        is_token = json.value_text_equals(token_name)
        name = json.get_string()
        json.read()
        if is_token:
            token = _protect_token(json, token_protector)
        else:
            values[name] = JsonValue.read_from(json)
    return token, values


def _protect_token(json: JsonReader, token_protector: DataProtector) -> StaticVaultToken | None:
    # The token string json has just read, protected: unescaped into a bytearray zeroed once it's
    # encrypted. DataProtector.encrypt takes a str, so the token is one for that call alone - the
    # only str it ever becomes. None for null or an empty string.
    if json.token() is JsonToken.NULL:
        return None
    if json.token() is not JsonToken.STRING:
        json.skip()
        raise VaultJsonError("Expected a token string.")

    # Unescaped, a string is never longer than it is escaped.
    unescaped = bytearray(json.value_length)
    try:
        length = json.copy_string(unescaped)
        if length == 0:
            return None
        with memoryview(unescaped) as whole, whole[:length] as token:
            if not is_valid_token(token):
                raise VaultJsonError("Vault returned a token that isn't one: printable ASCII, with no spaces.")
            try:
                return StaticVaultToken(token_protector.encrypt(token.tobytes().decode("ascii")))
            except (ValueError, CryptographicError) as error:
                raise VaultJsonError(f"Vault's token couldn't be protected: {type(error).__name__}.") from None
    finally:
        ArrayUtility.zero_memory(unescaped)


def _read_errors(body: memoryview) -> list[str] | None:
    if not len(body):
        return None
    try:
        reader = JsonReader(body)
        if not reader.read() or reader.token() is not JsonToken.START_OBJECT:
            return None
        errors: list[str] | None = None
        error: str | None = None
        while reader.read() and reader.token() is JsonToken.PROPERTY_NAME:
            if reader.value_text_equals("errors"):
                reader.read()
                errors = _read_strings(reader)
            elif reader.value_text_equals("error"):
                reader.read()
                if reader.token() is JsonToken.STRING:
                    error = reader.get_string()
                else:
                    reader.skip()
            else:
                reader.read()
                reader.skip()
        # Anything after the object makes it not JSON: the reader is given the whole body.
        if reader.read():
            return None
    except MalformedJsonError:
        return None
    if errors:
        return errors
    return [error] if error else None


def _read_strings(reader: JsonReader) -> list[str] | None:
    # A JSON array of strings; None if it is anything else.
    if reader.token() is not JsonToken.START_ARRAY:
        reader.skip()
        return None
    strings: list[str] = []
    all_strings = True
    while reader.read() and reader.token() is not JsonToken.END_ARRAY:
        if reader.token() is JsonToken.STRING:
            strings.append(reader.get_string())
        else:
            all_strings = False
            reader.skip()
    return strings if all_strings else None
