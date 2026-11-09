"""How a VaultClient reaches Vault, and what a request may set over the client's settings."""

from __future__ import annotations

import math
import os
import re
import ssl
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from email.message import Message
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from hkdfguard.abstractions import DataProtector
from hkdfguard.integration.hashicorpvault._connection import is_valid_token
from hkdfguard.integration.hashicorpvault._duration import parse_go_duration
from hkdfguard.integration.hashicorpvault._replication import ReplicationForwardingMode
from hkdfguard.integration.hashicorpvault._retry import VaultRateLimiter, VaultRetryOptions
from hkdfguard.integration.hashicorpvault._token_provider import StaticVaultToken, VaultTokenProvider

if TYPE_CHECKING:
    from hkdfguard.integration.hashicorpvault._tls import VaultTlsOptions

DEFAULT_ADDRESS: Final = "https://127.0.0.1:8200"
"""The address used when none is set: a local Vault server or agent."""

# RFC 9110's token: what a header name may be.
_HEADER_NAME: Final = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
# Headers http.client writes itself, from the request.
_RESTRICTED_HEADERS: Final = frozenset({"host", "content-length", "transfer-encoding", "connection"})


class VaultRequest:
    """An attempt's request as request callbacks see it, before it's sent: its method, its URL and
    the headers the client has given it - never the token, which is added after every callback."""

    __slots__ = ("_headers", "method", "url")

    def __init__(self, method: str, url: str, headers: list[tuple[str, str]]) -> None:
        self.method = method
        """The HTTP method."""
        self.url = url
        """The URL, its query included."""
        self._headers = headers

    @property
    def headers(self) -> list[tuple[str, str]]:
        """The headers, as name and value, in the order they are sent; a copy."""
        return list(self._headers)

    def header(self, name: str) -> str | None:
        """The values of the header ``name`` (case ignored) joined with ","; ``None`` if it isn't set."""
        values = [v for n, v in self._headers if n.lower() == name.lower()]
        return ",".join(values) if values else None

    def add_header(self, name: str, value: str) -> None:
        """Adds a header; names starting X-Vault-Token are refused.

        :raises ValueError: the header can't be sent, or is X-Vault-Token
        """
        _check_header(name, value, allow_vault=True)
        if name.lower() == "x-vault-token":
            raise ValueError("A request callback can't set the token.")
        self._headers.append((name, value))

    def __repr__(self) -> str:
        return f"VaultRequest({self.method} {self.url})"


type VaultRequestCallback = Callable[[VaultRequest], object]
"""Called with each attempt's request before a :class:`VaultClient` sends it, to add headers to it -
:meth:`VaultReplication.require_replication_states`, say."""

type VaultResponseCallback = Callable[[VaultRequest, int, Message], object]
"""Called once Vault has answered a :class:`VaultClient` request (after any retries and redirect),
before its body is read, with the request Vault answered (without its token), the status and the
response's headers - :meth:`VaultReplication.record_replication_state`, say."""


@dataclass(frozen=True, kw_only=True, slots=True)
class VaultClientOptions:
    """How a :class:`VaultClient` reaches Vault: vault-client-go's ClientConfiguration. Change one
    with ``dataclasses.replace``, or read one from the environment with :meth:`from_environment`. The
    values are checked by the client's constructor, not here."""

    address: str = DEFAULT_ADDRESS
    """Vault's address, scheme://host:port - VAULT_ADDR. https; http only on a loopback address (a
    local agent or dev server) unless :attr:`allow_unencrypted_http` is set, since every request
    carries a token. A path, if any, is kept as a prefix (Vault behind a reverse proxy). Unix domain
    sockets (unix://), which vault-client-go also reaches, aren't."""
    allow_unencrypted_http: bool = False
    """Allows an http address that isn't loopback, and redirects to one. Off: the token would cross
    the network in the clear."""
    ssl_context: ssl.SSLContext | None = None
    """The TLS settings to connect with, e.g. a context of your own; can't be combined with
    :attr:`tls`. ``None`` (the default) for one :attr:`tls` makes - or ``ssl.create_default_context()``."""
    request_timeout: timedelta = timedelta(seconds=60)
    """How long each request may take, its token, retries and redirect included - VAULT_CLIENT_TIMEOUT.
    Zero for none. Not applied to reading a :meth:`VaultClient.read_raw` body."""
    tls: VaultTlsOptions | None = None
    """Which certificates to trust and to present; ``None`` for the system's trust store and no
    client certificate."""
    retry: VaultRetryOptions = field(default_factory=VaultRetryOptions)
    """When and how often a failed request is retried."""
    rate_limiter: VaultRateLimiter | None = None
    """Limits how often requests are sent - VAULT_RATE_LIMIT. ``None`` for no limit. One limiter can
    be shared by several clients."""
    enforce_read_your_writes_consistency: bool = False
    """Sends the replication states seen in earlier responses with every request, so a performance
    standby that hasn't caught up forwards it to the active node: read-your-writes consistency
    across a cluster, at a cost on every request. Requires Vault Enterprise."""
    follow_redirects: bool = False
    """Follows one redirect (301, 302 or 307) per request, never from https to http, and only to the
    address's own host or one of :attr:`redirect_hosts`. Off: a redirect fails with
    :class:`VaultRedirectError`, since it would carry the token wherever it points."""
    redirect_hosts: Sequence[str] = ()
    """Hosts besides the address's own that :attr:`follow_redirects` may follow a redirect to - the
    other nodes of an HA cluster, whose standbys redirect to the active node. Names as the redirect's
    location gives them (``vault-2.example.com``, ``10.0.0.12``), compared ignoring case; any port.
    A redirect anywhere else fails with :class:`VaultRedirectError`: it would carry the token, any
    MFA credentials and the request body to that host."""
    token: VaultTokenProvider | None = None
    """The token every request is made with unless the request sets its own; ``None`` for none
    until :meth:`VaultClient.set_token`."""
    namespace: str | None = None
    """The namespace every request is made in unless the request sets its own - VAULT_NAMESPACE.
    Vault Enterprise."""

    @staticmethod
    def from_environment(token_protector: DataProtector | None = None, environ: Mapping[str, str] | None = None) -> VaultClientOptions:  # noqa: PLR0912, PLR0915 - one per variable
        """Options from the environment variables vault-client-go reads, over the defaults:

        - VAULT_ADDR, VAULT_AGENT_ADDR - :attr:`address` (VAULT_AGENT_ADDR wins if both are set)
        - VAULT_CLIENT_TIMEOUT - :attr:`request_timeout`, a Go duration such as 30s
        - VAULT_RATE_LIMIT - :attr:`rate_limiter`, rate[:burst] in requests per second
        - VAULT_DISABLE_REDIRECTS - true turns :attr:`follow_redirects` off; false leaves it as it is
        - VAULT_TOKEN - :attr:`token`, protected with ``token_protector``; ignored without one
        - VAULT_NAMESPACE - :attr:`namespace`
        - VAULT_SKIP_VERIFY, VAULT_CACERT, VAULT_CACERT_BYTES, VAULT_CAPATH, VAULT_CLIENT_CERT,
          VAULT_CLIENT_KEY, VAULT_TLS_SERVER_NAME - :attr:`tls`
        - VAULT_RETRY_WAIT_MIN, VAULT_RETRY_WAIT_MAX, VAULT_MAX_RETRIES - :attr:`retry`

        :param token_protector: the protector the client will be given, to protect VAULT_TOKEN with;
            ``None`` to ignore VAULT_TOKEN
        :param environ: the variables; ``None`` for ``os.environ``
        :raises ValueError: a variable is set to a value that isn't one
        """
        variables = os.environ if environ is None else environ

        def value(name: str) -> str | None:
            # An unset variable and an empty one are the same, as in vault-client-go.
            return variables.get(name) or None

        settings: dict[str, Any] = {}
        # Later variables win, as in vault-client-go.
        for name in ("VAULT_ADDR", "VAULT_AGENT_ADDR"):
            address = value(name)
            if address is not None:
                settings["address"] = _parse(name, address, _parse_address)
        timeout = value("VAULT_CLIENT_TIMEOUT")
        if timeout is not None:
            settings["request_timeout"] = _parse("VAULT_CLIENT_TIMEOUT", timeout, parse_go_duration)
        rate_limit = value("VAULT_RATE_LIMIT")
        if rate_limit is not None:
            settings["rate_limiter"] = _parse("VAULT_RATE_LIMIT", rate_limit, _parse_rate_limit)
        disable_redirects = value("VAULT_DISABLE_REDIRECTS")
        if disable_redirects is not None and _parse("VAULT_DISABLE_REDIRECTS", disable_redirects, parse_go_bool):
            settings["follow_redirects"] = False
        namespace = value("VAULT_NAMESPACE")
        if namespace is not None:
            if not is_valid_namespace(namespace):
                raise ValueError("VAULT_NAMESPACE contains non-printable characters.")
            settings["namespace"] = namespace
        token = None if token_protector is None else value("VAULT_TOKEN")
        if token is not None:
            if not is_valid_token(token.encode("utf-8", "surrogatepass")):
                raise ValueError("VAULT_TOKEN isn't a token: printable ASCII, with no spaces.")
            settings["token"] = StaticVaultToken.protect(token_protector, token)  # type: ignore[arg-type]  # checked above

        tls: dict[str, Any] = {}
        skip_verify = value("VAULT_SKIP_VERIFY")
        if skip_verify is not None:
            tls["insecure_skip_verify"] = _parse("VAULT_SKIP_VERIFY", skip_verify, parse_go_bool)
        for variable, option in (("VAULT_CACERT", "server_certificate_file"), ("VAULT_CAPATH", "server_certificate_directory"),
                                 ("VAULT_CLIENT_CERT", "client_certificate_file"), ("VAULT_CLIENT_KEY", "client_certificate_key_file")):
            path = value(variable)
            if path is not None:
                tls[option] = Path(path)
        ca_bytes = value("VAULT_CACERT_BYTES")
        if ca_bytes is not None:
            tls["server_certificate_pem"] = ca_bytes.encode("utf-8")
        server_name = value("VAULT_TLS_SERVER_NAME")
        if server_name is not None:
            tls["server_name"] = server_name
        if tls:
            from hkdfguard.integration.hashicorpvault._tls import VaultTlsOptions  # noqa: PLC0415 - only when the environment configures TLS

            settings["tls"] = VaultTlsOptions(**tls)

        retry: dict[str, Any] = {}
        for variable, option in (("VAULT_RETRY_WAIT_MIN", "retry_wait_min"), ("VAULT_RETRY_WAIT_MAX", "retry_wait_max")):
            wait = value(variable)
            if wait is not None:
                retry[option] = _parse(variable, wait, parse_go_duration)
        max_retries = value("VAULT_MAX_RETRIES")
        if max_retries is not None:
            retry["retry_max"] = _parse("VAULT_MAX_RETRIES", max_retries, int)
        if retry:
            settings["retry"] = VaultRetryOptions(**retry)

        return VaultClientOptions(**settings)


@dataclass(frozen=True, kw_only=True, slots=True)
class VaultRequestOptions:
    """Settings for one request, over the client's: its own token, namespace, headers, callbacks,
    the mount a generated method calls, and query parameters. Every setting left unset is the
    client's."""

    token: VaultTokenProvider | None = None
    """The token to make this request with, instead of the client's; ``None`` for the client's."""
    namespace: str | None = None
    """The namespace to make this request in, instead of the client's; ``None`` or empty keeps the client's."""
    mfa_credentials: Sequence[str] = ()
    """Multi-factor credentials (X-Vault-MFA), added to the client's; see
    https://developer.hashicorp.com/vault/docs/auth/login-mfa."""
    response_wrapping_ttl: timedelta | None = None
    """Asks Vault to wrap the response for this long (X-Vault-Wrap-TTL) instead of returning it: the
    response holds only :attr:`VaultResponse.wrap_info`, for :meth:`VaultClient.unwrap`. ``None`` or
    zero keeps the client's setting."""
    custom_headers: Mapping[str, Sequence[str]] = field(default_factory=dict)
    """Headers to add, over the client's; names starting X-Vault- are the client's own and refused."""
    request_callbacks: Sequence[VaultRequestCallback] = ()
    """Called with each attempt's request before it's sent, after the client's own callbacks. The
    token isn't on it yet."""
    response_callbacks: Sequence[VaultResponseCallback] = ()
    """Called once Vault has answered, after the client's own callbacks."""
    mount_path: str | None = None
    """Where the auth method or secrets engine is mounted, instead of its default - for the
    generated methods; leading and trailing '/' are ignored."""
    query_parameters: Sequence[tuple[str, str]] = ()
    """Query parameters to add to the request; meant for the generic read, read_raw, list and delete."""
    replication_forwarding_mode: ReplicationForwardingMode = ReplicationForwardingMode.NONE
    """Whether a performance standby forwards this request to the active node; NONE keeps the client's."""


def is_valid_namespace(value: str) -> bool:
    """Whether ``value`` can go in a header: printable ASCII, spaces allowed."""
    return isinstance(value, str) and all(" " <= c <= "~" for c in value)


def check_mfa_credentials(credentials: Sequence[str]) -> None:
    """:raises ValueError: a credential can't go in a header"""
    if isinstance(credentials, str):
        raise TypeError("MFA credentials are a sequence of str, not one str.")
    for credential in credentials:
        if not isinstance(credential, str) or not credential or not is_valid_namespace(credential):
            raise ValueError("An MFA credential must be non-empty printable ASCII.")


def copy_headers(headers: Mapping[str, Sequence[str]] | None) -> dict[str, tuple[str, ...]]:
    """``headers`` checked and copied, their names compared ignoring case (the last of two spellings
    winning).

    :raises ValueError: a header has no name, is named X-Vault-*, or can't be sent
    """
    copied: dict[str, tuple[str, ...]] = {}
    if not headers:
        return copied
    by_lower: dict[str, str] = {}
    for name, values in headers.items():
        if isinstance(values, str):
            raise TypeError(f"The custom header '{name}' must map to a sequence of values, not one str.")
        values_copy = tuple(values)
        for one in values_copy:
            _check_header(name, one, allow_vault=False)
        if not values_copy:
            _check_header(name, "", allow_vault=False)
        previous = by_lower.pop(name.lower(), None)
        if previous is not None:
            del copied[previous]
        by_lower[name.lower()] = name
        copied[name] = values_copy
    return copied


def merge_headers(base: Mapping[str, tuple[str, ...]], over: Mapping[str, tuple[str, ...]]) -> dict[str, tuple[str, ...]]:
    """``base`` with ``over``'s headers replacing those of the same name, case ignored."""
    merged = {name: values for name, values in base.items() if name.lower() not in {n.lower() for n in over}}
    merged.update(over)
    return merged


def _check_header(name: object, value: object, *, allow_vault: bool) -> None:
    if not isinstance(name, str) or not name.strip():
        raise ValueError("A custom header must have a name.")
    if not allow_vault and name.lower().startswith("x-vault-"):
        raise ValueError(f"The custom header '{name}' isn't allowed: the 'X-Vault-' prefix is for the client's own use.")
    if not _HEADER_NAME.fullmatch(name) or name.lower() in _RESTRICTED_HEADERS:
        raise ValueError(f"The header '{name}' can't be sent: it isn't a header name, or is one the client sets itself.")
    if not isinstance(value, str) or any(c in value for c in "\r\n\0") or not all(" " <= c <= "~" or c == "\t" for c in value):
        raise ValueError(f"The header '{name}' has a value that can't be sent.")


def _parse[T](name: str, value: str, parse: Callable[[str], T]) -> T:
    try:
        return parse(value)
    except ValueError as error:
        raise ValueError(f"Configuration error: could not convert the {name} environment variable's value '{value}': {error}") from error


def _parse_address(address: str) -> str:
    if "://" not in address:
        raise ValueError("Not an absolute URI.")
    return address


def parse_go_bool(value: str) -> bool:
    """strconv.ParseBool's spellings."""
    if value in {"1", "t", "T", "TRUE", "true", "True"}:
        return True
    if value in {"0", "f", "F", "FALSE", "false", "False"}:
        return False
    raise ValueError("Expected a boolean: 1, t, T, TRUE, true, True, 0, f, F, FALSE, false or False.")


def _parse_rate_limit(value: str) -> VaultRateLimiter:
    # "rate:burst", or "rate" with a burst of the rate rounded down (at least 1).
    rate_text, colon, burst_text = value.partition(":")
    if colon:
        return VaultRateLimiter(float(rate_text), int(burst_text))
    rate = float(value)
    return VaultRateLimiter(rate, max(1, int(min(rate, 2**31 - 1))) if math.isfinite(rate) else 1)
