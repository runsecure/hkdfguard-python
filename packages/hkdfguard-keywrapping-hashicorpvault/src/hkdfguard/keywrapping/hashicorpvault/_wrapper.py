"""The key wrapper over one key in a HashiCorp Vault transit secrets engine."""

from __future__ import annotations

import base64
import http
import http.client
import ipaddress
import itertools
import os
import re
import secrets
import socket
import ssl
import time
from collections.abc import Buffer
from datetime import timedelta
from types import TracebackType
from typing import ClassVar, Final, Self
from urllib.parse import urlsplit

from hkdfguard.abstractions import ArrayUtility, CryptographicError, KeyWrapper, ObjectClosedError, WrappedKeyLimits, WritableBuffer
from hkdfguard.keywrapping.hashicorpvault._errors import VaultRequestError
from hkdfguard.keywrapping.hashicorpvault._json_reader import JsonReader, JsonToken, MalformedJsonError
from hkdfguard.keywrapping.hashicorpvault._options import HashiCorpVaultTransitKeyWrapperOptions
from hkdfguard.keywrapping.hashicorpvault._token import MAX_TOKEN_LENGTH, VaultTokenSource, copy_token_within, is_valid_token
from hkdfguard.securefile import KeyFileTrust, TrustedKeyFile

_TOKEN_HEADER: Final = "X-Vault-Token"  # noqa: S105 - a header name
_IPV4_LITERAL: Final = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
_PATH_SEGMENT: Final = re.compile(r"[A-Za-z0-9._-]+")
_CIPHERTEXT: Final = re.compile(rb"vault:v[0-9]{1,10}:[A-Za-z0-9+/=]+")

_BASE64_ALPHABET: Final = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_PAD: Final = ord("=")
# Each byte's base64 value; 0xFF for a byte that isn't in the alphabet.
_BASE64_VALUES: Final = bytes(_BASE64_ALPHABET.index(b) if b in _BASE64_ALPHABET else 0xFF for b in range(256))

# Asks for a 256-bit key: GENERATED_KEY_LENGTH bytes.
_DATA_KEY_BODY: Final = b'{"bits":256}'
_PLAINTEXT_PREFIX: Final = b'{"plaintext":"'
_CIPHERTEXT_PREFIX: Final = b'{"ciphertext":"'


class HashiCorpVaultTransitKeyWrapper(KeyWrapper):
    """Protects (encrypt) and reveals (decrypt) a DEK under one key in a HashiCorp Vault transit
    secrets engine, and generates fresh DEKs with datakey/wrapped - so on that path the plaintext DEK
    never leaves Vault. The KEK never enters this process; every call is a request to Vault's HTTP
    API, authorized by the token's policy and recorded in Vault's audit log. A wrapped DEK is Vault's
    ciphertext as it returns it, ``vault:v{version}:{base64}``, in ASCII - byte for byte what the .NET
    ``HashiCorpVaultTransitKeyWrapper`` and the other ports produce, so a key file made by any of them
    is read by the others, given the same key and context.

    The key is pinned by its path: every request names it, and a ciphertext carries only its key
    version, never its key, so a key file wrapped under another transit key fails to authenticate
    rather than being revealed. Vault's key rotation (transit/keys/{name}/rotate) keeps the name and
    is transparent here: new DEKs are wrapped under the latest version, and older ones still reveal
    while their version is at or above the key's min_decryption_version. The key must be an AEAD key
    that isn't derived - aes256-gcm96 (Vault's default), aes128-gcm96 or chacha20-poly1305.

    The context, if any, is bound into every wrapped DEK as Vault's associated_data (AAD): decrypt
    fails unless it is presented again exactly. datakey/wrapped ignores associated_data, so with a
    context :meth:`generate_and_wrap` generates the DEK here and wraps it with encrypt instead - the
    plaintext DEK then does cross the network to Vault, as on :meth:`wrap`. A response whose warnings
    say Vault ignored a parameter (a Vault too old for associated_data) is refused, so a context is
    never silently dropped. Vault's audit log HMACs request fields by default, but the context isn't
    a secret and must not hold one.

    Key files are read only from where an untrusted account can't have written or replaced them (see
    :meth:`read_key_file` and :class:`KeyFileTrust`). Pinning the key stops a key file wrapped under
    another key; this stops one wrapped under this key by anyone whose policy allows encrypt, which
    would otherwise choose the DEK new data is encrypted under.

    Plaintext key bytes this class owns are zeroed once used: the request body encrypt is sent (the
    DEK, base64-encoded, written straight into a bytearray and sent from it), the response body
    decrypt answers with (read off the socket into a bytearray of the class's own, at most
    :attr:`MAX_RESPONSE_LENGTH` bytes), the base64 value read out of it, and the DEK decoded from that.
    The caller's ``result`` is zeroed whenever an unwrap fails. The token is copied by its
    :class:`VaultTokenSource` into a bytearray zeroed once the request has been sent; it never becomes
    a ``str`` here. What can't be zeroed is below that. ``http.client`` copies each header line - the
    token's among them - into ``bytes`` of its own, and joins them into the request head, which
    nothing references once it is sent but which stays in memory until it is reused. It reads the
    response through a buffered reader whose buffer holds the body bytes that arrived with the
    headers. And the socket's and, over TLS, OpenSSL's buffers. With a context,
    :meth:`generate_and_wrap` takes its DEK from ``os.urandom``, whose immutable ``bytes`` is copied
    into a bytearray and dropped. Process hardening (``hkdfguard-keywrapping-v1``'s
    ``NativeProcessHardening``) is what keeps such copies out of reach of a debugger or a crash dump.

    Requests go to ``/v1/`` under Vault's address, which must be https except on loopback, through
    ``http.client``, on a connection of their own: no proxy, and no redirect is ever followed, which
    would carry the token elsewhere - Vault's standbys forward requests to the active node themselves,
    so a redirect is answered as an error. A request that fails transiently - no answer, a connection
    lost mid-response, a timed-out attempt, 429 or a 5xx other than 501 - is retried
    :attr:`~HashiCorpVaultTransitKeyWrapperOptions.retry_count` times (3-10), waiting
    :attr:`~HashiCorpVaultTransitKeyWrapperOptions.retry_delay` and doubling, up to 10 seconds, plus a
    random 0-100 ms each time. Every call blocks the calling thread until Vault answers or the
    retries are spent; the :attr:`~HashiCorpVaultTransitKeyWrapperOptions.timeout` bounds each attempt
    (the connection, the response's headers and its whole body).

    Argument errors raise ``ValueError`` or ``TypeError``. A Vault refusal, or failing to reach it once
    the retries are spent, raises :class:`CryptographicError` naming the operation, the key and Vault's
    status and errors (``Vault answered 400 Bad Request: cipher: message authentication failed``), with
    the :class:`VaultRequestError`, ``OSError`` or ``http.client.HTTPException`` as its ``__cause__``.
    A token source's own failure propagates as it is; one that supplies no token, or one that isn't a
    token, raises ``RuntimeError`` without a request.
    """

    GENERATED_KEY_LENGTH: Final = 32
    """The length of the DEK :meth:`generate_and_wrap` generates: 32 bytes (AES-256)."""

    MAX_PLAINTEXT_LENGTH: Final = 256
    """The largest plaintext :meth:`wrap` accepts, in bytes: its ciphertext still fits
    :attr:`WrappedKeyLimits.MAX_BYTES`."""

    MAX_CONTEXT_LENGTH: Final = 1024
    """The longest context, in UTF-8 bytes."""

    MAX_KEY_NAME_LENGTH: Final = 128
    """The longest key name."""

    MAX_TOKEN_LENGTH: Final = MAX_TOKEN_LENGTH
    """The longest token a :class:`VaultTokenSource` may supply, in bytes."""

    MAX_RESPONSE_LENGTH: ClassVar[int] = 16 * 1024
    """The largest response read from Vault, in bytes; a transit answer is well under 1 KB."""

    def __init__(self, address: str, key_name: str, token_source: VaultTokenSource, context: str | None = None, *,
                 key_file_trust: KeyFileTrust | None = None, options: HashiCorpVaultTransitKeyWrapperOptions | None = None) -> None:
        """A wrapper over one transit key. No call is made until it is used.

        :param address: Vault's address, e.g. ``https://vault.example.com:8200`` - the same value as
            VAULT_ADDR. Must be https, except on a loopback address (a local Vault Agent or dev
            server). A path, if any, is kept as a prefix (Vault behind a reverse proxy).
        :param key_name: the transit key that wraps every DEK, e.g. ``"myapp-kek"``
        :param token_source: supplies the token every request is made with
        :param context: bound into every wrapped DEK as associated_data and required again to reveal
            it; ``None`` or empty binds none. Not secret.
        :param key_file_trust: who besides the operating system's administrators may have written a
            key file :meth:`read_key_file` reads; ``None`` trusts administrators only
            (:attr:`KeyFileTrust.ADMINISTRATORS_ONLY`)
        :param options: the transit engine called and how to reach it; ``None`` for the engine at
            ``transit``
        :raises TypeError: ``address``, ``key_name`` or ``token_source`` is ``None``, or an argument or
            option is of the wrong type
        :raises ValueError: ``address`` isn't https (or http on loopback), or holds credentials, a
            query or a fragment; ``key_name`` isn't a key name; the context is over
            :attr:`MAX_CONTEXT_LENGTH` bytes or not well-formed text; the mount path or namespace isn't
            one; or the timeout isn't positive, the retry count isn't 3-10 or the retry delay isn't
            zero to 10 seconds
        """
        if address is None:
            raise TypeError("address must not be None.")
        if key_name is None:
            raise TypeError("key_name must not be None.")
        if token_source is None:
            raise TypeError("token_source must not be None.")
        if not isinstance(token_source, VaultTokenSource):
            raise TypeError("token_source must be a VaultTokenSource.")
        if key_file_trust is not None and not isinstance(key_file_trust, KeyFileTrust):
            raise TypeError("key_file_trust must be a KeyFileTrust.")
        if options is None:
            options = HashiCorpVaultTransitKeyWrapperOptions()
        self._https, self._host, self._port, api_base = _api_base(address)
        if not isinstance(key_name, str):
            raise TypeError("key_name must be a str.")
        if len(key_name) > self.MAX_KEY_NAME_LENGTH or not _is_valid_segment(key_name):
            raise ValueError(f"The key name '{key_name}' isn't one: 1-{self.MAX_KEY_NAME_LENGTH} ASCII letters, digits, '-', '_' and '.', "
                             'and not "." or "..".')
        _check(options)
        context_bytes = self._encode_context(context)

        self._token_source = token_source
        self._key_name = key_name
        self._encrypt_path = f"{api_base}{options.mount_path}/encrypt/{key_name}"
        self._decrypt_path = f"{api_base}{options.mount_path}/decrypt/{key_name}"
        self._data_key_path = f"{api_base}{options.mount_path}/datakey/wrapped/{key_name}"
        # Vault treats an empty associated_data as none, so an empty context is none too.
        self._has_context = len(context_bytes) > 0
        # Closes every encrypt and decrypt body: the closing quote of its value, the context if any,
        # and the closing brace.
        self._body_suffix = (b'","associated_data":"' + base64.b64encode(context_bytes) + b'"}') if self._has_context else b'"}'
        self._namespace = options.namespace
        self._timeout = options.timeout
        self._timeout_seconds = options.timeout.total_seconds()
        self._retry_count = options.retry_count
        self._retry_delay = options.retry_delay
        self._ssl_context = (options.ssl_context or ssl.create_default_context()) if self._https else None
        self._key_file_trust = key_file_trust if key_file_trust is not None else KeyFileTrust.ADMINISTRATORS_ONLY
        self._closed = False

    @classmethod
    def _encode_context(cls, context: str | None) -> bytes:
        # Refuses a lone surrogate, which .NET would encode differently (as U+FFFD).
        if context is None:
            return b""
        if not isinstance(context, str):
            raise TypeError("context must be a str.")
        try:
            encoded = context.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("The context isn't well-formed text: it holds a lone surrogate.") from error
        if len(encoded) > cls.MAX_CONTEXT_LENGTH:
            raise ValueError(f"The context is {len(encoded)} bytes in UTF-8; at most {cls.MAX_CONTEXT_LENGTH} are allowed.")
        return encoded

    def close(self) -> None:
        """Stops the wrapper calling Vault: a call afterwards fails with
        :class:`~hkdfguard.abstractions.ObjectClosedError`. Close it only once nothing uses it,
        including a key ring's background refresh. Every request has a connection of its own, closed
        as it completes, so there is nothing else to release; the token source isn't closed."""
        self._closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()

    def wrap(self, plaintext: Buffer, result: WritableBuffer) -> int:
        """Protects a DEK with Vault's encrypt, writing the ciphertext to ``result``.

        :param plaintext: the key, 1 to :attr:`MAX_PLAINTEXT_LENGTH` bytes; not modified - it is the
            caller's to zero
        :returns: the number of bytes written to ``result``
        :raises ValueError: ``plaintext`` is empty or over :attr:`MAX_PLAINTEXT_LENGTH` bytes, or
            ``result`` is too small for the wrapped DEK
        :raises CryptographicError: Vault refused the request, or could not be reached (the
            :class:`VaultRequestError`, ``OSError`` or ``http.client.HTTPException`` is the
            ``__cause__``), or returned no ciphertext
        :raises RuntimeError: the token source supplied no token, or one that isn't a token
        """
        source = memoryview(plaintext).cast("B")
        if len(source) == 0 or len(source) > self.MAX_PLAINTEXT_LENGTH:
            raise ValueError(f"Vault transit wraps 1-{self.MAX_PLAINTEXT_LENGTH} bytes here; got {len(source)}.")

        # The base64-encoded DEK is written straight into this bytearray, sent from it, and zeroed.
        body = bytearray(len(_PLAINTEXT_PREFIX) + (len(source) + 2) // 3 * 4 + len(self._body_suffix))
        try:
            length = self._write_body(body, _PLAINTEXT_PREFIX, source, encode=True)
            response, response_length = self._post("wrap", self._encrypt_path, memoryview(body)[:length])
            return self._read_answer(response, response_length, "wrap", result, plaintext=False)
        finally:
            ArrayUtility.zero_memory(body)

    def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
        """Reveals a DEK with Vault's decrypt, the key pinned, into ``result``. On any failure
        ``result`` is zeroed.

        :returns: the number of bytes written to ``result``
        :raises ValueError: ``result`` is too small for the revealed key
        :raises CryptographicError: ``wrapped`` is empty, over :attr:`WrappedKeyLimits.MAX_BYTES` or
            isn't a Vault ciphertext (refused without calling Vault); or Vault refused it - tampered
            with, wrapped under another key or under a different context, or its key version is below
            min_decryption_version - or could not be reached (the cause is the ``__cause__``)
        :raises RuntimeError: the token source supplied no token, or one that isn't a token
        """
        try:
            source = memoryview(wrapped).cast("B")
            # Refused locally: no ciphertext Vault produces is outside these bounds, and one that is
            # Vault's ciphertext needs no escaping to go in the request body.
            if len(source) == 0 or len(source) > WrappedKeyLimits.MAX_BYTES:
                raise CryptographicError(f"A wrapped DEK is 1-{WrappedKeyLimits.MAX_BYTES} bytes; got {len(source)}.")
            if not is_vault_ciphertext(source):
                raise CryptographicError("A wrapped DEK is a Vault transit ciphertext, vault:v{version}:{base64}; this isn't one.")

            body = bytearray(len(_CIPHERTEXT_PREFIX) + len(source) + len(self._body_suffix))
            length = self._write_body(body, _CIPHERTEXT_PREFIX, source, encode=False)
            response, response_length = self._post("unwrap", self._decrypt_path, memoryview(body)[:length])
            return self._read_answer(response, response_length, "unwrap", result, plaintext=True)
        except BaseException:
            # Whatever a failed call left in the DEK buffer is erased.
            ArrayUtility.zero_memory(result)
            raise

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        """Generates a fresh :attr:`GENERATED_KEY_LENGTH`-byte DEK wrapped under the key. Without a
        context Vault generates it and returns it wrapped only (datakey/wrapped), so the plaintext DEK
        never leaves Vault on this call. With a context - which datakey/wrapped would ignore - it is
        generated here and wrapped with encrypt, then zeroed.

        :param result: receives the wrapped key
        :returns: the number of bytes written to ``result``
        :raises ValueError: ``result`` is too small for the wrapped DEK
        :raises CryptographicError: as :meth:`wrap`
        :raises RuntimeError: as :meth:`wrap`
        """
        if self._has_context:
            # os.urandom returns an immutable bytes, dropped at once: its copy here is zeroed.
            dek = bytearray(os.urandom(self.GENERATED_KEY_LENGTH))
            try:
                return self.wrap(dek, result)
            finally:
                ArrayUtility.zero_memory(dek)

        response, response_length = self._post("generate-and-wrap", self._data_key_path, memoryview(_DATA_KEY_BODY))
        return self._read_answer(response, response_length, "generate-and-wrap", result, plaintext=False)

    def read_key_file(self, path: str | os.PathLike[str]) -> bytearray:
        """Reads a key file this wrapper wrote, still wrapped, refusing one that an account other than
        the operating system's administrators and the :class:`KeyFileTrust` given at construction could
        have written or replaced - the Python equivalent of the native library's checks
        (:class:`TrustedKeyFile`). On Windows the file must be on a local fixed drive, reached through
        real folders (no symbolic link, junction or substituted drive), and it and every folder above it
        must be owned by, and modifiable only by, trusted principals. On Linux and macOS it and every
        directory above it must be owned by root or a trusted user and writable by nobody else (by its
        group only if that group is trusted), and only symbolic links a trusted user owns are followed.
        It is also refused if it is empty, over :attr:`WrappedKeyLimits.MAX_BYTES`, or looks like an
        unwrapped key. No Vault call is made.

        :returns: the file's contents, still wrapped; the caller owns them
        :raises FileNotFoundError: the file, or a folder in its path, doesn't exist
        :raises PermissionError: this account may not read the file, or it isn't somewhere only trusted
            principals can modify
        :raises InvalidKeyFileError: the file is empty, too long, or holds what looks like an unwrapped
            key (an ``OSError``)
        :raises OSError: the file can't be read, or another process has it open for writing
        :raises ValueError: the path is empty, or the :class:`KeyFileTrust` names a principal that can't be trusted
        :raises TypeError: the path is ``None``
        """
        return TrustedKeyFile.read(path, self._key_file_trust)

    def _write_body(self, body: bytearray, prefix: bytes, value: memoryview, *, encode: bool) -> int:
        # prefix, then value (base64-encoded if encode), then the suffix: a whole encrypt or decrypt
        # body. Returns its length.
        body[:len(prefix)] = prefix
        length = len(prefix)
        if encode:
            length += _encode_base64(value, body, length)
        else:
            body[length:length + len(value)] = value
            length += len(value)
        body[length:length + len(self._body_suffix)] = self._body_suffix
        return length + len(self._body_suffix)

    def _post(self, operation: str, path: str, body: memoryview) -> tuple[bytearray, int]:
        # Posts body to path and returns Vault's successful response and its length, in a bytearray
        # the caller zeroes. The token is asked for once; a request that fails transiently is retried.
        # Vault's refusals, and failures to reach it once the retries are spent, become
        # CryptographicError.
        if self._closed:
            raise ObjectClosedError("This HashiCorp Vault transit key wrapper has been closed.")
        token = bytearray(MAX_TOKEN_LENGTH)
        try:
            # A source's failure is its own to retry, so isn't retried here, and propagates as it is.
            token_length = copy_token_within(self._token_source, token, self._timeout)
            if not 0 < token_length <= MAX_TOKEN_LENGTH or not is_valid_token(memoryview(token)[:token_length]):
                raise RuntimeError("The Vault token source supplied no token, or one that isn't a token: printable ASCII, with no spaces.")
            token_view = memoryview(token)[:token_length]

            failure: Exception
            for retry in itertools.count():
                try:
                    return self._send(path, body, token_view)
                except VaultRequestError as error:
                    failure = error
                    if not error.is_transient:
                        break
                except (OSError, http.client.HTTPException) as error:
                    failure = error

                if retry >= self._retry_count or self._closed:
                    break
                time.sleep(_retry_delay(self._retry_delay, retry, secrets.randbelow(101)).total_seconds())

            reason = f"no answer within {self._timeout}" if isinstance(failure, TimeoutError) else str(failure) or type(failure).__name__
            raise CryptographicError(f"Vault transit {operation} failed for key '{self._key_name}': {reason}") from failure
        finally:
            ArrayUtility.zero_memory(token)

    def _send(self, path: str, body: memoryview, token: memoryview) -> tuple[bytearray, int]:
        # One attempt: one request, and Vault's whole response, within the attempt's timeout. A
        # successful response is returned in a bytearray; any other is raised as a VaultRequestError
        # carrying Vault's status and errors.
        deadline = time.monotonic() + self._timeout_seconds
        connection = (http.client.HTTPSConnection(self._host, self._port, timeout=self._timeout_seconds, context=self._ssl_context)
                      if self._https else http.client.HTTPConnection(self._host, self._port, timeout=self._timeout_seconds))
        try:
            connection.putrequest("POST", path)
            connection.putheader("X-Vault-Request", "true")
            if self._namespace is not None:
                connection.putheader("X-Vault-Namespace", self._namespace)
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", str(len(body)))
            # Checked by _post - printable ASCII, nothing to escape - so handed over as it is. http.client
            # copies it into the header line (see the class comment); the bytearray is zeroed by _post.
            connection.putheader(_TOKEN_HEADER, token)
            # Sent from body itself, not a copy: http.client hands a buffer straight to the socket.
            connection.endheaders(body)
            sock = connection.sock
            if sock is None:
                raise ConnectionError("The connection to Vault was closed before its answer.")
            _set_remaining(sock, deadline, self._timeout)
            response = connection.getresponse()
            try:
                return self._read_response(response, sock, deadline)
            finally:
                response.close()
        finally:
            connection.close()

    def _read_response(self, response: http.client.HTTPResponse, sock: socket.socket, deadline: float) -> tuple[bytearray, int]:
        # One byte over the limit, so a body that doesn't fit is noticed rather than truncated.
        buffer = bytearray(self.MAX_RESPONSE_LENGTH + 1)
        handed_over = False
        try:
            length = _read_body(response, sock, deadline, buffer, self._timeout)
            if length > self.MAX_RESPONSE_LENGTH:
                raise CryptographicError(f"Vault's answer for key '{self._key_name}' is over {self.MAX_RESPONSE_LENGTH} bytes; "
                                         "a transit answer is far smaller.")

            status = response.status
            if 200 <= status < 300:
                handed_over = True
                return buffer, length

            errors = _read_errors(memoryview(buffer)[:length])
            detail = ": " + "; ".join(errors) if errors else ""
            raise VaultRequestError(f"Vault answered {status}{_phrase(status)}{detail}", status)
        finally:
            if not handed_over:
                ArrayUtility.zero_memory(buffer)

    def _read_answer(self, response: bytearray, response_length: int, operation: str, result: WritableBuffer, *, plaintext: bool) -> int:
        # Takes data.plaintext (decoded) or data.ciphertext out of a successful answer into result,
        # then zeroes the answer and the copy of the value read out of it.
        # Never longer than the answer it is read out of.
        value = bytearray(response_length)
        try:
            length = self._read_data(memoryview(response)[:response_length], "plaintext" if plaintext else "ciphertext", operation, value)
            if plaintext:
                return self._decode_plaintext(memoryview(value)[:length], result)
            return self._copy_ciphertext(memoryview(value)[:length], result, operation)
        finally:
            ArrayUtility.zero_memory(value)
            ArrayUtility.zero_memory(response)

    def _read_data(self, json: memoryview, name: str, operation: str, value: bytearray) -> int:  # noqa: PLR0912 - one pass, as in .NET
        # Copies the string at data.{name} in a successful response into value, unescaped, and returns
        # its length. Refused if it is missing or repeated, isn't a string, or the response's warnings
        # say Vault ignored a parameter - as a Vault too old for associated_data does, leaving a DEK
        # bound to no context.
        length = 0
        found = False
        ignored_parameter = False
        reader = JsonReader(json)
        try:
            if not reader.read() or reader.token() is not JsonToken.START_OBJECT:
                raise self._malformed(operation)

            while reader.read() and reader.token() is JsonToken.PROPERTY_NAME:
                if reader.value_text_equals("data"):
                    reader.read()
                    if reader.token() is not JsonToken.START_OBJECT:
                        reader.skip()
                        continue

                    while reader.read() and reader.token() is JsonToken.PROPERTY_NAME:
                        is_value = reader.value_text_equals(name)
                        reader.read()
                        if not is_value:
                            reader.skip()
                            continue

                        if found or reader.token() is not JsonToken.STRING:
                            raise self._malformed(operation)
                        # Vault doesn't escape base64 or its ciphertext, but a proxy re-encoding the
                        # answer might.
                        length = reader.copy_string(value)
                        found = True
                elif reader.value_text_equals("warnings"):
                    reader.read()
                    if reader.token() is not JsonToken.START_ARRAY:
                        reader.skip()
                        continue

                    while reader.read() and reader.token() is not JsonToken.END_ARRAY:
                        if reader.token() is JsonToken.STRING and "unrecognized parameters" in reader.get_string().lower():
                            ignored_parameter = True
                        reader.skip()
                else:
                    reader.read()
                    reader.skip()

            # Anything after the object makes it not Vault's.
            if reader.read():
                raise self._malformed(operation)
        except MalformedJsonError:
            raise self._malformed(operation) from None

        if ignored_parameter:
            raise CryptographicError(f"Vault transit {operation} for key '{self._key_name}' ignored a parameter it was sent, so its answer "
                                     "can't be used: a context needs a Vault that supports associated_data.")
        if not found or length == 0:
            raise CryptographicError(f"Vault transit {operation} for key '{self._key_name}' returned no {name}.")
        return length

    def _malformed(self, operation: str) -> CryptographicError:
        return CryptographicError(f"Vault transit {operation} for key '{self._key_name}' returned a response that isn't Vault's.")

    def _copy_ciphertext(self, ciphertext: memoryview, result: WritableBuffer, operation: str) -> int:
        if not is_vault_ciphertext(ciphertext):
            raise CryptographicError(f"Vault transit {operation} for key '{self._key_name}' returned something that isn't a ciphertext.")

        # A key file over the limit would be refused when read back, so refuse to produce one.
        if len(ciphertext) > WrappedKeyLimits.MAX_BYTES:
            raise CryptographicError(f"Vault transit {operation} for key '{self._key_name}' returned {len(ciphertext)} bytes; a wrapped DEK is at "
                                     f"most {WrappedKeyLimits.MAX_BYTES}.")

        target = memoryview(result).cast("B")
        if len(ciphertext) > len(target):
            raise ValueError(f"The wrapped DEK is {len(ciphertext)} bytes; result holds {len(target)}.")
        target[:len(ciphertext)] = ciphertext
        return len(ciphertext)

    def _decode_plaintext(self, encoded: memoryview, result: WritableBuffer) -> int:
        # Decodes the revealed key into result, through a bytearray that is zeroed: decoded straight
        # into result, a key too long for it would be partly written before that was known.
        decoded = bytearray(len(encoded) // 4 * 3)
        try:
            length = _decode_base64(encoded, decoded)
            if length <= 0:
                raise CryptographicError(f"Vault transit unwrap for key '{self._key_name}' returned a plaintext that isn't base64.")
            target = memoryview(result).cast("B")
            if length > len(target):
                raise ValueError(f"The revealed key is {length} bytes; result holds {len(target)}.")
            target[:length] = memoryview(decoded)[:length]
            return length
        finally:
            ArrayUtility.zero_memory(decoded)


def is_vault_ciphertext(value: Buffer) -> bool:
    """Whether ``value`` is a transit ciphertext as Vault writes it: ``vault:v{version}:{base64}``."""
    return _CIPHERTEXT.fullmatch(memoryview(value).cast("B")) is not None


def _encode_base64(data: memoryview, destination: bytearray, offset: int) -> int:
    # Standard padded base64 of data, written into destination from offset - the library codecs return
    # an immutable bytes that could never be zeroed. Only byte-sized values are ever computed: CPython
    # caches those, whereas a wider integer would be a freed, unzeroed heap copy. Returns the length.
    position = offset
    for i in range(0, len(data), 3):
        count = min(3, len(data) - i)
        b0 = data[i]
        b1 = data[i + 1] if count > 1 else 0
        b2 = data[i + 2] if count > 2 else 0
        destination[position] = _BASE64_ALPHABET[b0 >> 2]
        destination[position + 1] = _BASE64_ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)]
        destination[position + 2] = _BASE64_ALPHABET[((b1 & 0x0F) << 2) | (b2 >> 6)] if count > 1 else _PAD
        destination[position + 3] = _BASE64_ALPHABET[b2 & 0x3F] if count > 2 else _PAD
        position += 4
    return position - offset


def _decode_base64(encoded: memoryview, destination: bytearray) -> int:
    # Standard padded base64 (RFC 4648 section 4) into destination, as strictly as .NET's
    # Base64.DecodeFromUtf8: whole four-character groups, padding only at the end. Decoded here rather
    # than by binascii, which returns immutable bytes; only byte-sized values are computed. Returns the
    # bytes written, or -1 if encoded isn't base64.
    length = len(encoded)
    if length == 0 or length % 4 != 0:
        return -1
    padding = 0
    if encoded[length - 1] == _PAD:
        padding = 2 if encoded[length - 2] == _PAD else 1

    written = 0
    for i in range(0, length, 4):
        last = i + 4 == length
        s0 = _BASE64_VALUES[encoded[i]]
        s1 = _BASE64_VALUES[encoded[i + 1]]
        s2 = 0 if last and padding == 2 else _BASE64_VALUES[encoded[i + 2]]
        s3 = 0 if last and padding >= 1 else _BASE64_VALUES[encoded[i + 3]]
        if s0 == 0xFF or s1 == 0xFF or s2 == 0xFF or s3 == 0xFF:
            return -1
        destination[written] = ((s0 << 2) & 0xFF) | (s1 >> 4)
        written += 1
        if not (last and padding == 2):
            destination[written] = ((s1 & 0x0F) << 4) | (s2 >> 2)
            written += 1
        if not (last and padding >= 1):
            destination[written] = ((s2 & 0x03) << 6) | s3
            written += 1
    return written


def _read_body(response: http.client.HTTPResponse, sock: socket.socket, deadline: float, buffer: bytearray, timeout: timedelta) -> int:
    # Reads the response body into buffer until it ends or buffer is full, each read waiting at most
    # the time left; a body shorter than its Content-Length is a lost connection, not the end.
    expected = response.length
    view = memoryview(buffer)
    length = 0
    while length < len(buffer) and not response.isclosed():
        _set_remaining(sock, deadline, timeout)
        try:
            read = response.readinto(view[length:])
        except http.client.IncompleteRead:
            # Its partial bytes may hold a DEK: neither kept nor chained.
            raise ConnectionError("The connection was lost during Vault's response.") from None
        except TimeoutError:
            raise _timed_out(timeout) from None
        if read == 0:
            if expected is not None and length < expected:
                raise ConnectionError("The connection was lost during Vault's response.")
            break
        length += read
    return length


def _read_errors(body: memoryview) -> list[str] | None:
    # The errors Vault listed in an error response; None if it isn't Vault's JSON. An error response
    # holds no key material, so its strings may become str.
    reader = JsonReader(body)
    try:
        if not reader.read() or reader.token() is not JsonToken.START_OBJECT:
            return None

        found: list[str] = []
        while reader.read() and reader.token() is JsonToken.PROPERTY_NAME:
            is_errors = reader.value_text_equals("errors")
            reader.read()
            if not is_errors:
                reader.skip()
            elif reader.token() is not JsonToken.START_ARRAY:
                return None
            else:
                found = []
                while reader.read() and reader.token() is not JsonToken.END_ARRAY:
                    start = reader.token_start
                    if reader.token() is JsonToken.STRING:
                        found.append(reader.get_string())
                        continue
                    reader.skip()
                    found.append(bytes(body[start:reader.bytes_consumed]).decode("utf-8", "replace"))

        # Anything after the object makes it not JSON.
        return None if reader.read() else found
    except MalformedJsonError:
        return None


def _phrase(status: int) -> str:
    try:
        return " " + http.HTTPStatus(status).phrase
    except ValueError:
        return ""


def _set_remaining(sock: socket.socket, deadline: float, timeout: timedelta) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _timed_out(timeout)
    sock.settimeout(remaining)


def _timed_out(timeout: timedelta) -> TimeoutError:
    return TimeoutError(f"Vault's response took longer than {timeout}.")


def _retry_delay(base_delay: timedelta, retry: int, jitter_millis: int) -> timedelta:
    """The wait before retry number ``retry`` (0 for the first): ``base_delay``, doubled for each
    retry before it, at most :attr:`HashiCorpVaultTransitKeyWrapperOptions.MAX_RETRY_DELAY` - plus
    ``jitter_millis``."""
    maximum = HashiCorpVaultTransitKeyWrapperOptions.MAX_RETRY_DELAY
    backoff = maximum if retry >= 30 else base_delay * (1 << retry)
    return min(backoff, maximum) + timedelta(milliseconds=jitter_millis)


def _check(options: HashiCorpVaultTransitKeyWrapperOptions) -> None:
    limits = HashiCorpVaultTransitKeyWrapperOptions
    if not isinstance(options, HashiCorpVaultTransitKeyWrapperOptions):
        raise TypeError("options must be HashiCorpVaultTransitKeyWrapperOptions.")
    if not isinstance(options.timeout, timedelta) or not isinstance(options.retry_delay, timedelta):
        raise TypeError("timeout and retry_delay must be timedeltas.")
    if not isinstance(options.retry_count, int) or isinstance(options.retry_count, bool):
        raise TypeError("retry_count must be an int.")
    if options.ssl_context is not None and not isinstance(options.ssl_context, ssl.SSLContext):
        raise TypeError("ssl_context must be an ssl.SSLContext.")
    if not _is_valid_path(options.mount_path):
        raise ValueError(f"The mount path '{options.mount_path}' isn't a Vault path.")
    if options.namespace is not None and not _is_valid_path(options.namespace):
        raise ValueError(f"The namespace '{options.namespace}' isn't a Vault path.")
    if options.timeout <= timedelta(0):
        raise ValueError(f"The timeout must be positive; it is {options.timeout}.")
    if not limits.MIN_RETRY_COUNT <= options.retry_count <= limits.MAX_RETRY_COUNT:
        raise ValueError(f"The retry count must be {limits.MIN_RETRY_COUNT}-{limits.MAX_RETRY_COUNT}; it is {options.retry_count}.")
    if not timedelta(0) <= options.retry_delay <= limits.MAX_RETRY_DELAY:
        raise ValueError(f"The retry delay must be zero to {limits.MAX_RETRY_DELAY}; it is {options.retry_delay}.")


def _api_base(address: str) -> tuple[bool, str, int | None, str]:
    # Whether Vault's address is https, its host and port, and the path of /v1/ under it - refusing an
    # address that would send tokens and DEKs in the clear (http anywhere but loopback) or that
    # carries credentials, a query or a fragment.
    if not isinstance(address, str):
        raise TypeError("address must be a str.")
    parts = urlsplit(address)
    host = parts.hostname
    if not parts.scheme or not parts.netloc or not host:
        raise ValueError(f"Vault's address '{address}' isn't absolute, e.g. https://vault.example.com:8200.")

    scheme = parts.scheme.lower()
    if scheme != "https" and not (scheme == "http" and _is_loopback(host, parts.netloc)):
        raise ValueError(f"Vault's address '{address}' must be https; http is allowed only on a loopback address (a local Vault Agent or "
                         "dev server), since every request carries a token and DEKs.")
    if "@" in parts.netloc or "?" in address or "#" in address:
        raise ValueError(f"Vault's address '{address}' must not hold credentials, a query or a fragment.")

    return scheme == "https", host, parts.port, parts.path.rstrip("/") + "/v1/"


def _is_loopback(host: str, netloc: str) -> bool:
    # localhost, or an IP literal on the loopback network. Only literals are parsed, so no name is
    # ever resolved.
    if host.lower() == "localhost":
        return True
    if not netloc.rsplit("@", maxsplit=1)[-1].startswith("[") and not _IPV4_LITERAL.fullmatch(host):
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _is_valid_path(path: object) -> bool:
    # '/'-separated segments, none empty, "." or "..": a path that stays where it's put.
    return isinstance(path, str) and all(_is_valid_segment(segment) for segment in path.split("/"))


def _is_valid_segment(segment: str) -> bool:
    return _PATH_SEGMENT.fullmatch(segment) is not None and segment not in {".", ".."}

