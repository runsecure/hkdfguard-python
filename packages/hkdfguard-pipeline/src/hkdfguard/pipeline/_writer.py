"""The shared plumbing of a secret store's SecretPipelineWriter."""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import secrets
import tarfile
import time
from abc import abstractmethod
from collections.abc import Buffer, Callable, Iterator, Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from typing import ClassVar, Final

from hkdfguard import abstractions
from hkdfguard.abstractions import (
    ArrayUtility,
    AsyncBinaryDestination,
    BinaryDestination,
    KeyNotFoundError,
    PipelineDataProtector,
    Utf8,
    WritableBuffer,
)
from hkdfguard.cache import FilePerSecretCache, InvalidSecretDataError, SecretJsonBody, SecretValueReceiver

_KEY_SEPARATOR: Final = "#"
_FILE_NAME_SEPARATOR: Final = "__"
_JSON_INDENT: Final = "  "
_SECRET_FILE_MODE: Final = 0o644
"""rw-r--r--: what each file in a tar archive is unpacked as, and what a written file is created as."""


@dataclass(frozen=True, slots=True)
class SecretRequest:
    """One secret name a :class:`SecretPipelineWriter` pulls: what to read, and the file it is written as."""

    secret_name: str
    """The name as it was given, key and all."""

    key: str | None
    """The key to read; ``None`` for the secret's whole value."""

    file_name: str
    """The file it is written as, and the name its value is bound to."""


class SecretPipelineWriter(abstractions.SecretPipelineWriter):
    """The shared plumbing of a :class:`~hkdfguard.abstractions.SecretPipelineWriter` over one secret
    store: the store's writer supplies only :meth:`_read_secret` (and, for a store with an
    asyncio-capable client, :meth:`_read_secret_async`), which reads one secret and hands its values
    to :meth:`_protect_secret` - or to a :class:`~hkdfguard.cache.SecretValueReceiver` from
    :meth:`_receiver`, for :class:`~hkdfguard.cache.SecretJsonBody` to take them out of a response
    body. Everything else - naming, grouping, encrypting, keeping and writing - is here: one file per
    secret (:meth:`write_protected_secret_files`, the folder FilePerSecretCache reads) or one JSON
    file of them all (:meth:`write_json_secrets`, the file JsonSecretsFileReadOnlyCache reads), and
    each also to a process's standard input - a tar archive of the files, or the JSON - blocking
    (``..._to_stream``) or from asyncio (``..._async``). No key ring is involved: the protector's key
    is the only one.

    A secret name is the store's name for a secret, optionally followed by :attr:`KEY_SEPARATOR` and
    a key it holds: ``"prod/app#password"`` is the password key of the secret prod/app. A name
    without one reads the store's default key, if it has one, or else the secret's whole value. The
    secrets named are grouped by the store's name, so each is read once however many of its keys are
    listed.

    A secret's file name is its name with every ``/`` and ``#`` replaced by
    :attr:`FILE_NAME_SEPARATOR` (see :meth:`get_file_name`): ``"prod/app#password"`` is written as
    prod__app__password. A name whose file name :class:`~hkdfguard.cache.FilePerSecretCache` couldn't
    read is refused. Each value is encrypted bound to its file name - ``encrypt(value, file_name)`` -
    which is the name FilePerSecretCache decrypts it under, so a renamed file fails authentication.

    A secret's plaintext never becomes a ``str``: it reaches the protector as UTF-8 bytes in a
    bytearray the store's writer zeroes (the protector encrypts from a copy of its own, which it
    zeroes too), and only text is accepted - a value that isn't well-formed UTF-8 is refused, since
    the protector encrypts text. A JSON object's keys are read in place by
    :meth:`SecretJsonBody.capture_json_keys <hkdfguard.cache.SecretJsonBody.capture_json_keys>`, each
    value unescaped into a bytearray of its own that is zeroed once encrypted. The protector is the
    caller's and is never closed, so its key can be handed to the wrap process once the files are
    written. An instance isn't thread-safe.
    """

    KEY_SEPARATOR: ClassVar[str] = _KEY_SEPARATOR
    """Separates a secret's name from the key it reads: ``"prod/app#password"``."""

    FILE_NAME_SEPARATOR: ClassVar[str] = _FILE_NAME_SEPARATOR
    """Replaces each ``/`` and ``#`` of a secret name in its file name."""

    def __init__(self, protector: PipelineDataProtector, secret_names: Sequence[str], is_valid_secret_name: Callable[[str], bool],
                 default_key: str | None = None) -> None:
        """:param protector: encrypts every value read. Owned by the caller: the writer never closes it.
        :param secret_names: the secrets to pull, each a name with the key to read after ``#`` if
            any. Copied: a later change to the sequence isn't seen.
        :param is_valid_secret_name: whether the store can hold a secret by a name, before any ``#``
        :param default_key: the key a name without one reads, for a store whose secrets are all sets
            of keys (HashiCorp Vault's KV); ``None`` when such a name reads the secret's whole value
        :raises TypeError: ``protector``, ``secret_names`` or ``is_valid_secret_name`` is ``None``,
            ``secret_names`` is a ``str`` rather than a sequence of them, or holds something other
            than a ``str`` or ``None``
        :raises ValueError: ``secret_names`` is empty, or holds ``None``, a name the store can't hold
            (with a key), one whose file name isn't one FilePerSecretCache can read, or two with the
            same file name, in any case; or ``default_key`` is empty or holds ``#``
        """
        if protector is None:
            raise TypeError("protector must not be None.")
        if secret_names is None:
            raise TypeError("secret_names must not be None.")
        if isinstance(secret_names, (str, bytes)):
            raise TypeError("secret_names must be a sequence of names, not one name.")
        if is_valid_secret_name is None:
            raise TypeError("is_valid_secret_name must not be None.")
        if default_key is not None and (not isinstance(default_key, str) or not default_key or _KEY_SEPARATOR in default_key):
            raise ValueError(f"The default key '{default_key}' isn't a key.")

        self._protector = protector
        # The secrets to pull, by the store's name: each is read once, for its whole value and its keys.
        self._requests: dict[str, list[SecretRequest]] = {}
        self._add_requests(list(secret_names), is_valid_secret_name, default_key)
        # Each secret's encrypted, formatted value, by file name. File names are found ignoring case
        # on Windows and macOS, so two differing only in case are refused as one.
        self._protected_secrets = _FileNames()
        self._pulled = False

    @property
    def protected_secrets(self) -> Mapping[str, str]:
        """Every secret pulled, by file name - looked up ignoring ASCII case, as the file system may
        find it - its value encrypted and formatted. Empty until a pull completes."""
        return self._protected_secrets

    @staticmethod
    def get_file_name(secret_name: str) -> str:
        """The file a secret name is written as: the name with every ``/`` and ``#`` replaced by
        :attr:`FILE_NAME_SEPARATOR` - ``"prod/app#password"`` is prod__app__password - and the name
        its value is bound to, so the one to look it up by in FilePerSecretCache.

        :raises TypeError: ``secret_name`` is ``None``
        """
        if secret_name is None:
            raise TypeError("secret_name must not be None.")
        return secret_name.replace("/", _FILE_NAME_SEPARATOR).replace(_KEY_SEPARATOR, _FILE_NAME_SEPARATOR)

    def pull_secrets(self) -> None:
        """Reads every secret named in the constructor from the store and encrypts each value,
        keeping it in :attr:`protected_secrets` - replacing whatever an earlier pull kept. All of them
        are read before any missing one is reported. Blocks the calling thread until the store has
        answered every read.

        :raises KeyNotFoundError: a secret doesn't exist, or has no such key, or its value there is
            empty or isn't a value; every other secret is kept
        :raises InvalidSecretDataError: a value isn't UTF-8 text, or a secret holding a JSON object
            names a key twice; nothing is kept

        Any other failure :meth:`_read_secret` raises propagates, and nothing is kept.
        """
        self._start_pull()
        pulled: dict[str, str] = {}
        for name, requests in self._requests.items():
            values: dict[str, str] = {}
            self._read_secret(name, requests, values)
            _collect(requests, values, pulled)
        self._finish_pull(pulled)

    async def pull_secrets_async(self) -> None:
        """:meth:`pull_secrets` without blocking the event loop: each read through
        :meth:`_read_secret_async`. Cancelling the task awaiting it stops the pull, keeping nothing.

        :raises KeyNotFoundError: as :meth:`pull_secrets`
        :raises InvalidSecretDataError: as :meth:`pull_secrets`
        """
        self._start_pull()
        pulled: dict[str, str] = {}
        for name, requests in self._requests.items():
            values: dict[str, str] = {}
            await self._read_secret_async(name, requests, values)
            _collect(requests, values, pulled)
        self._finish_pull(pulled)

    def write_protected_secret_files(self, folder_path: str | os.PathLike[str]) -> None:
        """Writes every secret in :attr:`protected_secrets` as a file in ``folder_path``, creating the
        folder if it doesn't exist: the file named for it, holding its encrypted, formatted value as
        UTF-8, with no byte order mark. A file already there by that name is replaced; any other file
        is left as it is. Each file is written whole to a temporary file beside it and then renamed
        over it, so a reader - or a write that fails part-way - never leaves it half written. Files
        are created ``rw-r--r--`` (less whatever the umask removes), as the tar archive unpacks them.

        File names are matched only within one writer: two writers sharing a folder can each write a
        secret to the same file - ``prod/app`` and ``prod__app`` are both ``prod__app`` - and the last
        one wins. Give each writer a folder of its own, or names that can't meet.

        Only encrypted values are written, but FilePerSecretCache refuses a folder or file anyone but
        administrators and the principals it trusts can modify: write them where the deployment can
        set that, or set it once they're written.

        :param folder_path: the folder to write to, absolute or relative to the working directory
        :raises TypeError: ``folder_path`` is ``None``
        :raises ValueError: ``folder_path`` is empty
        :raises RuntimeError: no pull has completed
        :raises OSError: the folder or a file couldn't be written
        """
        if folder_path is None:
            raise TypeError("folder_path must not be None.")
        if not os.fspath(folder_path):
            raise ValueError("The folder path is empty.")
        self._require_pulled()

        folder = os.path.abspath(folder_path)
        os.makedirs(folder, exist_ok=True)
        for file_name, value in self._protected_secrets.items():
            _write_atomically(os.path.join(folder, file_name), value.encode("utf-8"))

    def write_json_secrets(self, file_path: str | os.PathLike[str]) -> None:
        """Writes every secret in :attr:`protected_secrets` to one JSON file at ``file_path``,
        creating its folder if it doesn't exist: a single object with a member per secret, its file
        name mapped to its encrypted, formatted value, in file-name order (ordinal), as UTF-8 without
        a byte order mark. A file already there is replaced. Each value is bound to its member's name
        - ``decrypt(value, name)`` - as it is to its file name in :meth:`write_protected_secret_files`;
        ``JsonSecretsFileReadOnlyCache`` (``hkdfguard-cache-jsonsecretsfile``) reads the file.

        The layout is .NET's ``Utf8JsonWriter``'s, indented, byte for byte: ``{``, then each member on
        a line of its own indented by two spaces - ``"name": "value"``, separated by commas - then
        ``}``, with no line ending after it, and the lines ended as the platform ends them
        (:data:`os.linesep`, as .NET's ``Environment.NewLine``); an empty object is ``{}``. Names and
        values are written as they are, unescaped but for what JSON requires: a ``+`` in a base64
        value stays ``+``.

        :param file_path: the file to write, absolute or relative to the working directory
        :raises TypeError: ``file_path`` is ``None``
        :raises ValueError: ``file_path`` is empty
        :raises RuntimeError: no pull has completed
        :raises OSError: the folder or the file couldn't be written
        """
        if file_path is None:
            raise TypeError("file_path must not be None.")
        if not os.fspath(file_path):
            raise ValueError("The file path is empty.")
        self._require_pulled()

        path = os.path.abspath(file_path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        _write_atomically(path, self._json_secrets())

    def write_protected_secret_files_to_stream(self, destination: BinaryDestination) -> None:
        """Writes every secret in :attr:`protected_secrets` to ``destination`` as a tar archive of
        the files :meth:`write_protected_secret_files` would write - for a remote tar to unpack, e.g.
        the stdin of ``ssh -T host sudo -n tar -x --no-same-owner -f - -C folder``. The archive is
        POSIX (:data:`tarfile.PAX_FORMAT`), which GNU tar and bsdtar (macOS, and Windows' tar.exe)
        both read: one regular file per secret, in file-name order (ordinal), mode 0644 - the values
        are encrypted, and only who may write them matters to FilePerSecretCache; with
        ``--no-same-owner`` they belong to whoever unpacks them - modified now. The archive holds
        only encrypted values, so it is built in memory and written at once. ``destination`` is
        flushed and left open: close it afterwards, so tar sees the end of its input.

        :param destination: where to write the archive: a process's standard input
        :raises TypeError: ``destination`` is ``None``
        :raises RuntimeError: no pull has completed
        """
        if destination is None:
            raise TypeError("destination must not be None.")
        self._require_pulled()

        destination.write(self._tar_secret_files())
        destination.flush()

    async def write_protected_secret_files_async(self, destination: AsyncBinaryDestination) -> None:
        """:meth:`write_protected_secret_files_to_stream` to an asyncio stream, such as the stdin of
        :func:`asyncio.create_subprocess_exec`, drained rather than flushed, without blocking the
        event loop. Cancelling the awaiting task stops the drain.

        :param destination: where to write the archive: a process's standard input
        :raises TypeError: ``destination`` is ``None``
        :raises RuntimeError: no pull has completed
        """
        if destination is None:
            raise TypeError("destination must not be None.")
        self._require_pulled()

        destination.write(self._tar_secret_files())
        await destination.drain()

    def write_json_secrets_to_stream(self, destination: BinaryDestination) -> None:
        """Writes every secret in :attr:`protected_secrets` to ``destination`` as the JSON object
        :meth:`write_json_secrets` would write, byte for byte - for a remote command to store, e.g.
        the stdin of ``ssh -T host sudo -n tee /etc/app/secrets.json``. ``destination`` is flushed
        and left open: close it afterwards, so the remote command sees the end of its input.

        :param destination: where to write the JSON: a process's standard input
        :raises TypeError: ``destination`` is ``None``
        :raises RuntimeError: no pull has completed
        """
        if destination is None:
            raise TypeError("destination must not be None.")
        self._require_pulled()

        destination.write(self._json_secrets())
        destination.flush()

    async def write_json_secrets_async(self, destination: AsyncBinaryDestination) -> None:
        """:meth:`write_json_secrets_to_stream` to an asyncio stream, such as the stdin of
        :func:`asyncio.create_subprocess_exec`, drained rather than flushed, without blocking the
        event loop. Cancelling the awaiting task stops the drain.

        :param destination: where to write the JSON: a process's standard input
        :raises TypeError: ``destination`` is ``None``
        :raises RuntimeError: no pull has completed
        """
        if destination is None:
            raise TypeError("destination must not be None.")
        self._require_pulled()

        destination.write(self._json_secrets())
        await destination.drain()

    def close(self) -> None:
        """Releases the writer's connection to the store; the default has none. Safe to call more
        than once. The protector is the caller's, and is left open."""

    @abstractmethod
    def _read_secret(self, name: str, requests: Sequence[SecretRequest], values: MutableMapping[str, str]) -> None:
        """Reads the one secret named ``name`` and encrypts the value each of ``requests`` asks for
        into ``values``, by its file name - with :meth:`_protect_secret`, or through a
        :meth:`_receiver` - or returns without doing so if it doesn't exist. Any other failure should
        raise. A request left out of ``values`` is reported missing.

        :param name: the store's name for the secret, before any ``#``
        :param requests: what to read from it: its whole value, a key, or both
        :param values: receives each value encrypted, by file name
        """

    async def _read_secret_async(self, name: str, requests: Sequence[SecretRequest], values: MutableMapping[str, str]) -> None:
        """:meth:`_read_secret` without blocking the event loop, for :meth:`pull_secrets_async`. The
        default runs _read_secret in a worker thread (:func:`asyncio.to_thread`) on a mapping of its
        own, copied into ``values`` once it returns; a store with an asyncio-capable client
        overrides it. Python can't interrupt a thread, so a read whose pull was cancelled runs on to
        its end, and what it encrypted is dropped.
        """
        read: dict[str, str] = {}
        await asyncio.to_thread(self._read_secret, name, requests, read)
        values.update(read)

    def _receiver(self, requests: Sequence[SecretRequest], values: MutableMapping[str, str], *, binary: str | None = None) -> SecretValueReceiver:
        """A :class:`~hkdfguard.cache.SecretValueReceiver` that encrypts what
        :class:`~hkdfguard.cache.SecretJsonBody` takes out of a response body into ``values``: a text
        property's value (and its JSON object's keys) as :meth:`_protect_secret` does, and each key
        :meth:`SecretJsonBody.capture_keys <hkdfguard.cache.SecretJsonBody.capture_keys>` hands over
        that one of ``requests`` asks for. Every buffer it is handed is zeroed.

        :param binary: what a binary property is called, to refuse its value with: the protector
            encrypts text, so a binary value - which can be anything - is refused rather than
            written altered. ``None`` for a store with none, whose receiver is never handed one.
        """
        return _Receiver(self, requests, values, binary)

    def _protect_secret(self, secret: Buffer, requests: Sequence[SecretRequest], values: MutableMapping[str, str]) -> None:
        """Encrypts a secret's whole value into ``values`` for each of ``requests`` without a key,
        and, when it is a JSON object, the value of each requested key it holds (see
        :meth:`_protect_keys`), by file name. An empty secret holds nothing. ``secret`` is read, never
        written: it is the caller's to zero.

        :raises InvalidSecretDataError: the secret isn't UTF-8 text, or is a JSON object holding a
            key more than once
        """
        if memoryview(secret).nbytes == 0:
            return

        for request in requests:
            if request.key is None:
                values[request.file_name] = self._protect(secret, request.file_name)

        if any(request.key is not None for request in requests):
            self._protect_keys(secret, requests, values)

    def _protect_keys(self, json: Buffer, requests: Sequence[SecretRequest], values: MutableMapping[str, str]) -> None:
        """When ``json`` is exactly one JSON object, encrypts the value of each key of ``requests``
        it holds into ``values``, by file name: a string as its text, a number, true or false as its
        JSON text. A null, object, array or empty value is left out, and anything that isn't one JSON
        object - plain text that merely starts like JSON included - holds no keys. Every value is
        unescaped into a bytearray of its own (:meth:`SecretJsonBody.capture_json_keys
        <hkdfguard.cache.SecretJsonBody.capture_json_keys>`), zeroed once encrypted.

        :raises InvalidSecretDataError: the object holds a key more than once, or a requested key's
            value isn't UTF-8 text
        """
        SecretJsonBody.capture_json_keys(json, _Receiver(self, requests, values, None))

    def _protect(self, plaintext: Buffer, file_name: str) -> str:
        """Encrypts ``plaintext``'s UTF-8 bytes bound to ``file_name``. ``plaintext`` is the caller's
        to zero; the protector encrypts from a copy of its own, which it zeroes.

        :returns: the encrypted, formatted value
        :raises InvalidSecretDataError: ``plaintext`` isn't UTF-8 text, which the protector can't
            encrypt as it is
        """
        # Decoding would replace every invalid sequence, so a binary value would be written altered.
        if not Utf8.is_valid(plaintext):
            raise InvalidSecretDataError("The secret isn't UTF-8 text: the pipeline protector encrypts text.")
        return self._protector.encrypt(plaintext, file_name)

    def _require_pulled(self) -> None:
        if not self._pulled:
            raise RuntimeError("No secrets have been pulled: call pull_secrets first.")

    def _sorted_secrets(self) -> list[tuple[str, str]]:
        # In file-name order: ordinal, as .NET's StringComparer.Ordinal sorts them (file names are ASCII).
        return sorted(self._protected_secrets.items())

    def _json_secrets(self) -> bytearray:
        # Utf8JsonWriter's indented layout, with relaxed escaping (UnsafeRelaxedJsonEscaping).
        members = [f"{_JSON_INDENT}{_json_string(name)}: {_json_string(value)}" for name, value in self._sorted_secrets()]
        text = "{" + os.linesep + ("," + os.linesep).join(members) + os.linesep + "}" if members else "{}"
        return bytearray(text.encode("utf-8"))

    def _tar_secret_files(self) -> bytearray:
        archive = io.BytesIO()
        # A float: tarfile then gives each entry a PAX header recording it to the microsecond, as
        # .NET's PaxTarEntry does, rather than falling back to a plain ustar header.
        modified = time.time()
        with tarfile.open(fileobj=archive, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for file_name, value in self._sorted_secrets():
                contents = value.encode("utf-8")
                entry = tarfile.TarInfo(file_name)
                entry.type = tarfile.REGTYPE
                entry.size = len(contents)
                entry.mode = _SECRET_FILE_MODE
                entry.mtime = modified
                tar.addfile(entry, io.BytesIO(contents))
        return bytearray(archive.getbuffer())

    def _start_pull(self) -> None:
        self._protected_secrets.clear()
        self._pulled = False

    def _finish_pull(self, pulled: dict[str, str]) -> None:
        for file_name, value in pulled.items():
            self._protected_secrets.put(file_name, value)
        self._pulled = True

        missing = [request.secret_name for requests in self._requests.values() for request in requests if request.file_name not in pulled]
        if missing:
            raise KeyNotFoundError(f"The secret store holds no value for: {', '.join(missing)}.")

    def _add_requests(self, secret_names: list[str], is_valid_secret_name: Callable[[str], bool], default_key: str | None) -> None:
        if not secret_names:
            raise ValueError("No secrets are named.")

        file_names: set[str] = set()
        for secret_name in secret_names:
            if secret_name is None:
                raise ValueError("A secret name is None.")
            if not isinstance(secret_name, str):
                raise TypeError("Every secret name must be a str.")

            name, separator, key_part = secret_name.partition(_KEY_SEPARATOR)
            key = key_part if separator else default_key
            file_name = self.get_file_name(secret_name)
            if not name or not is_valid_secret_name(name) or key == "":
                raise ValueError(f"'{secret_name}' isn't a secret name this store can hold, with a key after '{_KEY_SEPARATOR}' if any.")
            if not FilePerSecretCache.is_valid_name(file_name):
                raise ValueError(f"'{secret_name}' can't be written as a file: its file name '{file_name}' must be "
                                 f"1-{FilePerSecretCache.MAX_NAME_LENGTH} ASCII letters, digits, '-', '_' and '.', not starting with '.'.")
            # File names are ASCII, so lower() folds exactly their ASCII case.
            if file_name.lower() in file_names:
                raise ValueError(f"'{secret_name}' would be written as '{file_name}', as another secret named is.")
            file_names.add(file_name.lower())

            self._requests.setdefault(name, []).append(SecretRequest(secret_name, key, file_name))


def _write_atomically(path: str, data: Buffer) -> None:
    """Writes ``data`` to ``path`` whole or not at all: to a new file beside it, flushed to disk, then
    renamed over it (``os.replace``, atomic on one file system). The temporary file is created
    exclusively, never through a link, and removed if anything fails."""
    folder, name = os.path.split(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    while True:
        temporary = os.path.join(folder, f".{name}.{secrets.token_hex(8)}.tmp")
        try:
            descriptor = os.open(temporary, flags, _SECRET_FILE_MODE)
            break
        except FileExistsError:
            continue
    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(temporary)
        raise


def _json_string(text: str) -> str:
    # A JSON string escaping only what JSON requires - '"', backslash and control characters - and
    # writing anything else as it is, non-ASCII as UTF-8, as .NET's relaxed escaping does.
    return json.dumps(text, ensure_ascii=False)


def _collect(requests: Sequence[SecretRequest], values: Mapping[str, str], pulled: dict[str, str]) -> None:
    # What one read encrypted for the requests it was made for, and nothing else it may have added.
    for request in requests:
        value = values.get(request.file_name)
        if value is not None:
            pulled[request.file_name] = value


class _FileNames(Mapping[str, str]):
    """The protected secrets by file name, looked up ignoring ASCII case - file names are ASCII - and
    listed as they were spelled."""

    __slots__ = ("_entries",)

    def __init__(self) -> None:
        self._entries: dict[str, tuple[str, str]] = {}

    def __getitem__(self, file_name: str) -> str:
        if not isinstance(file_name, str):
            raise KeyError(file_name)
        return self._entries[file_name.lower()][1]

    def __iter__(self) -> Iterator[str]:
        return (file_name for file_name, _ in self._entries.values())

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"{type(self).__name__}({dict(self.items())!r})"

    def put(self, file_name: str, value: str) -> None:
        self._entries[file_name.lower()] = (file_name, value)

    def clear(self) -> None:
        self._entries.clear()


class _Receiver:
    """A :class:`~hkdfguard.cache.SecretValueReceiver` encrypting what it is handed for the requests
    of one read into that read's values. Zeroes every buffer it is handed."""

    __slots__ = ("_binary", "_requests", "_values", "_writer")

    def __init__(self, writer: SecretPipelineWriter, requests: Sequence[SecretRequest], values: MutableMapping[str, str], binary: str | None) -> None:
        self._writer = writer
        self._requests = requests
        self._values = values
        self._binary = binary

    def set_bytes(self, plaintext: WritableBuffer) -> None:
        # Only a binary property's value is handed over this way.
        ArrayUtility.zero_memory(plaintext)
        what = "A binary value" if self._binary is None else f"A {self._binary}"
        raise InvalidSecretDataError(f"{what} can't be protected: the pipeline protector encrypts text.")

    def set_bytes_with_json_keys(self, plaintext: WritableBuffer) -> None:
        try:
            self._writer._protect_secret(plaintext, self._requests, self._values)
        finally:
            ArrayUtility.zero_memory(plaintext)

    def set_key_bytes(self, key: str, plaintext: WritableBuffer) -> None:
        try:
            request = next((r for r in self._requests if r.key == key), None)
            if request is not None and memoryview(plaintext).nbytes > 0:
                self._values[request.file_name] = self._writer._protect(plaintext, request.file_name)
        finally:
            ArrayUtility.zero_memory(plaintext)
