"""The shared writer's contract over an in-memory store, and what only it does: the default key, file
names, its own arguments, the receiver it hands SecretJsonBody."""

from __future__ import annotations

import asyncio
import base64
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
from collections.abc import Buffer, Iterator, MutableMapping, Sequence
from pathlib import Path
from typing import ClassVar

import pytest
from hkdfguard import abstractions
from hkdfguard.abstractions import KeyNotFoundError, KeyWrapper, PipelineDataProtector, WritableBuffer
from hkdfguard.cache import FilePerSecretCache, InvalidSecretDataError, SecretJsonBody, SecretValueReceiver
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProvider, AesGcmPipelineDataProtector
from hkdfguard.dataencryptionkey import DataEncryptionKey, DefaultFormatProvider
from hkdfguard.dataencryptionkey import KeyRing as DefaultKeyRing
from hkdfguard.pipeline import SecretPipelineWriter, SecretRequest
from hkdfguard_test_support import current_user_trust, trusted_directory
from pipeline_test_support import KEY_VERSION, RecordingStream, SecretPipelineWriterContract, reveal, run


class FakeStore:
    """A store of secret values by name, as UTF-8 bytes; names are ASCII letters, digits, hyphens and '/'."""

    def __init__(self) -> None:
        self.secrets: dict[str, bytes] = {}
        self.reads: list[str] = []
        self.fail_with: BaseException | None = None

    @staticmethod
    def is_valid_name(name: str) -> bool:
        return all(c.isascii() and (c.isalnum() or c in "-/") for c in name)

    def set(self, name: str, value: str) -> None:
        self.secrets[name] = value.encode()


class FakeWriter(SecretPipelineWriter):
    def __init__(self, protector: PipelineDataProtector, secret_names: Sequence[str], store: FakeStore, default_key: str | None = None) -> None:
        super().__init__(protector, secret_names, FakeStore.is_valid_name, default_key)
        self.store = store
        self.closed = 0

    def _read_secret(self, name: str, requests: Sequence[SecretRequest], values: MutableMapping[str, str]) -> None:
        self.store.reads.append(name)
        if self.store.fail_with is not None:
            raise self.store.fail_with
        secret = self.store.secrets.get(name)
        if secret is not None:
            # As a store's writer holds a value: in a bytearray it zeroes.
            plaintext = bytearray(secret)
            try:
                self._protect_secret(plaintext, requests, values)
            finally:
                plaintext[:] = bytes(len(plaintext))

    def close(self) -> None:
        self.closed += 1


class TestSecretPipelineWriter(SecretPipelineWriterContract):
    read_failure: ClassVar[type[BaseException]] = ConnectionError

    @pytest.fixture(autouse=True)
    def _store(self) -> None:
        self.store = FakeStore()

    def create_writer_with(self, protector: PipelineDataProtector, secret_names: Sequence[str]) -> abstractions.SecretPipelineWriter:
        return FakeWriter(protector, secret_names, self.store)

    def set_text(self, name: str, text: str) -> None:
        self.store.set(name, text)

    def set_keys(self, name: str, json: str) -> None:
        self.store.set(name, json)

    def fail_reads(self) -> None:
        self.store.fail_with = ConnectionError("down")

    def reads(self) -> list[str]:
        return self.store.reads

    def test_a_name_without_a_key_reads_the_whole_value_or_the_default_key_when_there_is_one(self) -> None:
        self.store.set("app", '{"value":"s3cret"}')
        with FakeWriter(self.protector, ["app"], self.store) as whole, FakeWriter(self.protector, ["app"], self.store, default_key="value") as by_default:
            whole.pull_secrets()
            by_default.pull_secrets()

            assert self.decrypt(whole.protected_secrets["app"], "app") == '{"value":"s3cret"}'
            assert self.decrypt(by_default.protected_secrets["app"], "app") == "s3cret"

    def test_a_secret_is_read_once_for_its_whole_value_and_its_keys(self) -> None:
        self.store.set("prod/app", '{"user":"app"}')
        with FakeWriter(self.protector, ["prod/app", "prod/app#user"], self.store) as writer:
            writer.pull_secrets()

            assert self.store.reads == ["prod/app"]
            assert self.decrypt(writer.protected_secrets["prod__app"], "prod__app") == '{"user":"app"}'
            assert self.decrypt(writer.protected_secrets["prod__app__user"], "prod__app__user") == "app"

    def test_a_value_that_isnt_utf8_text_is_refused(self) -> None:
        self.store.secrets["binary"] = bytes([0xFF, 0xFE, 0x00, 0x80])
        with FakeWriter(self.protector, ["binary"], self.store) as writer:
            with pytest.raises(InvalidSecretDataError, match="UTF-8"):
                writer.pull_secrets()
            assert len(writer.protected_secrets) == 0

    def test_a_key_whose_value_isnt_utf8_text_is_refused(self) -> None:
        # The JSON reader hands a string's unescaped bytes over as they are; the writer checks them.
        self.store.secrets["app"] = b'{"key":"' + bytes([0xFF]) + b'"}'
        with FakeWriter(self.protector, ["app#key"], self.store) as writer, pytest.raises(InvalidSecretDataError, match="UTF-8"):
            writer.pull_secrets()

    def test_a_whitespace_value_holds_no_keys(self) -> None:
        self.store.set("blank", "   ")
        with FakeWriter(self.protector, ["blank#key"], self.store) as writer, pytest.raises(KeyNotFoundError):
            writer.pull_secrets()

    def test_through_the_interface_closing_closes_the_store(self) -> None:
        writer = FakeWriter(self.protector, ["app"], self.store)
        interface: abstractions.SecretPipelineWriter = writer
        with interface:
            pass

        assert writer.closed == 1

    @pytest.mark.parametrize(("secret_name", "file_name"), [("prod/app#password", "prod__app__password"), ("prod/app", "prod__app"), ("app", "app")])
    def test_get_file_name_replaces_each_separator(self, secret_name: str, file_name: str) -> None:
        assert SecretPipelineWriter.get_file_name(secret_name) == file_name

    def test_names_mapping_to_one_file_name_are_refused(self) -> None:
        with pytest.raises(ValueError, match="as another secret named is"):
            FakeWriter(self.protector, ["a/b", "a#b"], self.store)

    def test_a_name_too_long_for_a_file_is_refused(self) -> None:
        FakeWriter(self.protector, ["a" * 255], self.store)
        with pytest.raises(ValueError, match="1-255"):
            FakeWriter(self.protector, ["a" * 256], self.store)

    def test_the_constructor_checks_the_default_key_and_the_name_rule(self) -> None:
        with pytest.raises(TypeError):
            SecretPipelineWriter.get_file_name(None)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            FakeWriter(self.protector, ["app"], self.store, default_key="")
        with pytest.raises(ValueError):
            FakeWriter(self.protector, ["app"], self.store, default_key="a#b")
        with pytest.raises(TypeError):
            NullRuleWriter(self.protector)
        with pytest.raises(TypeError):
            FakeWriter(self.protector, ["app", 1], self.store)  # type: ignore[list-item]

    def test_the_list_is_copied(self) -> None:
        self.store.set("item", "s3cret")
        names = ["item"]
        with FakeWriter(self.protector, names, self.store) as writer:
            names.append("other")

            writer.pull_secrets()

            assert list(writer.protected_secrets) == ["item"]

    def test_the_requests_are_the_names_as_given_with_their_key_and_file_name(self) -> None:
        seen: list[Sequence[SecretRequest]] = []

        class Recording(FakeWriter):
            def _read_secret(self, name: str, requests: Sequence[SecretRequest], values: MutableMapping[str, str]) -> None:
                seen.append(requests)

        with Recording(self.protector, ["prod/app", "prod/app#user", "other"], self.store, default_key="value") as writer, pytest.raises(KeyNotFoundError):
            writer.pull_secrets()

        assert seen == [[SecretRequest("prod/app", "value", "prod__app"), SecretRequest("prod/app#user", "user", "prod__app__user")],
                        [SecretRequest("other", "value", "other")]]

    def test_a_read_adding_a_value_for_no_request_of_its_own_adds_nothing(self) -> None:
        class Stray(FakeWriter):
            def _read_secret(self, name: str, requests: Sequence[SecretRequest], values: MutableMapping[str, str]) -> None:
                values["other"] = "enc::v3::stray"

        with Stray(self.protector, ["item"], self.store) as writer, pytest.raises(KeyNotFoundError):
            writer.pull_secrets()
        assert len(writer.protected_secrets) == 0

    def test_the_json_and_the_tar_list_file_names_in_ordinal_order_capitals_first(self) -> None:
        for name in ("b", "B-2", "a", "A-1", "prod/x"):
            self.store.set(name, name)
        with FakeWriter(self.protector, ["b", "B-2", "a", "A-1", "prod/x"], self.store) as writer:
            writer.pull_secrets()
            stream = RecordingStream()

            writer.write_json_secrets_to_stream(stream)
            writer.write_protected_secret_files_to_stream(tar_stream := RecordingStream())

        assert list(json.loads(stream.data)) == ["A-1", "B-2", "a", "b", "prod__x"]
        with tarfile.open(fileobj=io.BytesIO(tar_stream.data), mode="r:") as tar:
            assert tar.getnames() == ["A-1", "B-2", "a", "b", "prod__x"]

    def test_a_real_tar_unpacks_the_stream_from_popen_into_the_folder_file_per_secret_cache_reads(self) -> None:
        tar = system_tar()
        self.store.set("db-login", '{"password":"pässwörd"}')
        self.store.set("api-key", "key")
        with FakeWriter(self.protector, ["db-login#password", "api-key"], self.store) as writer, trusted_directory() as folder:
            writer.pull_secrets()
            # Unbuffered, as for the key: nothing is copied into a buffer of Popen's own.
            with subprocess.Popen([tar, "-x", "--no-same-owner", "-f", "-", "-C", str(folder)], stdin=subprocess.PIPE, bufsize=0) as process:
                assert process.stdin is not None
                writer.write_protected_secret_files_to_stream(process.stdin)
                process.stdin.close()
            assert process.returncode == 0

            assert sorted(os.listdir(folder)) == ["api-key", "db-login__password"]
            self.assert_cache_reads(folder, {"api-key": "key", "db-login__password": "pässwörd"})

    def test_a_real_tar_unpacks_the_stream_from_asyncio_into_the_folder_file_per_secret_cache_reads(self) -> None:
        tar = system_tar()
        self.store.set("db-login", '{"password":"pässwörd"}')
        with FakeWriter(self.protector, ["db-login#password"], self.store) as writer, trusted_directory() as folder:
            writer.pull_secrets()

            async def unpack() -> int:
                process = await asyncio.create_subprocess_exec(tar, "-x", "--no-same-owner", "-f", "-", "-C", str(folder), stdin=asyncio.subprocess.PIPE)
                assert process.stdin is not None
                await writer.write_protected_secret_files_async(process.stdin)
                process.stdin.close()
                await process.stdin.wait_closed()
                return await process.wait()

            assert run(unpack()) == 0
            self.assert_cache_reads(folder, {"db-login__password": "pässwörd"})

    def test_the_json_reaches_a_real_process_from_popen_and_from_asyncio_as_the_file_holds_it(self, tmp_path: Path) -> None:
        self.store.set("item", "s3cret")
        # Copies its standard input to a file, as tee would.
        copy = ["-I", "-c", "import shutil, sys; shutil.copyfileobj(sys.stdin.buffer, open(sys.argv[1], 'wb'))"]
        with FakeWriter(self.protector, ["item"], self.store) as writer:
            writer.pull_secrets()
            writer.write_json_secrets(tmp_path / "expected.json")

            with subprocess.Popen([sys.executable, *copy, str(tmp_path / "popen.json")], stdin=subprocess.PIPE) as process:
                assert process.stdin is not None
                writer.write_json_secrets_to_stream(process.stdin)
                process.stdin.close()

            async def tee() -> int:
                process = await asyncio.create_subprocess_exec(sys.executable, *copy, str(tmp_path / "asyncio.json"), stdin=asyncio.subprocess.PIPE)
                assert process.stdin is not None
                await writer.write_json_secrets_async(process.stdin)
                process.stdin.close()
                return await process.wait()

            assert run(tee()) == 0

        expected = (tmp_path / "expected.json").read_bytes()
        assert (tmp_path / "popen.json").read_bytes() == expected
        assert (tmp_path / "asyncio.json").read_bytes() == expected

    def assert_cache_reads(self, folder: Path, expected: dict[str, str]) -> None:
        """FilePerSecretCache over ``folder``, with a ring holding the protector's key as it will once wrapped and registered."""
        key = bytearray(base64.b64decode(bytes(self.protector.get_key_as_base64())))
        with DefaultKeyRing(DefaultFormatProvider()) as ring:
            ring.add(KEY_VERSION, DataEncryptionKey(AesGcmCryptoProvider.create(FixedKeyWrapper(key), b"wrapped", 60)))
            cache = FilePerSecretCache(folder, current_user_trust(), ring, DefaultFormatProvider())
            for name, value in expected.items():
                result = bytearray(64)
                assert result[:cache.decrypt(name, result)].decode() == value


def system_tar() -> str:
    """The operating system's own tar - bsdtar on Windows (System32\\tar.exe) and macOS, usually GNU tar on Linux; skips the test without one."""
    if sys.platform == "win32":
        system32 = os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32", "tar.exe")
        path = system32 if os.path.isfile(system32) else None
    else:
        path = shutil.which("tar")
    if path is None:
        pytest.skip("No tar to unpack with.")
    return path


class FixedKeyWrapper(KeyWrapper):
    """Reveals one fixed key: the pipeline's, as the wrap tool would have wrapped it."""

    def __init__(self, key: bytearray) -> None:
        self.key = key

    def wrap(self, plaintext: Buffer, result: WritableBuffer) -> int:
        raise NotImplementedError

    def unwrap(self, wrapped: Buffer, result: WritableBuffer) -> int:
        memoryview(result).cast("B")[:32] = self.key
        return 32

    def generate_and_wrap(self, result: WritableBuffer) -> int:
        raise NotImplementedError

    def read_key_file(self, path: str | os.PathLike[str]) -> bytearray:
        raise NotImplementedError


class TestReceiver:
    """The receiver a store's writer hands SecretJsonBody, as the AWS, Azure and Vault writers use it."""

    @pytest.fixture
    def writer(self) -> Iterator[FakeWriter]:
        with AesGcmPipelineDataProtector(DefaultFormatProvider(), 3) as protector:
            yield FakeWriter(protector, ["app", "app#user", "app#port"], FakeStore())

    @staticmethod
    def requests(writer: FakeWriter) -> list[SecretRequest]:
        return writer._requests["app"]

    def test_a_text_value_is_encrypted_whole_and_by_key_and_its_buffer_zeroed(self, writer: FakeWriter) -> None:
        values: dict[str, str] = {}
        receiver = writer._receiver(self.requests(writer), values)
        assert isinstance(receiver, SecretValueReceiver)

        redacted = SecretJsonBody.capture(b'{"SecretString":"{\\"user\\":\\"app\\",\\"port\\":5432}"}', receiver, "SecretString")

        assert redacted == b'{"SecretString":""}'
        assert sorted(values) == ["app", "app__port", "app__user"]
        assert reveal(writer._protector, values["app"], "app") == '{"user":"app","port":5432}'
        assert reveal(writer._protector, values["app__port"], "app__port") == "5432"

    def test_each_key_of_an_object_is_encrypted_only_when_asked_for(self, writer: FakeWriter) -> None:
        values: dict[str, str] = {}
        SecretJsonBody.capture_keys(b'{"data":{"user":"app","unasked":"x","port":""}}', writer._receiver(self.requests(writer), values), ["data"])

        assert list(values) == ["app__user"]

    def test_a_binary_value_is_refused_and_zeroed(self, writer: FakeWriter) -> None:
        receiver = writer._receiver(self.requests(writer), {}, binary="SecretBinary")
        with pytest.raises(InvalidSecretDataError, match="A SecretBinary can't be protected"):
            SecretJsonBody.capture(b'{"SecretBinary":"AQID"}', receiver, "SecretString", "SecretBinary")

        buffer = bytearray(b"\x01\x02")
        with pytest.raises(InvalidSecretDataError, match="A binary value"):
            writer._receiver(self.requests(writer), {}).set_bytes(buffer)
        assert buffer == bytearray(2)

    def test_every_buffer_handed_over_is_zeroed_even_when_refused(self, writer: FakeWriter) -> None:
        receiver = writer._receiver(self.requests(writer), {})
        text = bytearray(b'{"user":"app"}')
        receiver.set_bytes_with_json_keys(text)
        assert text == bytearray(len(text))

        invalid = bytearray(b"\xff")
        with pytest.raises(InvalidSecretDataError):
            receiver.set_key_bytes("user", invalid)
        assert invalid == bytearray(1)

        unasked = bytearray(b"x")
        receiver.set_key_bytes("unasked", unasked)
        assert unasked == bytearray(1)


class NullRuleWriter(SecretPipelineWriter):
    def __init__(self, protector: PipelineDataProtector) -> None:
        super().__init__(protector, ["app"], None)  # type: ignore[arg-type]

    def _read_secret(self, name: str, requests: Sequence[SecretRequest], values: MutableMapping[str, str]) -> None:
        pass


def test_a_buffer_is_handed_to_the_protector_as_it_is_never_as_a_str() -> None:
    handed: list[object] = []

    class Spy(AesGcmPipelineDataProtector):
        def encrypt(self, plaintext: str | Buffer, secret_identifier: str) -> str:
            handed.append(plaintext)
            return super().encrypt(plaintext, secret_identifier)

    store = FakeStore()
    store.set("app", '{"user":"app"}')
    with Spy(DefaultFormatProvider(), 3) as protector, FakeWriter(protector, ["app", "app#user"], store) as writer:
        writer.pull_secrets()

    assert len(handed) == 2
    assert not any(isinstance(plaintext, (str, bytes)) for plaintext in handed)
