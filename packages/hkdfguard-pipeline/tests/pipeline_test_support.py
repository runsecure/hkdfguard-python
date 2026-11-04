"""What every store's SecretPipelineWriter must do, whatever its store: :class:`SecretPipelineWriterContract`,
which each store's test class derives from, against its writer and fake, so every writer meets every
scenario."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Coroutine, Iterator, Sequence
from pathlib import Path
from typing import Any, ClassVar

import pytest
from hkdfguard import abstractions
from hkdfguard.abstractions import AuthenticationTagMismatchError, KeyNotFoundError, PipelineDataProtector
from hkdfguard.cache import InvalidSecretDataError
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmPipelineDataProtector
from hkdfguard.dataencryptionkey import DefaultFormatProvider

KEY_VERSION = 3


def run[T](coroutine: Coroutine[Any, Any, T]) -> T:
    """Runs a test's coroutine, with a timeout so a hang fails instead of stalling the run."""

    async def bounded() -> T:
        async with asyncio.timeout(30):
            return await coroutine

    return asyncio.run(bounded())


def reveal(protector: PipelineDataProtector, encrypted: str, file_name: str) -> str:
    """Decrypts as FilePerSecretCache's caller would: size the buffer, decrypt into it, then decode."""
    result = bytearray(protector.get_max_decrypted_length(encrypted))
    return result[:protector.decrypt(encrypted, file_name, result)].decode()


class SecretPipelineWriterContract:
    """What every :class:`~hkdfguard.abstractions.SecretPipelineWriter` must do, whatever its store:
    run against each store's writer and fake by a test class deriving from this one, which supplies
    the hooks below. Secret names here are lower-case letters, digits and hyphens, which every store
    accepts; a store's own tests cover what only it does.

    No key ring anywhere: :attr:`protector` is the only key in the pipeline.
    """

    read_failure: ClassVar[type[BaseException]]
    """The exception a failing read raises."""

    protector: AesGcmPipelineDataProtector
    """The only key in the pipeline, closed once the test is done."""

    folder: Path
    """A folder to write to, which doesn't exist until a test makes it."""

    @pytest.fixture(autouse=True)
    def _pipeline(self, tmp_path: Path) -> Iterator[None]:
        with AesGcmPipelineDataProtector(DefaultFormatProvider(), KEY_VERSION) as protector:
            self.protector = protector
            self.folder = tmp_path / "hkdfguard-pipeline"
            yield

    # --- The store's hooks --------------------------------------------------------------------

    def create_writer_with(self, protector: PipelineDataProtector, secret_names: Sequence[str]) -> abstractions.SecretPipelineWriter:
        """The store's writer, reading from this test's fake."""
        raise NotImplementedError

    def set_text(self, name: str, text: str) -> None:
        """Stores ``text`` as the value a name without a key reads."""
        raise NotImplementedError

    def set_keys(self, name: str, json: str) -> None:
        """Stores a secret whose keys are the members of ``json``, a JSON object - which may hold a member twice."""
        raise NotImplementedError

    def fail_reads(self) -> None:
        """Makes every later read fail as the store fails, with :attr:`read_failure`."""
        raise NotImplementedError

    def reads(self) -> list[str]:
        """The name of every secret the store was asked for, in order."""
        raise NotImplementedError

    # --- Helpers ------------------------------------------------------------------------------

    def create_writer(self, *secret_names: str) -> abstractions.SecretPipelineWriter:
        return self.create_writer_with(self.protector, list(secret_names))

    def decrypt(self, encrypted: str, file_name: str) -> str:
        return reveal(self.protector, encrypted, file_name)

    # --- The contract -------------------------------------------------------------------------

    def test_pull_reads_each_secret_once_and_keeps_every_value_encrypted_for_its_file_name(self) -> None:
        self.set_keys("db-login", '{"username":"app","password":"s3cr\\"et","port":5432,"tls":true,"off":false,"unasked":"x"}')
        self.set_text("api-key", "api-key-value")
        with self.create_writer("db-login#username", "db-login#password", "db-login#port", "db-login#tls", "db-login#off", "api-key") as writer:
            writer.pull_secrets()

            secrets = writer.protected_secrets
            assert len(secrets) == 6
            assert secrets["db-login__password"].startswith(f"enc::v{KEY_VERSION}::")
            assert self.decrypt(secrets["db-login__username"], "db-login__username") == "app"
            assert self.decrypt(secrets["db-login__password"], "db-login__password") == 's3cr"et'
            assert self.decrypt(secrets["db-login__port"], "db-login__port") == "5432"
            assert self.decrypt(secrets["db-login__tls"], "db-login__tls") == "true"
            assert self.decrypt(secrets["db-login__off"], "db-login__off") == "false"
            assert self.decrypt(secrets["api-key"], "api-key") == "api-key-value"
            assert self.reads() == ["db-login", "api-key"]

    def test_a_value_is_bound_to_its_file_name(self) -> None:
        self.set_text("item", "s3cret")
        with self.create_writer("item") as writer:
            writer.pull_secrets()

            with pytest.raises(AuthenticationTagMismatchError):
                self.decrypt(writer.protected_secrets["item"], "other")

    def test_a_large_value_is_protected(self) -> None:
        # As large as DefaultFormatProvider's 4096-character limit allows once encrypted and formatted.
        large = "x" * 2_500
        self.set_text("big", large)
        with self.create_writer("big") as writer:
            writer.pull_secrets()

            assert self.decrypt(writer.protected_secrets["big"], "big") == large

    def test_a_pull_again_replaces_what_the_last_kept(self) -> None:
        self.set_text("item", "first")
        with self.create_writer("item") as writer:
            writer.pull_secrets()
            self.set_text("item", "second")

            writer.pull_secrets()

            assert self.decrypt(writer.protected_secrets["item"], "item") == "second"

    def test_missing_values_are_all_reported_and_the_rest_kept(self) -> None:
        self.set_keys("db-login", '{"username":"app","empty":"","nothing":null,"nested":{"a":"b"},"list":[1]}')
        self.set_text("plain", "not json")
        self.set_text("trailing", '{"key":"v"} more')
        self.set_text("array", '["key"]')
        self.set_text("blank", "")
        with self.create_writer("absent", "db-login#username", "db-login#password", "db-login#empty", "db-login#nothing", "db-login#nested",
                                "db-login#list", "plain#key", "trailing#key", "array#key", "blank") as writer:
            with pytest.raises(KeyNotFoundError) as raised:
                writer.pull_secrets()

            assert str(raised.value) == ("The secret store holds no value for: absent, db-login#password, db-login#empty, db-login#nothing, "
                                         "db-login#nested, db-login#list, plain#key, trailing#key, array#key, blank.")
            assert list(writer.protected_secrets) == ["db-login__username"]

            # What was found is still written.
            writer.write_protected_secret_files(self.folder)
            assert os.listdir(self.folder) == ["db-login__username"]

    def test_a_secret_holding_a_key_twice_is_refused(self) -> None:
        self.set_keys("db-login", '{"password":"a","password":"b"}')
        with self.create_writer("db-login#password") as writer:
            with pytest.raises(InvalidSecretDataError):
                writer.pull_secrets()
            assert len(writer.protected_secrets) == 0

    def test_a_failed_read_propagates_and_keeps_nothing(self) -> None:
        self.set_text("item", "s3cret")
        with self.create_writer("item") as writer:
            writer.pull_secrets()
            self.fail_reads()

            with pytest.raises(self.read_failure):
                writer.pull_secrets()

            assert len(writer.protected_secrets) == 0
            with pytest.raises(RuntimeError):
                writer.write_protected_secret_files(self.folder)

    def test_through_the_interface_writes_one_file_per_secret_as_utf8_without_a_bom(self) -> None:
        self.set_keys("db-login", '{"password":"pässwörd"}')
        self.set_text("api-key", "key")
        writer: abstractions.SecretPipelineWriter = self.create_writer("db-login#password", "api-key")
        with writer:
            writer.pull_secrets()

            writer.write_protected_secret_files(str(self.folder))

        assert sorted(os.listdir(self.folder)) == ["api-key", "db-login__password"]
        contents = (self.folder / "db-login__password").read_bytes()
        assert contents[:1] != b"\xef"
        assert self.decrypt(contents.decode("utf-8"), "db-login__password") == "pässwörd"

    def test_write_protected_secret_files_replaces_only_its_own_files(self) -> None:
        self.folder.mkdir()
        (self.folder / "item").write_text("old")
        (self.folder / "unrelated").write_text("untouched")
        self.set_text("item", "new")
        with self.create_writer("item") as writer:
            writer.pull_secrets()

            writer.write_protected_secret_files(self.folder)

        assert self.decrypt((self.folder / "item").read_text(), "item") == "new"
        assert (self.folder / "unrelated").read_text() == "untouched"

    def test_write_protected_secret_files_before_a_pull_or_without_a_folder_raises(self) -> None:
        with self.create_writer("item") as writer:
            with pytest.raises(RuntimeError):
                writer.write_protected_secret_files(self.folder)
            with pytest.raises(TypeError):
                writer.write_protected_secret_files(None)  # type: ignore[arg-type]
            with pytest.raises(ValueError):
                writer.write_protected_secret_files("")
        assert not self.folder.exists()

    @pytest.mark.parametrize("secret_name", ["", "bad name", "#key", "db-login#", "db-login#bad key", "db-login#a:b"])
    def test_an_invalid_name_is_refused(self, secret_name: str) -> None:
        with pytest.raises(ValueError):
            self.create_writer(secret_name)

    def test_the_constructor_checks_the_list_and_the_protector(self) -> None:
        with pytest.raises(TypeError):
            self.create_writer_with(None, ["item"])  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            self.create_writer_with(self.protector, None)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            self.create_writer_with(self.protector, "item")
        with pytest.raises(ValueError):
            self.create_writer_with(self.protector, [])
        with pytest.raises(ValueError):
            self.create_writer_with(self.protector, [None])  # type: ignore[list-item]
        with pytest.raises(ValueError):
            self.create_writer_with(self.protector, ["item", "ITEM"])
        with pytest.raises(ValueError):
            self.create_writer_with(self.protector, ["item", "item"])

    # --- What only the Python port has ----------------------------------------------------------

    def test_pull_secrets_async_keeps_what_pull_secrets_does(self) -> None:
        self.set_keys("db-login", '{"username":"app","password":"s3cret"}')
        self.set_text("api-key", "api-key-value")
        with self.create_writer("db-login#username", "db-login#password", "api-key", "absent") as writer:
            with pytest.raises(KeyNotFoundError, match="absent"):
                run(writer.pull_secrets_async())

            assert sorted(writer.protected_secrets) == ["api-key", "db-login__password", "db-login__username"]
            assert self.decrypt(writer.protected_secrets["db-login__password"], "db-login__password") == "s3cret"
            assert self.decrypt(writer.protected_secrets["api-key"], "api-key") == "api-key-value"
            assert self.reads() == ["db-login", "api-key", "absent"]

    def test_a_failed_async_read_propagates_and_keeps_nothing(self) -> None:
        self.set_text("item", "s3cret")
        with self.create_writer("item") as writer:
            run(writer.pull_secrets_async())
            self.fail_reads()

            with pytest.raises(self.read_failure):
                run(writer.pull_secrets_async())
            assert len(writer.protected_secrets) == 0

    def test_protected_secrets_is_a_read_only_view_found_ignoring_case(self) -> None:
        self.set_text("item", "s3cret")
        with self.create_writer("item") as writer:
            secrets = writer.protected_secrets
            assert len(secrets) == 0
            writer.pull_secrets()

            assert secrets["ITEM"] == secrets["item"]
            assert list(secrets) == ["item"]
            assert "Item" in secrets
            assert not hasattr(secrets, "__setitem__")

    def test_closing_twice_is_safe_and_leaves_the_protector_open(self) -> None:
        self.set_text("item", "s3cret")
        writer = self.create_writer("item")
        writer.close()
        writer.close()

        assert self.protector.encrypt("still open", "item")
