from __future__ import annotations

import base64
import ctypes
import functools
import io
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from hkdfguard.abstractions import InvalidKeyFileError, WrappedKeyLimits
from hkdfguard.securefile import KeyFileTrust, TrustedKeyFile
from hkdfguard_test_support import long_path, private_key_directory

IS_WINDOWS = sys.platform == "win32"
IS_UNIX = sys.platform.startswith("linux") or (sys.platform == "darwin" and platform.machine() == "arm64")
windows_only = pytest.mark.skipif(not IS_WINDOWS, reason="Windows only.")
unix_only = pytest.mark.skipif(not IS_UNIX, reason="Linux and Apple silicon macOS only.")


def wrapped() -> bytes:
    """About the size of a KMS ciphertext blob for a 32-byte DEK."""
    return os.urandom(184)


def read_contents(contents: bytes) -> bytearray:
    return TrustedKeyFile.read_contents(io.BytesIO(contents).readinto, "v1.key")


# --- Contents --------------------------------------------------------------------------------------


def test_read_contents_a_wrapped_key_is_returned_exactly_in_a_buffer_the_caller_owns() -> None:
    key = wrapped()

    result = read_contents(key)

    assert result == key
    assert isinstance(result, bytearray)


def test_read_contents_exactly_the_limit_is_accepted() -> None:
    key = os.urandom(WrappedKeyLimits.MAX_BYTES)

    assert read_contents(key) == key


def test_read_contents_empty_is_refused() -> None:
    with pytest.raises(InvalidKeyFileError, match="empty"):
        read_contents(b"")


def test_read_contents_over_the_limit_is_refused_reading_only_one_byte_past() -> None:
    stream = io.BytesIO(bytes(WrappedKeyLimits.MAX_BYTES * 4))

    with pytest.raises(InvalidKeyFileError, match="larger than 512 bytes"):
        TrustedKeyFile.read_contents(stream.readinto, "v1.key")
    assert stream.tell() == WrappedKeyLimits.MAX_BYTES + 1


def test_read_contents_a_plaintext_key_is_refused_as_exposed() -> None:
    with pytest.raises(InvalidKeyFileError, match="exposed"):
        read_contents(os.urandom(32))


def test_read_contents_reads_until_the_end_however_the_reads_are_split() -> None:
    key = wrapped()
    chunks = [key[:1], key[1:100], key[100:]]

    def readinto(view: memoryview) -> int:
        if not chunks:
            return 0
        chunk = chunks.pop(0)
        view[:len(chunk)] = chunk
        return len(chunk)

    assert TrustedKeyFile.read_contents(readinto, "v1.key") == key


def test_read_contents_zeroes_its_buffer_whether_it_returns_or_refuses() -> None:
    seen: list[memoryview] = []

    def readinto(view: memoryview) -> int:
        seen.append(view)
        if len(seen) > 1:
            return 0
        view[:32] = b"\xab" * 32
        return 32

    with pytest.raises(InvalidKeyFileError):
        TrustedKeyFile.read_contents(readinto, "v1.key")
    assert bytes(seen[0].obj) == bytes(WrappedKeyLimits.MAX_BYTES + 1)


def test_read_contents_an_error_reading_is_passed_on() -> None:
    def readinto(view: memoryview) -> int:
        raise OSError("disk on fire")

    with pytest.raises(OSError, match="disk on fire"):
        TrustedKeyFile.read_contents(readinto, "v1.key")


def plaintext_keys_as_text() -> list[str]:
    # Fixed, so the standard and URL-safe encodings always differ: FB EF BE encodes as "++++", FF FF FF
    # as "////". A random key would sometimes encode with neither, merging two rows.
    key = bytes((0xFB, 0xEF, 0xBE, 0xFF, 0xFF, 0xFF)[i % 6] for i in range(32))
    hex_text = key.hex().upper()
    standard = base64.b64encode(key).decode()
    url_safe = base64.urlsafe_b64encode(key).decode()
    return [hex_text, hex_text.lower() + "\n", standard, standard.rstrip("="), url_safe, url_safe.rstrip("=") + "\r\n", "  \t" + standard + " \n",
            "\v" + hex_text + "\f"]


@pytest.mark.parametrize("text", plaintext_keys_as_text())
def test_looks_like_plaintext_key_a_key_written_as_text_is_detected(text: str) -> None:
    assert TrustedKeyFile.looks_like_plaintext_key(text.encode("ascii"))


def test_looks_like_plaintext_key_a_raw_key_is_detected() -> None:
    assert TrustedKeyFile.looks_like_plaintext_key(os.urandom(32))
    assert TrustedKeyFile.looks_like_plaintext_key(bytearray(32))


@pytest.mark.parametrize("text", [
    "a" * 63,                    # one hex digit short
    "a" * 62 + "zz",             # not hex
    "A" * 42,                    # too short for base64
    "A" * 45,                    # too long for base64
    "A" * 41 + "+-",             # mixes the two alphabets
    "A" * 42 + "!",              # not base64
    "A" * 43 + "==",             # 45 characters
    "A" * 42 + "==",             # 44, but padded for 31 bytes
])
def test_looks_like_plaintext_key_other_text_is_not_detected(text: str) -> None:
    assert not TrustedKeyFile.looks_like_plaintext_key(text.encode("ascii"))


def test_looks_like_plaintext_key_a_wrapped_key_is_not_detected() -> None:
    assert not TrustedKeyFile.looks_like_plaintext_key(wrapped())
    assert not TrustedKeyFile.looks_like_plaintext_key(os.urandom(TrustedKeyFile.PLAINTEXT_TEXT_SCAN_LIMIT + 1))


# --- Arguments and KeyFileTrust -------------------------------------------------------------------


@pytest.mark.parametrize(("path", "expected"), [(None, TypeError), (b"v1.key", TypeError), ("", ValueError), ("v1\0.key", ValueError)])
def test_read_refuses_a_missing_or_unusable_path_before_anything_is_examined(path: object, expected: type[Exception]) -> None:
    with pytest.raises(expected):
        TrustedKeyFile.read(path, KeyFileTrust.ADMINISTRATORS_ONLY)  # type: ignore[arg-type]


@pytest.mark.parametrize("trust", [None, "S-1-5-18"])
def test_read_refuses_a_missing_trust(trust: object) -> None:
    with pytest.raises(TypeError):
        TrustedKeyFile.read("v1.key", trust)  # type: ignore[arg-type]


def test_read_off_the_supported_platforms_is_not_implemented(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "freebsd14")
    with pytest.raises(NotImplementedError, match="Windows, Linux and macOS only"):
        TrustedKeyFile.read("/etc/hkdfguard/v1.key", KeyFileTrust.ADMINISTRATORS_ONLY)


def test_read_on_an_intel_mac_is_not_implemented(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")
    with pytest.raises(NotImplementedError, match="Apple silicon Macs only; this process is x86_64"):
        TrustedKeyFile.read("/etc/hkdfguard/v1.key", KeyFileTrust.ADMINISTRATORS_ONLY)


def test_key_file_trust_copies_its_lists_and_refuses_what_is_not_an_id() -> None:
    sids = ["S-1-5-21-1-2-3-1005"]
    trust = KeyFileTrust(windows_principals=sids, unix_user_ids=[1001], unix_group_ids=(2001,))
    sids.append("S-1-1-0")

    assert trust.windows_principals == ("S-1-5-21-1-2-3-1005",)
    assert trust.unix_user_ids == (1001,)
    assert trust.unix_group_ids == (2001,)
    assert KeyFileTrust(unix_user_ids=[4294967295]).unix_user_ids == (4294967295,)
    assert KeyFileTrust() == KeyFileTrust.ADMINISTRATORS_ONLY
    with pytest.raises(ValueError, match="not a valid id"):
        KeyFileTrust(unix_user_ids=[-1])
    with pytest.raises(ValueError, match="not a valid id"):
        KeyFileTrust(unix_group_ids=[0x1_0000_0000])
    with pytest.raises(TypeError):
        KeyFileTrust(unix_user_ids=[True])
    with pytest.raises(TypeError):
        KeyFileTrust(unix_group_ids=["2001"])  # type: ignore[list-item]
    with pytest.raises(TypeError):
        KeyFileTrust(windows_principals="S-1-5-21-1-2-3-1005")
    with pytest.raises(TypeError):
        KeyFileTrust(windows_principals=[1005])  # type: ignore[list-item]
    with pytest.raises(TypeError):
        KeyFileTrust(unix_user_ids=None)  # type: ignore[arg-type]


def test_key_file_trust_is_immutable() -> None:
    with pytest.raises(AttributeError):
        KeyFileTrust.ADMINISTRATORS_ONLY.unix_user_ids = (1001,)  # type: ignore[misc]


# --- Windows, real files ------------------------------------------------------------------------


@functools.cache
def current_user_sid() -> str:
    """The SID of the account running the tests, as whoami reports it."""
    whoami = os.path.join(os.environ["SYSTEMROOT"], "System32", "whoami.exe")
    output = subprocess.run([whoami, "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True).stdout.strip()
    sid = output.rsplit(",", 1)[1].strip('"')  # "DOMAIN\name","S-1-5-21-..."
    assert sid.startswith("S-1-"), output
    return sid


def trust_current_user() -> KeyFileTrust:
    """Trusts the account running the tests, which owns, and may modify, its own temp folder."""
    return KeyFileTrust(windows_principals=[current_user_sid()])


@pytest.fixture
def windows_key_directory() -> Iterator[Path]:
    """A fresh folder under the user's temp folder, named by its long path - Windows may report the
    temp folder by an 8.3 short name, which key files are never read through - and made with
    os.mkdir's default mode, so it inherits the temp folder's permissions: tempfile.mkdtemp's 0o700
    gives it a protected DACL with an OWNER RIGHTS entry, which the checks refuse like any other
    principal they don't trust."""
    directory = long_path(Path(tempfile.gettempdir())) / f"hkdfguard-keys-{uuid.uuid4().hex}"
    directory.mkdir()
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def icacls(*arguments: str) -> None:
    command = [os.path.join(os.environ["SYSTEMROOT"], "System32", "icacls.exe"), *arguments]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


@windows_only
def test_read_on_windows_a_file_in_the_users_own_folder_is_refused_by_default(windows_key_directory: Path) -> None:
    path = windows_key_directory / "v1.key"
    path.write_bytes(wrapped())

    with pytest.raises(PermissionError, match="not trusted"):
        TrustedKeyFile.read(path, KeyFileTrust.ADMINISTRATORS_ONLY)


@windows_only
def test_read_on_windows_with_the_user_trusted_reads_the_file(windows_key_directory: Path) -> None:
    key = wrapped()
    path = windows_key_directory / "v1.key"
    path.write_bytes(key)

    assert TrustedKeyFile.read(path, trust_current_user()) == key
    assert TrustedKeyFile.read(str(path), trust_current_user()) == key


@windows_only
def test_read_on_windows_a_relative_path_is_read_from_the_working_directory(windows_key_directory: Path) -> None:
    key = wrapped()
    path = windows_key_directory / "v1.key"
    path.write_bytes(key)
    if Path.cwd().drive.upper() != path.drive.upper():
        pytest.skip("The temp folder is on another drive than the working directory.")

    relative = os.path.relpath(path)
    assert not os.path.isabs(relative)
    assert TrustedKeyFile.read(relative, trust_current_user()) == key


@windows_only
def test_read_on_windows_a_file_others_may_write_is_refused_even_with_the_user_trusted(windows_key_directory: Path) -> None:
    path = windows_key_directory / "v1.key"
    path.write_bytes(wrapped())
    icacls(str(path), "/grant", "*S-1-5-32-545:(W)")  # Users: Write

    with pytest.raises(PermissionError, match="grants"):
        TrustedKeyFile.read(path, trust_current_user())


@windows_only
def test_read_on_windows_a_folder_others_may_write_is_refused_even_with_the_user_trusted(windows_key_directory: Path) -> None:
    path = windows_key_directory / "v1.key"
    path.write_bytes(wrapped())
    icacls(str(windows_key_directory), "/grant", "*S-1-5-32-545:(AD)")  # Users: create subfolders, on the folder only

    with pytest.raises(PermissionError, match=re.escape(f"'{windows_key_directory}' grants")):
        TrustedKeyFile.read(path, trust_current_user())


@windows_only
def test_read_on_windows_a_short_name_is_expanded_and_the_real_path_checked(windows_key_directory: Path) -> None:
    key = wrapped()
    path = windows_key_directory / "a-long-key-file-name.key"
    path.write_bytes(key)
    buffer = ctypes.create_unicode_buffer(1024)
    length = ctypes.WinDLL("kernel32", use_last_error=True).GetShortPathNameW(str(path), buffer, len(buffer))  # type: ignore[attr-defined,unused-ignore]
    short = buffer.value if 0 < length < len(buffer) else str(path)

    # The full path expands 8.3 names, so the folders checked are the real ones.
    assert TrustedKeyFile.read(short, trust_current_user()) == key
    with pytest.raises(PermissionError):
        TrustedKeyFile.read(short, KeyFileTrust.ADMINISTRATORS_ONLY)


@windows_only
def test_read_on_windows_a_missing_file_is_not_found(windows_key_directory: Path) -> None:
    with pytest.raises(FileNotFoundError):
        TrustedKeyFile.read(windows_key_directory / "missing.key", trust_current_user())
    with pytest.raises(FileNotFoundError):
        TrustedKeyFile.read(windows_key_directory / "missing" / "v1.key", trust_current_user())


@windows_only
def test_read_on_windows_a_folder_is_refused(windows_key_directory: Path) -> None:
    with pytest.raises(PermissionError):
        TrustedKeyFile.read(windows_key_directory, trust_current_user())


@windows_only
def test_read_on_windows_a_file_open_for_writing_is_refused(windows_key_directory: Path) -> None:
    path = windows_key_directory / "v1.key"
    path.write_bytes(wrapped())

    with path.open("ab"), pytest.raises(OSError, match="open for writing by another process") as error:
        TrustedKeyFile.read(path, trust_current_user())
    assert not isinstance(error.value, PermissionError | FileNotFoundError)


@windows_only
@pytest.mark.parametrize("path", ["\\\\hkdfguard-no-such-server.invalid\\share\\v1.key", "//hkdfguard-no-such-server.invalid/share/v1.key",
                                  "\\\\?\\C:\\HkdfGuardKeys\\v1.key"])
def test_read_on_windows_a_unc_or_device_path_is_refused_without_being_opened(path: str) -> None:
    with pytest.raises(PermissionError, match="UNC or device path"):
        TrustedKeyFile.read(path, KeyFileTrust.ADMINISTRATORS_ONLY)


@windows_only
def test_read_on_windows_trusting_everyone_is_refused(windows_key_directory: Path) -> None:
    path = windows_key_directory / "v1.key"
    path.write_bytes(wrapped())

    with pytest.raises(ValueError, match="every account"):
        TrustedKeyFile.read(path, KeyFileTrust(windows_principals=["S-1-1-0"]))


@windows_only
def test_read_on_windows_a_plaintext_key_is_refused_once_its_location_passes(windows_key_directory: Path) -> None:
    path = windows_key_directory / "v1.key"
    path.write_bytes(os.urandom(32).hex().encode())

    with pytest.raises(InvalidKeyFileError, match="unwrapped"):
        TrustedKeyFile.read(path, trust_current_user())


# --- Linux and macOS, real files --------------------------------------------------------------------


def unix_trust_current_user() -> KeyFileTrust:
    return KeyFileTrust(unix_user_ids=[os.geteuid()], unix_group_ids=[os.getegid()])  # type: ignore[attr-defined,unused-ignore]


@unix_only
def test_read_on_unix_a_file_under_the_shared_temp_directory_is_refused() -> None:
    # /tmp is writable by everyone (sticky or not), so nothing beneath it is trusted.
    directory = Path("/tmp") / f"hkdfguard-{uuid.uuid4().hex}"
    directory.mkdir()
    try:
        path = directory / "v1.key"
        path.write_bytes(wrapped())

        with pytest.raises(PermissionError, match="not trusted"):
            TrustedKeyFile.read(path, unix_trust_current_user())
    finally:
        shutil.rmtree(directory)


@unix_only
def test_read_on_unix_a_file_the_user_owns_is_refused_by_default() -> None:
    if os.geteuid() == 0:  # type: ignore[attr-defined,unused-ignore]
        pytest.skip("Running as root, whose files are trusted.")
    with private_key_directory() as directory:
        path = directory / "v1.key"
        path.write_bytes(wrapped())

        with pytest.raises(PermissionError, match="not trusted"):
            TrustedKeyFile.read(path, KeyFileTrust.ADMINISTRATORS_ONLY)


@unix_only
def test_read_on_unix_a_missing_file_is_not_found() -> None:
    with pytest.raises(FileNotFoundError):
        TrustedKeyFile.read(f"/hkdfguard-missing-{uuid.uuid4().hex}.key", KeyFileTrust.ADMINISTRATORS_ONLY)


@unix_only
def test_read_on_unix_a_root_owned_system_file_passes_the_location_checks() -> None:
    # /etc/hosts: root-owned all the way up, and not a key - so it's refused for its contents (or
    # size), never for where it lives.
    try:
        TrustedKeyFile.read("/etc/hosts", KeyFileTrust.ADMINISTRATORS_ONLY)
    except PermissionError as error:
        pytest.fail(f"/etc/hosts was refused for its location: {error}")
    except InvalidKeyFileError:
        pass  # its contents


@unix_only
def test_read_on_unix_a_file_only_its_trusted_owner_can_replace_is_read_and_a_link_to_it_followed_only_when_trusted(
        monkeypatch: pytest.MonkeyPatch) -> None:
    trust = unix_trust_current_user()
    with private_key_directory() as directory:
        key = wrapped()
        path = directory / "v1.key"
        path.write_bytes(key)
        path.chmod(0o600)
        link = directory / "current.key"
        link.symlink_to("v1.key")

        assert TrustedKeyFile.read(path, trust) == key
        assert TrustedKeyFile.read(link, trust) == key
        assert TrustedKeyFile.read(f"{directory}/../{directory.name}/./v1.key", trust) == key
        monkeypatch.chdir(directory)
        assert TrustedKeyFile.read("v1.key", trust) == key
        if os.geteuid() != 0:  # type: ignore[attr-defined,unused-ignore]
            # The same file and link, owned by a user only the first trust names.
            with pytest.raises(PermissionError):
                TrustedKeyFile.read(link, KeyFileTrust.ADMINISTRATORS_ONLY)


@unix_only
def test_read_on_unix_a_group_writable_file_is_read_only_when_its_group_is_trusted() -> None:
    with private_key_directory() as directory:
        key = wrapped()
        path = directory / "v1.key"
        path.write_bytes(key)
        path.chmod(0o660)

        assert TrustedKeyFile.read(path, unix_trust_current_user()) == key
        with pytest.raises(PermissionError, match="writable by group"):
            TrustedKeyFile.read(path, KeyFileTrust(unix_user_ids=[os.geteuid()]))  # type: ignore[attr-defined,unused-ignore]


@unix_only
def test_read_on_unix_a_plaintext_key_is_refused_once_its_location_passes() -> None:
    with private_key_directory() as directory:
        path = directory / "v1.key"
        path.write_bytes(base64.b64encode(os.urandom(32)) + b"\n")

        with pytest.raises(InvalidKeyFileError, match="unwrapped"):
            TrustedKeyFile.read(path, unix_trust_current_user())
