from __future__ import annotations

import io
import os
import platform
import shutil
import sys
import uuid
from pathlib import Path

import pytest
from hkdfguard.securefile import FileTooLargeError, KeyFileTrust, TrustedFile
from hkdfguard_test_support import current_user_trust, trusted_directory

IS_WINDOWS = sys.platform == "win32"
IS_UNIX = sys.platform.startswith("linux") or (sys.platform == "darwin" and platform.machine() == "arm64")
real_files = pytest.mark.skipif(not (IS_WINDOWS or IS_UNIX), reason="Windows, Linux and Apple silicon macOS only.")
unix_only = pytest.mark.skipif(not IS_UNIX, reason="Linux and Apple silicon macOS only.")


def running_as_root() -> bool:
    return not IS_WINDOWS and os.geteuid() == 0  # type: ignore[attr-defined,unused-ignore]


# --- Contents --------------------------------------------------------------------------------------


def test_read_contents_returns_what_was_read_in_a_buffer_the_caller_owns() -> None:
    contents = os.urandom(300)

    result = TrustedFile.read_contents(io.BytesIO(contents).readinto, "secret", 1024)

    assert result == contents
    assert isinstance(result, bytearray)


def test_read_contents_an_empty_file_is_returned_empty() -> None:
    assert TrustedFile.read_contents(io.BytesIO(b"").readinto, "secret", 16) == bytearray()


def test_read_contents_exactly_the_limit_is_accepted() -> None:
    contents = os.urandom(64)

    assert TrustedFile.read_contents(io.BytesIO(contents).readinto, "secret", 64) == contents


def test_read_contents_over_the_limit_is_refused_reading_only_one_byte_past() -> None:
    stream = io.BytesIO(bytes(4096))

    with pytest.raises(FileTooLargeError, match="'secret' is larger than 100 bytes") as error:
        TrustedFile.read_contents(stream.readinto, "secret", 100)
    assert stream.tell() == 101
    assert isinstance(error.value, OSError)


def test_read_contents_reads_until_the_end_however_the_reads_are_split() -> None:
    contents = os.urandom(200)
    chunks = [contents[:1], contents[1:150], contents[150:]]

    def readinto(view: memoryview) -> int:
        if not chunks:
            return 0
        chunk = chunks.pop(0)
        view[:len(chunk)] = chunk
        return len(chunk)

    assert TrustedFile.read_contents(readinto, "secret", 256) == contents


@pytest.mark.parametrize("size", [32, 128])
def test_read_contents_zeroes_its_buffer_whether_it_returns_or_refuses(size: int) -> None:
    limit = 64
    seen: list[memoryview] = []

    def readinto(view: memoryview) -> int:
        seen.append(view)
        if len(seen) > 1:
            return 0
        count = min(size, len(view))
        view[:count] = b"\xab" * count
        return count

    if size > limit:
        with pytest.raises(FileTooLargeError):
            TrustedFile.read_contents(readinto, "secret", limit)
    else:
        assert TrustedFile.read_contents(readinto, "secret", limit) == b"\xab" * size
    assert bytes(seen[0].obj) == bytes(limit + 1)


def test_parse_contents_hands_a_read_only_view_to_parse_and_zeroes_the_buffer_after() -> None:
    contents = os.urandom(48)
    views: list[memoryview] = []

    def parse(view: memoryview) -> bytes:
        views.append(view)
        assert view.readonly
        return bytes(view)

    assert TrustedFile.parse_contents(io.BytesIO(contents).readinto, "secret", 64, parse) == contents
    with pytest.raises(ValueError, match="released"):
        len(views[0])


def test_parse_contents_zeroes_the_buffer_when_parse_raises() -> None:
    buffers: list[bytearray] = []

    def readinto(view: memoryview) -> int:
        if buffers:
            return 0
        buffers.append(view.obj)  # type: ignore[arg-type]
        view[:8] = b"\xcd" * 8
        return 8

    def parse(view: memoryview) -> None:
        raise ValueError("not a certificate")

    with pytest.raises(ValueError, match="not a certificate"):
        TrustedFile.parse_contents(readinto, "secret", 16, parse)
    assert buffers[0] == bytes(17)


def test_parse_contents_over_the_limit_is_refused_without_calling_parse() -> None:
    called: list[bool] = []

    with pytest.raises(FileTooLargeError):
        TrustedFile.parse_contents(io.BytesIO(bytes(32)).readinto, "secret", 16, lambda view: called.append(True))
    assert not called


def test_an_error_reading_is_passed_on() -> None:
    def readinto(view: memoryview) -> int:
        raise OSError("disk on fire")

    with pytest.raises(OSError, match="disk on fire"):
        TrustedFile.read_contents(readinto, "secret", 16)


# --- Arguments ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(("path", "expected"), [(None, TypeError), (b"secret", TypeError), ("", ValueError), ("se\0cret", ValueError)])
def test_read_refuses_a_missing_or_unusable_path_before_anything_is_examined(path: object, expected: type[Exception]) -> None:
    with pytest.raises(expected):
        TrustedFile.read(path, KeyFileTrust.ADMINISTRATORS_ONLY, 16)  # type: ignore[arg-type]
    with pytest.raises(expected):
        TrustedFile.read_with(path, KeyFileTrust.ADMINISTRATORS_ONLY, 16, bytes)  # type: ignore[arg-type]


@pytest.mark.parametrize("trust", [None, "S-1-5-18"])
def test_read_refuses_a_missing_trust(trust: object) -> None:
    with pytest.raises(TypeError):
        TrustedFile.read("secret", trust, 16)  # type: ignore[arg-type]


@pytest.mark.parametrize(("max_bytes", "expected"), [(0, ValueError), (-1, ValueError), (sys.maxsize, ValueError), (None, TypeError),
                                                     (True, TypeError), (16.0, TypeError)])
def test_read_refuses_a_limit_that_isnt_a_positive_int_one_buffer_can_hold(max_bytes: object, expected: type[Exception]) -> None:
    with pytest.raises(expected):
        TrustedFile.read("secret", KeyFileTrust.ADMINISTRATORS_ONLY, max_bytes)  # type: ignore[arg-type]


def test_read_with_refuses_a_parse_that_isnt_callable() -> None:
    with pytest.raises(TypeError, match="parse"):
        TrustedFile.read_with("secret", KeyFileTrust.ADMINISTRATORS_ONLY, 16, None)  # type: ignore[arg-type]


def test_read_off_the_supported_platforms_is_not_implemented(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "freebsd14")
    with pytest.raises(NotImplementedError, match="Windows, Linux and macOS only"):
        TrustedFile.read("/etc/hkdfguard/secret", KeyFileTrust.ADMINISTRATORS_ONLY, 16)


def test_read_on_an_intel_mac_is_not_implemented(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")
    with pytest.raises(NotImplementedError, match="Apple silicon Macs only; this process is x86_64"):
        TrustedFile.read("/etc/hkdfguard/secret", KeyFileTrust.ADMINISTRATORS_ONLY, 16)


# --- Real files --------------------------------------------------------------------------------------


@real_files
def test_read_a_file_in_a_trusted_folder_is_read_whatever_its_contents() -> None:
    # 32 random bytes: a key file would be refused as an unwrapped key; TrustedFile has no such rule.
    contents = os.urandom(32)
    with trusted_directory() as directory:
        path = directory / "secret"
        path.write_bytes(contents)

        assert TrustedFile.read(path, current_user_trust(), 64) == contents
        assert TrustedFile.read(str(path), current_user_trust(), 32) == contents
        assert TrustedFile.read_with(path, current_user_trust(), 64, bytes) == contents


@real_files
def test_read_an_empty_file_is_read_as_empty() -> None:
    with trusted_directory() as directory:
        path = directory / "empty"
        path.write_bytes(b"")

        assert TrustedFile.read(path, current_user_trust(), 16) == bytearray()
        assert TrustedFile.read_with(path, current_user_trust(), 16, len) == 0


@real_files
def test_read_a_file_over_the_limit_is_refused() -> None:
    with trusted_directory() as directory:
        path = directory / "huge"
        path.write_bytes(bytes(1025))

        with pytest.raises(FileTooLargeError, match="larger than 1024 bytes"):
            TrustedFile.read(path, current_user_trust(), 1024)
        with pytest.raises(FileTooLargeError):
            TrustedFile.read_with(path, current_user_trust(), 1024, bytes)


@real_files
def test_read_a_missing_file_or_folder_is_not_found_and_distinguishable_from_a_refusal() -> None:
    with trusted_directory() as directory:
        for missing in (directory / "missing", directory / "missing" / "secret"):
            with pytest.raises(FileNotFoundError):
                TrustedFile.read(missing, current_user_trust(), 16)
            with pytest.raises(FileNotFoundError):
                TrustedFile.read_with(missing, current_user_trust(), 16, bytes)


@real_files
def test_read_a_file_in_the_users_own_folder_is_refused_by_default() -> None:
    if running_as_root():
        pytest.skip("Running as root, whose files are trusted.")
    with trusted_directory() as directory:
        path = directory / "secret"
        path.write_bytes(b"enc::v1::AAAA")

        with pytest.raises(PermissionError, match="not trusted"):
            TrustedFile.read(path, KeyFileTrust.ADMINISTRATORS_ONLY, 64)
        with pytest.raises(PermissionError, match="not trusted"):
            TrustedFile.read_with(path, KeyFileTrust.ADMINISTRATORS_ONLY, 64, bytes)


@unix_only
def test_read_on_unix_a_file_under_the_shared_temp_directory_is_refused() -> None:
    # /tmp is writable by everyone (sticky or not), so nothing beneath it is trusted.
    directory = Path("/tmp") / f"hkdfguard-{uuid.uuid4().hex}"
    directory.mkdir()
    try:
        path = directory / "secret"
        path.write_bytes(b"enc::v1::AAAA")

        with pytest.raises(PermissionError, match="not trusted"):
            TrustedFile.read(path, current_user_trust(), 64)
    finally:
        shutil.rmtree(directory)
