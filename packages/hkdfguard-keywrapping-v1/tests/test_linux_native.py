"""The Linux native library's contract, through the verified loader and the binding, against the real
KEK provider - on a TPM host, provisioned by this repository's scripts/provision-linux-test-key.sh::

    sudo scripts/provision-linux-test-key.sh
    HKDFGUARD_TEST_SERVICE=com.hkdfguard.integration.test.221 \\
    uv run pytest packages/hkdfguard-keywrapping-v1/tests/test_linux_native.py

The integration tests in test_keywrapping.py cover what every platform shares; these pin down the exact
Linux status codes, the native library's own input checks (which NativeHkdfKeyWrapperV1's validation
normally keeps it from seeing), its zeroing on failure, and the deployment path through hkdfguard.
Ported from hkdfguard-dotnet's LinuxNativeIntegrationTests and hkdfguard-go's TestLinuxNative_*.

Every test is skipped - never passed - off Linux, without the libhkdfguard1 package, or without
HKDFGUARD_TEST_SERVICE; a few need more (a second service, the policy's pinned-names allowlist, a private
directory for key files, or the hkdfguard command-line tool) and say so when they skip."""

from __future__ import annotations

import base64
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from hkdfguard.abstractions import CryptographicError, InvalidKeyFileError, ServiceNames, WrappedKeyLimits
from hkdfguard.keywrapping.v1 import NativeHkdfKeyWrapperV1
from hkdfguard.keywrapping.v1._interop._kms import DEK_LENGTH, OK, AbstractHkdfGuardKmsLibrary, CpuArchitecture
from hkdfguard.keywrapping.v1._interop._linux import LinuxHkdfGuardKmsLibrary, LinuxNativeLibraryLoader
from hkdfguard_test_support import DEFAULT_TEST_SERVICE, OTHER_SERVICE_VARIABLE, SERVICE_VARIABLE, key_directory, write_key_file

IS_LINUX = sys.platform.startswith("linux")

UNPROVISIONED_SERVICE = "hkdfguard.integrationtest.unprovisioned"
POLICY_PATH = "/etc/hkdfguard/policy.toml"
CLI = "/usr/bin/hkdfguard"

MAX_BYTES = WrappedKeyLimits.MAX_BYTES
Library = LinuxHkdfGuardKmsLibrary


# --- Gating ---------------------------------------------------------------------------------------


def _variable(name: str) -> str | None:
    return os.environ.get(name) or None


def installed_linux_library() -> str | None:
    """Where the package installed the library, or ``None`` if it isn't installed (or this is not Linux)."""
    if not IS_LINUX:
        return None
    try:
        return next((path for path in LinuxNativeLibraryLoader.candidate_paths(CpuArchitecture.current()) if os.path.isfile(path)), None)
    except OSError:
        return None  # no package for this architecture


def policy_requires_pinned_names() -> bool:
    try:
        with open(POLICY_PATH, encoding="utf-8") as policy:
            return any(line.replace(" ", "").strip() == "require_pinned_names=true" for line in policy)
    except OSError:
        return False


def skip_reason(*, needs_other_service: bool = False, needs_pinned_names_allowlist: bool = False, needs_cli: bool = False) -> str | None:
    """Why a Linux native integration test can't run here, or ``None`` if it can. The Linux library
    has no non-prompting way to ask whether a KEK exists, so the service is only ever the one named in
    HKDFGUARD_TEST_SERVICE: once it is set, a missing or failing library is a failure."""
    if not IS_LINUX:
        return "Linux only."
    if installed_linux_library() is None:
        return "The libhkdfguard1 package is not installed."
    if _variable(SERVICE_VARIABLE) is None:
        return (f"Set {SERVICE_VARIABLE} to a service provisioned with hkdfguard to run native integration tests. On a Linux TPM host, "
                f"sudo scripts/provision-linux-test-key.sh provisions {DEFAULT_TEST_SERVICE}.")
    if needs_other_service and _variable(OTHER_SERVICE_VARIABLE) is None:
        return f"Set {OTHER_SERVICE_VARIABLE} to a second provisioned service."
    if needs_pinned_names_allowlist and not policy_requires_pinned_names():
        return f"{POLICY_PATH} does not set tpm.require_pinned_names = true (scripts/provision-linux-test-key.sh does)."
    if needs_cli and not os.path.isfile(CLI):
        return f"{CLI} is not installed (the hkdfguard package)."
    return None


def linux_native_integration(*, needs_other_service: bool = False, needs_pinned_names_allowlist: bool = False,
                             needs_cli: bool = False) -> pytest.MarkDecorator:
    reason = skip_reason(needs_other_service=needs_other_service, needs_pinned_names_allowlist=needs_pinned_names_allowlist, needs_cli=needs_cli)
    return pytest.mark.skipif(reason is not None, reason=reason or "")


def service() -> str:
    name = _variable(SERVICE_VARIABLE)
    assert name is not None
    return name


def other_service() -> str:
    return _variable(OTHER_SERVICE_VARIABLE) or UNPROVISIONED_SERVICE


# --- Helpers --------------------------------------------------------------------------------------


def wrap(dek: bytes, on: str | None = None) -> bytes:
    wrapped = bytearray(MAX_BYTES)
    status, written = Library().wrap_dek(on or service(), dek, wrapped)
    assert status == OK, f"wrap_dek = {status} ({Library().describe_status(status)})"
    return bytes(wrapped[:written])


def assert_status(expected: int, actual: int) -> None:
    """The status, and that the binding describes it."""
    library = Library()
    assert actual == expected, f"status {actual} ({library.describe_status(actual)}), want {expected} ({library.describe_status(expected)})"
    assert library.describe_status(actual) is not None, f"status {actual} has no description"


def zeroed(buffer: bytearray) -> bool:
    return not any(buffer)


# --- The library's contract -----------------------------------------------------------------------


@linux_native_integration()
def test_a_wrapped_dek_round_trips_and_fits_the_key_file_limit() -> None:
    dek = os.urandom(DEK_LENGTH)

    wrapped = wrap(dek)
    recovered = bytearray(DEK_LENGTH)
    status, written = Library().unwrap_dek(service(), wrapped, recovered)

    assert_status(OK, status)
    assert written == DEK_LENGTH
    assert recovered == dek
    assert DEK_LENGTH < len(wrapped) <= MAX_BYTES


@linux_native_integration()
def test_wrapping_the_same_dek_twice_gives_different_payloads() -> None:
    # A fresh salt per payload: equal DEKs must not be recognizable from their wrapped form.
    dek = os.urandom(DEK_LENGTH)

    first = wrap(dek)
    second = wrap(dek)

    assert first != second


@linux_native_integration()
def test_generated_deks_are_distinct() -> None:
    library = Library()
    deks: set[bytes] = set()
    for _ in range(4):
        wrapped = bytearray(MAX_BYTES)
        status, written = library.generate_and_wrap_dek(service(), wrapped)
        assert_status(OK, status)

        dek = bytearray(DEK_LENGTH)
        assert_status(OK, library.unwrap_dek(service(), wrapped[:written], dek).status)
        deks.add(bytes(dek))

    assert len(deks) == 4


@linux_native_integration(needs_other_service=True)
def test_unwrapping_under_another_provisioned_service_is_a_fingerprint_mismatch_and_zeroes_the_whole_buffer() -> None:
    wrapped = wrap(os.urandom(DEK_LENGTH))
    destination = bytearray(b"\xaa" * 64)

    status, _ = Library().unwrap_dek(other_service(), wrapped, destination)

    assert_status(AbstractHkdfGuardKmsLibrary.ERR_KEK_FINGERPRINT_MISMATCH, status)
    assert zeroed(destination)


@linux_native_integration(needs_pinned_names_allowlist=True)
def test_a_service_the_allowlist_does_not_name_has_no_kek() -> None:
    library = Library()

    assert_status(AbstractHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND,
                  library.wrap_dek(UNPROVISIONED_SERVICE, bytes(DEK_LENGTH), bytearray(MAX_BYTES)).status)
    assert_status(AbstractHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND, library.generate_and_wrap_dek(UNPROVISIONED_SERVICE, bytearray(MAX_BYTES)).status)
    assert "provision" in (library.describe_status(AbstractHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND) or "")


@linux_native_integration()
def test_changing_any_byte_of_the_payload_is_refused_and_reveals_nothing() -> None:
    # Every byte is either ciphertext or bound into the AEAD's associated data and the HKDF info, so
    # no single-byte change may unwrap - to the original DEK or to any other. Each refusal can cost a
    # TPM ECDH, so this changes the first and last eight bytes and every fifth byte between: a spread
    # that lands in every field of the payload.
    library = Library()
    wrapped = wrap(os.urandom(DEK_LENGTH))
    refusals = {AbstractHkdfGuardKmsLibrary.ERR_PAYLOAD_AUTH_FAILED, AbstractHkdfGuardKmsLibrary.ERR_PAYLOAD_MALFORMED,
                AbstractHkdfGuardKmsLibrary.ERR_PAYLOAD_UNSUPPORTED, AbstractHkdfGuardKmsLibrary.ERR_KEK_FINGERPRINT_MISMATCH}

    for i in (i for i in range(len(wrapped)) if i < 8 or i >= len(wrapped) - 8 or i % 5 == 0):
        tampered = bytearray(wrapped)
        tampered[i] ^= 0x01
        destination = bytearray(b"\xaa" * DEK_LENGTH)

        status, _ = library.unwrap_dek(service(), tampered, destination)

        # A changed header byte makes the payload malformed or of an unknown version; a changed
        # fingerprint routes it to no KEK; anything else fails authentication.
        assert status in refusals, f"byte {i} of {len(wrapped)}: status {status} ({library.describe_status(status)})"
        assert zeroed(destination), f"the destination after changing byte {i}"


@linux_native_integration()
def test_a_truncated_or_extended_payload_is_refused() -> None:
    wrapped = wrap(os.urandom(DEK_LENGTH))
    destination = bytearray(DEK_LENGTH)

    for payload in (wrapped[:-1], wrapped + b"\x00", wrapped[:8]):
        assert_status(AbstractHkdfGuardKmsLibrary.ERR_PAYLOAD_MALFORMED, Library().unwrap_dek(service(), payload, destination).status)


@linux_native_integration()
def test_an_empty_payload_is_refused() -> None:
    status, _ = Library().unwrap_dek(service(), b"", bytearray(DEK_LENGTH))

    assert status in (AbstractHkdfGuardKmsLibrary.ERR_INVALID_ARGUMENT, AbstractHkdfGuardKmsLibrary.ERR_PAYLOAD_MALFORMED), f"status {status}"


@linux_native_integration()
@pytest.mark.parametrize("length", [0, 16, DEK_LENGTH - 1, DEK_LENGTH + 1, 64])
def test_a_dek_of_the_wrong_length_is_an_invalid_argument(length: int) -> None:
    assert_status(AbstractHkdfGuardKmsLibrary.ERR_INVALID_ARGUMENT, Library().wrap_dek(service(), bytes(length), bytearray(MAX_BYTES)).status)


INVALID_SERVICE_NAMES = ["", ".leading.dot", "double..dot", "has space", "slash/inside", "dash-inside", "caf" + chr(0xE9), "a" * 129]


@linux_native_integration()
@pytest.mark.parametrize("name", INVALID_SERVICE_NAMES)
def test_the_native_library_checks_service_names_itself(name: str) -> None:
    # NativeHkdfKeyWrapperV1's ServiceNames rule normally stops these before the boundary; the
    # library must refuse them on its own too, for every operation.
    assert not ServiceNames.is_valid(name)
    library = Library()

    assert_status(AbstractHkdfGuardKmsLibrary.ERR_INVALID_SERVICE_NAME, library.wrap_dek(name, bytes(DEK_LENGTH), bytearray(MAX_BYTES)).status)
    assert_status(AbstractHkdfGuardKmsLibrary.ERR_INVALID_SERVICE_NAME, library.generate_and_wrap_dek(name, bytearray(MAX_BYTES)).status)
    assert_status(AbstractHkdfGuardKmsLibrary.ERR_INVALID_SERVICE_NAME, library.unwrap_dek(name, bytes(100), bytearray(DEK_LENGTH)).status)


@linux_native_integration()
def test_a_service_name_of_the_maximum_length_is_accepted() -> None:
    # 128 characters is valid; with the allowlist it simply has no KEK, without one it may.
    status, _ = Library().wrap_dek("a" * ServiceNames.MAX_LENGTH, bytes(DEK_LENGTH), bytearray(MAX_BYTES))

    assert status != AbstractHkdfGuardKmsLibrary.ERR_INVALID_SERVICE_NAME


@linux_native_integration()
def test_a_too_small_buffer_reports_a_capacity_that_suffices() -> None:
    # The reported capacity is an upper bound for any payload (276 bytes on 0.9.0, for a 164-byte
    # payload), not the exact size of this one; it must fit a key file and be enough.
    library = Library()
    dek = os.urandom(DEK_LENGTH)

    status, required = library.wrap_dek(service(), dek, bytearray(1))
    assert_status(AbstractHkdfGuardKmsLibrary.ERR_BUFFER_TOO_SMALL, status)
    assert DEK_LENGTH < required <= MAX_BYTES

    exact = bytearray(required)
    status, written = library.wrap_dek(service(), dek, exact)
    assert status == OK
    assert DEK_LENGTH < written <= required
    payload = exact[:written]

    status, generate_required = library.generate_and_wrap_dek(service(), bytearray(1))
    assert_status(AbstractHkdfGuardKmsLibrary.ERR_BUFFER_TOO_SMALL, status)
    assert generate_required == required

    short = bytearray(b"\xaa" * (DEK_LENGTH - 1))
    status, unwrap_required = library.unwrap_dek(service(), payload, short)
    assert_status(AbstractHkdfGuardKmsLibrary.ERR_BUFFER_TOO_SMALL, status)
    assert unwrap_required == DEK_LENGTH
    assert zeroed(short)


@linux_native_integration()
def test_concurrent_callers_each_get_their_own_dek_back() -> None:
    library = Library()

    def round_trip(_: int) -> tuple[int, bool]:
        dek = os.urandom(DEK_LENGTH)
        recovered = bytearray(DEK_LENGTH)
        status, _ = library.unwrap_dek(service(), wrap(dek), recovered)
        return status, recovered == dek

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(round_trip, range(8)))

    assert results == [(OK, True)] * 8


# --- Key files, read through hkdfguard_open_file ------------------------------------------------------
#
# Each test gets a fresh private key directory and, where it needs one, one real wrapped payload. Every
# key file is written 0600 whatever the umask (hkdfguard_test_support.write_key_file), as hkdfguard wrap
# writes it. Without a private directory these tests skip, saying why - never pass.


@pytest.fixture
def key_dir(tmp_path: Path) -> Iterator[Path]:
    """A private 0700 directory outside /tmp, /var/tmp and /dev/shm (hkdfguard_test_support.key_directory):
    the library refuses a key file under any group- or world-writable directory, sticky or not."""
    with key_directory(tmp_path) as directory:
        yield directory


def reader() -> NativeHkdfKeyWrapperV1:
    # Any valid name: reading a file never touches a KEK.
    return NativeHkdfKeyWrapperV1("hkdfguard.keyfile.reader")


def refused(path: Path, error: type[OSError], status: int) -> OSError:
    """That reading ``path`` raises exactly ``error``, naming ``status`` and its meaning."""
    with pytest.raises(error) as raised:
        reader().read_key_file(path)
    assert type(raised.value) is error, f"{type(raised.value).__name__}: {raised.value}"
    assert f"status {status} (" in str(raised.value), str(raised.value)
    return raised.value


@linux_native_integration()
def test_a_key_file_reads_back_exactly_as_written(key_dir: Path) -> None:
    wrapped = wrap(os.urandom(DEK_LENGTH))

    assert reader().read_key_file(write_key_file(key_dir / "key.bin", wrapped)) == wrapped


@linux_native_integration()
def test_a_key_file_of_the_wrong_size_is_refused_as_too_short_or_too_long(key_dir: Path) -> None:
    wrapped = wrap(os.urandom(DEK_LENGTH))
    too_short, too_long = AbstractHkdfGuardKmsLibrary.ERR_FILE_TOO_SHORT, AbstractHkdfGuardKmsLibrary.ERR_FILE_TOO_LONG

    for size, status in ((0, too_short), (100, too_short), (len(wrapped) - 1, too_short), (len(wrapped) + 1, too_long), (4096, too_long)):
        contents = wrapped[:size].ljust(size, b"\x00")
        refused(write_key_file(key_dir / f"size-{size}.bin", contents), InvalidKeyFileError, status)


PLAINTEXT_FORMS: dict[str, Callable[[bytes], bytes]] = {
    "raw": lambda dek: dek,
    "hex": lambda dek: dek.hex().upper().encode("ascii"),
    "lower-hex": lambda dek: dek.hex().encode("ascii"),
    "base64": base64.b64encode,
    "base64-with-newline": lambda dek: base64.b64encode(dek) + b"\n",
}


@linux_native_integration()
@pytest.mark.parametrize("form", PLAINTEXT_FORMS)
def test_a_file_holding_what_looks_like_an_unwrapped_dek_is_refused_as_a_key_exposure(key_dir: Path, form: str) -> None:
    path = write_key_file(key_dir / f"plaintext-{form}.bin", PLAINTEXT_FORMS[form](os.urandom(DEK_LENGTH)))

    refused(path, InvalidKeyFileError, AbstractHkdfGuardKmsLibrary.ERR_FILE_PLAINTEXT_KEY)


@linux_native_integration()
def test_a_change_to_the_payloads_structure_is_refused_when_read_but_a_changed_tag_only_at_unwrap(key_dir: Path) -> None:
    # The version byte and a byte mid-payload are checked when the file is read; the AEAD tag can only
    # be checked with the KEK, so a changed tag reads fine and fails unwrap.
    wrapped = wrap(os.urandom(DEK_LENGTH))
    for position in (0, len(wrapped) // 2):
        tampered = bytearray(wrapped)
        tampered[position] ^= 0x01
        refused(write_key_file(key_dir / f"structure-{position}.bin", bytes(tampered)), InvalidKeyFileError, AbstractHkdfGuardKmsLibrary.ERR_FILE_MALFORMED)

    tag = bytearray(wrapped)
    tag[-1] ^= 0x01
    read = reader().read_key_file(write_key_file(key_dir / "tag.bin", bytes(tag)))
    destination = bytearray(DEK_LENGTH)

    with pytest.raises(CryptographicError):
        NativeHkdfKeyWrapperV1(service()).unwrap(read, destination)
    assert zeroed(destination)


@linux_native_integration()
def test_a_missing_file_or_folder_is_not_found_and_a_folder_is_not_a_key_file(key_dir: Path) -> None:
    refused(key_dir / "missing.bin", FileNotFoundError, AbstractHkdfGuardKmsLibrary.ERR_FILE_NOT_FOUND)
    refused(key_dir / "missing" / "key.bin", FileNotFoundError, AbstractHkdfGuardKmsLibrary.ERR_FILE_NOT_FOUND)
    refused(key_dir, OSError, AbstractHkdfGuardKmsLibrary.ERR_FILE_IO)


@linux_native_integration()
def test_a_link_is_followed_only_where_it_leads_is_trusted_too(key_dir: Path) -> None:
    # The library judges where a link leads, not the link: within private folders it is followed; into
    # /tmp (sticky, world-writable) it is refused, as is /tmp itself.
    wrapped = wrap(os.urandom(DEK_LENGTH))
    key = write_key_file(key_dir / "key.bin", wrapped)
    file_link = key_dir / "file-link.bin"
    file_link.symlink_to(key)
    folder_link = key_dir / "folder-link"
    folder_link.symlink_to(key_dir, target_is_directory=True)

    assert reader().read_key_file(file_link) == wrapped
    assert reader().read_key_file(folder_link / "key.bin") == wrapped

    shared = Path(tempfile.mkdtemp(prefix="hkdfguard-shared-", dir="/tmp"))
    try:
        exposed = write_key_file(shared / "key.bin", wrapped)
        into_shared = key_dir / "into-tmp.bin"
        into_shared.symlink_to(exposed)
        shared_folder_link = key_dir / "tmp-folder"
        shared_folder_link.symlink_to(shared, target_is_directory=True)

        untrusted = AbstractHkdfGuardKmsLibrary.ERR_FILE_UNTRUSTED
        refused(exposed, PermissionError, untrusted)
        refused(into_shared, PermissionError, untrusted)
        refused(shared_folder_link / "key.bin", PermissionError, untrusted)
    finally:
        shutil.rmtree(shared, ignore_errors=True)


@linux_native_integration()
def test_a_key_file_another_account_could_rewrite_is_refused_while_owner_only_and_group_read_are_not(key_dir: Path) -> None:
    # A group- or other-writable key file could be replaced by another account, so the library refuses
    # it (-39) whatever the folders above it. Group read is fine: hkdfguard wrap --group hands a key
    # file to a service's group as 0640. This is also why key files are written 0600 explicitly: an
    # Ubuntu desktop session's umask of 002 makes Python write 0664.
    path = write_key_file(key_dir / "key.bin", wrap(os.urandom(DEK_LENGTH)))
    wrapper = NativeHkdfKeyWrapperV1(service())

    for writable in (stat.S_IWGRP, stat.S_IWOTH):
        os.chmod(path, 0o644 | writable)
        with pytest.raises(PermissionError) as error:
            wrapper.read_key_file(path)
        assert f"status {AbstractHkdfGuardKmsLibrary.ERR_FILE_UNTRUSTED}" in str(error.value), f"mode {0o644 | writable:04o}: {error.value}"

    for mode in (0o600, 0o640, 0o644):
        os.chmod(path, mode)
        assert wrapper.read_key_file(path), f"mode {mode:04o}"


# --- The deployment path through hkdfguard ---------------------------------------------------------


def run_cli(*arguments: str) -> tuple[int, str]:
    completed = subprocess.run([CLI, *arguments], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60, check=False)
    return completed.returncode, completed.stdout + completed.stderr


@linux_native_integration(needs_cli=True)
def test_a_key_file_wrapped_by_the_provisioning_tool_reveals_its_dek_through_the_wrapper(key_dir: Path) -> None:
    # The deployment path: hkdfguard wraps a delivered DEK on the host, in its own process, and the
    # application reads the key file and unwraps it through this binding.
    dek = os.urandom(DEK_LENGTH)
    dek_file = key_dir / "dek"
    key_file = key_dir / "key.bin"
    descriptor = os.open(dek_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(base64.b64encode(dek))

    exit_code, output = run_cli("wrap", "--key-file-path", str(key_file), "--service-name", service(), "--dek-file", str(dek_file))
    assert exit_code == 0, f"hkdfguard wrap exited {exit_code}: {output}"
    assert key_file.stat().st_mode & 0o777 == 0o600

    wrapper = NativeHkdfKeyWrapperV1(service())
    wrapped = wrapper.read_key_file(key_file)  # through hkdfguard_open_file, which checks the directory chain
    assert wrapped == key_file.read_bytes()
    recovered = bytearray(DEK_LENGTH)
    written = wrapper.unwrap(wrapped, recovered)

    assert written == DEK_LENGTH
    assert recovered == dek


@linux_native_integration(needs_cli=True)
def test_the_provisioning_tool_reports_the_test_service_as_provisioned() -> None:
    exit_code, output = run_cli("provision", "--service-name", service())

    assert exit_code == 0, f"hkdfguard provision exited {exit_code}: {output}"


# --- The gating itself (runs everywhere) ------------------------------------------------------------


def test_without_linux_the_package_or_a_service_the_native_tests_skip_saying_why(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(SERVICE_VARIABLE, raising=False)

    reason = skip_reason()

    assert reason is not None
    if IS_LINUX and installed_linux_library() is not None:
        assert SERVICE_VARIABLE in reason and DEFAULT_TEST_SERVICE in reason
    elif IS_LINUX:
        assert "libhkdfguard1" in reason
    else:
        assert reason == "Linux only."
