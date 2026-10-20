"""The macOS loader's system-call layer against the real filesystem and Security framework, and the
installed library and provisioning tool where there are some. Ported from hkdfguard-go's TestDarwin_*;
the loader's decisions on simulated filesystems are in test_keywrapping.py and run everywhere.

Every test is skipped off macOS; those that need the installed library (system-wide under
/Library/Application Support/HkdfGuard/v1, or per user under ~/.hkdfguard/v1) or its provisioning tool,
hkdfguard-v1-initialize beside it, are skipped - never passed - when it isn't there."""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import pytest
from hkdfguard.abstractions import WrappedKeyLimits
from hkdfguard.keywrapping.v1 import NativeHkdfKeyWrapperV1, NativeLibraryNotFoundError
from hkdfguard.keywrapping.v1._interop import _macos
from hkdfguard.keywrapping.v1._interop._macos import MacOsNativeLibraryLoader, PathChoice
from hkdfguard.keywrapping.v1._interop._unix import UnixFileStatus, probe
from hkdfguard_test_support import (
    DEFAULT_TEST_SERVICE,
    MACOS_PROVISIONING_TOOL,
    SERVICE_VARIABLE,
    macos_kek_status,
    macos_provisioning_tool,
    macos_test_environment,
    native_test_service,
    provisioned_service,
)

IS_MACOS = sys.platform == "darwin"
pytestmark = pytest.mark.skipif(not IS_MACOS, reason="macOS only.")

Loader = MacOsNativeLibraryLoader

PROVISIONING_TOOL = MACOS_PROVISIONING_TOOL
UNPROVISIONED_SERVICE = "hkdfguard.integrationtest.unprovisioned"


def installed_library() -> PathChoice | None:
    """The install the loader would choose, or ``None`` when there is none."""
    try:
        return Loader.choose_path(probe, os.path.expanduser("~"))
    except NativeLibraryNotFoundError:
        return None


# --- The loader against the real filesystem and Security framework ---------------------------------


def test_the_installed_library_passes_every_check() -> None:
    choice = installed_library()
    if choice is None:
        pytest.skip("The macOS native KMS library is not installed.")

    owners = [0] if choice.is_system else [0, os.geteuid()]  # type: ignore[attr-defined,unused-ignore]
    Loader.verify_location(choice.path, UnixFileStatus.of, owners)
    Loader.verify_signature(choice.path, _macos._check_code_signature)


def test_the_provisioning_tool_is_signed_by_the_team_but_refused() -> None:
    # Installed beside the library and signed by the same team: only the identifier in the code
    # requirement tells them apart.
    tool = f"{Loader.SYSTEM_DIRECTORY}/{PROVISIONING_TOOL}"
    if not os.path.isfile(tool):
        pytest.skip(f"{tool} is not installed.")

    with pytest.raises(PermissionError, match=Loader.TEAM_ID):
        Loader.verify_signature(tool, _macos._check_code_signature)


def test_an_unsigned_file_is_refused(tmp_path: Path) -> None:
    path = tmp_path / Loader.FILE_NAME
    path.write_bytes(b"\xcf\xfa\xed\xfe")

    with pytest.raises(PermissionError, match=Loader.TEAM_ID):
        Loader.verify_signature(str(path), _macos._check_code_signature)


def test_a_user_writable_temporary_directory_fails_the_location_check(tmp_path: Path) -> None:
    # The planting scenario: a correctly named file somewhere the system install check would refuse.
    # The temporary directory is owned by this user, never root, so a system-owner check fails.
    path = tmp_path / Loader.FILE_NAME
    path.write_bytes(b"")
    resolved = os.path.realpath(path)  # /var -> /private/var

    with pytest.raises(PermissionError, match="owned by uid"):
        Loader.verify_location(resolved, UnixFileStatus.of, [0])


def test_probe_distinguishes_missing_from_present() -> None:
    assert probe("/") == 0
    assert probe("/definitely/not/here") == errno.ENOENT


# --- The provisioning tool and the test service ------------------------------------------------------


def test_the_provisioning_tool_reports_an_unprovisioned_service_as_absent() -> None:
    tool = macos_provisioning_tool()
    if tool is None:
        pytest.skip(f"{PROVISIONING_TOOL} is not installed beside the native library.")

    completed = macos_kek_status(tool, UNPROVISIONED_SERVICE)

    assert completed.returncode == 0 and "kek: absent" in completed.stdout, f"status exited {completed.returncode}: {completed.stdout}{completed.stderr}"


def test_the_default_test_service_is_found_only_when_provisioned() -> None:
    tool = macos_provisioning_tool()
    if tool is None:
        pytest.skip(f"{PROVISIONING_TOOL} is not installed beside the native library.")
    completed = macos_kek_status(tool, DEFAULT_TEST_SERVICE)
    assert completed.returncode == 0, f"status exited {completed.returncode}: {completed.stdout}{completed.stderr}"

    service, reason = macos_test_environment(DEFAULT_TEST_SERVICE)

    provisioned = "kek: present" in completed.stdout
    assert (service is not None) == provisioned, f"environment = {service!r} ({reason}), but the tool reports provisioned = {provisioned}"


def test_without_the_variable_the_shared_service_is_the_default_test_service_when_provisioned() -> None:
    # What the service fixtures in test_keywrapping.py and test_dataencryptionkey.py resolve to here.
    if os.environ.get(SERVICE_VARIABLE):
        pytest.skip(f"{SERVICE_VARIABLE} is set, so it is the service.")

    assert provisioned_service() == macos_test_environment(DEFAULT_TEST_SERVICE)


def test_the_resolved_service_answers_its_first_native_call_before_the_deadline() -> None:
    # The first call from this Python can wait on a keychain dialog: native_test_service makes it
    # with a deadline and fails, saying so, instead of hanging the run.
    service = native_test_service()

    wrapper = NativeHkdfKeyWrapperV1(service)
    wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
    length = wrapper.generate_and_wrap(wrapped)
    assert wrapper.unwrap(wrapped[:length], bytearray(32)) == 32
