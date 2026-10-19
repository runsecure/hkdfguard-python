"""The macOS loader's system-call layer against the real filesystem and Security framework, and the
installed library and provisioning tool where there are some. Ported from hkdfguard-go's TestDarwin_*;
the loader's decisions on simulated filesystems are in test_keywrapping.py and run everywhere.

Every test is skipped off macOS; those that need the installed library (system-wide under
/Library/Application Support/HkdfGuard/v1, or per user under ~/.hkdfguard/v1) or its provisioning tool,
hkdfguard-v1-initialize beside it, are skipped - never passed - when it isn't there."""

from __future__ import annotations

import errno
import os
import subprocess
import sys
from pathlib import Path

import pytest
from hkdfguard.keywrapping.v1 import NativeLibraryNotFoundError
from hkdfguard.keywrapping.v1._interop import _macos
from hkdfguard.keywrapping.v1._interop._macos import MacOsNativeLibraryLoader, PathChoice
from hkdfguard.keywrapping.v1._interop._unix import UnixFileStatus, probe

IS_MACOS = sys.platform == "darwin"
pytestmark = pytest.mark.skipif(not IS_MACOS, reason="macOS only.")

Loader = MacOsNativeLibraryLoader

PROVISIONING_TOOL = "hkdfguard-v1-initialize"
DEFAULT_MACOS_SERVICE = "com.hkdfguard.integration.test.221"
UNPROVISIONED_SERVICE = "hkdfguard.integrationtest.unprovisioned"
SERVICE_VARIABLE = "HKDFGUARD_TEST_SERVICE"


def installed_library() -> PathChoice | None:
    """The install the loader would choose, or ``None`` when there is none."""
    try:
        return Loader.choose_path(probe, os.path.expanduser("~"))
    except NativeLibraryNotFoundError:
        return None


def provisioning_tool() -> str | None:
    """The hkdfguard-v1-initialize installed beside the library the loader would choose, if any."""
    choice = installed_library()
    if choice is None:
        return None
    tool = str(Path(choice.path).with_name(PROVISIONING_TOOL))
    return tool if os.path.isfile(tool) else None


def kek_status(tool: str, service: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([tool, "status", "--service-name", service], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                          timeout=60, check=False)


def macos_test_environment(default_service: str) -> tuple[str | None, str]:
    """Whether the default test service is provisioned, asked of the installed provisioning tool. The
    tool created the KEK, so it is on the keychain item's access list and never prompts; asking the
    library from this process would. ``(service, "")`` to run against it - also when the tool can't
    answer, so that failure is reported - or ``(None, why)`` to skip."""
    tool = provisioning_tool()
    if tool is None:
        return default_service, ""
    try:
        completed = kek_status(tool, default_service)
    except (OSError, subprocess.TimeoutExpired):
        return default_service, ""
    output = completed.stdout + completed.stderr
    if completed.returncode == 0 and "kek: absent" in output:
        return None, (f"The test KEK '{default_service}' is not provisioned. Run {PROVISIONING_TOOL} provision --service-name "
                      f"{default_service}, or set {SERVICE_VARIABLE} to a provisioned service.")
    return default_service, ""


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
    tool = provisioning_tool()
    if tool is None:
        pytest.skip(f"{PROVISIONING_TOOL} is not installed beside the native library.")

    completed = kek_status(tool, UNPROVISIONED_SERVICE)

    assert completed.returncode == 0 and "kek: absent" in completed.stdout, f"status exited {completed.returncode}: {completed.stdout}{completed.stderr}"


def test_the_default_test_service_is_found_only_when_provisioned() -> None:
    tool = provisioning_tool()
    if tool is None:
        pytest.skip(f"{PROVISIONING_TOOL} is not installed beside the native library.")
    completed = kek_status(tool, DEFAULT_MACOS_SERVICE)
    assert completed.returncode == 0, f"status exited {completed.returncode}: {completed.stdout}{completed.stderr}"

    service, reason = macos_test_environment(DEFAULT_MACOS_SERVICE)

    provisioned = "kek: present" in completed.stdout
    assert (service is not None) == provisioned, f"environment = {service!r} ({reason}), but the tool reports provisioned = {provisioned}"
