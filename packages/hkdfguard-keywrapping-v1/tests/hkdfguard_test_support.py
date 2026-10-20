"""What the native integration tests in every package share: the one test service, how it is chosen,
where a test may write a key file the native library reads, and the deadline on the first native
call. Not part of any distribution: the workspace's pytest and mypy settings put this directory on
the import path."""

from __future__ import annotations

import contextlib
import ctypes
import functools
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

import pytest

# --- The test service -------------------------------------------------------------------------------

DEFAULT_TEST_SERVICE = "com.hkdfguard.integration.test.221"
"""The test KEK every platform's provisioning creates and every HkdfGuard port shares:
scripts/provision-windows-test-key.ps1, scripts/provision-linux-test-key.sh, and
hkdfguard-v1-initialize on macOS."""

SERVICE_VARIABLE = "HKDFGUARD_TEST_SERVICE"
"""Names a service already provisioned on this machine. It always wins over DEFAULT_TEST_SERVICE,
and setting it means the native tests must run."""

OTHER_SERVICE_VARIABLE = "HKDFGUARD_TEST_SERVICE_OTHER"
"""An optional second provisioned service, for the cross-service isolation tests."""

MACOS_PROVISIONING_TOOL = "hkdfguard-v1-initialize"


def kek_exists(service: str) -> tuple[int, bool]:
    """hkdfguard_kek_exists(const char* service, int32_t* out_exists) on the library the verified
    Windows loader loaded: the library's status, and whether the KEK exists when it is 0."""
    from hkdfguard.keywrapping.v1._interop._kms import OK
    from hkdfguard.keywrapping.v1._interop._windows import WindowsNativeLibraryLoader

    function = WindowsNativeLibraryLoader.load().hkdfguard_kek_exists
    function.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int32)]
    function.restype = ctypes.c_int
    exists = ctypes.c_int32()
    status = int(function(service.encode("utf-8"), ctypes.byref(exists)))
    return status, status == OK and exists.value != 0


def windows_test_environment(default_service: str) -> tuple[str | None, str]:
    """Whether the installed Windows library reports the default test service provisioned and usable.
    ``(service, "")`` to run against it - also when the library can't answer, so that failure is
    reported - or ``(None, why)`` to skip."""
    from hkdfguard.keywrapping.v1._interop._kms import AbstractHkdfGuardKmsLibrary
    from hkdfguard.keywrapping.v1._interop._windows import WindowsNativeLibraryLoader

    if not os.path.isfile(WindowsNativeLibraryLoader.installed_path()):
        return None, f"The native KMS library is not installed at {WindowsNativeLibraryLoader.installed_path()}."
    try:
        status, exists = kek_exists(default_service)
    except Exception:
        return default_service, ""
    if status == 0 and exists:
        return default_service, ""
    if status in (0, AbstractHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND):
        return None, (f"The test KEK '{default_service}' is not provisioned. Run scripts/provision-windows-test-key.ps1 from an elevated PowerShell, "
                      f"or set {SERVICE_VARIABLE} to a provisioned service.")
    if status == AbstractHkdfGuardKmsLibrary.ERR_KEK_ACCESS_DENIED:
        return None, (f"The test KEK '{default_service}' exists, but this account may not use it. Add it to the HkdfGuardUsers group "
                      "(then sign out and in), or run the tests elevated.")
    return default_service, ""


def macos_installed_library() -> str | None:
    """The macOS install the loader would choose, or ``None`` when there is none."""
    from hkdfguard.keywrapping.v1 import NativeLibraryNotFoundError
    from hkdfguard.keywrapping.v1._interop._macos import MacOsNativeLibraryLoader
    from hkdfguard.keywrapping.v1._interop._unix import probe

    try:
        return MacOsNativeLibraryLoader.choose_path(probe, os.path.expanduser("~")).path
    except NativeLibraryNotFoundError:
        return None


def macos_provisioning_tool() -> str | None:
    """The hkdfguard-v1-initialize installed beside the library the macOS loader would choose, if any."""
    library = macos_installed_library()
    if library is None:
        return None
    tool = str(Path(library).with_name(MACOS_PROVISIONING_TOOL))
    return tool if os.path.isfile(tool) else None


def macos_kek_status(tool: str, service: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([tool, "status", "--service-name", service], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                          timeout=60, check=False)


def macos_test_environment(default_service: str) -> tuple[str | None, str]:
    """Whether the default test service is provisioned, asked of the installed provisioning tool. The
    tool created the KEK, so it is on the keychain item's access list and never prompts; asking the
    library from this process would. ``(service, "")`` to run against it - also when the tool can't
    answer, so that failure is reported - or ``(None, why)`` to skip."""
    if macos_installed_library() is None:
        return None, "The macOS native KMS library is not installed."
    tool = macos_provisioning_tool()
    if tool is None:
        return default_service, ""
    try:
        completed = macos_kek_status(tool, default_service)
    except (OSError, subprocess.TimeoutExpired):
        return default_service, ""
    output = completed.stdout + completed.stderr
    if completed.returncode == 0 and "kek: absent" in output:
        return None, (f"The test KEK '{default_service}' is not provisioned. Run {MACOS_PROVISIONING_TOOL} provision --service-name "
                      f"{default_service}, or set {SERVICE_VARIABLE} to a provisioned service.")
    return default_service, ""


@functools.cache
def provisioned_service() -> tuple[str | None, str]:
    """The service native integration tests run against, chosen once per process: SERVICE_VARIABLE if
    set; otherwise DEFAULT_TEST_SERVICE where the platform can tell, without prompting, that it is
    provisioned (Windows asks the installed library, macOS the provisioning tool). Linux has no such
    question, so there the service is only ever the one named in SERVICE_VARIABLE. ``(None, why)``
    when there is none."""
    explicit = os.environ.get(SERVICE_VARIABLE)
    if explicit:
        return explicit, ""
    if sys.platform == "win32":
        return windows_test_environment(DEFAULT_TEST_SERVICE)
    if sys.platform == "darwin":
        return macos_test_environment(DEFAULT_TEST_SERVICE)
    return None, (f"Set {SERVICE_VARIABLE} to a service provisioned with hkdfguard to run native integration tests. On a Linux TPM host, "
                  f"sudo scripts/provision-linux-test-key.sh provisions {DEFAULT_TEST_SERVICE}.")


def native_test_service() -> str:
    """The provisioned service, after its first native call has answered in time (await_native_access);
    skips the test when there is none."""
    name, reason = provisioned_service()
    if name is None:
        pytest.skip(reason)
    await_native_access(name)
    return name


# --- The first native call on macOS -------------------------------------------------------------------
#
# In the macOS library's legacy keychain mode the KEK's access list names the binary that created it
# (the provisioning tool), so the first call from any other binary - this Python - is answered with a
# keychain dialog in a logged-in session (click "Always Allow"), or with KEK_ACCESS_DENIED (-18) in a
# session without one. A dialog nobody answers blocks the call forever; await_native_access turns
# that into a failure that says so. Ported from hkdfguard-go's awaitNativeAccess.

NATIVE_CALL_TIMEOUT = 60.0
"""Seconds the first native call under the test service may take."""

_first_call_failures: dict[str, str | None] = {}
_first_call_lock = threading.Lock()


def _generate_and_wrap(service: str) -> None:
    from hkdfguard.abstractions import WrappedKeyLimits
    from hkdfguard.keywrapping.v1 import NativeHkdfKeyWrapperV1

    NativeHkdfKeyWrapperV1(service).generate_and_wrap(bytearray(WrappedKeyLimits.MAX_BYTES))


def await_native_access(service: str, first_call: Callable[[str], object] = _generate_and_wrap, *, timeout: float = NATIVE_CALL_TIMEOUT,
                        platform: str = sys.platform) -> None:
    """On macOS, makes the first native call under ``service`` in a worker thread with a deadline,
    once per process, and fails the test - and every later one under that service - with what to do
    if it hasn't returned, instead of hanging the run. What the call answers is left to each test.
    Elsewhere nothing prompts, so it does nothing."""
    if platform != "darwin":
        return
    with _first_call_lock:
        if service not in _first_call_failures:
            # A daemon thread, not an executor: a call stuck behind a dialog must not hold up the
            # interpreter's exit as well.
            worker = threading.Thread(target=_ignoring_errors, args=(first_call, service), name=f"first native call ({service})", daemon=True)
            worker.start()
            worker.join(timeout)
            _first_call_failures[service] = None if not worker.is_alive() else (
                f"The first native call under service '{service}' has not returned after {timeout:g} seconds. On macOS the KEK's keychain "
                "item is asking for access in a dialog: click \"Always Allow\" (a newly installed or updated Python asks once). In a "
                "session with no UI the library reports KEK_ACCESS_DENIED (-18) instead; run the tests from a logged-in session.")
        failure = _first_call_failures[service]
    if failure is not None:
        pytest.fail(failure)


def _ignoring_errors(call: Callable[[str], object], service: str) -> None:
    with contextlib.suppress(Exception):  # each test checks what the library answers; only the time matters here
        call(service)


# --- Directories for key files ------------------------------------------------------------------------


def long_path(path: Path) -> Path:
    """``path`` with every 8.3 short name expanded. hkdfguard_open_file refuses a short name anywhere
    in a path, and Windows can hand out %TEMP% - and so pytest's tmp_path - in short form (for example
    C:\\Users\\RUNNER~1\\... on GitHub-hosted runners)."""
    if sys.platform == "win32":
        buffer = ctypes.create_unicode_buffer(32_767)
        length = ctypes.WinDLL("kernel32", use_last_error=True).GetLongPathNameW(str(path), buffer, len(buffer))
        if 0 < length < len(buffer):
            return Path(buffer.value)
    return path


PRIVATE_ROOT_NAME = "hkdfguard-tests"


def untrusted_directory(directory: Path, uid: int) -> str | None:
    """Why the Linux native library would refuse a key file in ``directory``, or ``None`` if it
    wouldn't: every directory from it up to / must be a real directory, owned by root or ``uid``, and
    writable by neither its group nor other users - sticky or not, so nothing under /tmp, /var/tmp or
    /dev/shm passes."""
    current = Path(os.path.abspath(directory))
    while True:
        try:
            status = os.lstat(current)
        except OSError as error:
            return f"'{current}' can't be examined ({error.strerror})"
        if stat.S_ISLNK(status.st_mode):
            return f"'{current}' is a symbolic link"
        if not stat.S_ISDIR(status.st_mode):
            return f"'{current}' is not a directory"
        if status.st_uid not in (0, uid):
            return f"'{current}' is owned by uid {status.st_uid}, not root or uid {uid}"
        if status.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            sticky = ", sticky, which does not make it trusted" if status.st_mode & stat.S_ISVTX else ""
            return f"'{current}' is writable by its group or by other users (mode {stat.S_IMODE(status.st_mode):04o}{sticky})"
        if current.parent == current:
            return None
        current = current.parent


def private_key_directory_root(environ: Mapping[str, str], uid: int, account_home: str) -> tuple[Path | None, str]:
    """Where key directories are made on Linux: ``$XDG_RUNTIME_DIR/hkdfguard-tests`` when
    XDG_RUNTIME_DIR is set and trusted, otherwise ``~/.cache/hkdfguard-tests`` (HOME, or
    ``account_home`` without it) - each created 0700 if missing and its whole chain checked with
    untrusted_directory - or ``(None, why)`` when neither will do."""
    candidates: list[tuple[str, str | None, tuple[str, ...]]] = [
        ("XDG_RUNTIME_DIR", environ.get("XDG_RUNTIME_DIR") or None, (PRIVATE_ROOT_NAME,)),
        ("HOME", environ.get("HOME") or account_home or None, (".cache", PRIVATE_ROOT_NAME)),
    ]
    reasons: list[str] = []
    for variable, value, beneath in candidates:
        if value is None:
            reasons.append(f"{variable} is not set")
            continue
        if not os.path.isabs(value):
            reasons.append(f"{variable} '{value}' is not an absolute path")
            continue
        base = Path(os.path.realpath(value))
        why = untrusted_directory(base, uid)
        if why is None:
            root = base.joinpath(*beneath)
            try:
                for depth in range(1, len(beneath) + 1):
                    base.joinpath(*beneath[:depth]).mkdir(mode=0o700, exist_ok=True)
            except OSError as error:
                why = f"'{root}' can't be created ({error.strerror})"
            else:
                why = untrusted_directory(root, uid)
                if why is None:
                    return root, ""
        reasons.append(f"{variable} ({value}): {why}")
    return None, ("No private directory for key files: the Linux native library refuses a key file under any directory its group or "
                  "other users can write, sticky or not (so nothing under /tmp, /var/tmp or /dev/shm), and " + "; ".join(reasons) + ".")


@contextmanager
def private_key_directory(environ: Mapping[str, str] | None = None) -> Iterator[Path]:
    """A new 0700 directory under private_key_directory_root, removed afterwards; skips the test when
    there is no such root. Linux (or another POSIX system) only."""
    if sys.platform == "win32":
        raise NotImplementedError("POSIX only.")
    import pwd

    uid = os.geteuid()
    try:
        account_home = pwd.getpwuid(uid).pw_dir
    except KeyError:
        account_home = ""
    root, reason = private_key_directory_root(os.environ if environ is None else environ, uid, account_home)
    if root is None:
        pytest.skip(reason)
    directory = Path(tempfile.mkdtemp(dir=root))  # mode 0700
    try:
        why = untrusted_directory(directory, uid)
        if why is not None:
            pytest.fail(f"The private key directory {directory} is not trusted: {why}.")
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


@contextmanager
def key_directory(tmp_path: Path) -> Iterator[Path]:
    """Where a test writes a file the native library reads (hkdfguard_open_file, read_key_file) or the
    hkdfguard command-line tool writes. On Linux, a private directory outside the shared temporary
    directories (private_key_directory), since pytest's tmp_path is under /tmp and the library
    refuses it with ERR_FILE_UNTRUSTED (-39); on Windows, tmp_path in long form (long_path);
    elsewhere tmp_path."""
    if sys.platform == "linux":
        with private_key_directory() as directory:
            yield directory
    else:
        yield long_path(tmp_path)
