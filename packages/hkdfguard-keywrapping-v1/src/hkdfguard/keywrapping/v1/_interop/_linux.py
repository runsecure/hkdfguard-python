"""The Linux native KMS binding, and the loader that verifies libhkdfguard.so.1 before mapping it."""

from __future__ import annotations

import ctypes
import errno
import os
import re
import subprocess
import threading
from collections.abc import Callable, Mapping, Sequence
from typing import Any, ClassVar, Final

from hkdfguard.keywrapping.v1._interop._elf import ElfDependencies
from hkdfguard.keywrapping.v1._interop._kms import CpuArchitecture, KmsFunctions, NativeKmsLibrary, NativeLibraryNotFoundError
from hkdfguard.keywrapping.v1._interop._unix import UnixFileStatus, UnixFileType, probe


class LinuxNativeLibraryLoader:
    """Loads the Linux native KMS library from its package's install location and nowhere else. The
    library receives every plaintext DEK on unwrap and chooses every "random" DEK on
    generate-and-wrap, and the tpm2-tss library it loads receives every ECDH shared secret, so
    loading an impostor of either would hand over every key. ``ctypes.CDLL`` of a bare name would
    search LD_LIBRARY_PATH; this loader replaces that search.

    1. **Location.** The file the libhkdfguard1 package installs: the Debian multiarch directory
       (/usr/lib/x86_64-linux-gnu or /usr/lib/aarch64-linux-gnu) if it is there, otherwise
       /usr/lib64 (the RPM packages). Only "nothing is there" moves on to the next location; a path
       that can't be examined is refused.
    2. **Path integrity.** Every directory walked through, every symbolic link followed, and the
       file itself must be owned by root, and no directory or file may be writable by its group or
       by others. Symbolic links are followed component by component, each one checked where it
       lies, so a link can only lead somewhere root chose (/lib to usr/lib, say).
    3. **Environment.** An absolute path is never searched for, but the library's dependencies are
       found by name: through LD_LIBRARY_PATH, and after LD_PRELOAD and LD_AUDIT objects that can
       interpose on any symbol. So every directory on LD_LIBRARY_PATH and every path-named
       LD_PRELOAD or LD_AUDIT object must pass the same path checks, and none may be relative, empty
       (the working directory) or use $ORIGIN-style substitutions. Both the environment the process
       started with (/proc/self/environ, what the dynamic linker read) and the current one
       (``os.environ``) are checked.
    4. **What would be loaded.** Before dlopen, the process's own dynamic linker (PT_INTERP of
       /proc/self/exe, which must pass the path checks) is asked, in list mode (``ld.so --list``,
       the mechanism ldd uses), where it would find every object the library pulls in, under the
       LD_LIBRARY_PATH and LD_PRELOAD the process started with. List mode resolves exactly as
       dlopen would - RUNPATH, ld.so.cache and all - but runs none of the libraries' code, so every
       path it reports must pass the path checks before any of it can run here. A name it can't
       find refuses the load.
    5. **What was loaded.** After dlopen, dladdr must place the library's export in the verified
       file, and every object in its dependency closure (read from each file's DT_NEEDED entries)
       must be bound to a file that passes the path checks. This catches what list mode can't see:
       a dependency name the process had already bound to some other object before the library was
       loaded. On failure the library is unloaded - though, as on macOS, any initializer an
       impostor had has already run; the checks before it exist so that it never gets that far in
       practice.

    The file is not content-pinned: a release's authenticity is verified with Sigstore/cosign when
    the package is installed, so path integrity is what this loader enforces.

    Any failed check raises ``PermissionError``; there is deliberately no fallback and no override.
    The policy methods take the system calls as arguments, so they are tested on every platform.

    Two things are out of reach here. The tpm2-tss TCTI module is loaded later, at the first TPM
    call, by name; the environment check is what covers it. And Python's own injection points
    (PYTHONPATH, sitecustomize, .pth files) are not dynamic-linker settings; protect the service's
    environment for those, as on every platform.
    """

    FILE_NAME: Final = "libhkdfguard.so.1"
    """The library's SONAME, which the package installs as a regular file."""

    LIB64_DIRECTORY: Final = "/usr/lib64"
    """The RPM packages' library directory, used when there is no Debian multiarch one."""

    PROBE_EXPORT: Final = "hkdfguard_wrap_dek"
    """An export every genuine build has; its address tells dladdr which file was loaded."""

    # The dynamic-linker variables that decide where, or what, it loads.
    LIBRARY_PATH_VARIABLE: Final = "LD_LIBRARY_PATH"
    PRELOAD_VARIABLE: Final = "LD_PRELOAD"
    AUDIT_VARIABLE: Final = "LD_AUDIT"

    MAX_SYMBOLIC_LINKS: Final = 40
    """The kernel's own limit on symbolic links followed in one lookup."""

    SELF_EXECUTABLE: Final = "/proc/self/exe"
    """This process's executable, whose PT_INTERP names the dynamic linker it runs under."""

    LISTING_TIMEOUT_SECONDS: Final = 30
    """Bounds the dynamic linker's list run: it only maps files and reads headers."""

    _lock: ClassVar = threading.Lock()
    _library: ClassVar[Any] = None

    @classmethod
    def load(cls) -> Any:
        """Verifies and loads the installed library once per process; later calls return the same
        library. A failure isn't cached, so a fixed installation is picked up on the next call.

        :raises OSError: the process is neither x64 nor arm64 (an ``OSError`` with errno ENOTSUP)
        :raises NativeLibraryNotFoundError: the library is not installed, or the dynamic linker
            could not load it
        :raises PermissionError: the installed file, its location, its dependencies or the
            environment failed verification
        """
        with cls._lock:
            if cls._library is not None:
                return cls._library

            def trusted(path: str) -> str:
                resolved = cls.resolve_trusted(path, UnixFileType.REGULAR_FILE, get_status_or_none, read_link)
                if resolved is None:  # unreachable: a missing path raises unless allow_missing
                    raise PermissionError(f"'{path}' does not exist.")
                return resolved

            candidates = cls.candidate_paths(CpuArchitecture.current())
            path = trusted(cls.choose_path(candidates, probe))

            initial_environment = read_initial_environment()
            environment = cls.read_environment(os.environ.get, initial_environment)
            cls.verify_environment(environment, lambda p, kind: cls.resolve_trusted(p, kind, get_status_or_none, read_link, allow_missing=True))
            cls.verify_before_loading(path, initial_environment, ElfDependencies.read_interpreter, trusted, list_dependencies)

            try:
                library = ctypes.CDLL(path, mode=os.RTLD_NOW | os.RTLD_LOCAL)  # type: ignore[attr-defined,unused-ignore]
            except OSError as error:
                raise NativeLibraryNotFoundError(f"The HkdfGuard native KMS library '{path}' passed verification but could not be loaded: "
                                                 f"{error}") from error
            try:
                export = getattr(library, cls.PROBE_EXPORT, None)
                loaded = image_path(ctypes.cast(export, ctypes.c_void_p).value) if export else None
                cls.verify_loaded_image(path, None if loaded is None else trusted(loaded))
                cls.verify_dependencies(path, ElfDependencies.read_needed, loaded_path, trusted)
            except BaseException:
                _dlclose(library._handle)
                raise
            cls._library = library
            return library

    @classmethod
    def candidate_paths(cls, architecture: CpuArchitecture) -> list[str]:
        """Where the package may have installed the library for a process of ``architecture``, in
        the order they are tried.

        :raises OSError: no package is built for that architecture (an ``OSError`` with errno ENOTSUP)
        """
        triplets = {CpuArchitecture.X64: "x86_64-linux-gnu", CpuArchitecture.ARM64: "aarch64-linux-gnu"}
        triplet = triplets.get(architecture)
        if triplet is None:
            raise OSError(errno.ENOTSUP, "The HkdfGuard native KMS library is built for x64 and arm64 Linux only; "
                                         f"this process is {architecture.value}.")
        return [f"/usr/lib/{triplet}/{cls.FILE_NAME}", f"{cls.LIB64_DIRECTORY}/{cls.FILE_NAME}"]

    @classmethod
    def choose_path(cls, candidates: Sequence[str], probe: Callable[[str], int]) -> str:
        """The first candidate that exists. ``probe`` returns lstat's errno for a path (0 if it
        exists), so "can't look" is never mistaken for "not there".

        :raises NativeLibraryNotFoundError: none exists
        :raises PermissionError: a candidate could not be examined
        """
        for candidate in candidates:
            error = probe(candidate)
            if error == 0:
                return candidate
            if error not in (errno.ENOENT, errno.ENOTDIR):
                raise PermissionError(f"Could not tell whether the HkdfGuard native library '{candidate}' exists (lstat failed with errno "
                                      f"{error}); refusing to guess or to fall back to another location.")

        locations = " or ".join(f"'{candidate}'" for candidate in candidates)
        raise NativeLibraryNotFoundError("The HkdfGuard native KMS library is not installed. Install the libhkdfguard1 package "
                                         f"(hkdfguard-libs on RPM distributions); it is loaded only from {locations}.")

    @classmethod
    def resolve_trusted(cls, path: str, expected_type: UnixFileType, get_status: Callable[[str], UnixFileStatus | None],  # noqa: PLR0912 - one walk, as in .NET
                        read_link: Callable[[str], str | None], allow_missing: bool = False) -> str | None:
        """Resolves ``path`` the way the kernel would, checking everything it passes through: every
        directory and the final object must be owned by root and writable by neither group nor
        others, and every symbolic link must be owned by root (its target is then resolved and
        checked in turn). Returns the resolved path, which contains no symbolic links.

        :param get_status: lstat-style status of a path, or ``None`` if nothing is there
        :param read_link: a symbolic link's stored target
        :param allow_missing: when true, a path that runs into a missing component returns ``None``
            instead of raising: everything up to it was checked, so only root could create what is missing
        :raises PermissionError: a check failed, or the final object is not of ``expected_type``
        :raises OSError: a component could not be examined
        """
        if not path.startswith("/"):
            raise PermissionError(f"'{path}' is not an absolute path; the HkdfGuard native library and its dependencies are only trusted at "
                                  "absolute paths.")

        root = get_status("/")
        if root is None:
            raise PermissionError("'/' could not be examined.")
        cls._require_root_controlled("/", root)

        pending: list[str] = []  # a stack: the next component is last
        cls._push_components(pending, path)
        resolved = "/"
        resolved_type = UnixFileType.DIRECTORY
        links_followed = 0

        while pending:
            name = pending.pop()
            if name in ("", "."):
                continue

            if resolved_type is not UnixFileType.DIRECTORY:
                raise PermissionError(f"'{path}' runs through '{resolved}', which is not a directory.")

            if name == "..":
                # resolved never contains a symbolic link, so its parent is its lexical parent.
                resolved = cls.parent_of(resolved)
                continue

            candidate = f"/{name}" if resolved == "/" else f"{resolved}/{name}"
            status = get_status(candidate)
            if status is None:
                if allow_missing:
                    return None
                raise PermissionError(f"'{candidate}' does not exist (resolving '{path}').")

            if status.type is UnixFileType.SYMBOLIC_LINK:
                if status.owner_id != 0:
                    raise PermissionError(f"'{candidate}' is a symbolic link owned by uid {status.owner_id}; only links owned by root are "
                                          f"followed (resolving '{path}').")
                links_followed += 1
                if links_followed > cls.MAX_SYMBOLIC_LINKS:
                    raise PermissionError(f"'{path}' follows more than {cls.MAX_SYMBOLIC_LINKS} symbolic links.")

                target = read_link(candidate)
                if target is None:
                    raise PermissionError(f"'{candidate}' could not be read as a symbolic link.")
                if target.startswith("/"):
                    resolved = "/"
                cls._push_components(pending, target)
                continue

            cls._require_root_controlled(candidate, status)
            resolved = candidate
            resolved_type = status.type

        if resolved_type is not expected_type:
            raise PermissionError(f"'{path}' resolves to '{resolved}', which is a {cls._describe(resolved_type)}, not a "
                                  f"{cls._describe(expected_type)}.")
        return resolved

    @staticmethod
    def _require_root_controlled(path: str, status: UnixFileStatus) -> None:
        if status.owner_id != 0:
            raise PermissionError(f"'{path}' is owned by uid {status.owner_id}; the HkdfGuard native library and its dependencies are only "
                                  "trusted in locations owned by root.")
        if status.mode & 0o022:  # group- or other-writable
            raise PermissionError(f"'{path}' is writable by its group or by every user; the HkdfGuard native library and its dependencies are "
                                  "only trusted in locations only root can modify.")

    @staticmethod
    def _push_components(pending: list[str], path: str) -> None:
        pending.extend(reversed(path.split("/")))

    @staticmethod
    def parent_of(path: str) -> str:
        slash = path.rfind("/")
        return "/" if slash <= 0 else path[:slash]

    @staticmethod
    def _describe(kind: UnixFileType) -> str:
        # Never a symbolic link: resolve_trusted always follows them.
        return kind.value

    @classmethod
    def read_environment(cls, current: Callable[[str], str | None], initial_environment: bytes | None) -> dict[str, list[str]]:
        """Every value each dynamic-linker variable has had: in the environment the process started
        with (``initial_environment``, /proc/self/environ's NUL-separated block, if it could be read)
        and in the current one."""
        values: dict[str, list[str]] = {name: [] for name in (cls.LIBRARY_PATH_VARIABLE, cls.PRELOAD_VARIABLE, cls.AUDIT_VARIABLE)}

        if initial_environment is not None:
            for entry in initial_environment.split(b"\0"):
                # As os.environ decodes it, so the same value read both ways compares equal.
                text = os.fsdecode(entry)
                equals = text.find("=")
                if equals > 0 and text[:equals] in values:
                    values[text[:equals]].append(text[equals + 1:])

        for name, found in values.items():
            value = current(name)
            if value is not None and value not in found:
                found.append(value)
        return values

    @classmethod
    def verify_environment(cls, environment: Mapping[str, Sequence[str]],
                           resolve_trusted: Callable[[str, UnixFileType], str | None]) -> None:
        """Requires every location the dynamic-linker variables could make it load from to pass the
        path checks.

        :param environment: every value of each variable (see :meth:`read_environment`)
        :param resolve_trusted: :meth:`resolve_trusted` with missing paths allowed: raises if the
            path is untrusted, returns ``None`` if nothing is there
        :raises PermissionError: a value names a location that isn't trusted
        """
        # An empty LD_LIBRARY_PATH is ignored by the dynamic linker; an empty entry within one is
        # the working directory.
        for value in environment.get(cls.LIBRARY_PATH_VARIABLE, ()):
            if not value:
                continue
            for entry in re.split("[:;]", value):
                if not entry:
                    raise cls._untrusted(cls.LIBRARY_PATH_VARIABLE, value, "an empty entry, which means the working directory")
                cls._verify_location(cls.LIBRARY_PATH_VARIABLE, value, entry, UnixFileType.DIRECTORY, resolve_trusted)

        # Objects to preload or audit: separated by spaces or colons (LD_PRELOAD), or colons
        # (LD_AUDIT). A bare name is found by the same search as any dependency, which the
        # LD_LIBRARY_PATH check above already covers.
        for variable, separators in ((cls.PRELOAD_VARIABLE, "[ :]"), (cls.AUDIT_VARIABLE, "[:]")):
            for value in environment.get(variable, ()):
                for entry in filter(None, re.split(separators, value)):
                    if "/" in entry or "$" in entry:
                        cls._verify_location(variable, value, entry, UnixFileType.REGULAR_FILE, resolve_trusted)

    @classmethod
    def _verify_location(cls, variable: str, value: str, entry: str, kind: UnixFileType,
                         resolve_trusted: Callable[[str, UnixFileType], str | None]) -> None:
        if "$" in entry:
            raise cls._untrusted(variable, value, f"'{entry}', which uses a dynamic string token ($ORIGIN, $LIB or $PLATFORM) that can't be "
                                                  "checked in advance")
        if not entry.startswith("/"):
            raise cls._untrusted(variable, value, f"'{entry}', which is relative to the working directory")

        try:
            resolve_trusted(entry, kind)
        except OSError as error:  # PermissionError (untrusted) is an OSError too
            raise PermissionError(f"{variable} ('{value}') names '{entry}', which the dynamic linker could load the HkdfGuard native library's "
                                  f"dependencies from: {error} Remove it from {variable}, or make it a location only root can modify.") from error

    @staticmethod
    def _untrusted(variable: str, value: str, what: str) -> PermissionError:
        return PermissionError(f"{variable} ('{value}') contains {what}; the dynamic linker could load the HkdfGuard native library's "
                               "dependencies from there. Refusing to load it.")

    @classmethod
    def verify_before_loading(cls, library: str, initial_environment: bytes | None, read_interpreter: Callable[[str], str | None],
                              resolve_trusted: Callable[[str], str], list_dependencies: Callable[[str, str, Mapping[str, str]], str]) -> None:
        """Asks this process's own dynamic linker, in list mode, where it would find everything
        ``library`` pulls in, and requires each of those files to pass the path checks - before
        dlopen, so nothing that would fail them ever runs here.

        :param library: the verified library
        :param initial_environment: /proc/self/environ's block, or ``None`` if it couldn't be read
        :param read_interpreter: an ELF file's PT_INTERP path, or ``None`` if it has none
        :param resolve_trusted: resolves a path, raising unless it passes the path checks
        :param list_dependencies: runs ``interpreter --list library`` with exactly the given
            environment and returns what it printed (see :func:`list_dependencies`)
        :raises PermissionError: the dynamic linker can't be identified, trusted or asked, or it
            would load something that isn't trusted
        """
        try:
            interpreter = read_interpreter(cls.SELF_EXECUTABLE)
        except OSError as error:  # PermissionError (malformed) is an OSError too
            raise PermissionError(f"Could not read which dynamic linker this process runs under: {error}") from error
        if interpreter is None:
            raise PermissionError(f"This process has no dynamic linker (a statically linked executable), so it can't be asked what '{library}' "
                                  "would load; refusing to load it.")
        try:
            trusted_interpreter = resolve_trusted(interpreter)
        except OSError as error:
            raise PermissionError(f"This process's dynamic linker '{interpreter}' is not trusted, so it can't be asked what '{library}' would "
                                  f"load: {error}") from error

        output = list_dependencies(trusted_interpreter, library, cls.listing_environment(initial_environment))
        cls.verify_listing(library, cls.parse_listing(library, output), resolve_trusted)

    @classmethod
    def listing_environment(cls, initial_environment: bytes | None) -> dict[str, str]:
        """The whole environment the dynamic linker's list mode runs with: the LD_LIBRARY_PATH and
        LD_PRELOAD the process started with (``initial_environment``, /proc/self/environ's block) -
        what dlopen itself uses, since the linker reads them once at startup - and nothing else.
        LD_AUDIT is left out: an audit module is code the list run would execute, and its locations
        were already checked before this runs."""
        environment: dict[str, str] = {}
        for entry in (initial_environment or b"").split(b"\0"):
            # Decoded as os.environ would be; subprocess encodes it back to the same bytes.
            name, equals, value = os.fsdecode(entry).partition("=")
            if equals and name in (cls.LIBRARY_PATH_VARIABLE, cls.PRELOAD_VARIABLE):
                # A variable set twice keeps its last value, as the dynamic linker does.
                environment[name] = value
        return environment

    @staticmethod
    def parse_listing(library: str, output: str) -> list[str]:
        """Every file path in the output of the dynamic linker's list mode, in order. Its lines are
        ``\\tname => /path (0xaddress)``, ``\\t/path (0xaddress)`` (the linker itself and preloaded
        objects) and ``\\tname (0xaddress)`` (the vDSO, which has no file).

        :raises PermissionError: a name it couldn't find (``=> not found``), or any line in another
            form: what can't be read can't be checked
        """
        paths: list[str] = []
        for raw_line in output.split("\n"):
            line = raw_line.strip()
            if not line:
                continue
            if line.endswith(" => not found"):
                name = line.removesuffix(" => not found")
                raise PermissionError(f"The dynamic linker can't find '{name}', which '{library}' needs; refusing to load it.")
            address = line.rfind(" (0x")
            if address < 0 or not line.endswith(")"):
                raise PermissionError(f"The dynamic linker's list of what '{library}' would load has a line this loader doesn't understand "
                                      f"('{line}'); refusing to load it.")
            entry = line[:address]
            _, arrow, path = entry.partition(" => ")
            if arrow:
                entry = path
            if not entry.startswith("/"):
                if "/" in entry or " " in entry:
                    raise PermissionError(f"The dynamic linker would load '{entry}' for '{library}', which is not an absolute path; refusing to "
                                          "load it.")
                continue  # the vDSO: in the kernel, not a file
            paths.append(entry)
        return paths

    @staticmethod
    def verify_listing(library: str, paths: Sequence[str], resolve_trusted: Callable[[str], str]) -> None:
        """Requires every path the dynamic linker's list mode reported to pass the path checks.

        :param resolve_trusted: resolves a path, raising unless it passes the path checks
        :raises PermissionError: the first path that doesn't
        """
        for path in paths:
            try:
                resolve_trusted(path)
            except OSError as error:
                raise PermissionError(f"Loading '{library}' would also load '{path}', which is not trusted; nothing was loaded: {error}") from error

    @classmethod
    def verify_loaded_image(cls, expected_path: str, loaded_path: str | None) -> None:
        """Requires that the file the dynamic linker reports having loaded is the one that was verified.

        :param expected_path: the verified path that was passed to dlopen
        :param loaded_path: the resolved path dladdr reports for the library's export, or ``None``
            if it has no such export or the linker can't say
        :raises PermissionError: they differ
        """
        if loaded_path is None:
            raise PermissionError(f"The library loaded for '{expected_path}' has no '{cls.PROBE_EXPORT}' export, or the dynamic linker cannot "
                                  "say where it came from; it is not the HkdfGuard native library and has been unloaded.")
        if loaded_path != expected_path:
            raise PermissionError(f"The dynamic linker bound '{expected_path}' to '{loaded_path}', a different file; it has been unloaded and "
                                  "the HkdfGuard native library was not loaded.")

    @staticmethod
    def verify_dependencies(library_path: str, read_needed: Callable[[str], Sequence[str]], loaded_path_of: Callable[[str], str | None],
                            resolve_trusted: Callable[[str], str]) -> None:
        """Walks the library's dependency closure - each file's DT_NEEDED names, then theirs - and
        requires every one to be bound to a trusted file.

        :param library_path: the verified library
        :param read_needed: a file's DT_NEEDED names
        :param loaded_path_of: the path of the already-loaded object a name is bound to, or ``None``
            if none is
        :param resolve_trusted: resolves a path, raising unless it passes the path checks
        :raises PermissionError: a dependency is not loaded from a trusted file
        """
        visited = {library_path}
        pending = [library_path]  # a queue: breadth first, as the dynamic linker loads them
        while pending:
            file = pending.pop(0)
            for name in read_needed(file):
                loaded = loaded_path_of(name)
                if loaded is None:
                    raise PermissionError(f"'{file}' depends on '{name}', but no loaded object answers to that name; cannot tell where it "
                                          "came from.")
                try:
                    resolved = resolve_trusted(loaded)
                except OSError as error:
                    raise PermissionError(f"The HkdfGuard native library's dependency '{name}' (needed by '{file}') was loaded from "
                                          f"'{loaded}', which is not trusted: {error}") from error
                if resolved not in visited:
                    visited.add(resolved)
                    pending.append(resolved)


# --- Linux system calls (bound on first use) ------------------------------------------------------
# Every libc import is in glibc's libc.so.6 (2.34 or later, which the native package itself
# requires). The process has already loaded libc.so.6, and the dynamic linker matches an
# already-loaded library by name before it searches anywhere, so LD_LIBRARY_PATH cannot substitute it.

_RTLD_LAZY: Final = 0x1
_RTLD_NOLOAD: Final = 0x4
_RTLD_DI_LINKMAP: Final = 2


def get_status_or_none(path: str) -> UnixFileStatus | None:
    """lstat: describes the path itself, never what a symbolic link points to. ``None`` when nothing
    is there (ENOENT or ENOTDIR).

    :raises OSError: lstat failed for any other reason, such as EACCES
    """
    try:
        return UnixFileStatus.of(path)
    except OSError as error:
        if error.errno in (errno.ENOENT, errno.ENOTDIR):
            return None
        raise OSError(error.errno, f"lstat('{path}') failed with errno {error.errno}.") from error


def read_link(path: str) -> str | None:
    """A symbolic link's target, exactly as stored (possibly relative), or ``None`` if it can't be read as one."""
    try:
        return os.readlink(path)
    except OSError:
        return None


def read_initial_environment() -> bytes | None:
    """The process's environment as it was at exec, which is what the dynamic linker read, or
    ``None`` if /proc/self/environ can't be read."""
    try:
        with open("/proc/self/environ", "rb") as environ:
            return environ.read()
    except OSError:
        return None


def list_dependencies(interpreter: str, library: str, environment: Mapping[str, str]) -> str:
    """Runs ``interpreter --list library`` - the dynamic linker's list mode - with exactly
    ``environment``, and returns what it printed.

    This is the package's one child process, a deliberate and narrow exception: only the dynamic
    linker itself can say where dlopen would find each dependency (RUNPATH, ld.so.cache, hwcaps
    subdirectories, its own compiled-in defaults), and list mode answers without running any of the
    libraries' code, which dlopen would. So it runs a verified absolute path, never through a shell,
    with a fixed argument list and an environment built from scratch (never ``os.environ``), bounded
    by a timeout.

    :raises PermissionError: it could not be started, failed or timed out
    """
    seconds = LinuxNativeLibraryLoader.LISTING_TIMEOUT_SECONDS
    try:
        # env={} is an empty environment; only None would inherit this process's.
        completed = subprocess.run([interpreter, "--list", library], shell=False, env=dict(environment),  # noqa: S603 - see above
                                   capture_output=True, timeout=seconds, check=False)
    except subprocess.TimeoutExpired as error:
        raise PermissionError(f"The dynamic linker did not say within {seconds} seconds what '{library}' would load; refusing to load "
                              "it.") from error
    except OSError as error:
        raise PermissionError(f"The dynamic linker '{interpreter}' could not be run to say what '{library}' would load: {error}") from error
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", "replace").strip()
        raise PermissionError(f"The dynamic linker could not say what '{library}' would load ({stderr}): exit status {completed.returncode}; "
                              "refusing to load it.")
    return os.fsdecode(completed.stdout)


def _libc() -> Any:
    return ctypes.CDLL("libc.so.6")


class _DlInfo(ctypes.Structure):
    _fields_ = [("dli_fname", ctypes.c_char_p), ("dli_fbase", ctypes.c_void_p), ("dli_sname", ctypes.c_char_p),
                ("dli_saddr", ctypes.c_void_p)]


class _LinkMap(ctypes.Structure):
    # struct link_map begins l_addr, l_name; only l_name is read.
    _fields_ = [("l_addr", ctypes.c_void_p), ("l_name", ctypes.c_char_p)]


def image_path(address: int | None) -> str | None:
    """dladdr: the path the dynamic linker recorded for the object containing ``address``, or
    ``None`` if it doesn't know the address."""
    library = _libc()
    library.dladdr.argtypes = [ctypes.c_void_p, ctypes.POINTER(_DlInfo)]
    library.dladdr.restype = ctypes.c_int
    info = _DlInfo()
    if not address or not library.dladdr(address, ctypes.byref(info)) or not info.dli_fname:
        return None
    file_name: bytes = info.dli_fname
    return os.fsdecode(file_name)


def loaded_path(soname: str) -> str | None:
    """The path the dynamic linker recorded for the already-loaded object it would bind ``soname``
    to, or ``None`` if no such object is loaded. Never loads anything."""
    library = _libc()
    library.dlopen.argtypes = [ctypes.c_char_p, ctypes.c_int]
    library.dlopen.restype = ctypes.c_void_p
    library.dlinfo.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(_LinkMap))]
    library.dlinfo.restype = ctypes.c_int
    library.dlclose.argtypes = [ctypes.c_void_p]

    handle = library.dlopen(os.fsencode(soname), _RTLD_LAZY | _RTLD_NOLOAD)
    if not handle:
        return None
    try:
        link_map = ctypes.POINTER(_LinkMap)()
        if library.dlinfo(handle, _RTLD_DI_LINKMAP, ctypes.byref(link_map)) != 0 or not link_map:
            return None
        name: bytes | None = link_map.contents.l_name
        return os.fsdecode(name) if name else None
    finally:
        # RTLD_NOLOAD still took a reference; give it back.
        library.dlclose(handle)


def _dlclose(handle: int) -> None:
    library = _libc()
    library.dlclose.argtypes = [ctypes.c_void_p]
    library.dlclose(handle)


class LinuxHkdfGuardKmsLibrary(NativeKmsLibrary):
    """Binds libhkdfguard.so.1 from the libhkdfguard1 package, loaded only from its install location
    after the checks in :class:`LinuxNativeLibraryLoader`. It holds the per-service KEK on the
    strongest provider the root-owned policy allows - TPM2, PKCS#11 or an external secret file. No
    call creates a KEK: ``hkdfguard provision --service-name <name>`` (/usr/bin/hkdfguard) must
    create it first, or wrap fails with ERR_KEK_NOT_FOUND."""

    _PLATFORM_DESCRIPTIONS: Final[dict[int, str]] = {
        NativeKmsLibrary.ERR_PROVIDER_UNAVAILABLE:
            "no KEK provider could be reached: no usable TPM, PKCS#11 token or external secret under /etc/hkdfguard/policy.toml",
        NativeKmsLibrary.ERR_PROVIDER_ERROR:
            "a KEK provider was reached but failed (policy file, secret file permissions, TPM or token error); the native library's log names the reason",
        NativeKmsLibrary.ERR_POLICY_INVALID:
            "/etc/hkdfguard/policy.toml can't be used: unparsable, an invalid or contradictory setting, insecure ownership or permissions, "
            "or a provider this build lacks",
        NativeKmsLibrary.ERR_KEK_NOT_FOUND: "no KEK is provisioned for this service; run hkdfguard provision",
        NativeKmsLibrary.ERR_KEK_FINGERPRINT_MISMATCH:
            "the payload was wrapped under a different KEK than this service's current one: another service, or the KEK or TPM derivation secret "
            "has changed",
        NativeKmsLibrary.ERR_PROCESS_HARDENING_FAILED: "process hardening failed: core dumps or ptrace access could not be disabled",
    }

    def describe_status(self, status: int) -> str | None:
        return self._PLATFORM_DESCRIPTIONS.get(status) or super().describe_status(status)

    def _bind(self) -> KmsFunctions:
        return KmsFunctions(LinuxNativeLibraryLoader.load())
