"""The Linux loader's decisions - where the library is, whether every path to it and to its
dependencies can be trusted, and whether the dynamic linker's environment could substitute anything
- checked against simulated filesystems, so they run on every platform; DT_NEEDED parsing against
synthetic ELF images; and, on Linux only, the same checks against the real filesystem, dynamic
linker and (where installed) the libhkdfguard1 package. Ported from hkdfguard-dotnet's
LinuxNativeLibraryLoaderTests, ElfDependenciesTests and LinuxNativeLibraryLoaderSystemTests."""

from __future__ import annotations

import ctypes
import dataclasses
import errno
import os
import re
import struct
import sys
import tempfile
from collections.abc import Mapping

import pytest
from hkdfguard.keywrapping.v1 import NativeLibraryNotFoundError
from hkdfguard.keywrapping.v1._interop import _linux
from hkdfguard.keywrapping.v1._interop._elf import ElfDependencies
from hkdfguard.keywrapping.v1._interop._kms import OK, CpuArchitecture
from hkdfguard.keywrapping.v1._interop._linux import LinuxHkdfGuardKmsLibrary, LinuxNativeLibraryLoader
from hkdfguard.keywrapping.v1._interop._unix import UnixFileStatus, UnixFileType, probe

Loader = LinuxNativeLibraryLoader

ROOT = 0
USER = 1000

MODE_755 = 0o755
MODE_775 = 0o775
MODE_1777 = 0o1777
MODE_644 = 0o644
MODE_664 = 0o664
MODE_777 = 0o777

LIB_DIR = "/usr/lib/x86_64-linux-gnu"
LIBRARY = f"{LIB_DIR}/libhkdfguard.so.1"
ESYS = f"{LIB_DIR}/libtss2-esys.so.0.0.1"


class FileSystem:
    """A simulated filesystem: what lstat sees, and what each symbolic link holds."""

    def __init__(self) -> None:
        self.entries: dict[str, UnixFileStatus] = {}
        self.links: dict[str, str] = {}

    def dir(self, path: str, owner: int = ROOT, mode: int = MODE_755) -> FileSystem:
        self.entries[path] = UnixFileStatus(owner, owner, mode, UnixFileType.DIRECTORY)
        return self

    def file(self, path: str, owner: int = ROOT, mode: int = MODE_644) -> FileSystem:
        self.entries[path] = UnixFileStatus(owner, owner, mode, UnixFileType.REGULAR_FILE)
        return self

    def link(self, path: str, target: str, owner: int = ROOT) -> FileSystem:
        self.entries[path] = UnixFileStatus(owner, owner, MODE_777, UnixFileType.SYMBOLIC_LINK)
        self.links[path] = target
        return self

    def status(self, path: str) -> UnixFileStatus | None:
        return self.entries.get(path)

    def read_link(self, path: str) -> str | None:
        return self.links.get(path)

    def resolve(self, path: str, kind: UnixFileType = UnixFileType.REGULAR_FILE, allow_missing: bool = False) -> str | None:
        return Loader.resolve_trusted(path, kind, self.status, self.read_link, allow_missing)


def standard_host() -> FileSystem:
    """A standard Debian/Ubuntu host with merged /usr: /lib is a root-owned link to usr/lib."""
    return (FileSystem()
            .dir("/").dir("/usr").dir("/usr/lib").dir(LIB_DIR).dir("/usr/lib64").dir("/opt")
            .link("/lib", "usr/lib")
            .link("/lib64", "usr/lib64")
            .file(LIBRARY)
            .link(f"{LIB_DIR}/HkdfGuard.Kms.Linux.v1.so", "libhkdfguard.so.1")
            .link(f"{LIB_DIR}/libtss2-esys.so.0", "libtss2-esys.so.0.0.1")
            .file(ESYS)
            .file(f"{LIB_DIR}/libc.so.6")
            .dir("/home").dir("/home/dev", USER).dir("/home/dev/lib", USER).file("/home/dev/lib/libtss2-esys.so.0", USER)
            .dir("/tmp", ROOT, MODE_1777))


# --- Platform and location ------------------------------------------------------------------------


def test_candidate_paths_are_the_packages_install_locations_for_each_architecture() -> None:
    assert Loader.candidate_paths(CpuArchitecture.X64) == ["/usr/lib/x86_64-linux-gnu/libhkdfguard.so.1", "/usr/lib64/libhkdfguard.so.1"]
    assert Loader.candidate_paths(CpuArchitecture.ARM64) == ["/usr/lib/aarch64-linux-gnu/libhkdfguard.so.1", "/usr/lib64/libhkdfguard.so.1"]


@pytest.mark.parametrize("architecture", [CpuArchitecture.X86, CpuArchitecture.ARM, CpuArchitecture.OTHER])
def test_candidate_paths_refuse_every_other_architecture(architecture: CpuArchitecture) -> None:
    with pytest.raises(OSError, match=architecture.value) as error:
        Loader.candidate_paths(architecture)
    assert error.value.errno == errno.ENOTSUP
    assert not isinstance(error.value, (PermissionError, NativeLibraryNotFoundError))


PRESENT = 0
ENOENT = 2
EACCES = 13
ENOTDIR = 20

CANDIDATES = Loader.candidate_paths(CpuArchitecture.X64)


def test_choose_path_prefers_the_multiarch_directory() -> None:
    assert Loader.choose_path(CANDIDATES, lambda p: PRESENT) == CANDIDATES[0]


@pytest.mark.parametrize("error", [ENOENT, ENOTDIR])
def test_choose_path_uses_lib64_only_when_there_is_nothing_in_the_multiarch_directory(error: int) -> None:
    assert Loader.choose_path(CANDIDATES, lambda p: error if p == CANDIDATES[0] else PRESENT) == CANDIDATES[1]


def test_choose_path_when_a_location_cannot_be_examined_refuses_instead_of_falling_back() -> None:
    asked: list[str] = []

    def probe(path: str) -> int:
        asked.append(path)
        return EACCES

    with pytest.raises(PermissionError, match="errno 13"):
        Loader.choose_path(CANDIDATES, probe)
    assert asked == [CANDIDATES[0]]


def test_choose_path_with_nothing_installed_throws_naming_the_package_and_every_location() -> None:
    with pytest.raises(NativeLibraryNotFoundError) as error:
        Loader.choose_path(CANDIDATES, lambda p: ENOENT)
    assert "libhkdfguard1" in str(error.value)
    assert CANDIDATES[0] in str(error.value)
    assert CANDIDATES[1] in str(error.value)


# --- Path integrity -------------------------------------------------------------------------------


def test_a_standard_install_resolves_to_itself() -> None:
    assert standard_host().resolve(LIBRARY) == LIBRARY


def test_a_root_owned_link_is_followed_and_its_target_checked() -> None:
    fs = standard_host()

    assert fs.resolve("/lib/x86_64-linux-gnu/libtss2-esys.so.0") == ESYS
    assert fs.resolve(f"{LIB_DIR}/HkdfGuard.Kms.Linux.v1.so") == LIBRARY
    assert fs.resolve("/lib/x86_64-linux-gnu/", UnixFileType.DIRECTORY) == LIB_DIR


def test_dot_dot_is_resolved_against_the_real_directory_not_the_link_that_led_there() -> None:
    # /opt/app -> ../usr/lib: "/opt/app/.." is /usr, not /opt.
    fs = standard_host().link("/opt/app", "../usr/lib")

    assert fs.resolve("/opt/app/x86_64-linux-gnu/libhkdfguard.so.1") == LIBRARY
    assert fs.resolve("/opt/app/..", UnixFileType.DIRECTORY) == "/usr"
    assert fs.resolve("/..", UnixFileType.DIRECTORY) == "/"
    assert fs.resolve("/usr/./lib/x86_64-linux-gnu//libhkdfguard.so.1") == LIBRARY


@pytest.mark.parametrize("path", ["usr/lib/x86_64-linux-gnu/libhkdfguard.so.1", "./libhkdfguard.so.1", ""])
def test_a_relative_path_is_refused(path: str) -> None:
    with pytest.raises(PermissionError, match="not an absolute path"):
        standard_host().resolve(path)


def test_a_file_owned_by_a_user_is_refused() -> None:
    fs = standard_host().file(LIBRARY, USER)

    with pytest.raises(PermissionError, match="uid 1000"):
        fs.resolve(LIBRARY)


def test_a_directory_owned_by_a_user_is_refused_wherever_it_is_on_the_path() -> None:
    fs = standard_host().dir("/usr/lib", USER)

    with pytest.raises(PermissionError, match="'/usr/lib'"):
        fs.resolve(LIBRARY)


@pytest.mark.parametrize(("path", "mode"), [("/", MODE_775), ("/usr", MODE_775), (LIB_DIR, MODE_775), (LIB_DIR, MODE_777), (LIBRARY, MODE_664)])
def test_anything_writable_by_group_or_others_is_refused_even_when_root_owned(path: str, mode: int) -> None:
    fs = standard_host()
    fs.entries[path] = dataclasses.replace(fs.entries[path], mode=mode)

    with pytest.raises(PermissionError, match=re.escape(f"'{path}' is writable")):
        fs.resolve(LIBRARY)


def test_a_sticky_world_writable_directory_is_refused() -> None:
    fs = standard_host().file("/tmp/libtss2-esys.so.0")

    with pytest.raises(PermissionError):
        fs.resolve("/tmp/libtss2-esys.so.0")


def test_a_link_owned_by_a_user_is_refused_even_when_it_points_somewhere_trusted() -> None:
    fs = standard_host().link("/opt/lib", "/usr/lib", USER)

    with pytest.raises(PermissionError, match="symbolic link owned by uid 1000"):
        fs.resolve("/opt/lib/x86_64-linux-gnu/libhkdfguard.so.1")


def test_a_root_owned_link_into_a_users_directory_is_refused() -> None:
    fs = standard_host().link("/opt/lib", "/home/dev/lib")

    with pytest.raises(PermissionError, match="'/home/dev'"):
        fs.resolve("/opt/lib/libtss2-esys.so.0")


def test_a_link_loop_is_refused() -> None:
    fs = standard_host().link("/opt/a", "/opt/b").link("/opt/b", "/opt/a")

    with pytest.raises(PermissionError, match=f"{Loader.MAX_SYMBOLIC_LINKS} symbolic links"):
        fs.resolve("/opt/a/x")


def test_a_link_that_cannot_be_read_is_refused() -> None:
    fs = standard_host()
    fs.entries["/opt/broken"] = UnixFileStatus(ROOT, ROOT, MODE_777, UnixFileType.SYMBOLIC_LINK)

    with pytest.raises(PermissionError, match="could not be read"):
        fs.resolve("/opt/broken/x")


def test_a_missing_path_is_refused_unless_missing_is_allowed() -> None:
    fs = standard_host()

    with pytest.raises(PermissionError, match="does not exist"):
        fs.resolve(f"{LIB_DIR}/nothing.so")
    assert fs.resolve(f"{LIB_DIR}/nothing.so", allow_missing=True) is None
    assert fs.resolve("/opt/not/yet/created", UnixFileType.DIRECTORY, allow_missing=True) is None


def test_a_missing_path_under_an_untrusted_directory_is_still_refused() -> None:
    # Something missing is only harmless if nobody but root could create it.
    with pytest.raises(PermissionError):
        standard_host().resolve("/home/dev/lib/nothing.so", allow_missing=True)


def test_the_wrong_kind_of_object_is_refused() -> None:
    fs = standard_host()
    fs.entries["/opt/fifo"] = UnixFileStatus(ROOT, ROOT, MODE_644, UnixFileType.OTHER)

    with pytest.raises(PermissionError, match="is a directory, not a regular file"):
        fs.resolve(LIB_DIR)
    with pytest.raises(PermissionError, match="is a regular file, not a directory"):
        fs.resolve(LIBRARY, UnixFileType.DIRECTORY)
    with pytest.raises(PermissionError, match="is a special file"):
        fs.resolve("/opt/fifo")


def test_a_path_through_a_file_is_refused() -> None:
    with pytest.raises(PermissionError, match="not a directory"):
        standard_host().resolve(f"{LIBRARY}/x")


def test_an_unexaminable_root_is_refused() -> None:
    with pytest.raises(PermissionError, match="'/'"):
        Loader.resolve_trusted(LIBRARY, UnixFileType.REGULAR_FILE, lambda p: None, lambda p: None)


def test_a_component_that_cannot_be_examined_raises_os_error() -> None:
    # lstat failing for any reason but "nothing there" is never treated as "not there".
    fs = standard_host()

    def status(path: str) -> UnixFileStatus | None:
        if path == "/usr/lib":
            raise OSError(errno.EIO, "lstat('/usr/lib') failed with errno 5.")
        return fs.status(path)

    with pytest.raises(OSError, match="errno 5"):
        Loader.resolve_trusted(LIBRARY, UnixFileType.REGULAR_FILE, status, fs.read_link, allow_missing=True)


@pytest.mark.parametrize(("path", "parent"), [("/", "/"), ("/usr", "/"), ("/usr/lib", "/usr")])
def test_parent_of_walks_up_to_root(path: str, parent: str) -> None:
    assert Loader.parent_of(path) == parent


# --- Environment ----------------------------------------------------------------------------------


def environ_block(*entries: str) -> bytes:
    return ("\0".join(entries) + "\0").encode("utf-8")


def test_read_environment_collects_the_initial_and_current_values_of_the_linkers_variables_only() -> None:
    current = {"LD_LIBRARY_PATH": "/now", "LD_PRELOAD": "/same.so"}
    values = Loader.read_environment(
        current.get,
        environ_block("PATH=/usr/bin", "LD_LIBRARY_PATH=/at/exec", "LD_PRELOAD=/same.so", "LD_AUDIT=/a.so=b", "=junk", "NOEQUALS"))

    assert values["LD_LIBRARY_PATH"] == ["/at/exec", "/now"]
    assert values["LD_PRELOAD"] == ["/same.so"]
    assert values["LD_AUDIT"] == ["/a.so=b"]
    assert len(values) == 3


def test_read_environment_without_proc_environ_uses_the_current_environment() -> None:
    values = Loader.read_environment(lambda n: "x.so" if n == "LD_PRELOAD" else None, None)

    assert values["LD_PRELOAD"] == ["x.so"]
    assert values["LD_LIBRARY_PATH"] == []


def verify_environment(fs: FileSystem, variable: str, *values: str) -> None:
    Loader.verify_environment({variable: list(values)}, lambda p, kind: fs.resolve(p, kind, allow_missing=True))


def test_an_unset_environment_passes() -> None:
    def resolve(path: str, kind: UnixFileType) -> str | None:
        raise AssertionError("nothing to resolve")

    Loader.verify_environment({}, resolve)


@pytest.mark.parametrize("value", [
    "",                                     # ignored by the dynamic linker
    "/usr/lib/x86_64-linux-gnu",
    "/lib/x86_64-linux-gnu:/usr/lib64",     # through root-owned links
    "/usr/lib;/usr/lib64",                  # ';' separates too
    "/opt/not/installed/yet",               # missing, but only root could create it
])
def test_a_library_path_of_root_controlled_directories_passes(value: str) -> None:
    verify_environment(standard_host(), "LD_LIBRARY_PATH", value)


@pytest.mark.parametrize("value", ["/home/dev/lib", "/usr/lib:/home/dev/lib", "/tmp", "/home/dev/lib/not-yet"])
def test_a_library_path_with_a_directory_others_can_write_is_refused(value: str) -> None:
    with pytest.raises(PermissionError) as error:
        verify_environment(standard_host(), "LD_LIBRARY_PATH", value)
    assert "LD_LIBRARY_PATH" in str(error.value)
    assert "Remove it" in str(error.value)


@pytest.mark.parametrize("value", [":/usr/lib", "/usr/lib:", "/usr/lib::/usr/lib64"])
def test_a_library_path_with_an_empty_entry_is_refused_as_the_working_directory(value: str) -> None:
    with pytest.raises(PermissionError, match="working directory"):
        verify_environment(standard_host(), "LD_LIBRARY_PATH", value)


@pytest.mark.parametrize(("value", "reason"), [
    ("lib", "relative"),
    ("./lib", "relative"),
    ("$ORIGIN/lib", "dynamic string token"),
    ("/usr/${LIB}", "dynamic string token"),
])
def test_a_library_path_that_cant_be_checked_in_advance_is_refused(value: str, reason: str) -> None:
    with pytest.raises(PermissionError, match=reason):
        verify_environment(standard_host(), "LD_LIBRARY_PATH", value)


def test_every_value_the_variable_has_had_is_checked() -> None:
    # A clean current value must not hide what the process started with.
    with pytest.raises(PermissionError):
        verify_environment(standard_host(), "LD_LIBRARY_PATH", "/usr/lib", "/home/dev/lib")


@pytest.mark.parametrize(("variable", "value"), [
    ("LD_PRELOAD", "libjemalloc.so.2"),                         # a bare name: found by the checked search
    ("LD_PRELOAD", "/usr/lib/x86_64-linux-gnu/libc.so.6"),
    ("LD_PRELOAD", "libjemalloc.so.2 /lib/x86_64-linux-gnu/libc.so.6"),
    ("LD_PRELOAD", "   "),
    ("LD_AUDIT", "/usr/lib/x86_64-linux-gnu/libc.so.6:libaudit.so"),
])
def test_preloading_or_auditing_from_root_controlled_locations_passes(variable: str, value: str) -> None:
    verify_environment(standard_host(), variable, value)


@pytest.mark.parametrize(("variable", "value"), [
    ("LD_PRELOAD", "/home/dev/lib/libtss2-esys.so.0"),
    ("LD_PRELOAD", "libjemalloc.so.2 /home/dev/lib/libtss2-esys.so.0"),
    ("LD_PRELOAD", "libjemalloc.so.2:/home/dev/lib/libtss2-esys.so.0"),
    ("LD_PRELOAD", "./evil.so"),
    ("LD_PRELOAD", "$LIB/evil.so"),
    ("LD_AUDIT", "/home/dev/lib/libtss2-esys.so.0"),
    ("LD_AUDIT", "lib/evil.so"),
])
def test_preloading_or_auditing_from_anywhere_else_is_refused(variable: str, value: str) -> None:
    with pytest.raises(PermissionError, match=variable):
        verify_environment(standard_host(), variable, value)


def test_a_location_that_cannot_be_examined_is_refused() -> None:
    def resolve(path: str, kind: UnixFileType) -> str | None:
        raise OSError(errno.EIO, "lstat('/srv') failed with errno 5.")

    with pytest.raises(PermissionError, match="errno 5") as error:
        Loader.verify_environment({"LD_LIBRARY_PATH": ["/srv/lib"]}, resolve)
    assert isinstance(error.value.__cause__, OSError) and not isinstance(error.value.__cause__, PermissionError)


# --- What was loaded ------------------------------------------------------------------------------


def test_verify_loaded_image_accepts_the_verified_path() -> None:
    Loader.verify_loaded_image(LIBRARY, LIBRARY)


def test_verify_loaded_image_refuses_another_file() -> None:
    with pytest.raises(PermissionError, match=re.escape("/usr/lib64/libhkdfguard.so.1")):
        Loader.verify_loaded_image(LIBRARY, "/usr/lib64/libhkdfguard.so.1")


def test_verify_loaded_image_refuses_when_the_loaded_file_has_no_probe_export() -> None:
    with pytest.raises(PermissionError, match=Loader.PROBE_EXPORT):
        Loader.verify_loaded_image(LIBRARY, None)


def test_the_probe_export_is_one_the_binding_calls() -> None:
    assert Loader.PROBE_EXPORT == "hkdfguard_wrap_dek"


# The installed library's closure, as ldd reports it on Ubuntu 24.04.
NEEDED: dict[str, list[str]] = {
    LIBRARY: ["libtss2-esys.so.0", "libgcc_s.so.1", "libc.so.6"],
    ESYS: ["libtss2-mu.so.0", "libcrypto.so.3", "libc.so.6"],
    f"{LIB_DIR}/libtss2-mu.so.0.0.1": ["libc.so.6"],
    f"{LIB_DIR}/libcrypto.so.3": ["libc.so.6"],
    f"{LIB_DIR}/libgcc_s.so.1": ["libc.so.6"],
    f"{LIB_DIR}/libc.so.6": ["ld-linux-x86-64.so.2"],
    f"{LIB_DIR}/ld-linux-x86-64.so.2": [],
}

LOADED: dict[str, str] = {
    "libtss2-esys.so.0": "/lib/x86_64-linux-gnu/libtss2-esys.so.0",
    "libtss2-mu.so.0": "/lib/x86_64-linux-gnu/libtss2-mu.so.0",
    "libcrypto.so.3": "/lib/x86_64-linux-gnu/libcrypto.so.3",
    "libgcc_s.so.1": "/lib/x86_64-linux-gnu/libgcc_s.so.1",
    "libc.so.6": "/lib/x86_64-linux-gnu/libc.so.6",
    "ld-linux-x86-64.so.2": "/lib64/ld-linux-x86-64.so.2",
}


def host_with_closure() -> FileSystem:
    return (standard_host()
            .link(f"{LIB_DIR}/libtss2-mu.so.0", "libtss2-mu.so.0.0.1").file(f"{LIB_DIR}/libtss2-mu.so.0.0.1")
            .file(f"{LIB_DIR}/libcrypto.so.3").file(f"{LIB_DIR}/libgcc_s.so.1")
            .link("/usr/lib64/ld-linux-x86-64.so.2", "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2").file(f"{LIB_DIR}/ld-linux-x86-64.so.2"))


def verify_dependencies(fs: FileSystem, loaded: Mapping[str, str], read: list[str] | None = None) -> None:
    def read_needed(file: str) -> list[str]:
        if read is not None:
            read.append(file)
        return NEEDED[file]

    def trusted(path: str) -> str:
        resolved = fs.resolve(path)
        assert resolved is not None
        return resolved

    Loader.verify_dependencies(LIBRARY, read_needed, loaded.get, trusted)


def test_a_trusted_dependency_closure_passes_and_every_file_in_it_is_read_once() -> None:
    read: list[str] = []
    verify_dependencies(host_with_closure(), LOADED, read)

    assert sorted(read) == sorted(NEEDED)


def test_a_direct_dependency_loaded_from_a_users_directory_is_refused() -> None:
    loaded = {**LOADED, "libtss2-esys.so.0": "/home/dev/lib/libtss2-esys.so.0"}

    with pytest.raises(PermissionError) as error:
        verify_dependencies(host_with_closure(), loaded)
    assert "'libtss2-esys.so.0'" in str(error.value)
    assert LIBRARY in str(error.value)


def test_a_transitive_dependency_loaded_from_an_untrusted_directory_is_refused() -> None:
    fs = host_with_closure().file("/tmp/libcrypto.so.3")
    loaded = {**LOADED, "libcrypto.so.3": "/tmp/libcrypto.so.3"}

    with pytest.raises(PermissionError) as error:
        verify_dependencies(fs, loaded)
    assert f"'libcrypto.so.3' (needed by '{ESYS}')" in str(error.value)


def test_a_dependency_nothing_answers_to_is_refused() -> None:
    loaded = dict(LOADED)
    del loaded["libgcc_s.so.1"]

    with pytest.raises(PermissionError, match=r"libgcc_s\.so\.1"):
        verify_dependencies(host_with_closure(), loaded)


def test_a_dependency_that_cannot_be_examined_is_refused() -> None:
    def resolve(path: str) -> str:
        raise OSError(errno.EIO, "lstat failed with errno 5.")

    with pytest.raises(PermissionError) as error:
        Loader.verify_dependencies(LIBRARY, lambda f: ["libc.so.6"], lambda n: "/lib/x86_64-linux-gnu/libc.so.6", resolve)
    assert isinstance(error.value.__cause__, OSError) and not isinstance(error.value.__cause__, PermissionError)


# --- The binding ----------------------------------------------------------------------------------


def test_the_binding_loads_through_the_verified_loader(monkeypatch: pytest.MonkeyPatch) -> None:
    # Never by name: whatever the loader raises is what the binding raises.
    refused = PermissionError("refused")

    def load() -> object:
        raise refused

    monkeypatch.setattr(LinuxNativeLibraryLoader, "load", load)
    with pytest.raises(PermissionError) as error:
        LinuxHkdfGuardKmsLibrary().wrap_dek("svc", bytes(32), bytearray(512))
    assert error.value is refused


# --- DT_NEEDED parsing (ElfDependencies) ----------------------------------------------------------

LOAD_ADDRESS = 0x40_0000


def elf(needed: list[str], *, with_dynamic: bool = True, with_string_table: bool = True, string_table_address_override: int | None = None,
        needed_offset_override: int | None = None, string_table_size_adjustment: int = 0, with_string_table_size: bool = True) -> bytearray:
    """A minimal 64-bit little-endian ELF image: one PT_LOAD mapping the whole file at
    LOAD_ADDRESS, one PT_DYNAMIC, and a string table holding the given names."""
    header, phdrs = 64, 2 * 56
    strings = bytearray(b"\0")
    offsets: list[int] = []
    for name in needed:
        offsets.append(needed_offset_override if needed_offset_override is not None else len(strings))
        strings += name.encode("utf-8") + b"\0"

    dynamic_entries: list[tuple[int, int]] = [(1, offset) for offset in offsets]
    string_table_offset = header + phdrs + (len(needed) + 3) * 16
    if with_string_table:
        dynamic_entries.append((5, string_table_address_override if string_table_address_override is not None
                                else LOAD_ADDRESS + string_table_offset))
        if with_string_table_size:
            dynamic_entries.append((10, len(strings) + string_table_size_adjustment))
    dynamic_entries.append((0, 0))

    image = bytearray(string_table_offset + len(strings))
    image[0:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<Q", image, 32, header)  # e_phoff
    struct.pack_into("<H", image, 54, 56)      # e_phentsize
    struct.pack_into("<H", image, 56, 2)       # e_phnum

    def program_header(index: int, segment_type: int, offset: int, address: int, size: int) -> None:
        at = header + index * 56
        struct.pack_into("<I", image, at, segment_type)
        struct.pack_into("<Q", image, at + 8, offset)
        struct.pack_into("<Q", image, at + 16, address)
        struct.pack_into("<Q", image, at + 32, size)

    dynamic_offset = header + phdrs
    program_header(0, 1, 0, LOAD_ADDRESS, len(image))
    program_header(1, 2 if with_dynamic else 4, dynamic_offset, LOAD_ADDRESS + dynamic_offset, len(dynamic_entries) * 16)
    for index, (tag, value) in enumerate(dynamic_entries):
        struct.pack_into("<qQ", image, dynamic_offset + index * 16, tag, value)

    image[string_table_offset:] = strings
    return image


def parse(image: bytes | bytearray) -> list[str]:
    return ElfDependencies.read_needed_from(
        "test.so", lambda offset, count: bytes(image[offset:offset + count]) if offset + count <= len(image) else None)


def test_reads_every_needed_name_in_order() -> None:
    assert parse(elf(["libtss2-esys.so.0", "libc.so.6"])) == ["libtss2-esys.so.0", "libc.so.6"]


def test_an_object_with_no_dependencies_has_none() -> None:
    assert parse(elf([])) == []
    assert parse(elf([], with_string_table=False)) == []
    assert parse(elf(["ignored.so"], with_dynamic=False)) == []


def malformed_images() -> list[tuple[str, bytes | bytearray]]:
    not_elf = elf(["x.so"])
    not_elf[1] = ord("X")
    elf32 = elf(["x.so"])
    elf32[4] = 1
    big_endian = elf(["x.so"])
    big_endian[5] = 2
    no_program_headers = elf(["x.so"])
    struct.pack_into("<H", no_program_headers, 56, 0)
    huge_offset = elf(["x.so"])
    struct.pack_into("<Q", huge_offset, 32, (1 << 64) - 1)
    huge_dynamic = elf(["x.so"])
    struct.pack_into("<Q", huge_dynamic, 64 + 56 + 32, 2 << 20)

    return [
        ("not an ELF file", not_elf),
        ("not a 64-bit little-endian", elf32),
        ("not a 64-bit little-endian", big_endian),
        ("program header table is malformed", no_program_headers),
        ("out of range", huge_offset),
        ("implausibly large", huge_dynamic),
        ("runs past the end", elf(["x.so"])[:40]),
        ("runs past the end", elf(["x.so"])[:-3]),
        ("no string table", elf(["x.so"], with_string_table=False)),
        ("no string table", elf(["x.so"], with_string_table_size=False)),  # DT_STRTAB without DT_STRSZ
        ("outside every loaded segment", elf(["x.so"], string_table_address_override=0x10)),
        ("runs past its string table", elf(["x.so"], needed_offset_override=4096)),
        ("runs past its string table", elf(["x.so"], string_table_size_adjustment=-1)),  # no terminating NUL
    ]


@pytest.mark.parametrize(("reason", "image"), malformed_images())
def test_a_malformed_image_is_refused(reason: str, image: bytes) -> None:
    with pytest.raises(PermissionError) as error:
        parse(image)
    assert "test.so" in str(error.value)
    assert reason in str(error.value)


def test_reads_from_a_file() -> None:
    descriptor, path = tempfile.mkstemp()
    os.close(descriptor)
    try:
        with open(path, "wb") as file:
            file.write(elf(["libc.so.6"]))
        assert ElfDependencies.read_needed(path) == ["libc.so.6"]

        with open(path, "wb") as file:
            file.write(elf(["libc.so.6"])[:100])
        with pytest.raises(PermissionError):
            ElfDependencies.read_needed(path)
    finally:
        os.remove(path)


# --- PT_INTERP parsing (ElfDependencies) ----------------------------------------------------------


def elf_with_interpreter(interpreter: bytes | None, *, size_override: int | None = None) -> bytearray:
    """A minimal 64-bit little-endian ELF image with one program header: PT_INTERP holding
    ``interpreter`` (raw, so tests can omit its NUL), or PT_NOTE if ``interpreter`` is ``None``."""
    header, phdr = 64, 56
    data = interpreter or b""
    image = bytearray(header + phdr + len(data))
    image[0:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<Q", image, 32, header)  # e_phoff
    struct.pack_into("<H", image, 54, phdr)    # e_phentsize
    struct.pack_into("<H", image, 56, 1)       # e_phnum
    struct.pack_into("<I", image, header, 3 if interpreter is not None else 4)
    struct.pack_into("<Q", image, header + 8, header + phdr)
    struct.pack_into("<Q", image, header + 32, size_override if size_override is not None else len(data))
    image[header + phdr:] = data
    return image


def parse_interpreter(image: bytes | bytearray) -> str | None:
    return ElfDependencies.read_interpreter_from(
        "test", lambda offset, count: bytes(image[offset:offset + count]) if offset + count <= len(image) else None)


def test_reads_the_interpreter_path() -> None:
    assert parse_interpreter(elf_with_interpreter(b"/lib64/ld-linux-x86-64.so.2\0")) == "/lib64/ld-linux-x86-64.so.2"


def test_an_executable_without_an_interpreter_has_none() -> None:
    assert parse_interpreter(elf_with_interpreter(None)) is None
    assert parse_interpreter(elf(["libc.so.6"])) is None  # a shared object: PT_LOAD and PT_DYNAMIC only


@pytest.mark.parametrize(("reason", "image"), [
    ("empty or implausibly long", elf_with_interpreter(b"")),
    ("empty or implausibly long", elf_with_interpreter(b"/x\0", size_override=ElfDependencies.MAX_INTERPRETER_BYTES + 1)),
    ("not a NUL-terminated string", elf_with_interpreter(b"/lib64/ld-linux-x86-64.so.2")),
    ("not a NUL-terminated string", elf_with_interpreter(b"\0/lib64/ld-linux-x86-64.so.2")),
    ("runs past the end", elf_with_interpreter(b"/x\0", size_override=64)),
    ("not an ELF file", bytearray(64)),
])
def test_a_malformed_interpreter_is_refused(reason: str, image: bytes) -> None:
    with pytest.raises(PermissionError, match=reason):
        parse_interpreter(image)


def test_reads_the_interpreter_from_a_file() -> None:
    descriptor, path = tempfile.mkstemp()
    os.close(descriptor)
    try:
        with open(path, "wb") as file:
            file.write(elf_with_interpreter(b"/lib/ld-linux-aarch64.so.1\0"))
        assert ElfDependencies.read_interpreter(path) == "/lib/ld-linux-aarch64.so.1"
    finally:
        os.remove(path)


# --- What would be loaded (the dynamic linker's list mode) ----------------------------------------

LISTING = ("\tlinux-vdso.so.1 (0x00007ffd2a5f2000)\n"
           "\tlibtss2-esys.so.0 => /lib/x86_64-linux-gnu/libtss2-esys.so.0 (0x00007f1c2a000000)\n"
           "\t/usr/lib/libpreloaded.so (0x00007f1c29e00000)\n"
           "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f1c29c00000)\n"
           "\t/lib64/ld-linux-x86-64.so.2 (0x00007f1c2a200000)\n")


def test_parse_listing_returns_every_file_skipping_the_vdso() -> None:
    assert Loader.parse_listing("lib", LISTING) == [
        "/lib/x86_64-linux-gnu/libtss2-esys.so.0", "/usr/lib/libpreloaded.so", "/lib/x86_64-linux-gnu/libc.so.6", "/lib64/ld-linux-x86-64.so.2"]


@pytest.mark.parametrize(("output", "reason"), [
    ("\tlibmissing.so.1 => not found\n", "can't find 'libmissing.so.1'"),
    ("\tstatically linked\n", "doesn't understand"),
    ("\tlibx.so => relative/libx.so (0x1000)\n", "not an absolute path"),
    ("\tlibx.so => lib x.so (0x1000)\n", "not an absolute path"),
])
def test_parse_listing_a_name_it_cannot_find_or_a_line_it_cannot_read_is_refused(output: str, reason: str) -> None:
    with pytest.raises(PermissionError, match=re.escape(reason)):
        Loader.parse_listing("lib", LISTING + output)


def test_listing_environment_is_only_the_startup_library_path_and_preload() -> None:
    initial = environ_block("HOME=/root", "LD_LIBRARY_PATH=/opt/lib", "LD_AUDIT=/opt/audit.so", "PATH=/usr/bin", "LD_PRELOAD=/opt/pre.so")

    assert Loader.listing_environment(initial) == {"LD_LIBRARY_PATH": "/opt/lib", "LD_PRELOAD": "/opt/pre.so"}
    assert Loader.listing_environment(b"") == {}
    assert Loader.listing_environment(None) == {}


def untrusted_in_tmp(path: str) -> str:
    if path.startswith("/tmp/"):
        raise PermissionError(f"'{path}' is writable by others.")
    return path


def test_verify_listing_refuses_the_first_untrusted_path() -> None:
    Loader.verify_listing("lib", ["/lib/libc.so.6", "/lib64/ld-linux-x86-64.so.2"], untrusted_in_tmp)

    with pytest.raises(PermissionError) as error:
        Loader.verify_listing("lib", ["/lib/libc.so.6", "/tmp/libtss2-esys.so.0", "/tmp/second.so"], untrusted_in_tmp)
    assert "/tmp/libtss2-esys.so.0" in str(error.value)
    assert "nothing was loaded" in str(error.value)
    assert "/tmp/second.so" not in str(error.value)


def verify_before_loading(interpreter: str | None, output: str = LISTING, initial: bytes | None = None,
                          calls: list[tuple[str, str, Mapping[str, str]]] | None = None) -> None:
    def list_dependencies(linker: str, library: str, environment: Mapping[str, str]) -> str:
        if calls is not None:
            calls.append((linker, library, environment))
        return output

    Loader.verify_before_loading(LIBRARY, initial, lambda path: interpreter, untrusted_in_tmp, list_dependencies)


def test_verify_before_loading_asks_the_trusted_interpreter_with_the_startup_environment() -> None:
    calls: list[tuple[str, str, Mapping[str, str]]] = []
    verify_before_loading("/lib64/ld-linux-x86-64.so.2", initial=environ_block("LD_PRELOAD=/opt/pre.so", "HOME=/root"), calls=calls)

    assert calls == [("/lib64/ld-linux-x86-64.so.2", LIBRARY, {"LD_PRELOAD": "/opt/pre.so"})]


def test_verify_before_loading_refuses_a_statically_linked_process() -> None:
    with pytest.raises(PermissionError, match="statically linked"):
        verify_before_loading(None)


def test_verify_before_loading_refuses_an_untrusted_interpreter_without_running_it() -> None:
    calls: list[tuple[str, str, Mapping[str, str]]] = []
    with pytest.raises(PermissionError, match=re.escape("dynamic linker '/tmp/ld.so' is not trusted")):
        verify_before_loading("/tmp/ld.so", calls=calls)
    assert calls == []


def test_verify_before_loading_refuses_an_untrusted_dependency() -> None:
    with pytest.raises(PermissionError, match="nothing was loaded"):
        verify_before_loading("/lib64/ld-linux-x86-64.so.2", output=LISTING + "\tlibevil.so => /tmp/libevil.so (0x1000)\n")


def test_verify_before_loading_refuses_an_unreadable_executable() -> None:
    def unreadable(path: str) -> str | None:
        raise OSError(errno.EACCES, "denied")

    with pytest.raises(PermissionError, match="Could not read which dynamic linker") as error:
        Loader.verify_before_loading(LIBRARY, None, unreadable, untrusted_in_tmp, lambda *_: "")
    assert isinstance(error.value.__cause__, OSError)


# --- On Linux: the real filesystem, dynamic linker and installed package --------------------------

IS_LINUX = sys.platform.startswith("linux")
linux_only = pytest.mark.skipif(not IS_LINUX, reason="Linux only.")


def installed_linux_library() -> str | None:
    """Where the package installed the library, or ``None`` if it isn't installed (or this is not Linux)."""
    if not IS_LINUX:
        return None
    try:
        return next((path for path in Loader.candidate_paths(CpuArchitecture.current()) if os.path.isfile(path)), None)
    except OSError:
        return None  # no package for this architecture


installed_linux_library_only = pytest.mark.skipif(installed_linux_library() is None,
                                                  reason="Linux only, with the libhkdfguard1 package installed." if IS_LINUX else "Linux only.")


def resolve(path: str, kind: UnixFileType = UnixFileType.REGULAR_FILE, allow_missing: bool = False) -> str | None:
    return Loader.resolve_trusted(path, kind, _linux.get_status_or_none, _linux.read_link, allow_missing)


@linux_only
def test_the_root_directory_and_this_processs_libc_are_trusted() -> None:
    assert resolve("/", UnixFileType.DIRECTORY) == "/"

    libc = _linux.loaded_path("libc.so.6")
    assert libc is not None
    assert (resolve(libc) or "").startswith("/")


@linux_only
def test_the_root_and_system_library_directories_are_trusted() -> None:
    for directory in ("/", "/usr/lib"):
        assert resolve(directory, UnixFileType.DIRECTORY) == directory


@linux_only
def test_probe_distinguishes_missing_from_present() -> None:
    assert probe("/") == 0
    assert probe("/definitely/not/here") == errno.ENOENT


@linux_only
def test_status_and_read_link_describe_this_users_files() -> None:
    directory = tempfile.mkdtemp(prefix="hkdfguard-status-")
    file = os.path.join(directory, "file")
    link = os.path.join(directory, "link")
    try:
        with open(file, "wb") as stream:
            stream.write(b"x")
        os.chmod(file, 0o640)
        os.symlink("file", link)
        uid = os.geteuid()  # type: ignore[attr-defined,unused-ignore]

        status = _linux.get_status_or_none(file)
        assert status is not None
        assert (status.type, status.owner_id, status.mode & 0o777) == (UnixFileType.REGULAR_FILE, uid, 0o640)
        status = _linux.get_status_or_none(link)
        assert status is not None
        assert (status.type, status.owner_id) == (UnixFileType.SYMBOLIC_LINK, uid)
        assert _linux.read_link(link) == "file"
        assert _linux.get_status_or_none(os.path.join(directory, "missing")) is None

        # Owned by this user, so the loader refuses it - however it is reached. (As root, the owner
        # is trusted, but the temporary directory above it is world-writable.)
        with pytest.raises(PermissionError):
            resolve(file)
    finally:
        for path in (link, file):
            if os.path.lexists(path):
                os.remove(path)
        os.rmdir(directory)


@linux_only
def test_a_name_nothing_is_loaded_under_has_no_loaded_path() -> None:
    assert _linux.loaded_path("libhkdfguard-never-loaded.so.0") is None


@linux_only
def test_a_directory_this_user_created_is_not_trusted_for_the_library_path() -> None:
    # The attack this loader exists to stop: a directory the service's own user (or anyone) can
    # write, put on LD_LIBRARY_PATH so a dependency is found there first.
    directory = tempfile.mkdtemp(prefix="hkdfguard-ldpath-")
    try:
        with pytest.raises(PermissionError) as error:
            Loader.verify_environment({"LD_LIBRARY_PATH": [directory]}, lambda p, kind: resolve(p, kind, allow_missing=True))
        assert directory in str(error.value)
    finally:
        os.rmdir(directory)


@linux_only
def test_the_linkers_variables_are_read_from_proc_environ() -> None:
    # Whatever this process started with, /proc/self/environ must be readable for the loader to see
    # it - and parse to the same three variables.
    block = _linux.read_initial_environment()
    assert block is not None

    values = Loader.read_environment(lambda n: None, block)
    assert sorted(values) == ["LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD"]


@linux_only
def test_dladdr_places_a_libc_export_in_libc() -> None:
    libc = ctypes.CDLL("libc.so.6")
    address = ctypes.cast(libc.dlopen, ctypes.c_void_p).value
    image = _linux.image_path(address)

    assert image is not None
    assert resolve(image) == resolve(_linux.loaded_path("libc.so.6") or "")
    assert _linux.image_path(None) is None


@linux_only
def test_this_processs_libc_has_a_trusted_dependency_closure() -> None:
    # The whole post-load check against real files: DT_NEEDED read from disk, each name bound
    # through dlopen(RTLD_NOLOAD) + dlinfo, each binding resolved through lstat and readlink.
    libc = resolve(_linux.loaded_path("libc.so.6") or "")
    assert libc is not None
    needed = ElfDependencies.read_needed(libc)
    assert any(name.startswith("ld-linux") for name in needed)

    def trusted(path: str) -> str:
        resolved = resolve(path)
        assert resolved is not None
        return resolved

    Loader.verify_dependencies(libc, ElfDependencies.read_needed, _linux.loaded_path, trusted)


@pytest.mark.skipif(not IS_LINUX or installed_linux_library() is not None, reason="Linux only, without the libhkdfguard1 package.")
def test_without_the_package_the_loader_and_the_binding_report_it_not_installed() -> None:
    with pytest.raises(NativeLibraryNotFoundError, match="libhkdfguard1"):
        Loader.load()
    with pytest.raises(NativeLibraryNotFoundError):
        LinuxHkdfGuardKmsLibrary().wrap_dek("svc", bytes(32), bytearray(512))


@installed_linux_library_only
def test_the_installed_library_is_in_a_trusted_location() -> None:
    path = installed_linux_library()
    assert path is not None

    assert resolve(path) == path


@installed_linux_library_only
def test_the_installed_library_loads_through_the_verified_loader_and_answers_the_binding() -> None:
    library = Loader.load()
    assert library is not None
    assert Loader.load() is library  # once per process

    # Through the binding: a wrap for a service nobody provisioned. Whatever this host's providers
    # say, the answer is a status code the binding can describe - never a load failure.
    binding = LinuxHkdfGuardKmsLibrary()
    status = binding.wrap_dek("hkdfguard.loadertest.unprovisioned", bytes(32), bytearray(512)).status
    assert status == OK or binding.describe_status(status) is not None, f"undescribed status {status}"

    # And the dynamic linker places the export in the verified file.
    export = getattr(library, Loader.PROBE_EXPORT)
    assert resolve(_linux.image_path(ctypes.cast(export, ctypes.c_void_p).value) or "") == installed_linux_library()


@installed_linux_library_only
def test_the_installed_library_loads_through_the_verified_loader_and_its_dependencies_are_trusted() -> None:
    # What the dynamic linker mapped is the verified file, and every dependency it pulled in came
    # from a trusted file - checked again from outside the loader, against the loaded process.
    path = installed_linux_library()
    assert path is not None
    library = Loader.load()

    expected = resolve(path)
    assert expected is not None
    export = getattr(library, Loader.PROBE_EXPORT)
    assert resolve(_linux.image_path(ctypes.cast(export, ctypes.c_void_p).value) or "") == expected

    def trusted(dependency: str) -> str:
        resolved = resolve(dependency)
        assert resolved is not None
        return resolved

    Loader.verify_dependencies(expected, ElfDependencies.read_needed, _linux.loaded_path, trusted)


@installed_linux_library_only
def test_the_installed_library_needs_tpm2_tss_and_libc() -> None:
    path = installed_linux_library()
    assert path is not None
    needed = ElfDependencies.read_needed(path)

    assert "libtss2-esys.so.0" in needed
    assert "libc.so.6" in needed


# The real dynamic linker in list mode, against files every Linux system has.


def trusted_file(path: str) -> str:
    resolved = resolve(path)
    assert resolved is not None
    return resolved


def this_processs_interpreter() -> str:
    interpreter = ElfDependencies.read_interpreter(Loader.SELF_EXECUTABLE)
    assert interpreter, f"PT_INTERP of {Loader.SELF_EXECUTABLE} = {interpreter!r}"
    return interpreter


def listing_for(target: str, environment: Mapping[str, str] | None = None) -> list[str]:
    output = _linux.list_dependencies(this_processs_interpreter(), target, environment or {})
    return Loader.parse_listing(target, output)


def libc_in_listing() -> str:
    libc = next((p for p in listing_for("/bin/sh") if os.path.basename(p).startswith("libc.so")), None)
    if libc is None:
        pytest.skip("no libc in /bin/sh's listing")
    return libc


@linux_only
def test_this_processs_interpreter_is_trusted() -> None:
    assert trusted_file(this_processs_interpreter()).startswith("/")


@linux_only
def test_the_listing_of_a_system_binary_names_libc_and_passes_the_path_checks() -> None:
    paths = listing_for("/bin/sh")

    assert any("libc.so" in os.path.basename(p) for p in paths), paths
    Loader.verify_listing("/bin/sh", paths, trusted_file)


@linux_only
def test_a_dependency_found_in_a_writable_folder_is_refused_before_anything_loads() -> None:
    # The real dynamic linker, told by LD_LIBRARY_PATH to look in a folder anyone can write, finds a
    # copy of libc there; the check refuses it whoever owns it, since the folder is 0777.
    libc = libc_in_listing()
    with tempfile.TemporaryDirectory(prefix="hkdfguard-planted-") as folder:
        os.chmod(folder, 0o777)
        planted = os.path.join(folder, os.path.basename(libc))
        with open(libc, "rb") as source, open(planted, "wb") as copy:
            copy.write(source.read())
        os.chmod(planted, 0o755)

        paths = listing_for("/bin/sh", {"LD_LIBRARY_PATH": folder})
        assert planted in paths, f"the linker did not pick up the planted copy: {paths}"
        with pytest.raises(PermissionError) as error:
            Loader.verify_listing("/bin/sh", paths, trusted_file)
        assert planted in str(error.value)
        assert "nothing was loaded" in str(error.value)


@linux_only
def test_the_listing_of_a_file_that_does_not_exist_fails() -> None:
    with pytest.raises(PermissionError, match="could not say"):
        _linux.list_dependencies(this_processs_interpreter(), "/nonexistent/libhkdfguard.so.1", {})


@linux_only
def test_the_listing_of_a_shared_library_names_the_dynamic_linker() -> None:
    # libhkdfguard.so.1 is a shared object, not an executable; list mode works on those too.
    libc = libc_in_listing()
    paths = listing_for(libc)

    assert any(os.path.basename(p).startswith("ld-linux") for p in paths), paths
    Loader.verify_listing(libc, paths, trusted_file)


@linux_only
def test_this_process_passes_the_check_before_loading_for_its_own_libc() -> None:
    # The whole pre-load check against the real process: PT_INTERP of /proc/self/exe, its trust,
    # the list run under the startup environment, and every listed path's trust.
    Loader.verify_before_loading(libc_in_listing(), _linux.read_initial_environment(), ElfDependencies.read_interpreter, trusted_file,
                                 _linux.list_dependencies)

