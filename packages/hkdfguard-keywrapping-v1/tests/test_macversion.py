"""The macOS loader's version check and home-folder rule, on Mach-O images built in memory - so they run on every platform."""

from __future__ import annotations

import errno
import struct
from pathlib import Path

import pytest
from hkdfguard.keywrapping.v1 import NativeLibraryNotFoundError
from hkdfguard.keywrapping.v1._interop._macos import MacOsNativeLibraryLoader as Loader

ARM64 = 0x0100000C
X86_64 = 0x01000007


def version(major: int, minor: int, patch: int) -> int:
    return (major << 16) | (minor << 8) | patch


def id_dylib(v: int) -> bytes:
    # cmd, cmdsize, name offset, timestamp, current, compatibility, then "x\0" padded to 32 bytes
    return struct.pack("<IIIIII", 0xD, 32, 24, 0, v, version(1, 0, 0)) + b"x".ljust(8, b"\0")


def other_command() -> bytes:  # LC_UUID
    return struct.pack("<II", 0x1B, 24) + bytes(16)


def thin_image(cputype: int, *commands: bytes) -> bytes:
    body = b"".join(commands)
    return struct.pack("<IIIIIIII", 0xFEEDFACF, cputype, 0, 6, len(commands), len(body), 0, 0) + body


def fat_image(*slices: tuple[int, bytes]) -> bytes:
    out = bytearray(4096 * (len(slices) + 1))
    struct.pack_into(">II", out, 0, 0xCAFEBABE, len(slices))
    for i, (cpu, image) in enumerate(slices):
        struct.pack_into(">IIIII", out, 8 + 20 * i, cpu, 0, 4096 * (i + 1), len(image), 12)
        out[4096 * (i + 1):4096 * (i + 1) + len(image)] = image
    return bytes(out)


def patched(image: bytes, offset: int, value: int) -> bytes:
    copy = bytearray(image)
    struct.pack_into("<I", copy, offset, value)
    return bytes(copy)


def test_reads_lc_id_dylib_from_a_thin_arm64_image() -> None:
    assert Loader.dylib_current_version(thin_image(ARM64, other_command(), id_dylib(version(0, 9, 0)))) == version(0, 9, 0)


def test_accepts_the_minimum_and_above_and_refuses_below_it() -> None:
    assert version(0, 9, 0) == Loader.MINIMUM_LIBRARY_VERSION
    for v in (version(0, 9, 0), version(0, 9, 1), version(0, 10, 0), version(1, 0, 0)):
        Loader.require_minimum_version("/lib.dylib", thin_image(ARM64, id_dylib(v)))
    with pytest.raises(PermissionError, match=r"/lib\.dylib.*0\.8\.0.*0\.9\.0"):
        Loader.require_minimum_version("/lib.dylib", thin_image(ARM64, id_dylib(version(0, 8, 0))))


GOOD = thin_image(ARM64, other_command(), id_dylib(version(0, 9, 0)))
MALFORMED = {
    "empty": b"",
    "truncated header": GOOD[:20],
    "truncated load commands": GOOD[:-8],
    "cmdsize overflow": patched(GOOD, 36, 0xFFFFFFF8),
    "cmdsize not 8-aligned": patched(GOOD, 36, 20),
    "cmdsize below 8": patched(GOOD, 36, 4),
    "ncmds beyond sizeofcmds": patched(thin_image(ARM64, other_command()), 16, 5),
    "sizeofcmds past the read": patched(thin_image(ARM64, id_dylib(version(0, 9, 0))), 20, 1 << 20),
    "wrong magic": patched(GOOD, 0, 0xFEEDFACE),
    "no LC_ID_DYLIB": thin_image(ARM64, other_command()),
    "x86_64-only thin file": thin_image(X86_64, id_dylib(version(0, 9, 0))),
    "fat without arm64": fat_image((X86_64, thin_image(X86_64, id_dylib(version(0, 9, 0))))),
}


@pytest.mark.parametrize("name", MALFORMED)
def test_refuses_what_is_not_a_well_formed_arm64_dylib(name: str) -> None:
    with pytest.raises(ValueError):
        Loader.dylib_current_version(MALFORMED[name])
    with pytest.raises(PermissionError, match=r"/lib\.dylib"):
        Loader.require_minimum_version("/lib.dylib", MALFORMED[name])


def test_reads_the_arm64_slice_of_a_fat_image_and_refuses_one_beyond_the_bytes_read() -> None:
    data = fat_image((X86_64, thin_image(X86_64, id_dylib(version(1, 0, 0)))), (ARM64, thin_image(ARM64, id_dylib(version(0, 10, 0)))))
    assert Loader.dylib_current_version(data) == version(0, 10, 0)
    for cut in (2 * 4096 + 16, 2 * 4096):
        with pytest.raises(ValueError):
            Loader.dylib_current_version(data[:cut])
    assert Loader.format_version(version(0, 10, 0)) == "0.10.0"


def test_accepts_the_release_installed_on_this_machine_when_there_is_one() -> None:
    path = Path(Loader.system_path())
    if not path.exists():
        pytest.skip(f"no system install at {path}")
    with path.open("rb") as file:
        Loader.require_minimum_version(str(path), file.read(Loader.VERSION_READ_LIMIT))


@pytest.mark.parametrize(("home", "expected"), [("/Users/dev", "/Users/dev"), (None, ""), ("", ""), ("Users/dev", ""), ("~/dev", "")])
def test_only_an_absolute_home_from_a_successful_account_lookup_is_used(home: str | None, expected: str) -> None:
    assert Loader.home_from_account(home) == expected


def test_with_no_usable_home_only_the_system_install_is_considered() -> None:
    probed: list[str] = []

    def probe(path: str) -> int:
        probed.append(path)
        return errno.ENOENT

    with pytest.raises(NativeLibraryNotFoundError):
        Loader.choose_path(probe, Loader.home_from_account(None))
    assert probed == [Loader.system_path()]
