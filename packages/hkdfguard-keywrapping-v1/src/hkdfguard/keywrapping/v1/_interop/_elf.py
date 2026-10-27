"""Reads the DT_NEEDED entries of an ELF shared object - the libraries it asks the dynamic linker to
load - and the PT_INTERP path of an ELF executable - the dynamic linker it runs under."""

from __future__ import annotations

import os
import struct
from collections.abc import Callable
from typing import Final


class ElfDependencies:
    """Reads the DT_NEEDED entries - the shared libraries an ELF object asks the dynamic linker to
    load - and the PT_INTERP path - the dynamic linker an executable names - from a 64-bit
    little-endian ELF file (x86-64 and arm64 Linux). Only the ELF header, the program headers, the
    interpreter path, the dynamic segment and its string table are read, each bounded. Anything
    malformed is refused with ``PermissionError``: the caller is deciding whether to trust what the
    file pulled into the process."""

    HEADER_SIZE: Final = 64
    PROGRAM_HEADER_SIZE: Final = 56
    DYNAMIC_ENTRY_SIZE: Final = 16
    MAX_PROGRAM_HEADERS: Final = 4096
    MAX_SEGMENT_BYTES: Final = 1 << 20

    PT_LOAD: Final = 1
    PT_DYNAMIC: Final = 2
    PT_INTERP: Final = 3

    MAX_INTERPRETER_BYTES: Final = 4096
    """Bounds PT_INTERP, a path: PATH_MAX."""

    DT_NULL: Final = 0
    DT_NEEDED: Final = 1
    DT_STRTAB: Final = 5
    DT_STRSZ: Final = 10

    _MAX_OFFSET: Final = (1 << 63) - 1

    @classmethod
    def read_needed(cls, path: str) -> list[str]:
        """The DT_NEEDED names of the ELF file at ``path``, in file order.

        :raises PermissionError: the file is not a well-formed 64-bit little-endian ELF object
        :raises OSError: the file could not be read
        """
        return cls._read_file(path, cls.read_needed_from)

    @classmethod
    def read_interpreter(cls, path: str) -> str | None:
        """The PT_INTERP path of the ELF file at ``path`` - for an executable, the dynamic linker the
        kernel started it with - or ``None`` if it has none.

        :raises PermissionError: the file is not a well-formed 64-bit little-endian ELF file
        :raises OSError: the file could not be read
        """
        return cls._read_file(path, cls.read_interpreter_from)

    @staticmethod
    def _read_file[T](path: str, parse: Callable[[str, Callable[[int, int], bytes | None]], T]) -> T:
        with open(path, "rb") as file:
            def read(offset: int, count: int) -> bytes | None:
                file.seek(offset)
                data = bytearray()
                while len(data) < count:
                    chunk = file.read(count - len(data))
                    if not chunk:
                        break
                    data += chunk
                return bytes(data) if len(data) == count else None

            return parse(path, read)

    @classmethod
    def read_interpreter_from(cls, path: str, read: Callable[[int, int], bytes | None]) -> str | None:
        """:param path: the file's name, for messages
        :param read: reads exactly ``count`` bytes at ``offset``, or returns ``None`` if the file is shorter
        """
        program_headers, program_header_size, program_header_count = cls._read_program_headers(path, read)
        for index in range(program_header_count):
            at = index * program_header_size
            if struct.unpack_from("<I", program_headers, at)[0] != cls.PT_INTERP:
                continue
            offset = cls._to_offset(path, struct.unpack_from("<Q", program_headers, at + 8)[0])
            file_size = struct.unpack_from("<Q", program_headers, at + 32)[0]
            if file_size == 0 or file_size > cls.MAX_INTERPRETER_BYTES:
                raise cls._malformed(path, "its interpreter path is empty or implausibly long")
            raw = cls._read(path, read, offset, file_size, "interpreter path")
            end = raw.find(b"\0")
            if end <= 0:
                raise cls._malformed(path, "its interpreter path is not a NUL-terminated string")
            return os.fsdecode(raw[:end])
        return None

    @classmethod
    def read_needed_from(cls, path: str, read: Callable[[int, int], bytes | None]) -> list[str]:  # noqa: PLR0912 - one pass, as in .NET
        """:param path: the file's name, for messages
        :param read: reads exactly ``count`` bytes at ``offset``, or returns ``None`` if the file is shorter
        """
        program_headers, program_header_size, program_header_count = cls._read_program_headers(path, read)
        loads: list[tuple[int, int, int]] = []  # (virtual address, file size, file offset)
        dynamic: tuple[int, int] | None = None  # (file offset, size)
        for index in range(program_header_count):
            at = index * program_header_size
            segment_type = struct.unpack_from("<I", program_headers, at)[0]
            offset = cls._to_offset(path, struct.unpack_from("<Q", program_headers, at + 8)[0])
            virtual_address = struct.unpack_from("<Q", program_headers, at + 16)[0]
            file_size = struct.unpack_from("<Q", program_headers, at + 32)[0]

            if segment_type == cls.PT_LOAD:
                loads.append((virtual_address, file_size, offset))
            elif segment_type == cls.PT_DYNAMIC:
                dynamic = (offset, cls._to_size(path, file_size, "dynamic segment"))

        if dynamic is None:
            return []

        needed_offsets: list[int] = []
        string_table_address: int | None = None
        string_table_size: int | None = None
        dynamic_offset, dynamic_size = dynamic
        entries = cls._read(path, read, dynamic_offset, dynamic_size - dynamic_size % cls.DYNAMIC_ENTRY_SIZE, "dynamic segment")
        for at in range(0, len(entries) - cls.DYNAMIC_ENTRY_SIZE + 1, cls.DYNAMIC_ENTRY_SIZE):
            tag, value = struct.unpack_from("<qQ", entries, at)
            if tag == cls.DT_NULL:
                break
            if tag == cls.DT_NEEDED:
                needed_offsets.append(value)
            elif tag == cls.DT_STRTAB:
                string_table_address = value
            elif tag == cls.DT_STRSZ:
                string_table_size = value

        if not needed_offsets:
            return []
        if string_table_address is None or string_table_size is None:
            raise cls._malformed(path, "it names dependencies but has no string table")

        # DT_STRTAB is a virtual address; the PT_LOAD segment containing it maps it to the file.
        address = string_table_address
        containing = next((load for load in loads if address >= load[0] and address - load[0] < load[1]), None)
        if containing is None:
            raise cls._malformed(path, "its string table lies outside every loaded segment")

        strings = cls._read(path, read, containing[2] + (address - containing[0]), cls._to_size(path, string_table_size, "string table"),
                            "string table")
        names: list[str] = []
        for offset in needed_offsets:
            end = strings.find(b"\0", offset) if offset < len(strings) else -1
            if end < 0:
                raise cls._malformed(path, "a dependency name runs past its string table")
            # As the file system would decode it, so a name round-trips to dlopen unchanged.
            names.append(os.fsdecode(strings[offset:end]))
        return names

    @classmethod
    def _read_program_headers(cls, path: str, read: Callable[[int, int], bytes | None]) -> tuple[bytes, int, int]:
        """Validates the ELF header; returns the program header table, the size of one entry and the
        number of entries."""
        header = cls._read(path, read, 0, cls.HEADER_SIZE, "ELF header")
        if header[:4] != b"\x7fELF":
            raise cls._malformed(path, "it is not an ELF file")
        if header[4] != 2 or header[5] != 1:
            raise cls._malformed(path, "it is not a 64-bit little-endian ELF file")

        program_header_offset = cls._to_offset(path, struct.unpack_from("<Q", header, 32)[0])
        program_header_size, program_header_count = struct.unpack_from("<HH", header, 54)
        if program_header_size < cls.PROGRAM_HEADER_SIZE or program_header_count == 0 or program_header_count > cls.MAX_PROGRAM_HEADERS:
            raise cls._malformed(path, "its program header table is malformed")
        # Both fields are 16-bit, so their product can reach 256 MB; bound the table like every other
        # region read, before anything is allocated for it.
        table_size = cls._to_size(path, program_header_size * program_header_count, "program header table")
        return cls._read(path, read, program_header_offset, table_size, "program headers"), program_header_size, program_header_count

    @classmethod
    def _read(cls, path: str, read: Callable[[int, int], bytes | None], offset: int, count: int, what: str) -> bytes:
        data = read(offset, count)
        if data is None or len(data) != count:
            raise cls._malformed(path, f"its {what} runs past the end of the file")
        return data

    @classmethod
    def _to_offset(cls, path: str, value: int) -> int:
        if value > cls._MAX_OFFSET:
            raise cls._malformed(path, "a file offset is out of range")
        return value

    @classmethod
    def _to_size(cls, path: str, value: int, what: str) -> int:
        if value > cls.MAX_SEGMENT_BYTES:
            raise cls._malformed(path, f"its {what} is implausibly large")
        return value

    @staticmethod
    def _malformed(path: str, reason: str) -> PermissionError:
        return PermissionError(f"'{path}' is not a well-formed ELF shared object: {reason}.")
