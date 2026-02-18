"""
bytecode.py – RealLive bytecode file header detection and parsing.

Mirrors src/common/bytecode.ml.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Magic / header constants
# ---------------------------------------------------------------------------

_V1_MAGICS = {b"KP2K", b"RD2K", b"\xcc\x01\x00\x00"}
_V2_MAGICS = {b"KPRL", b"RDRL", b"KPRM", b"RDRM", b"\xd0\x01\x00\x00"}
_UNCOMPRESSED_MAGICS = {b"KPRL", b"KP2K", b"KPRM", b"RDRL", b"RD2K", b"RDRM"}

_KNOWN_COMPILER_VERSIONS = {10002, 110002}


# ---------------------------------------------------------------------------
# Data structure
# ---------------------------------------------------------------------------

@dataclass
class FileHeader:
    header_version: int = 0
    compiler_version: int = 0
    data_offset: int = 0
    uncompressed_size: int = 0
    # None  → file is not compressed (version-1 headers, or version-2 with 0 stored)
    compressed_size: Optional[int] = None
    int_0x2c: int = 0
    entry_points: list[int] = field(default_factory=list)
    kidoku_lnums: list[int] = field(default_factory=list)
    dramatis_personae: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

def is_bytecode(data: bytes | bytearray, offset: int = 0) -> bool:
    """Return True if *data[offset:]* looks like a valid RealLive bytecode file."""
    if len(data) < offset + 8:
        return False
    magic = bytes(data[offset: offset + 4])
    if magic in {b"RDRL", b"RD2K", b"RDRM"}:
        return True
    if magic in {b"KPRL", b"KP2K", b"KPRM",
                 b"\xd0\x01\x00\x00", b"\xcc\x01\x00\x00", b"\xb8\x01\x00\x00"}:
        cver = struct.unpack_from("<I", data, offset + 4)[0]
        return cver in _KNOWN_COMPILER_VERSIONS
    return False


def uncompressed_header(magic: bytes) -> bool:
    """Return True if *magic* identifies an uncompressed bytecode file."""
    return magic in _UNCOMPRESSED_MAGICS


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------

def _get_u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _get_i32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def _read_cstring(data: bytes | bytearray, idx: int, length: int) -> str:
    """Read *length* bytes from *idx* and return as a string (stopping at NUL)."""
    raw = bytes(data[idx: idx + length])
    nul = raw.find(b"\x00")
    if nul != -1:
        raw = raw[:nul]
    return raw.decode("latin-1")


def read_file_header(data: bytes | bytearray, rd_handler=None) -> FileHeader:
    """
    Parse the file header of a RealLive bytecode blob and return a FileHeader.

    *rd_handler*, if provided, is called with *data* when the magic begins with
    ``RD`` (mirrors the OCaml rd_handler optional argument).

    Raises ValueError for unrecognised / unsupported files.
    """
    if not is_bytecode(data):
        raise ValueError("not a bytecode file")

    magic = bytes(data[0:4])

    # Determine compiler version
    if magic[:2] == b"RD":
        if rd_handler is not None:
            rd_handler(data)
        compiler_version = 110002 if magic[2:4] == b"RM" else 10002
    else:
        compiler_version = _get_u32(data, 4)

    hdr = FileHeader(compiler_version=compiler_version)

    if magic in _V1_MAGICS:
        # Version 1: AVG2000 format — never compressed
        hdr.header_version = 1
        n_kidoku = _get_u32(data, 0x20)
        hdr.data_offset = 0x1cc + n_kidoku * 4
        hdr.uncompressed_size = _get_u32(data, 0x24)
        hdr.int_0x2c = _get_u32(data, 0x28)
        hdr.compressed_size = None

    elif magic in _V2_MAGICS:
        # Version 2: RealLive format — may be compressed
        hdr.header_version = 2
        hdr.data_offset = _get_u32(data, 0x20)
        hdr.uncompressed_size = _get_u32(data, 0x24)
        csize = _get_u32(data, 0x28)
        hdr.compressed_size = csize if csize != 0 else None
        hdr.int_0x2c = _get_u32(data, 0x2c)

    else:
        raise ValueError(f"unsupported header format: {magic!r}")

    return hdr


def read_full_header(data: bytes | bytearray, rd_handler=None) -> FileHeader:
    """
    Like read_file_header but also populates entry_points, kidoku_lnums, and
    (for version 2) dramatis_personae.
    """
    hdr = read_file_header(data, rd_handler)

    if hdr.header_version == 1:
        hdr.entry_points = [
            _get_u32(data, 0x30 + i * 4) for i in range(100)
        ]
        n_kidoku = _get_u32(data, 0x20)
        hdr.kidoku_lnums = [
            _get_i32(data, 0x1cc + i * 4) for i in range(n_kidoku)
        ]

    elif hdr.header_version == 2:
        hdr.entry_points = [
            _get_u32(data, 0x34 + i * 4) for i in range(100)
        ]
        t1_offset = _get_u32(data, 0x08)
        n_kidoku = _get_u32(data, 0x0c)
        hdr.kidoku_lnums = [
            _get_i32(data, t1_offset + i * 4) for i in range(n_kidoku)
        ]

        # Dramatis personae (character name list)
        n_persons = _get_u32(data, 0x18)
        offset = _get_u32(data, 0x14)
        persons = []
        for _ in range(n_persons):
            length = _get_u32(data, offset)
            idx = offset + 4
            persons.append(_read_cstring(data, idx, length))
            offset = idx + length
        hdr.dramatis_personae = persons

    return hdr
