"""
rlcmp.py – RealLive LZ77 compression/decompression and XOR masking.

Mirrors src/common/rlcmp.ml (OCaml) and src/common/lz_comp_rl.cpp (C++).
All operations work on plain Python bytes / bytearray; no C extensions needed.
"""

from __future__ import annotations

import struct
from typing import Optional


# ---------------------------------------------------------------------------
# XOR mask
# ---------------------------------------------------------------------------

# 256-byte key from lz_comp_rl.cpp (rl_prim_apply_mask).
# The C code uses `uchar i` which wraps at 256, giving a 256-byte cycle.
XOR_MASK: bytes = bytes([
    0x8b, 0xe5, 0x5d, 0xc3, 0xa1, 0xe0, 0x30, 0x44, 0x00, 0x85, 0xc0, 0x74,
    0x09, 0x5f, 0x5e, 0x33, 0xc0, 0x5b, 0x8b, 0xe5, 0x5d, 0xc3, 0x8b, 0x45,
    0x0c, 0x85, 0xc0, 0x75, 0x14, 0x8b, 0x55, 0xec, 0x83, 0xc2, 0x20, 0x52,
    0x6a, 0x00, 0xe8, 0xf5, 0x28, 0x01, 0x00, 0x83, 0xc4, 0x08, 0x89, 0x45,
    0x0c, 0x8b, 0x45, 0xe4, 0x6a, 0x00, 0x6a, 0x00, 0x50, 0x53, 0xff, 0x15,
    0x34, 0xb1, 0x43, 0x00, 0x8b, 0x45, 0x10, 0x85, 0xc0, 0x74, 0x05, 0x8b,
    0x4d, 0xec, 0x89, 0x08, 0x8a, 0x45, 0xf0, 0x84, 0xc0, 0x75, 0x78, 0xa1,
    0xe0, 0x30, 0x44, 0x00, 0x8b, 0x7d, 0xe8, 0x8b, 0x75, 0x0c, 0x85, 0xc0,
    0x75, 0x44, 0x8b, 0x1d, 0xd0, 0xb0, 0x43, 0x00, 0x85, 0xff, 0x76, 0x37,
    0x81, 0xff, 0x00, 0x00, 0x04, 0x00, 0x6a, 0x00, 0x76, 0x43, 0x8b, 0x45,
    0xf8, 0x8d, 0x55, 0xfc, 0x52, 0x68, 0x00, 0x00, 0x04, 0x00, 0x56, 0x50,
    0xff, 0x15, 0x2c, 0xb1, 0x43, 0x00, 0x6a, 0x05, 0xff, 0xd3, 0xa1, 0xe0,
    0x30, 0x44, 0x00, 0x81, 0xef, 0x00, 0x00, 0x04, 0x00, 0x81, 0xc6, 0x00,
    0x00, 0x04, 0x00, 0x85, 0xc0, 0x74, 0xc5, 0x8b, 0x5d, 0xf8, 0x53, 0xe8,
    0xf4, 0xfb, 0xff, 0xff, 0x8b, 0x45, 0x0c, 0x83, 0xc4, 0x04, 0x5f, 0x5e,
    0x5b, 0x8b, 0xe5, 0x5d, 0xc3, 0x8b, 0x55, 0xf8, 0x8d, 0x4d, 0xfc, 0x51,
    0x57, 0x56, 0x52, 0xff, 0x15, 0x2c, 0xb1, 0x43, 0x00, 0xeb, 0xd8, 0x8b,
    0x45, 0xe8, 0x83, 0xc0, 0x20, 0x50, 0x6a, 0x00, 0xe8, 0x47, 0x28, 0x01,
    0x00, 0x8b, 0x7d, 0xe8, 0x89, 0x45, 0xf4, 0x8b, 0xf0, 0xa1, 0xe0, 0x30,
    0x44, 0x00, 0x83, 0xc4, 0x08, 0x85, 0xc0, 0x75, 0x56, 0x8b, 0x1d, 0xd0,
    0xb0, 0x43, 0x00, 0x85, 0xff, 0x76, 0x49, 0x81, 0xff, 0x00, 0x00, 0x04,
    0x00, 0x6a, 0x00, 0x76,
])

assert len(XOR_MASK) == 256, "XOR_MASK must be exactly 256 bytes"

# Default secondary XOR key (used for Little Busters! — compiler_version 110002).
# Configurable at runtime; matches the default in rlcmp.ml.
DEFAULT_KEY2: bytes = bytes([
    0xAF, 0x2F, 0xFB, 0x6B, 0xAF, 0x30, 0x77, 0x17,
    0x87, 0x48, 0xFE, 0x2C, 0x68, 0x1A, 0xB9, 0xF0,
])

# Bit-reversal lookup table used by RLDataContainer when writing flag bytes.
# reverse_bits[b] gives the byte with all 8 bits of b reversed.
_REVERSE_BITS: bytes = bytes([
    0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0,
    0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0,
    0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8,
    0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8,
    0x04, 0x84, 0x44, 0xc4, 0x24, 0xa4, 0x64, 0xe4,
    0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4,
    0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec,
    0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc,
    0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2,
    0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2,
    0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea,
    0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa,
    0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6,
    0x16, 0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6,
    0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee,
    0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe,
    0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1,
    0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1,
    0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9,
    0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9,
    0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5,
    0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5,
    0x0d, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed,
    0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd,
    0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3,
    0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3,
    0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb,
    0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb,
    0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7,
    0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7,
    0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef,
    0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f, 0xff,
])


# ---------------------------------------------------------------------------
# XOR helpers
# ---------------------------------------------------------------------------

def apply_mask(data: bytearray, offset: int, mask: bytes = XOR_MASK) -> None:
    """
    XOR *data[offset:]* in-place using the cycling *mask*.

    Mirrors ``rl_prim_apply_mask`` in lz_comp_rl.cpp.
    Applied identically when compressing and decompressing.
    """
    mask_len = len(mask)
    for i in range(len(data) - offset):
        data[offset + i] ^= mask[i % mask_len]


def _apply_xor2(data: bytearray, key: bytes) -> None:
    """
    Apply the secondary 16-byte XOR pass used by Little Busters!
    257 bytes starting at offset 256 are XORed (stopping at EOF if shorter).
    Mirrors the use_xor_2 block in both rl_prim_decompress and rl_prim_compress.
    """
    start = 256
    end = min(start + 257, len(data))
    key_len = len(key)
    for i in range(end - start):
        data[start + i] ^= key[i % key_len]


# ---------------------------------------------------------------------------
# Decompression
# ---------------------------------------------------------------------------

def decompress(
    data: bytes | bytearray,
    use_xor2: bool = False,
    key2: bytes = DEFAULT_KEY2,
) -> bytes:
    """
    Decompress a RealLive LZ-compressed data block (without file header).

    *data* is the raw compressed block as stored in the file starting at
    *data_offset*.  The first 8 bytes of the block are:
      [0:4]  compressed length (little-endian uint32)  — informational
      [4:8]  uncompressed length (little-endian uint32)

    Returns the decompressed bytes.

    Mirrors ``rl_prim_decompress`` in lz_comp_rl.cpp.
    """
    if len(data) < 8:
        raise ValueError("compressed block too short")

    uncompressed_size = struct.unpack_from("<I", data, 4)[0]
    if uncompressed_size == 0:
        return b""
    dst = bytearray(uncompressed_size)
    dst_pos = 0

    src_pos = 8  # skip the 8-byte header
    flag = data[src_pos]
    src_pos += 1
    bit = 1

    src_len = len(data)

    while src_pos < src_len and dst_pos < uncompressed_size:
        if bit == 256:
            bit = 1
            flag = data[src_pos]
            src_pos += 1

        if flag & bit:
            # Literal byte
            dst[dst_pos] = data[src_pos]
            dst_pos += 1
            src_pos += 1
        else:
            # Back-reference
            if src_pos + 1 >= src_len:
                break
            lo = data[src_pos]
            hi = data[src_pos + 1]
            src_pos += 2
            word = lo | (hi << 8)
            dist = word >> 4
            match_len = (word & 0x0f) + 2
            repeat_ptr = dst_pos - dist
            if repeat_ptr < 0:
                raise ValueError("corrupt data: back-reference out of bounds")
            for _ in range(match_len):
                if dst_pos >= uncompressed_size:
                    break
                dst[dst_pos] = dst[repeat_ptr]
                dst_pos += 1
                repeat_ptr += 1

        bit <<= 1

    if use_xor2:
        _apply_xor2(dst, key2)

    return bytes(dst)


# ---------------------------------------------------------------------------
# Compression (pure-Python LZ77 matching CInfoRealLive)
# ---------------------------------------------------------------------------

# CInfoRealLive parameters (from lzcomp.h)
_MAX_DIST  = 4095
_MAX_MATCH = 17
_MIN_MATCH = 3
_MAX_CHAIN = 16   # hash chain search depth (MaxChain in CInfoRealLive)


def _lz_compress_raw(src: bytes | bytearray) -> bytearray:
    """
    Compress *src* using the RealLive LZ77 variant (CInfoRealLive +
    RLDataContainer).  Returns the raw compressed stream **without** the
    8-byte length header.

    Uses a hash-chain index (same algorithm as lzcomp.h) for O(n) average
    time instead of the naive O(n²) scan.
    """
    src_len = len(src)
    out = bytearray()
    if src_len == 0:
        return out

    # head[h] = most recent position where the 3-byte sequence with hash h
    # appeared.  prev[pos] = previous position with the same hash.
    head: dict[int, int] = {}
    prev = [-1] * src_len  # allocated once; filled lazily

    def _insert(p: int) -> None:
        """Add position *p* to the hash chain (requires p+2 < src_len)."""
        h = src[p] | (src[p + 1] << 8) | (src[p + 2] << 16)
        prev[p] = head.get(h, -1)
        head[h] = p

    def _best_match(p: int) -> tuple[int, int]:
        """
        Return (match_pos, match_len) for the best back-reference at *p*,
        or (0, 0) if none of length >= _MIN_MATCH exists.
        """
        if p + _MIN_MATCH > src_len:
            return 0, 0
        h = src[p] | (src[p + 1] << 8) | (src[p + 2] << 16)
        candidate = head.get(h, -1)
        best_pos = 0
        best_len = 0
        max_lookahead = min(_MAX_MATCH, src_len - p)
        chain = _MAX_CHAIN
        while candidate != -1 and chain > 0:
            dist = p - candidate
            if dist > _MAX_DIST:
                break
            # Measure match length without going past end-of-input
            lo = 0
            while lo < max_lookahead and src[candidate + lo] == src[p + lo]:
                lo += 1
            if lo > best_len:
                best_len = lo
                best_pos = candidate
                if best_len == _MAX_MATCH:
                    break
            candidate = prev[candidate]
            chain -= 1
        return (best_pos, best_len) if best_len >= _MIN_MATCH else (0, 0)

    pos = 0
    while pos < src_len:
        chunk_data = bytearray()
        flag = 0
        flagmask = 0x80  # MSB first during construction

        for _ in range(8):
            if pos >= src_len:
                break

            match_pos, match_len = _best_match(pos)

            if match_len >= _MIN_MATCH:
                # Back-reference: flag bit stays 0
                dist = pos - match_pos
                word = (dist << 4) | (match_len - 2)
                chunk_data.append(word & 0xff)
                chunk_data.append((word >> 8) & 0xff)
                # Insert all positions consumed by the back-reference
                for k in range(match_len):
                    if pos + k + _MIN_MATCH <= src_len:
                        _insert(pos + k)
                pos += match_len
            else:
                # Literal: flag bit = 1
                flag |= flagmask
                if pos + _MIN_MATCH <= src_len:
                    _insert(pos)
                chunk_data.append(src[pos])
                pos += 1

            flagmask >>= 1
            if flagmask == 0:
                break

        # RLDataContainer reverses the bits of the flag byte before storing.
        out.append(_REVERSE_BITS[flag])
        out.extend(chunk_data)

    return out


def compress(
    data: bytes | bytearray,
    use_xor2: bool = False,
    key2: bytes = DEFAULT_KEY2,
) -> bytes:
    """
    Compress the payload of a RealLive bytecode file.

    *data* is the **full** bytecode file (header + uncompressed data).

    The function reads the file header to find *data_offset*, then:
      1. Applies the optional secondary XOR pass (use_xor2 / Little Busters!).
      2. LZ-compresses the data section.
      3. XOR-masks the compressed data with XOR_MASK.
      4. Rebuilds a compressed file with an updated header.

    If the header already indicates a compressed file (compressed_size is set
    and the magic is a ``KP*`` / ``RD*`` variant) the data is still
    re-compressed (idempotent if already handled upstream).

    Returns the complete compressed bytecode file as bytes.

    Mirrors ``Rlcmp.compress`` in rlcmp.ml.
    """
    from .bytecode import read_file_header, uncompressed_header

    hdr = read_file_header(data)
    data_offset = hdr.data_offset
    magic = bytes(data[0:4])

    buf = bytearray(data)  # work on a copy

    if hdr.header_version == 1:
        # Version-1 (KP2K / AVG2000): format does not support LZ compression.
        # Just apply the XOR mask and update the compiler_version field.
        # Mirrors the `compressed_size = None` branch in OCaml's Rlcmp.compress.
        apply_mask(buf, data_offset)
        struct.pack_into("<I", buf, 4, hdr.compiler_version)
        return bytes(buf)

    # Version-2 (KPRL / RealLive): LZ-compress the data section. -----------
    payload = bytearray(data[data_offset:])

    if use_xor2:
        _apply_xor2(payload, key2)

    compressed = _lz_compress_raw(payload)
    compressed_size = len(compressed) + 8  # include the 8-byte length prefix

    # Build output buffer: header + 8-byte length block + compressed data
    result = bytearray(data_offset + compressed_size)
    result[:data_offset] = data[:data_offset]

    # 8-byte length block at the start of the compressed region
    struct.pack_into("<I", result, data_offset,     compressed_size)
    struct.pack_into("<I", result, data_offset + 4, len(payload))
    result[data_offset + 8: data_offset + compressed_size] = compressed

    # Update header fields (mirrors OCaml put_int calls)
    struct.pack_into("<I", result, 0,    0x1d0)                   # magic override
    struct.pack_into("<I", result, 4,    hdr.compiler_version)
    struct.pack_into("<I", result, 0x28, compressed_size)

    # Apply XOR mask to the data section of the result
    apply_mask(result, data_offset)

    return bytes(result)


def decompress_file(
    data: bytes | bytearray,
    use_xor2: bool = False,
    key2: bytes = DEFAULT_KEY2,
) -> bytes:
    """
    Decompress a complete RealLive bytecode file (header + data).

    Returns the full decompressed file (header bytes replaced so that the
    magic indicates an uncompressed file).

    Mirrors ``Rlcmp.decompress`` in rlcmp.ml.
    """
    from .bytecode import read_file_header

    hdr = read_file_header(data)
    buf = bytearray(data)

    # XOR-unmask the data section first (same operation as masking)
    apply_mask(buf, hdr.data_offset)

    if hdr.compressed_size is None:
        # Already uncompressed after unmasking
        return bytes(buf)

    compressed_block = bytes(buf[hdr.data_offset: hdr.data_offset + hdr.compressed_size])
    decompressed = decompress(compressed_block, use_xor2=use_xor2, key2=key2)

    result = bytearray(hdr.data_offset + len(decompressed))
    result[:hdr.data_offset] = buf[:hdr.data_offset]
    result[hdr.data_offset:] = decompressed
    return bytes(result)
