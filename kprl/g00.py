"""
kprl.g00 — RealLive G00 image format ↔ PNG converter.

Port of src/vaconv/g00.ml + src/vaconv/g00-bt.cpp (vaconv tool by Haeleth).

G00 sub-formats (identified by first byte):
  0 — 24-bit RGB, pixel-unit LZSS (3 bytes/pixel)
  1 — 8-bit paletted RGBA, byte-unit LZSS
  2 — 32-bit RGBA with region table, byte-unit LZSS

G00 format 0 header (13 bytes):
  [0]      uint8  format=0
  [1..2]   int16  width
  [3..4]   int16  height
  [5..8]   int32  compressed_size   (includes 8-byte own header = data_size+8)
  [9..12]  int32  uncompressed_size (= width*height*4, in the C code but really W*H*3 pixels)

G00 format 1 header (13 bytes):  same layout, then uncompressed stream:
  [0..1]   int16  palette_len
  [2..]    RGBA palette (palette_len * 4 bytes)
  [..]     uint8 indices (width*height)

G00 format 2 header:
  [0]      uint8  format=2
  [1..2]   int16  width
  [3..4]   int16  height
  [5..8]   int32  region_count
  [9..]    region_count × 24 bytes:  x1,y1,x2,y2,ox,oy (each int32 LE)
  then compressed_size(4) + uncompressed_size(4) + compressed_data
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from PIL import Image as PILImage


# ---------------------------------------------------------------------------
# LZSS decompressors
# ---------------------------------------------------------------------------

def _decompress_g00_0(src: bytes, width: int, height: int) -> bytearray:
    """Pixel-unit LZSS for G00 format 0 (3 bytes per pixel)."""
    dst_size = width * height * 3
    dst = bytearray(dst_size)
    dp = 0
    sp = 0
    slen = len(src)
    bit = 256  # force flag read on first iteration
    flag = 0
    while sp < slen and dp < dst_size:
        if bit == 256:
            flag = src[sp]; sp += 1
            bit = 1
        if flag & bit:
            # literal pixel (3 bytes)
            dst[dp] = src[sp]; dp += 1; sp += 1
            dst[dp] = src[sp]; dp += 1; sp += 1
            dst[dp] = src[sp]; dp += 1; sp += 1
        else:
            # back-reference
            lo = src[sp]; sp += 1
            hi = src[sp]; sp += 1
            word = lo | (hi << 8)
            offset = (word >> 4) * 3          # pixel offset → byte offset
            count  = ((word & 0x0f) + 1) * 3  # pixel count → byte count
            rp = dp - offset
            if rp < 0 or rp >= dp:
                raise ValueError(f"G00-0 decompressor: bad back-reference rp={rp}")
            for _ in range(count):
                if dp >= dst_size:
                    break
                dst[dp] = dst[rp]; dp += 1; rp += 1
        bit <<= 1


    return dst


def _decompress_g00_1(src: bytes, dst_size: int) -> bytearray:
    """Byte-unit LZSS for G00 formats 1 and 2."""
    dst = bytearray(dst_size)
    dp = 0
    sp = 0
    slen = len(src)
    bit = 256
    flag = 0
    while sp < slen and dp < dst_size:
        if bit == 256:
            flag = src[sp]; sp += 1
            bit = 1
        if flag & bit:
            dst[dp] = src[sp]; dp += 1; sp += 1
        else:
            lo = src[sp]; sp += 1
            hi = src[sp]; sp += 1
            word = lo | (hi << 8)
            offset = word >> 4
            count  = (word & 0x0f) + 2
            rp = dp - offset
            if rp < 0 or rp >= dp:
                raise ValueError(f"G00-1 decompressor: bad back-reference rp={rp}")
            for _ in range(count):
                if dp >= dst_size:
                    break
                dst[dp] = dst[rp]; dp += 1; rp += 1
        bit <<= 1
    return dst


# ---------------------------------------------------------------------------
# LZSS compressors
# ---------------------------------------------------------------------------

def _compress_g00_0(pixels: bytes) -> bytes:
    """Pixel-unit LZSS compressor for G00 format 0."""
    src = pixels
    slen = len(src)
    assert slen % 3 == 0
    out = bytearray()
    sp = 0
    while sp < slen:
        ctrl_pos = len(out)
        out.append(0)
        ctrl = 0
        for bit in range(8):
            if sp >= slen:
                break
            # Try to find a back-reference (in pixel units)
            best_len = 0
            best_off = 0
            max_off = min(sp // 3, 4095)
            for off in range(1, max_off + 1):
                rp = sp - off * 3
                ml = 0
                while (ml < 16 and sp + ml * 3 + 2 < slen
                       and src[sp + ml*3]     == src[rp + ml*3]
                       and src[sp + ml*3 + 1] == src[rp + ml*3 + 1]
                       and src[sp + ml*3 + 2] == src[rp + ml*3 + 2]):
                    ml += 1
                if ml > best_len:
                    best_len, best_off = ml, off
                    if ml == 16:
                        break
            if best_len >= 1:
                word = (best_off << 4) | (best_len - 1)
                out.append(word & 0xff)
                out.append((word >> 8) & 0xff)
                sp += best_len * 3
            else:
                ctrl |= 1 << bit
                out.append(src[sp]); out.append(src[sp+1]); out.append(src[sp+2])
                sp += 3
        out[ctrl_pos] = ctrl
    return bytes(out)


def _compress_g00_1(data: bytes) -> bytes:
    """Byte-unit LZSS compressor for G00 formats 1 and 2."""
    src = data
    slen = len(src)
    out = bytearray()
    sp = 0
    while sp < slen:
        ctrl_pos = len(out)
        out.append(0)
        ctrl = 0
        for bit in range(8):
            if sp >= slen:
                break
            best_len = 0
            best_off = 0
            max_off = min(sp, 4095)
            for off in range(1, max_off + 1):
                rp = sp - off
                ml = 0
                while ml < 17 and sp + ml < slen and src[sp + ml] == src[rp + ml]:
                    ml += 1
                if ml > best_len:
                    best_len, best_off = ml, off
                    if ml == 17:
                        break
            if best_len >= 2:
                word = (best_off << 4) | (best_len - 2)
                out.append(word & 0xff)
                out.append((word >> 8) & 0xff)
                sp += best_len
            else:
                ctrl |= 1 << bit
                out.append(src[sp]); sp += 1
        out[ctrl_pos] = ctrl
    return bytes(out)


# ---------------------------------------------------------------------------
# Region / part types (format 2)
# ---------------------------------------------------------------------------

@dataclass
class G00Part:
    px: int; py: int; pw: int; ph: int; trans: int = 1


@dataclass
class G00Region:
    x1: int; y1: int; x2: int; y2: int
    ox: int = 0; oy: int = 0
    parts: list[G00Part] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------

def _decode_fmt0(data: bytes) -> PILImage.Image:
    w, = struct.unpack_from("<H", data, 1)
    h, = struct.unpack_from("<H", data, 3)
    comp_size, = struct.unpack_from("<I", data, 5)
    uncomp_size, = struct.unpack_from("<I", data, 9)
    if comp_size != len(data) - 5:
        raise ValueError("G00-0: compressed_size mismatch")
    src = data[0x0d: 0x0d + comp_size - 8]
    raw = _decompress_g00_0(src, w, h)
    img = PILImage.frombytes("RGB", (w, h), bytes(raw[:w*h*3]))
    # File stores BGR; swap to RGB
    r_ch, g_ch, b_ch = img.split()
    return PILImage.merge("RGB", (b_ch, g_ch, r_ch))


def _decode_fmt1(data: bytes) -> PILImage.Image:
    w, = struct.unpack_from("<H", data, 1)
    h, = struct.unpack_from("<H", data, 3)
    comp_size, = struct.unpack_from("<I", data, 5)
    uncomp_size, = struct.unpack_from("<I", data, 9)
    if comp_size != len(data) - 5:
        raise ValueError("G00-1: compressed_size mismatch")
    src = data[0x0d: 0x0d + comp_size - 8]
    raw = _decompress_g00_1(src, uncomp_size)
    # Parse palette + indices
    pal_len, = struct.unpack_from("<H", raw, 0)
    pal_off = 2
    palette = []
    for i in range(pal_len):
        # File stores BGRA; convert to RGBA for PIL
        b, g, r, a = raw[pal_off + i*4], raw[pal_off + i*4 + 1], raw[pal_off + i*4 + 2], raw[pal_off + i*4 + 3]
        palette.extend([r, g, b, a])
    idx_off = pal_off + pal_len * 4
    indices = bytes(raw[idx_off: idx_off + w * h])
    img = PILImage.frombytes("P", (w, h), indices)
    # Build RGBA palette for PIL (needs 256*4 bytes)
    full_pal = bytearray(256 * 4)
    full_pal[:len(palette)] = palette
    img.putpalette(full_pal, rawmode="RGBA")
    return img.convert("RGBA")


def _decode_fmt2(data: bytes) -> PILImage.Image:
    w, = struct.unpack_from("<H", data, 1)
    h, = struct.unpack_from("<H", data, 3)
    region_count, = struct.unpack_from("<I", data, 5)
    regions: list[G00Region] = []
    for i in range(region_count):
        p = 9 + i * 24
        x1, y1, x2, y2, ox, oy = struct.unpack_from("<6i", data, p)
        regions.append(G00Region(x1, y1, x2, y2, ox, oy))
    h_off = 9 + region_count * 24
    comp_size, = struct.unpack_from("<I", data, h_off)
    uncomp_size, = struct.unpack_from("<I", data, h_off + 4)
    if comp_size != len(data) - h_off:
        raise ValueError("G00-2: compressed_size mismatch")
    src = data[h_off + 8: h_off + comp_size]
    raw = _decompress_g00_1(src, uncomp_size)

    # Parse data index
    index_len, = struct.unpack_from("<I", raw, 0)
    if index_len != region_count:
        raise ValueError("G00-2: block index length mismatch")
    index = []
    for i in range(index_len):
        off, = struct.unpack_from("<I", raw, 4 + i * 8)
        length, = struct.unpack_from("<i", raw, 8 + i * 8)  # signed; negative = dup
        index.append((off, length))

    # Composite into RGBA canvas
    rgba = bytearray(w * h * 4)  # RGBA flat

    for r, (offset, length) in zip(regions, index):
        if length <= 0:
            continue
        block = raw[offset: offset + length]
        if struct.unpack_from("<H", block, 0)[0] != 1:
            raise ValueError("G00-2: unexpected block type")
        part_count, = struct.unpack_from("<H", block, 2)
        i_offs = 0x74
        for _ in range(part_count):
            px = struct.unpack_from("<h", block, i_offs)[0] + r.x1
            py = struct.unpack_from("<h", block, i_offs + 2)[0] + r.y1
            _tr = struct.unpack_from("<h", block, i_offs + 4)[0]
            pw_bytes = struct.unpack_from("<h", block, i_offs + 6)[0] * 4  # pw in pixels → bytes
            ph = struct.unpack_from("<h", block, i_offs + 8)[0]
            i_offs += 0x5c
            for ly in range(py, py + ph):
                dst_start = (px + ly * w) * 4
                src_start = i_offs
                rgba[dst_start: dst_start + pw_bytes] = block[src_start: src_start + pw_bytes]
                i_offs += pw_bytes

    # File stores BGRA; swap to RGBA
    img = PILImage.frombytes("RGBA", (w, h), bytes(rgba))
    r_ch, g_ch, b_ch, a_ch = img.split()
    return PILImage.merge("RGBA", (b_ch, g_ch, r_ch, a_ch))


# ---------------------------------------------------------------------------
# Encoders
# ---------------------------------------------------------------------------

def _encode_fmt0(img: PILImage.Image) -> bytes:
    rgb = img.convert("RGB")
    # File stores BGR; swap from RGB
    r_ch, g_ch, b_ch = rgb.split()
    bgr = PILImage.merge("RGB", (b_ch, g_ch, r_ch))
    pixels = bgr.tobytes()
    comp = _compress_g00_0(pixels)
    w, h = img.size
    header = struct.pack("<BHHii",
        0, w, h,
        len(comp) + 8,
        w * h * 3)
    return header + comp


def _encode_fmt1(img: PILImage.Image) -> bytes:
    rgba = img.convert("RGBA")
    w, h = rgba.size
    # Build palette
    palette_map: dict[tuple[int,int,int,int], int] = {}
    indices = bytearray(w * h)
    pixels_raw = list(rgba.getdata())
    for i, px in enumerate(pixels_raw):
        r, g, b, a = px
        key = (r, g, b, a)
        if key not in palette_map:
            if len(palette_map) >= 256:
                raise ValueError("G00-1: image has more than 256 unique colours")
            palette_map[key] = len(palette_map)
        indices[i] = palette_map[key]
    pal_bytes = bytearray()
    for (r, g, b, a), _ in sorted(palette_map.items(), key=lambda x: x[1]):
        pal_bytes.extend([b, g, r, a])  # file stores BGRA
    pal_len = len(palette_map)
    uncompressed = struct.pack("<H", pal_len) + bytes(pal_bytes) + bytes(indices)
    comp = _compress_g00_1(uncompressed)
    header = struct.pack("<BHHii",
        1, w, h,
        len(comp) + 8,
        len(uncompressed))
    return header + comp


def _encode_fmt2(img: PILImage.Image,
                 regions: Optional[list[G00Region]] = None) -> bytes:
    rgba = img.convert("RGBA")
    w, h = rgba.size
    if regions is None:
        regions = [G00Region(0, 0, w - 1, h - 1)]

    # File stores BGRA; swap from RGBA
    r_ch, g_ch, b_ch, a_ch = rgba.split()
    bgra = PILImage.merge("RGBA", (b_ch, g_ch, r_ch, a_ch))
    raw_pixels = bgra.tobytes()

    # Build data index + blocks
    header_len = 4 + len(regions) * 8
    dat_header = bytearray(header_len)
    struct.pack_into("<I", dat_header, 0, len(regions))
    blocks: list[Optional[bytes]] = []
    curr_offset = header_len

    for i, reg in enumerate(regions):
        x1, y1 = max(reg.x1, 0), max(reg.y1, 0)
        x2, y2 = min(reg.x2, w - 1), min(reg.y2, h - 1)
        pw = x2 - x1 + 1
        ph = y2 - y1 + 1
        px_off = x1 - reg.x1
        py_off = y1 - reg.y1

        # One part covers the whole region
        part_size = 0x5c + pw * ph * 4
        part = bytearray(part_size)
        struct.pack_into("<hh", part, 0, px_off, py_off)
        part[4] = 1  # trans
        part[5] = 0
        struct.pack_into("<hh", part, 6, pw, ph)
        # copy pixels row by row
        for ly in range(ph):
            src_row = ((y1 + ly) * w + x1) * 4
            dst_row = 0x5c + ly * pw * 4
            part[dst_row: dst_row + pw * 4] = raw_pixels[src_row: src_row + pw * 4]

        block_len = 0x74 + part_size
        block = bytearray(block_len)
        struct.pack_into("<HH", block, 0, 1, 1)  # type=1, part_count=1
        struct.pack_into("<iiiiii",  block, 4,
            x1 - reg.x1, y1 - reg.y1,
            pw, ph,
            reg.ox, reg.oy)
        struct.pack_into("<ii", block, 0x1c,
            reg.x2 - reg.x1 + 1, reg.y2 - reg.y1 + 1)
        block[0x74: 0x74 + part_size] = part

        struct.pack_into("<I", dat_header, 4 + i * 8, curr_offset)
        struct.pack_into("<I", dat_header, 8 + i * 8, block_len)
        blocks.append(bytes(block))
        curr_offset += block_len

    # Concatenate and compress
    data_raw = bytes(dat_header) + b"".join(b for b in blocks if b is not None)
    comp = _compress_g00_1(data_raw)

    # Build file
    reg_table = bytearray(len(regions) * 24)
    for i, reg in enumerate(regions):
        struct.pack_into("<6i", reg_table, i * 24, reg.x1, reg.y1, reg.x2, reg.y2, reg.ox, reg.oy)
    header = struct.pack("<BHHi", 2, w, h, len(regions))
    sizes = struct.pack("<ii", len(comp) + 8, len(data_raw))
    return header + bytes(reg_table) + sizes + comp


# ---------------------------------------------------------------------------
# Auto-select encoder
# ---------------------------------------------------------------------------

def _choose_format(img: PILImage.Image) -> int:
    """Pick the best G00 sub-format for the given image."""
    rgba = img.convert("RGBA")
    colours: set[tuple[int,int,int,int]] = set()
    too_many = False
    for px in rgba.getdata():
        colours.add(px)
        if len(colours) > 256:
            too_many = True
            break
    if too_many:
        # Check for alpha channel
        if any(a < 255 for _, _, _, a in colours):
            return 2
        return 0
    return 1


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def read_g00(path: str | Path) -> PILImage.Image:
    """Decode a G00 file to a PIL Image."""
    data = Path(path).read_bytes()
    fmt = data[0]
    if fmt == 0:
        return _decode_fmt0(data)
    elif fmt == 1:
        return _decode_fmt1(data)
    elif fmt == 2:
        return _decode_fmt2(data)
    else:
        raise ValueError(f"Unknown G00 format byte: {fmt}")


def write_g00(img: PILImage.Image, path: str | Path,
              fmt: Optional[int] = None,
              regions: Optional[list[G00Region]] = None) -> None:
    """Encode a PIL Image to a G00 file.

    Parameters
    ----------
    img:    Source image.
    path:   Output file path.
    fmt:    Force sub-format (0/1/2). Auto-detected if None.
    regions: Region list for format 2.  Defaults to one full-image region.
    """
    if fmt is None:
        fmt = _choose_format(img)
    if fmt == 0:
        raw = _encode_fmt0(img)
    elif fmt == 1:
        raw = _encode_fmt1(img)
    elif fmt == 2:
        raw = _encode_fmt2(img, regions)
    else:
        raise ValueError(f"Invalid G00 format {fmt}")
    Path(path).write_bytes(raw)


def is_g00(path: str | Path) -> bool:
    """Return True if the file looks like a G00 image."""
    try:
        data = Path(path).read_bytes()
        if len(data) < 13:
            return False
        fmt = data[0]
        if fmt == 0 or fmt == 1:
            comp_size, = struct.unpack_from("<I", data, 5)
            return comp_size == len(data) - 5
        elif fmt == 2:
            region_count, = struct.unpack_from("<I", data, 5)
            return len(data) > 9 + region_count * 24
        return False
    except Exception:
        return False
