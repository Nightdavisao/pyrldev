"""
kprl.rc8 — Majiro RC8 8-bit paletted image format ↔ PNG converter.

Port of src/vaconv/rc8.ml (vaconv tool by Haeleth).

RC8 file layout
---------------
  [0x00..0x07]  magic: b'\\x98\\x5a\\x92\\x9a8_00'  ("罪8_00" in Shift-JIS)
  [0x08..0x0b]  width   (int32 LE)
  [0x0c..0x0f]  height  (int32 LE)
  [0x10..0x13]  data_len (int32 LE)
  [0x14..0x313] 256-colour palette (256 × 3 bytes RGB)
  [0x314..]     pixel data

RC8 pixel encoding (1 byte per pixel, palette index)
-----------------------------------------------------
Same RLE scheme as RCT but byte-unit:
code byte 0x00–0x7e → literal run of (code + 1) bytes
code byte 0x7f      → long literal: next 2 LE16 + 128 bytes
code byte 0x80+     → back-reference (byte offsets, 7 distances × 7 codes each):

  Code offsets (7 codes per distance):
    0x80-0x86: dist=1    0x87=long1  (LE16 + 8 bytes)
    0x88-0x8d: dist=2    ...

  Actually from rc8.ml the distances are:
    1, 2, 3, 4, w-3, w-2, w-1, w, w+1, w+2, w+3, 2w-2, 2w-1, 2w, 2w+1, 2w+2
  Same as RCT, but the code groups are 7 wide (not 4):
    code%7 = 0→3, 1→4, 2→5, 3→6, 4→7, 5→8, 6→long(LE16+9)
  So per distance there are 7 codes.
"""
from __future__ import annotations

import struct
from pathlib import Path

from PIL import Image as PILImage

_RC8_MAGIC = b'\x98\x5a\x92\x9a8_00'


def _build_rc8_distance_table(w: int) -> list[int]:
    bases = [1, 2, 3, 4, w-3, w-2, w-1, w, w+1, w+2, w+3, 2*w-2, 2*w-1, 2*w, 2*w+1, 2*w+2]
    table = []
    for d in bases:
        for _ in range(7):
            table.append(d)
    return table


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

def _decode_rc8(data: bytes, width: int, height: int) -> bytearray:
    n = width * height
    dst = bytearray(n)
    dp = 0
    sp = 0
    slen = len(data)
    dist_table = _build_rc8_distance_table(width)

    while sp < slen and dp < n:
        code = data[sp]; sp += 1
        if code <= 0x7e:
            run = code + 1
            dst[dp: dp + run] = data[sp: sp + run]
            dp += run; sp += run
        elif code == 0x7f:
            extra = data[sp] | (data[sp + 1] << 8); sp += 2
            run = extra + 128
            dst[dp: dp + run] = data[sp: sp + run]
            dp += run; sp += run
        else:
            idx = code - 0x80
            if idx >= len(dist_table):
                raise ValueError(f"RC8: bad back-reference code {code:#04x}")
            dist = dist_table[idx]
            sub = idx % 7
            if sub < 6:
                rpt = sub + 3
            else:
                extra = data[sp] | (data[sp + 1] << 8); sp += 2
                rpt = extra + 9
            rp = dp - dist
            for _ in range(rpt):
                if dp >= n:
                    break
                dst[dp] = dst[rp]; dp += 1; rp += 1
    return dst


# ---------------------------------------------------------------------------
# Encoder (uncompressed)
# ---------------------------------------------------------------------------

def _encode_rc8(indices: bytes) -> bytes:
    n = len(indices)
    out = bytearray()
    pp = 0
    while pp < n:
        chunk = min(0x8000, n - pp)
        if chunk <= 128:
            out.append(chunk - 1)
        else:
            out.append(0x7f)
            extra = chunk - 128
            out.append(extra & 0xff)
            out.append((extra >> 8) & 0xff)
        out.extend(indices[pp: pp + chunk])
        pp += chunk
    return bytes(out)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def read_rc8(path: str | Path) -> PILImage.Image:
    """Decode an RC8 file to a PIL Image (P or RGB)."""
    data = Path(path).read_bytes()
    if data[:8] != _RC8_MAGIC:
        raise ValueError(f"Not an RC8 file: {path}")
    width,  = struct.unpack_from("<i", data, 0x08)
    height, = struct.unpack_from("<i", data, 0x0c)
    palette_raw = data[0x14: 0x14 + 256 * 3]
    # Palette is stored as BGR; convert to RGB for PIL
    pal_rgb = bytearray(768)
    for i in range(256):
        pal_rgb[i*3]     = palette_raw[i*3 + 2]  # R
        pal_rgb[i*3 + 1] = palette_raw[i*3 + 1]  # G
        pal_rgb[i*3 + 2] = palette_raw[i*3]       # B
    pixel_data  = data[0x314:]
    indices = _decode_rc8(pixel_data, width, height)
    img = PILImage.frombytes("P", (width, height), bytes(indices[:width * height]))
    img.putpalette(bytes(pal_rgb))
    return img.convert("RGB")


def write_rc8(img: PILImage.Image, path: str | Path) -> None:
    """Encode a PIL Image to an RC8 file (quantise to 256 colours if needed)."""
    w, h = img.size
    # Quantise to palette
    if img.mode == "P":
        pal_img = img
        pal_raw = img.getpalette()
        if pal_raw is None:
            raise ValueError("write_rc8: palette image has no palette")
        palette_bytes = bytes(pal_raw[:768])
        indices = pal_img.tobytes()
    else:
        pal_img = img.convert("RGB").quantize(colors=256)
        pal_raw = pal_img.getpalette()
        palette_bytes = bytes(pal_raw[:768])
        indices = pal_img.tobytes()

    # Pad palette to 768 bytes and convert RGB→BGR for file storage
    pal_bgr = bytearray(768)
    for i in range(256):
        if i * 3 + 2 < len(palette_bytes):
            pal_bgr[i*3]     = palette_bytes[i*3 + 2]  # B
            pal_bgr[i*3 + 1] = palette_bytes[i*3 + 1]  # G
            pal_bgr[i*3 + 2] = palette_bytes[i*3]       # R
    encoded = _encode_rc8(indices)
    header = bytearray(0x14)
    header[:8] = _RC8_MAGIC
    struct.pack_into("<i", header, 0x08, w)
    struct.pack_into("<i", header, 0x0c, h)
    struct.pack_into("<i", header, 0x10, len(encoded))
    Path(path).write_bytes(bytes(header) + bytes(pal_bgr) + encoded)


def is_rc8(path: str | Path) -> bool:
    try:
        return Path(path).read_bytes()[:8] == _RC8_MAGIC
    except Exception:
        return False
