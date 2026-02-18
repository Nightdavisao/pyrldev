"""
kprl.rct — Majiro RCT true-colour image format ↔ PNG converter.

Port of src/vaconv/rct.ml (vaconv tool by Haeleth).

RCT file layout
---------------
  [0x00..0x07]  magic: b'\\x98\\x5a\\x92\\x9aTC00'  ("罪TC00" in Shift-JIS)
  [0x08..0x0b]  width   (int32 LE)
  [0x0c..0x0f]  height  (int32 LE)
  [0x10..0x13]  data_len (int32 LE)
  [0x14..]      pixel data

RCT pixel encoding (RGB, 3 bytes per pixel)
-------------------------------------------
code byte 0x00–0x7e → literal run of (code + 1) pixels (each 3 bytes)
code byte 0x7f      → long literal: next 2 bytes LE16 = extra_count;
                      run = extra_count + 128 pixels
code byte 0x80+     → back-reference: copies (rpt_count) pixels from
                      table[code - 0x80] pixels behind current position

Back-reference table (pixel offsets, 1-indexed):
  Code offsets (4 codes per distance):
    0x80-0x83: dist=1    0x84-0x87: dist=2    0x88-0x8b: dist=3
    0x8c-0x8f: dist=4    0x90-0x93: dist=w-3  0x94-0x97: dist=w-2
    0x98-0x9b: dist=w-1  0x9c-0x9f: dist=w    0xa0-0xa3: dist=w+1
    0xa4-0xa7: dist=w+2  0xa8-0xab: dist=w+3  0xac-0xaf: dist=2w-2
    0xb0-0xb3: dist=2w-1 0xb4-0xb7: dist=2w   0xb8-0xbb: dist=2w+1
    0xbc-0xbf: dist=2w+2
  Within each group of 4: code%4 = 0→1 pixel, 1→2, 2→3, 3→long(LE16+4)

Writing: the OCaml source always writes uncompressed literal runs; we do the same.
"""
from __future__ import annotations

import struct
from pathlib import Path

from PIL import Image as PILImage

_RCT_MAGIC = b'\x98\x5a\x92\x9aTC00'


def _build_rct_distance_table(w: int) -> list[int]:
    """Build the 64-entry back-reference pixel-distance table."""
    bases = [1, 2, 3, 4, w-3, w-2, w-1, w, w+1, w+2, w+3, 2*w-2, 2*w-1, 2*w, 2*w+1, 2*w+2]
    table = []
    for d in bases:
        for _ in range(4):
            table.append(d)
    return table


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

def _decode_rct(data: bytes, width: int, height: int) -> bytearray:
    n_pixels = width * height
    dst = bytearray(n_pixels * 3)
    dp = 0
    sp = 0
    slen = len(data)
    dist_table = _build_rct_distance_table(width)

    while sp < slen and dp < n_pixels * 3:
        code = data[sp]; sp += 1
        if code <= 0x7e:
            run = (code + 1) * 3
            dst[dp: dp + run] = data[sp: sp + run]
            dp += run; sp += run
        elif code == 0x7f:
            extra = data[sp] | (data[sp + 1] << 8); sp += 2
            run = (extra + 128) * 3
            dst[dp: dp + run] = data[sp: sp + run]
            dp += run; sp += run
        else:
            idx = code - 0x80
            if idx >= len(dist_table):
                raise ValueError(f"RCT: bad back-reference code {code:#04x}")
            dist = dist_table[idx]
            sub = idx % 4
            if sub < 3:
                rpt = sub + 1
            else:
                extra = data[sp] | (data[sp + 1] << 8); sp += 2
                rpt = extra + 4
            rp = dp - dist * 3
            for _ in range(rpt * 3):
                if dp >= n_pixels * 3:
                    break
                dst[dp] = dst[rp]; dp += 1; rp += 1
    return dst


# ---------------------------------------------------------------------------
# Encoder (uncompressed — mirrors OCaml rct.ml write path)
# ---------------------------------------------------------------------------

def _encode_rct(pixels: bytes) -> bytes:
    """Write RGB pixels as uncompressed literal runs (code 0x7f)."""
    n_pixels = len(pixels) // 3
    out = bytearray()
    pp = 0
    while pp < n_pixels:
        chunk = min(0x8000, n_pixels - pp)  # max 32768 pixels per run
        if chunk <= 128:
            out.append(chunk - 1)
        else:
            out.append(0x7f)
            extra = chunk - 128
            out.append(extra & 0xff)
            out.append((extra >> 8) & 0xff)
        out.extend(pixels[pp * 3: (pp + chunk) * 3])
        pp += chunk
    return bytes(out)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def read_rct(path: str | Path) -> PILImage.Image:
    """Decode an RCT file to a PIL Image (RGB)."""
    data = Path(path).read_bytes()
    if data[:8] != _RCT_MAGIC:
        raise ValueError(f"Not an RCT file: {path}")
    width,    = struct.unpack_from("<i", data, 0x08)
    height,   = struct.unpack_from("<i", data, 0x0c)
    # data_len at 0x10 (not needed for decode)
    pixel_data = data[0x14:]
    raw = _decode_rct(pixel_data, width, height)
    img = PILImage.frombytes("RGB", (width, height), bytes(raw[:width * height * 3]))
    # File stores BGR; swap to RGB
    r_ch, g_ch, b_ch = img.split()
    return PILImage.merge("RGB", (b_ch, g_ch, r_ch))


def write_rct(img: PILImage.Image, path: str | Path) -> None:
    """Encode a PIL Image to an RCT file."""
    rgb = img.convert("RGB")
    w, h = rgb.size
    # File stores BGR; swap from RGB
    r_ch, g_ch, b_ch = rgb.split()
    bgr = PILImage.merge("RGB", (b_ch, g_ch, r_ch))
    pixels = bgr.tobytes()
    encoded = _encode_rct(pixels)
    header = bytearray(0x14)
    header[:8] = _RCT_MAGIC
    struct.pack_into("<i", header, 0x08, w)
    struct.pack_into("<i", header, 0x0c, h)
    struct.pack_into("<i", header, 0x10, len(encoded))
    Path(path).write_bytes(bytes(header) + encoded)


def is_rct(path: str | Path) -> bool:
    """Return True if the file looks like an RCT file."""
    try:
        return Path(path).read_bytes()[:8] == _RCT_MAGIC
    except Exception:
        return False
