"""
kprl.pdt — RealLive PDT10/PDT11 image format ↔ PNG converter.

Port of src/vaconv/pdt.ml + src/vaconv/pdt-bt.cpp (vaconv tool by Haeleth).

PDT file layout
---------------
  [0x00..0x07]  magic: b'PDT10\\x00\\x00\\x00' or b'PDT11\\x00\\x00\\x00'
  [0x08..0x0b]  file_size  (int32)
  [0x0c..0x0f]  width      (int32)
  [0x10..0x13]  height     (int32)
  [0x14..0x17]  unknown
  [0x18..0x1b]  unknown
  [0x1c..0x1f]  mask_ptr   (int32)  — offset into file of alpha mask; 0 = no mask
  [0x20..]      image data

PDT10 image decompression (flag byte MSB-first):
  flag bit set   → literal 3-byte BGR pixel
  flag bit clear → back-reference:
    2 bytes (lo, hi): `count = hi >> 4`; `ptr = (hi & 0x0f) << 8 | lo`
    `rp = dp - (ptr + 1) * 3`
    `copy_len = (count + 1) * 3`

PDT11 image decompression:
  The file has an extra area at 0x20..0x45f:
    [0x20..0x41f]  256 × 3 bytes → RGB colour table (palette)
    [0x420..0x43f]  16 × int32   → back-reference distance index table
  Actual data starts at 0x460.
  flag bit set   → literal 1-byte palette index → look up 3-byte colour
  flag bit clear → back-reference:
    1 byte `num`: `count = (((num >> 4) & 0x0f) + 2) * 3`
                  `rp = dp - index[num & 0x0f] * 3`

Mask decompression (same for both PDT10 and PDT11):
  flag bit set   → literal 1-byte alpha value
  flag bit clear → back-reference:
    2 bytes (lo, hi): `count = lo + 2`; `rp = dp - (hi + 1)`
  Starts at offset mask_ptr.
"""
from __future__ import annotations

import struct
from pathlib import Path

from PIL import Image as PILImage

_PDT10_MAGIC = b'PDT10\x00\x00\x00'
_PDT11_MAGIC = b'PDT11\x00\x00\x00'


# ---------------------------------------------------------------------------
# Decompressors
# ---------------------------------------------------------------------------

def _decompress_pdt10(src: bytes, width: int, height: int) -> bytearray:
    """Decode PDT10 pixel data (MSB-first flag byte, 3-byte BGR pixels)."""
    dst_size = width * height * 3
    dst = bytearray(dst_size)
    dp = 0
    sp = 0
    slen = len(src)
    while sp < slen and dp < dst_size:
        flag = src[sp]; sp += 1
        for i in range(7, -1, -1):
            if dp >= dst_size or sp >= slen:
                break
            if flag & (1 << i):
                # literal BGR
                dst[dp] = src[sp]; dp += 1; sp += 1
                dst[dp] = src[sp]; dp += 1; sp += 1
                dst[dp] = src[sp]; dp += 1; sp += 1
            else:
                lo = src[sp]; sp += 1
                hi = src[sp]; sp += 1
                ptr   = ((hi & 0x0f) << 8) | lo
                count = (hi >> 4)
                rp = dp - (ptr + 1) * 3
                copy_len = (count + 1) * 3
                for _ in range(copy_len):
                    if dp >= dst_size:
                        break
                    dst[dp] = dst[rp]; dp += 1; rp += 1
    return dst


def _decompress_pdt11(src: bytes, width: int, height: int) -> bytearray:
    """Decode PDT11 pixel data (palette + index table embedded in src)."""
    # src starts from offset 0x20 in the file (i.e. right after the 0x20-byte header)
    # Layout inside src:
    #   [0x00..0x2ff]  palette (256 × 3 bytes RGB)
    #   [0x300..0x33f]  index table (16 × int32 LE)  — NOTE: 0x400-0x20 = 0x3e0 total before data
    #   Actually per pdt-bt.cpp:
    #     srcbuf  = src (starts at file 0x20)
    #     palette starts at srcbuf[0]         → file 0x20
    #     index   starts at srcbuf[0x400]     → file 0x420
    #     data    starts at srcbuf[0x440]     → file 0x460
    palette_off = 0
    index_off   = 0x400
    data_off    = 0x440

    palette = src[palette_off: palette_off + 256 * 4]  # 4 bytes per entry (3 used)
    index = [struct.unpack_from("<I", src, index_off + i * 4)[0] for i in range(16)]
    data = src[data_off:]

    dst_size = width * height * 3
    dst = bytearray(dst_size)
    dp = 0
    sp = 0
    slen = len(data)
    while sp < slen and dp < dst_size:
        flag = data[sp]; sp += 1
        for i in range(7, -1, -1):
            if dp >= dst_size or sp >= slen:
                break
            if flag & (1 << i):
                idx = data[sp]; sp += 1
                base = idx * 4  # stride 4 bytes per palette entry
                dst[dp] = palette[base]; dp += 1
                dst[dp] = palette[base + 1]; dp += 1
                dst[dp] = palette[base + 2]; dp += 1
            else:
                num = data[sp]; sp += 1
                count = (((num >> 4) & 0x0f) + 2) * 3
                dist  = index[num & 0x0f]
                rp = dp - dist * 3
                for _ in range(count):
                    if dp >= dst_size:
                        break
                    dst[dp] = dst[rp]; dp += 1; rp += 1
    return dst


def _decompress_mask(src: bytes, width: int, height: int) -> bytearray:
    """Decode PDT alpha mask."""
    dst_size = width * height
    dst = bytearray(dst_size)
    dp = 0
    sp = 0
    slen = len(src)
    while sp < slen and dp < dst_size:
        flag = src[sp]; sp += 1
        for i in range(7, -1, -1):
            if dp >= dst_size or sp >= slen:
                break
            if flag & (1 << i):
                dst[dp] = src[sp]; dp += 1; sp += 1
            else:
                lo = src[sp]; sp += 1
                hi = src[sp]; sp += 1
                count = lo + 2
                rp = dp - (hi + 1)
                for _ in range(count):
                    if dp >= dst_size:
                        break
                    dst[dp] = dst[rp]; dp += 1; rp += 1
    return dst


# ---------------------------------------------------------------------------
# Compressors (store uncompressed with flag bytes all-ones)
# ---------------------------------------------------------------------------

def _compress_pdt10(pixels: bytes) -> bytes:
    """Encode BGR pixel data as PDT10 (uncompressed — all flag bits set)."""
    src = pixels
    n = len(src)
    assert n % 3 == 0
    out = bytearray()
    sp = 0
    while sp < n:
        chunk_pixels = min(8, (n - sp) // 3)
        flag = 0
        for i in range(7, 7 - chunk_pixels, -1):
            flag |= (1 << i)
        out.append(flag)
        out.extend(src[sp: sp + chunk_pixels * 3])
        sp += chunk_pixels * 3
    return bytes(out)


def _compress_mask(alpha: bytes) -> bytes:
    """Encode alpha mask as PDT mask (uncompressed — all flag bits set)."""
    out = bytearray()
    sp = 0
    n = len(alpha)
    while sp < n:
        chunk = min(8, n - sp)
        flag = 0
        for i in range(7, 7 - chunk, -1):
            flag |= (1 << i)
        out.append(flag)
        out.extend(alpha[sp: sp + chunk])
        sp += chunk
    return bytes(out)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def read_pdt(path: str | Path) -> PILImage.Image:
    """Decode a PDT10 or PDT11 file to a PIL Image (RGB or RGBA)."""
    data = Path(path).read_bytes()
    magic = data[:8]
    if magic not in (_PDT10_MAGIC, _PDT11_MAGIC):
        raise ValueError(f"Not a PDT file: {path}")

    width,  = struct.unpack_from("<i", data, 0x0c)
    height, = struct.unpack_from("<i", data, 0x10)
    mask_ptr, = struct.unpack_from("<i", data, 0x1c)

    img_data = data[0x20:]
    if magic == _PDT10_MAGIC:
        bgr = _decompress_pdt10(img_data, width, height)
        # Convert BGR → RGB
        rgb = bytearray(len(bgr))
        for i in range(len(bgr) // 3):
            rgb[i*3]   = bgr[i*3+2]
            rgb[i*3+1] = bgr[i*3+1]
            rgb[i*3+2] = bgr[i*3]
    else:  # PDT11
        bgr11 = _decompress_pdt11(img_data, width, height)
        # Convert BGR → RGB (same internal format as PDT10)
        rgb = bytearray(len(bgr11))
        for i in range(len(bgr11) // 3):
            rgb[i*3]   = bgr11[i*3+2]
            rgb[i*3+1] = bgr11[i*3+1]
            rgb[i*3+2] = bgr11[i*3]

    if mask_ptr:
        mask_data = data[mask_ptr:]
        alpha = _decompress_mask(mask_data, width, height)
        rgba = bytearray(width * height * 4)
        for i in range(width * height):
            rgba[i*4]   = rgb[i*3]
            rgba[i*4+1] = rgb[i*3+1]
            rgba[i*4+2] = rgb[i*3+2]
            rgba[i*4+3] = alpha[i]
        return PILImage.frombytes("RGBA", (width, height), bytes(rgba))
    else:
        return PILImage.frombytes("RGB", (width, height), bytes(rgb))


def write_pdt(img: PILImage.Image, path: str | Path, version: int = 10) -> None:
    """Encode a PIL Image to a PDT10 file.

    Parameters
    ----------
    img:     Source image.
    path:    Output file path.
    version: PDT version (10 only; 11 is palette-compressed, not generated).
    """
    if version not in (10,):
        raise ValueError("write_pdt: only version 10 encoding is supported")

    w, h = img.size
    has_alpha = img.mode in ("RGBA", "LA") or (img.mode == "P" and img.info.get("transparency"))
    if has_alpha:
        rgba = img.convert("RGBA")
        rgb_pixels = rgba.tobytes()  # RGBA flat
        # Split into BGR and alpha
        bgr = bytearray(w * h * 3)
        alpha = bytearray(w * h)
        for i in range(w * h):
            bgr[i*3]   = rgb_pixels[i*4+2]  # B
            bgr[i*3+1] = rgb_pixels[i*4+1]  # G
            bgr[i*3+2] = rgb_pixels[i*4]    # R
            alpha[i]   = rgb_pixels[i*4+3]
        comp_img  = _compress_pdt10(bytes(bgr))
        comp_mask = _compress_mask(bytes(alpha))
        mask_offset = 0x20 + len(comp_img)
    else:
        rgb = img.convert("RGB")
        rgb_pixels = rgb.tobytes()
        bgr = bytearray(w * h * 3)
        for i in range(w * h):
            bgr[i*3]   = rgb_pixels[i*3+2]
            bgr[i*3+1] = rgb_pixels[i*3+1]
            bgr[i*3+2] = rgb_pixels[i*3]
        comp_img  = _compress_pdt10(bytes(bgr))
        comp_mask = b""
        mask_offset = 0

    total_len = 0x20 + len(comp_img) + len(comp_mask)
    header = bytearray(0x20)
    header[:8] = _PDT10_MAGIC
    struct.pack_into("<i", header, 0x08, total_len)
    struct.pack_into("<i", header, 0x0c, w)
    struct.pack_into("<i", header, 0x10, h)
    struct.pack_into("<i", header, 0x1c, mask_offset)

    Path(path).write_bytes(bytes(header) + comp_img + comp_mask)


def is_pdt(path: str | Path) -> bool:
    """Return True if the file looks like a PDT file."""
    try:
        magic = Path(path).read_bytes()[:8]
        return magic in (_PDT10_MAGIC, _PDT11_MAGIC)
    except Exception:
        return False
