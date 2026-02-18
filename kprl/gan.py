"""
kprl.gan — RealLive GAN animation file ↔ XML converter.

Port of src/rlxml/gan.ml (rlxml tool by Haeleth).

GAN binary layout
-----------------
Header (4 × int32):
  10000  10000  10100  <filename_len>
  <filename bytes, null-terminated>
  20000  <set_count>
  [sets …]

Each set:
  30000  <frame_count>
  [frames …]

Each frame:
  Sequence of (tag_int32, value_int32) pairs, terminated by tag 999999.
  Tags: 30100=pattern, 30101=x, 30102=y, 30103=time, 30104=alpha, 30105=other

XML structure (vas_gan):
  <vas_gan bitmap="FILENAME.G00">
    <set [pattern="…"] [x="…"] …>    ← default (constant) attrs on <set>
      <frame [pattern="…"] [x="…"] …/>  ← per-frame attrs (only non-default ones)
      …
    </set>
    …
  </vas_gan>
"""
from __future__ import annotations

import struct
import xml.etree.ElementTree as ET
from pathlib import Path

# Tag → attribute name mapping
_TAG_TO_ATTR: dict[int, str] = {
    30_100: "pattern",
    30_101: "x",
    30_102: "y",
    30_103: "time",
    30_104: "alpha",
    30_105: "other",
}
_ATTR_TO_TAG: dict[str, int] = {v: k for k, v in _TAG_TO_ATTR.items()}
_ATTR_ORDER = ["pattern", "x", "y", "time", "alpha", "other"]

_TERMINATOR = 999_999


# ---------------------------------------------------------------------------
# Binary → XML
# ---------------------------------------------------------------------------

def _read_i32(data: bytes, pos: int) -> tuple[int, int]:
    """Read a signed 32-bit LE int; return (value, new_pos)."""
    v, = struct.unpack_from("<i", data, pos)
    return v, pos + 4


def _read_u32(data: bytes, pos: int) -> tuple[int, int]:
    v, = struct.unpack_from("<I", data, pos)
    return v, pos + 4


def _read_frame(data: bytes, pos: int) -> tuple[dict[str, int], int]:
    """Read one frame record; return ({attr: value}, new_pos)."""
    attrs: dict[str, int] = {}
    while True:
        tag, pos = _read_i32(data, pos)
        if tag == _TERMINATOR:
            break
        value, pos = _read_i32(data, pos)
        name = _TAG_TO_ATTR.get(tag)
        if name is None:
            raise ValueError(f"unknown GAN frame tag {tag}")
        attrs[name] = value
    return attrs, pos


def _get_default_attrs(frames: list[dict[str, int]]) -> dict[str, int]:
    """Return attrs that are constant across all frames."""
    if not frames:
        raise ValueError("empty frame list")
    defaults = dict(frames[0])
    for frame in frames[1:]:
        for key in list(defaults):
            if defaults.get(key) != frame.get(key):
                del defaults[key]
    return defaults


def gan_to_xml(data: bytes) -> ET.Element:
    """Parse GAN binary data and return an ElementTree ``<vas_gan>`` element."""
    pos = 0
    # Header
    for expected in (10_000, 10_000, 10_100):
        v, pos = _read_i32(data, pos)
        if v != expected:
            raise ValueError(f"unexpected GAN header value {v} (expected {expected})")
    # Filename
    fname_len, pos = _read_i32(data, pos)
    bitmap = data[pos: pos + fname_len - 1].decode("ascii", errors="replace")
    pos += fname_len  # includes null terminator
    # Data section header
    v, pos = _read_i32(data, pos)
    if v != 20_000:
        raise ValueError("expected start of GAN data section (20000)")
    set_count, pos = _read_i32(data, pos)

    root = ET.Element("vas_gan", bitmap=bitmap)
    for _ in range(set_count):
        v, pos = _read_i32(data, pos)
        if v != 30_000:
            raise ValueError("expected start of GAN set (30000)")
        frame_count, pos = _read_i32(data, pos)
        if frame_count == 0:
            raise ValueError("GAN set must have at least one frame")
        frames_data: list[dict[str, int]] = []
        for _ in range(frame_count):
            fd, pos = _read_frame(data, pos)
            frames_data.append(fd)

        defaults = _get_default_attrs(frames_data)
        set_attrs = {k: str(v) for k, v in defaults.items()}
        set_el = ET.SubElement(root, "set", **set_attrs)
        for fd in frames_data:
            # Only emit non-default attrs on individual <frame> elements
            frame_attrs = {k: str(v) for k, v in fd.items() if k not in defaults}
            ET.SubElement(set_el, "frame", **frame_attrs)

    return root


def xml_to_gan(root: ET.Element) -> bytes:
    """Serialise a ``<vas_gan>`` ElementTree element back to GAN binary data."""
    if root.tag != "vas_gan":
        raise ValueError("expected <vas_gan> root element")
    bitmap = root.get("BITMAP") or root.get("bitmap") or ""

    out = bytearray()

    def wi32(v: int) -> None:
        out.extend(struct.pack("<i", v))

    # Header
    wi32(10_000); wi32(10_000); wi32(10_100)
    bname = bitmap.encode("ascii")
    wi32(len(bname) + 1)
    out.extend(bname)
    out.append(0)  # null terminator
    wi32(20_000)

    sets = list(root)
    wi32(len(sets))

    for set_el in sets:
        if set_el.tag != "set":
            raise ValueError("expected <set> child of <vas_gan>")
        set_defaults = {k: int(v) for k, v in set_el.attrib.items() if k in _ATTR_TO_TAG}
        frames_el = list(set_el)
        wi32(30_000)
        wi32(len(frames_el))
        for frame_el in frames_el:
            if frame_el.tag != "frame":
                raise ValueError("expected <frame> inside <set>")
            # Merge set defaults with per-frame overrides (case-insensitive)
            merged = dict(set_defaults)
            for k, v in frame_el.attrib.items():
                kl = k.lower()
                if kl in _ATTR_TO_TAG:
                    merged[kl] = int(v)
            # Emit in canonical order
            for attr in _ATTR_ORDER:
                if attr in merged:
                    wi32(_ATTR_TO_TAG[attr])
                    wi32(merged[attr])
            wi32(_TERMINATOR)

    return bytes(out)


# ---------------------------------------------------------------------------
# File-level API
# ---------------------------------------------------------------------------

def gan_to_ganxml(src: str | Path, dst: str | Path) -> None:
    """Convert a ``.gan`` file to ``.ganxml`` (XML)."""
    data = Path(src).read_bytes()
    root = gan_to_xml(data)
    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    with open(dst, "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        tree.write(f, encoding="unicode", xml_declaration=False)
        f.write("\n")


def ganxml_to_gan(src: str | Path, dst: str | Path) -> None:
    """Convert a ``.ganxml`` file back to binary ``.gan``."""
    tree = ET.parse(str(src))
    root = tree.getroot()
    data = xml_to_gan(root)
    Path(dst).write_bytes(data)
