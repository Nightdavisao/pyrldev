"""
archive.py – RealLive SEEN.TXT archive pack and unpack.

Mirrors src/kprl/archiver.ml.

Archive layout
--------------
Bytes 0 – 79 999  : index table, 10 000 entries × 8 bytes each.
  entry[i] = (offset: uint32_le, length: uint32_le)
  offset=0, length=0 → slot is empty.
Bytes 80 000+      : concatenated sub-file data.

Empty archive sentinel: first 23 bytes == b"\\x00Empty RealLive archive".
"""

from __future__ import annotations

import os
import re
import struct
import tempfile
from pathlib import Path
from typing import Iterator


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INDEX_ENTRIES = 10_000
ENTRY_SIZE    = 8                           # 4-byte offset + 4-byte length
INDEX_SIZE    = INDEX_ENTRIES * ENTRY_SIZE  # 80 000 bytes
EMPTY_MARKER  = b"\x00Empty RealLive archive"

_SEEN_RE = re.compile(r"(?i)^seen(\d{1,4})\b", re.ASCII)


# ---------------------------------------------------------------------------
# Low-level index helpers
# ---------------------------------------------------------------------------

def read_index(data: bytes | bytearray) -> dict[int, tuple[int, int]]:
    """
    Parse the 80 000-byte index table from *data*.

    Returns a dict mapping ``{index: (offset, length)}`` for all non-empty
    slots (length > 0).
    """
    result: dict[int, tuple[int, int]] = {}
    for i in range(INDEX_ENTRIES):
        base = i * ENTRY_SIZE
        offset, length = struct.unpack_from("<II", data, base)
        if length > 0:
            result[i] = (offset, length)
    return result


def get_subfile(data: bytes | bytearray, idx: int) -> bytes | None:
    """
    Extract sub-file *idx* from an archive blob.

    Returns ``None`` when the slot is empty.
    """
    if len(data) < INDEX_SIZE:
        return None
    base = idx * ENTRY_SIZE
    offset, length = struct.unpack_from("<II", data, base)
    if length == 0:
        return None
    return bytes(data[offset: offset + length])


# ---------------------------------------------------------------------------
# Archive detection
# ---------------------------------------------------------------------------

def _test_index(data: bytes | bytearray) -> bool:
    """Return True if the index table of *data* looks structurally valid."""
    from .bytecode import is_bytecode
    if len(data) < INDEX_SIZE:
        return False
    for i in range(INDEX_ENTRIES):
        base = i * ENTRY_SIZE
        offset, length = struct.unpack_from("<II", data, base)
        if length == 0:
            continue
        end = offset + length
        if end <= INDEX_SIZE or end > len(data):
            return False
        if not is_bytecode(data, offset):
            return False
    return True


def is_archive(path: str | os.PathLike) -> bool:
    """
    Return True if *path* looks like a valid (possibly empty) SEEN.TXT archive.

    Mirrors ``Archiver.is_archive`` in archiver.ml.
    """
    path = Path(path)
    if not path.is_file():
        return False
    data = path.read_bytes()
    if data[:23] == EMPTY_MARKER:
        return True
    return _test_index(data)


# ---------------------------------------------------------------------------
# Build / write helpers
# ---------------------------------------------------------------------------

def _write_index(entries: dict[int, tuple[int, int]]) -> bytes:
    """Serialise 10 000 index entries into a 80 000-byte block."""
    buf = bytearray(INDEX_SIZE)
    for idx, (offset, length) in entries.items():
        base = idx * ENTRY_SIZE
        struct.pack_into("<II", buf, base, offset, length)
    return bytes(buf)


def build_archive(files: dict[int, bytes]) -> bytes:
    """
    Build a SEEN.TXT archive from a mapping of ``{index: raw_bytes}``.

    *raw_bytes* should already be the final (compressed / encrypted) form of
    each sub-file.  Returns the complete archive as bytes.
    """
    # Sort by index so the data section is laid out in order
    sorted_items = sorted(files.items())
    data_parts: list[bytes] = []
    index_entries: dict[int, tuple[int, int]] = {}
    cursor = INDEX_SIZE

    for idx, blob in sorted_items:
        index_entries[idx] = (cursor, len(blob))
        data_parts.append(blob)
        cursor += len(blob)

    return _write_index(index_entries) + b"".join(data_parts)


def _atomic_write(path: Path, data: bytes) -> None:
    """Write *data* to *path* atomically (via a temp file + rename)."""
    dir_ = path.parent
    fd, tmp_path = tempfile.mkstemp(suffix=".seen.tmp", dir=dir_)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# High-level operations
# ---------------------------------------------------------------------------

def break_archive(
    archive_path: str | os.PathLike,
    output_dir: str | os.PathLike = ".",
    verbose: bool = False,
    indices: set[int] | None = None,
) -> list[str]:
    """
    Extract all (or selected) sub-files from *archive_path* into *output_dir*.

    *indices* optionally restricts extraction to those index numbers.
    Returns the list of paths written.
    """
    archive_path = Path(archive_path)
    output_dir   = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    data = archive_path.read_bytes()
    if data[:23] == EMPTY_MARKER:
        return []

    index = read_index(data)
    written: list[str] = []

    for idx, (offset, length) in sorted(index.items()):
        if indices is not None and idx not in indices:
            continue
        fname = f"SEEN{idx:04d}.TXT"
        blob  = bytes(data[offset: offset + length])
        out_path = output_dir / fname
        if verbose:
            print(f"Extracting {fname}")
        out_path.write_bytes(blob)
        written.append(str(out_path))

    return written


def add_to_archive(
    archive_path: str | os.PathLike,
    file_paths: list[str | os.PathLike],
    verbose: bool = False,
) -> None:
    """
    Add or replace sub-files in *archive_path*.

    Each file in *file_paths* must be named ``SEENxxxx.*`` (case-insensitive)
    where *xxxx* is a 0-4 digit index.  The archive is created if it does not
    exist yet; existing entries not named in *file_paths* are preserved.

    Mirrors the ``add`` action in archiver.ml.
    """
    from .bytecode import is_bytecode
    from .rlcmp    import compress as rl_compress

    archive_path = Path(archive_path)

    # Load existing archive
    if archive_path.is_file():
        arc_data = archive_path.read_bytes()
        if arc_data[:23] == EMPTY_MARKER:
            existing: dict[int, bytes] = {}
        elif _test_index(arc_data):
            existing = {
                idx: bytes(arc_data[off: off + ln])
                for idx, (off, ln) in read_index(arc_data).items()
            }
        else:
            raise ValueError(
                f"{archive_path.name} is not a valid RealLive archive"
            )
    else:
        existing = {}

    # Merge new files
    any_added = False
    for fp in file_paths:
        fp = Path(fp)
        m = _SEEN_RE.match(fp.name)
        if not m:
            print(
                f"Warning: unable to add '{fp.name}': "
                "file name must begin 'SEENxxxx', where 0 <= xxxx <= 9999"
            )
            continue
        idx = int(m.group(1))
        if not fp.is_file():
            print(f"Warning: file not found: {fp}")
            continue
        blob = fp.read_bytes()
        if not is_bytecode(blob):
            print(f"Warning: unable to add '{fp.name}': not a bytecode file")
            continue
        # Compress if the file has an uncompressed header
        from .bytecode import uncompressed_header
        if uncompressed_header(bytes(blob[:4])):
            if verbose:
                print(f"Compressing {fp.name}")
            blob = rl_compress(blob)
        existing[idx] = blob
        any_added = True

    if not any_added:
        raise RuntimeError("no files to process")

    if verbose:
        print(f"Writing archive {archive_path.name}")
    _atomic_write(archive_path, build_archive(existing))


def remove_from_archive(
    archive_path: str | os.PathLike,
    indices: set[int],
    verbose: bool = False,
) -> None:
    """
    Remove the sub-files at *indices* from *archive_path*.

    Mirrors the ``remove`` action in archiver.ml.
    """
    archive_path = Path(archive_path)
    arc_data = archive_path.read_bytes()

    if not _test_index(arc_data):
        raise ValueError(
            f"{archive_path.name} is not a valid RealLive archive"
        )

    existing = {
        idx: bytes(arc_data[off: off + ln])
        for idx, (off, ln) in read_index(arc_data).items()
    }

    removed = 0
    for idx in indices:
        if idx in existing:
            del existing[idx]
            removed += 1

    if removed == 0:
        print("No files to remove.")
        return

    if not existing:
        print("Warning: all archive contents removed")

    if verbose:
        print(f"Rebuilding archive {archive_path.name}")
    _atomic_write(archive_path, build_archive(existing))
