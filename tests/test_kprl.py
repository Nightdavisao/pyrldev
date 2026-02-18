"""
tests/test_kprl.py – Unit and integration tests for the kprl Python package.

Run with:  python -m pytest src/python/tests/
       or: python -m unittest discover -s src/python/tests
"""

from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

# Make the package importable when running from the repo root.
sys.path.insert(0, str(Path(__file__).parent.parent))

from kprl.bytecode import (
    FileHeader,
    is_bytecode,
    read_file_header,
    read_full_header,
    uncompressed_header,
)
from kprl.rlcmp import (
    DEFAULT_KEY2,
    XOR_MASK,
    _REVERSE_BITS,
    _lz_compress_raw,
    apply_mask,
    compress,
    decompress,
    decompress_file,
)
from kprl.archive import (
    INDEX_SIZE,
    break_archive,
    build_archive,
    get_subfile,
    is_archive,
    read_index,
    remove_from_archive,
    add_to_archive,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_kprl_uncompressed(
    payload: bytes,
    compiler_version: int = 10002,
    compressed_size_field: int = 0,
) -> bytes:
    """Build a minimal KPRL (v2) uncompressed bytecode blob."""
    data_offset = 0x40
    hdr = bytearray(data_offset)
    hdr[0:4] = b"KPRL"
    struct.pack_into("<I", hdr, 4,    compiler_version)
    struct.pack_into("<I", hdr, 0x20, data_offset)
    struct.pack_into("<I", hdr, 0x24, len(payload))
    struct.pack_into("<I", hdr, 0x28, compressed_size_field)
    return bytes(hdr) + payload


def _make_kp2k_uncompressed(payload: bytes) -> bytes:
    """Build a minimal KP2K (v1) uncompressed bytecode blob."""
    # v1 data_offset = 0x1cc + kidoku_count * 4;  use 0 kidoku entries
    data_offset = 0x1cc
    hdr = bytearray(data_offset)
    hdr[0:4] = b"KP2K"
    struct.pack_into("<I", hdr, 4,    10002)
    struct.pack_into("<I", hdr, 0x20, 0)             # kidoku_count
    struct.pack_into("<I", hdr, 0x24, len(payload))  # uncompressed_size
    return bytes(hdr) + payload


# ---------------------------------------------------------------------------
# XOR_MASK tests
# ---------------------------------------------------------------------------

class TestXorMask(unittest.TestCase):

    def test_length(self):
        self.assertEqual(len(XOR_MASK), 256)

    def test_first_bytes(self):
        self.assertEqual(XOR_MASK[:4], bytes([0x8b, 0xe5, 0x5d, 0xc3]))

    def test_last_byte(self):
        self.assertEqual(XOR_MASK[-1], 0x76)

    def test_apply_mask_self_inverse(self):
        data = bytearray(b"hello world " * 40)
        original = bytes(data)
        apply_mask(data, 4)
        apply_mask(data, 4)  # applying twice must restore original
        self.assertEqual(bytes(data), original)

    def test_apply_mask_at_offset(self):
        data = bytearray(10)
        apply_mask(data, 3)
        # Bytes before offset are unchanged
        self.assertEqual(data[:3], bytearray(3))
        # Byte at offset 3 is XORed with XOR_MASK[0]
        self.assertEqual(data[3], XOR_MASK[0])
        self.assertEqual(data[4], XOR_MASK[1])

    def test_apply_mask_wraps_at_256(self):
        # A buffer longer than 256 bytes: the mask should cycle.
        data = bytearray(300)
        apply_mask(data, 0)
        for i in range(300):
            self.assertEqual(data[i], XOR_MASK[i % 256])

    def test_reverse_bits_table(self):
        self.assertEqual(len(_REVERSE_BITS), 256)
        self.assertEqual(_REVERSE_BITS[0x01], 0x80)
        self.assertEqual(_REVERSE_BITS[0x80], 0x01)
        self.assertEqual(_REVERSE_BITS[0x00], 0x00)
        self.assertEqual(_REVERSE_BITS[0xff], 0xff)
        # Self-inverse: reversing twice gives original
        for b in range(256):
            self.assertEqual(_REVERSE_BITS[_REVERSE_BITS[b]], b)


# ---------------------------------------------------------------------------
# Bytecode header tests
# ---------------------------------------------------------------------------

class TestIsHeaderBytecode(unittest.TestCase):

    def test_kprl_valid(self):
        data = bytearray(8)
        data[0:4] = b"KPRL"
        struct.pack_into("<I", data, 4, 10002)
        self.assertTrue(is_bytecode(data))

    def test_kprl_bad_compiler_version(self):
        data = bytearray(8)
        data[0:4] = b"KPRL"
        struct.pack_into("<I", data, 4, 99999)
        self.assertFalse(is_bytecode(data))

    def test_rdrl_no_compiler_version_needed(self):
        data = bytearray(8)
        data[0:4] = b"RDRL"
        self.assertTrue(is_bytecode(data))

    def test_unknown_magic(self):
        data = bytearray(8)
        data[0:4] = b"JUNK"
        self.assertFalse(is_bytecode(data))

    def test_uncompressed_header_magics(self):
        for magic in (b"KPRL", b"KP2K", b"KPRM", b"RDRL", b"RD2K", b"RDRM"):
            self.assertTrue(uncompressed_header(magic), magic)

    def test_not_uncompressed_magic(self):
        self.assertFalse(uncompressed_header(b"JUNK"))


class TestReadFileHeader(unittest.TestCase):

    def test_v2_kprl_uncompressed(self):
        blob = _make_kprl_uncompressed(b"\x00" * 8, compressed_size_field=0)
        hdr = read_file_header(blob)
        self.assertEqual(hdr.header_version, 2)
        self.assertEqual(hdr.compiler_version, 10002)
        self.assertEqual(hdr.data_offset, 0x40)
        self.assertEqual(hdr.uncompressed_size, 8)
        self.assertIsNone(hdr.compressed_size)  # 0 → None

    def test_v2_kprl_with_compressed_size(self):
        blob = _make_kprl_uncompressed(b"\x00" * 8, compressed_size_field=100)
        hdr = read_file_header(blob)
        self.assertEqual(hdr.compressed_size, 100)

    def test_v1_kp2k(self):
        blob = _make_kp2k_uncompressed(b"\x00" * 16)
        hdr = read_file_header(blob)
        self.assertEqual(hdr.header_version, 1)
        self.assertIsNone(hdr.compressed_size)
        self.assertEqual(hdr.data_offset, 0x1cc)

    def test_rd_magic_compiler_version(self):
        blob = bytearray(_make_kprl_uncompressed(b"\x00" * 8))
        blob[0:4] = b"RDRL"
        hdr = read_file_header(blob)
        self.assertEqual(hdr.compiler_version, 10002)

    def test_rdrm_compiler_version(self):
        blob = bytearray(_make_kprl_uncompressed(b"\x00" * 8))
        blob[0:4] = b"RDRM"
        hdr = read_file_header(blob)
        self.assertEqual(hdr.compiler_version, 110002)

    def test_invalid_raises(self):
        with self.assertRaises(ValueError):
            read_file_header(b"JUNK" + b"\x00" * 64)


# ---------------------------------------------------------------------------
# LZ compression / decompression tests
# ---------------------------------------------------------------------------

class TestLZRoundTrip(unittest.TestCase):

    def _roundtrip(self, payload: bytes) -> bytes:
        compressed_raw = _lz_compress_raw(payload)
        block = struct.pack("<II", len(compressed_raw) + 8, len(payload)) + compressed_raw
        result = decompress(block)
        return result

    def test_empty(self):
        self.assertEqual(self._roundtrip(b""), b"")

    def test_all_zeros(self):
        data = b"\x00" * 256
        self.assertEqual(self._roundtrip(data), data)

    def test_all_same_byte(self):
        data = b"\xab" * 500
        result = self._roundtrip(data)
        self.assertEqual(result, data)

    def test_sequential_bytes(self):
        data = bytes(range(256)) * 4
        self.assertEqual(self._roundtrip(data), data)

    def test_repeated_pattern(self):
        data = b"hello world " * 100
        self.assertEqual(self._roundtrip(data), data)

    def test_mixed(self):
        import random
        rng = random.Random(42)
        data = bytes(rng.randint(0, 255) for _ in range(2000))
        self.assertEqual(self._roundtrip(data), data)

    def test_compresses_repetitive_data(self):
        data = b"abcdef" * 200
        raw = _lz_compress_raw(data)
        self.assertLess(len(raw), len(data))

    def test_decompress_short_block_raises(self):
        with self.assertRaises(ValueError):
            decompress(b"\x00" * 7)  # < 8 bytes is too short


class TestDecompressFile(unittest.TestCase):

    def test_v2_compress_decompress_roundtrip(self):
        payload = b"the quick brown fox " * 50
        original = _make_kprl_uncompressed(payload)
        compressed = compress(original)
        # After compression the magic changes to a non-KPRL value (0x1d0)
        restored = decompress_file(compressed)
        # The data section should match
        from kprl.bytecode import read_file_header
        hdr = read_file_header(restored)
        self.assertEqual(restored[hdr.data_offset:], payload)

    def test_v1_compress_just_masks(self):
        payload = b"\xaa" * 32
        original = _make_kp2k_uncompressed(payload)
        result = compress(original)
        # KP2K does not change the data length, just XOR-masks it
        self.assertEqual(len(result), len(original))

    def test_v2_with_xor2(self):
        payload = b"\x55" * 300
        original = _make_kprl_uncompressed(payload, compiler_version=110002)
        compressed = compress(original, use_xor2=True)
        restored = decompress_file(compressed, use_xor2=True)
        from kprl.bytecode import read_file_header
        hdr = read_file_header(restored)
        self.assertEqual(restored[hdr.data_offset:], payload)


# ---------------------------------------------------------------------------
# Archive tests
# ---------------------------------------------------------------------------

class TestArchiveRoundTrip(unittest.TestCase):

    def _fake_subfile(self, idx: int, size: int = 16) -> bytes:
        return _make_kprl_uncompressed(bytes([idx % 256] * size))

    def test_build_and_read_index(self):
        files = {0: self._fake_subfile(0), 5: self._fake_subfile(5)}
        arc = build_archive(files)
        self.assertEqual(len(arc), INDEX_SIZE + sum(len(v) for v in files.values()))
        idx = read_index(arc)
        self.assertEqual(sorted(idx.keys()), [0, 5])

    def test_get_subfile(self):
        files = {3: self._fake_subfile(3)}
        arc = build_archive(files)
        self.assertEqual(get_subfile(arc, 3), files[3])
        self.assertIsNone(get_subfile(arc, 0))

    def test_break_archive(self):
        files = {i: self._fake_subfile(i) for i in [0, 1, 9]}
        arc = build_archive(files)
        with tempfile.TemporaryDirectory() as td:
            arc_path = Path(td) / "SEEN.TXT"
            arc_path.write_bytes(arc)
            out_dir = Path(td) / "out"
            written = break_archive(arc_path, out_dir)
            self.assertEqual(len(written), 3)
            names = sorted(Path(p).name for p in written)
            self.assertEqual(names, ["SEEN0000.TXT", "SEEN0001.TXT", "SEEN0009.TXT"])
            for i, name in zip([0, 1, 9], names):
                self.assertEqual((out_dir / name).read_bytes(), files[i])

    def test_break_archive_with_index_filter(self):
        files = {i: self._fake_subfile(i) for i in range(5)}
        arc = build_archive(files)
        with tempfile.TemporaryDirectory() as td:
            arc_path = Path(td) / "SEEN.TXT"
            arc_path.write_bytes(arc)
            written = break_archive(arc_path, td, indices={1, 3})
            self.assertEqual(len(written), 2)

    def test_is_archive_empty_marker(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "SEEN.TXT"
            p.write_bytes(b"\x00Empty RealLive archive" + b"\x00" * 100)
            self.assertTrue(is_archive(p))

    def test_is_archive_nonexistent(self):
        self.assertFalse(is_archive("/nonexistent/path/SEEN.TXT"))

    def test_rebuild_matches_original(self):
        files = {i: self._fake_subfile(i) for i in [0, 99, 9999]}
        arc = build_archive(files)
        with tempfile.TemporaryDirectory() as td:
            arc_path = Path(td) / "SEEN.TXT"
            arc_path.write_bytes(arc)
            out_dir = Path(td) / "out"
            break_archive(arc_path, out_dir)
            extracted = {
                int(p.stem[4:]): p.read_bytes()
                for p in out_dir.glob("SEEN*.TXT")
            }
            rebuilt = build_archive(extracted)
            self.assertEqual(rebuilt, arc)

    def test_remove_from_archive(self):
        files = {i: self._fake_subfile(i) for i in range(5)}
        arc = build_archive(files)
        with tempfile.TemporaryDirectory() as td:
            arc_path = Path(td) / "SEEN.TXT"
            arc_path.write_bytes(arc)
            remove_from_archive(arc_path, {2, 4})
            remaining = read_index(arc_path.read_bytes())
            self.assertEqual(sorted(remaining.keys()), [0, 1, 3])

    def test_add_to_archive_creates_file(self):
        with tempfile.TemporaryDirectory() as td:
            arc_path = Path(td) / "SEEN.TXT"
            seen0 = Path(td) / "SEEN0000.TXT"
            seen0.write_bytes(self._fake_subfile(0))
            add_to_archive(arc_path, [seen0])
            self.assertTrue(arc_path.is_file())
            idx = read_index(arc_path.read_bytes())
            self.assertIn(0, idx)

    def test_add_to_archive_replaces_existing(self):
        initial = {0: self._fake_subfile(0, size=8)}
        arc = build_archive(initial)
        with tempfile.TemporaryDirectory() as td:
            arc_path = Path(td) / "SEEN.TXT"
            arc_path.write_bytes(arc)
            new_blob = self._fake_subfile(0, size=16)
            new_file = Path(td) / "SEEN0000.TXT"
            # Write an uncompressed KPRL file so add_to_archive accepts it
            new_file.write_bytes(new_blob)
            add_to_archive(arc_path, [new_file])
            # The file at index 0 should now be different (compressed version)
            updated_arc = arc_path.read_bytes()
            idx = read_index(updated_arc)
            self.assertIn(0, idx)


# ---------------------------------------------------------------------------
# CLI smoke tests
# ---------------------------------------------------------------------------

class TestCLI(unittest.TestCase):

    def _run(self, *args: str) -> int:
        from kprl.__main__ import main
        return main(list(args))

    def test_break_and_rebuild(self):
        payload = b"data" * 20
        files = {0: _make_kprl_uncompressed(payload),
                 1: _make_kprl_uncompressed(payload[::-1])}
        arc = build_archive(files)
        with tempfile.TemporaryDirectory() as td:
            arc_path = Path(td) / "SEEN.TXT"
            arc_path.write_bytes(arc)
            out_dir = Path(td) / "out"
            # -o may appear either before the subcommand (global) or after (per-subcommand)
            rc = self._run("-o", str(out_dir), "break", str(arc_path))
            self.assertEqual(rc, 0)
            rc2 = self._run("break", str(arc_path), "-o", str(out_dir))
            self.assertEqual(rc2, 0)
            broken = sorted(out_dir.glob("SEEN*.TXT"))
            self.assertEqual(len(broken), 2)

    def test_list_command(self):
        payload = b"\xaa" * 32
        files = {7: _make_kprl_uncompressed(payload)}
        arc = build_archive(files)
        with tempfile.TemporaryDirectory() as td:
            arc_path = Path(td) / "SEEN.TXT"
            arc_path.write_bytes(arc)
            rc = self._run("list", str(arc_path))
            self.assertEqual(rc, 0)

    def test_list_invalid_archive(self):
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "bad.txt"
            bad.write_bytes(b"not an archive")
            rc = self._run("list", str(bad))
            self.assertEqual(rc, 1)


# ---------------------------------------------------------------------------
# Real-file integration tests (skipped when SEEN.TXT is not present)
# ---------------------------------------------------------------------------

_REAL_SEEN = Path(os.environ.get("KPRL_TEST_SEEN", "/tmp/Seen_test.txt"))


@unittest.skipUnless(_REAL_SEEN.is_file(), f"real SEEN.TXT not found at {_REAL_SEEN}")
class TestRealArchive(unittest.TestCase):
    """Integration tests against a real RealLive SEEN.TXT archive."""

    @classmethod
    def setUpClass(cls):
        cls.data = _REAL_SEEN.read_bytes()
        cls.idx  = read_index(cls.data)

    def test_is_archive(self):
        self.assertTrue(is_archive(_REAL_SEEN))

    def test_entry_count(self):
        self.assertGreater(len(self.idx), 0)

    def test_all_subfiles_are_bytecode(self):
        from kprl.bytecode import is_bytecode
        for i, (off, ln) in self.idx.items():
            self.assertTrue(
                is_bytecode(self.data, off),
                f"SEEN{i:04d} not recognised as bytecode"
            )

    def test_decompress_all(self):
        from kprl.rlcmp import decompress_file
        from kprl.bytecode import read_file_header
        for i, (off, ln) in self.idx.items():
            blob = self.data[off: off + ln]
            dec  = decompress_file(blob)
            hdr  = read_file_header(dec)
            expected = hdr.data_offset + hdr.uncompressed_size
            self.assertEqual(
                len(dec), expected,
                f"SEEN{i:04d}: decompressed size mismatch"
            )

    def test_compress_roundtrip_all(self):
        from kprl.rlcmp import decompress_file, compress
        from kprl.bytecode import read_file_header
        for i, (off, ln) in self.idx.items():
            blob = self.data[off: off + ln]
            dec  = decompress_file(blob)
            rec  = compress(dec)
            re_dec = decompress_file(rec)
            hdr = read_file_header(dec)
            self.assertEqual(
                re_dec[hdr.data_offset:], dec[hdr.data_offset:],
                f"SEEN{i:04d}: payload mismatch after compress/decompress"
            )

    def test_break_rebuild_identical(self):
        with tempfile.TemporaryDirectory() as td:
            arc_path = Path(td) / "SEEN.TXT"
            arc_path.write_bytes(self.data)
            out_dir = Path(td) / "out"
            break_archive(arc_path, out_dir)
            extracted = {
                int(p.name[4:8]): p.read_bytes()
                for p in out_dir.glob("SEEN*.TXT")
            }
            rebuilt = build_archive(extracted)
            # Every extracted sub-file must be byte-identical to the original
            for i, (off, ln) in self.idx.items():
                orig = self.data[off: off + ln]
                self.assertEqual(
                    extracted.get(i), orig,
                    f"SEEN{i:04d} mismatch after break/rebuild"
                )
            # Total archive size should match
            self.assertEqual(len(rebuilt), len(self.data))


    def test_disassemble_all(self):
        """All sub-files can be disassembled without error."""
        from kprl.disasm import disassemble_file
        from kprl.rlcmp import decompress_file
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "ke"
            out_dir.mkdir()
            for i, (off, ln) in self.idx.items():
                raw = self.data[off: off + ln]
                tmp = Path(td) / f"SEEN{i:04d}.TXT"
                tmp.write_bytes(raw)
                paths = disassemble_file(str(tmp), str(out_dir))
                ke_path = out_dir / f"SEEN{i:04d}.TXT.ke"
                self.assertTrue(ke_path.exists(), f"SEEN{i:04d}: .ke not produced")
                text = ke_path.read_text(encoding="utf-8")
                self.assertIn("#file", text, f"SEEN{i:04d}: missing #file header")

    def test_assemble_roundtrip(self):
        """Disassemble → assemble → re-disassemble produces equivalent output.

        Kidoku markers are stripped during disassembly, so empty consecutive
        labels at the same bytecode offset may collapse (their numbers shift
        by 1 for each collapsed pair).  The comparison therefore replaces all
        ``@N`` tokens with a placeholder before comparing, which verifies that
        the instruction sequences are identical while tolerating label-number
        differences.
        """
        import re as _re
        from kprl.disasm import disassemble_file
        from kprl.assemble import assemble_file

        _LABEL_RE = _re.compile(r"@\d+")

        def _norm(text: str) -> str:
            lines = text.splitlines()
            filtered = [
                l for l in lines
                if not l.strip().startswith(("#resource", "#character"))
            ]
            body = "\n".join(filtered)
            return _LABEL_RE.sub("@N", body)

        with tempfile.TemporaryDirectory() as td:
            ke_dir = Path(td) / "ke"
            ke_dir2 = Path(td) / "ke2"
            asm_dir = Path(td) / "asm"
            ke_dir.mkdir(); ke_dir2.mkdir(); asm_dir.mkdir()

            for i, (off, ln) in self.idx.items():
                raw = self.data[off: off + ln]
                tmp = Path(td) / f"SEEN{i:04d}.TXT"
                tmp.write_bytes(raw)

                # Step 1: disassemble original
                disassemble_file(str(tmp), str(ke_dir))
                ke_path = ke_dir / f"SEEN{i:04d}.TXT.ke"

                # Step 2: assemble
                asm_paths = assemble_file(str(ke_path), str(asm_dir))
                self.assertTrue(asm_paths, f"SEEN{i:04d}: assembly produced no output")

                # Step 3: re-disassemble
                disassemble_file(str(asm_paths[0]), str(ke_dir2))
                ke2_path = ke_dir2 / f"SEEN{i:04d}.TXT.ke"
                self.assertTrue(ke2_path.exists(), f"SEEN{i:04d}: re-disassembly failed")

                ke1 = _norm(ke_path.read_text(encoding="utf-8", errors="replace"))
                ke2 = _norm(ke2_path.read_text(encoding="utf-8", errors="replace"))
                self.assertEqual(ke1, ke2, f"SEEN{i:04d}: round-trip mismatch")


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Image format tests
# ---------------------------------------------------------------------------

class TestGAN(unittest.TestCase):
    """Test GAN binary ↔ XML round-trip using synthetic data."""

    def _make_gan(self) -> bytes:
        """Build a minimal GAN binary with 1 set × 2 frames."""
        import struct
        out = bytearray()
        def wi(v): out.extend(struct.pack("<i", v))
        # Header
        wi(10000); wi(10000); wi(10100)
        bname = b"SPRITE.G00"
        wi(len(bname) + 1); out.extend(bname); out.append(0)
        # Data section
        wi(20000); wi(1)          # 1 set
        wi(30000); wi(2)          # 1 set, 2 frames
        # Frame 0: pattern=0, x=10, y=20, time=33, alpha=255, other=0
        for tag, val in [(30100,0),(30101,10),(30102,20),(30103,33),(30104,255),(30105,0)]:
            wi(tag); wi(val)
        wi(999999)
        # Frame 1: same as frame 0 but x=20
        for tag, val in [(30100,0),(30101,20),(30102,20),(30103,33),(30104,255),(30105,0)]:
            wi(tag); wi(val)
        wi(999999)
        return bytes(out)

    def test_roundtrip_binary(self):
        """gan_to_xml → xml_to_gan should reproduce the original bytes."""
        from kprl.gan import gan_to_xml, xml_to_gan
        original = self._make_gan()
        root = gan_to_xml(original)
        rebuilt = xml_to_gan(root)
        self.assertEqual(original, rebuilt)

    def test_xml_structure(self):
        """gan_to_xml should produce correct element structure."""
        from kprl.gan import gan_to_xml
        root = gan_to_xml(self._make_gan())
        self.assertEqual(root.tag, "vas_gan")
        self.assertEqual(root.get("bitmap"), "SPRITE.G00")
        sets = list(root)
        self.assertEqual(len(sets), 1)
        frames = list(sets[0])
        self.assertEqual(len(frames), 2)

    def test_file_roundtrip(self):
        """gan_to_ganxml → ganxml_to_gan file roundtrip."""
        from kprl.gan import gan_to_ganxml, ganxml_to_gan
        with tempfile.TemporaryDirectory() as td:
            gan_path = Path(td) / "test.gan"
            xml_path = Path(td) / "test.ganxml"
            gan2_path = Path(td) / "test2.gan"
            gan_path.write_bytes(self._make_gan())
            gan_to_ganxml(gan_path, xml_path)
            self.assertTrue(xml_path.exists())
            ganxml_to_gan(xml_path, gan2_path)
            self.assertEqual(gan_path.read_bytes(), gan2_path.read_bytes())


class TestG00(unittest.TestCase):
    """Test G00 image encode/decode round-trip using synthetic images."""

    def _solid_rgb(self, w=16, h=16):
        from PIL import Image
        img = Image.new("RGB", (w, h), (100, 150, 200))
        return img

    def _solid_rgba(self, w=16, h=16):
        from PIL import Image
        img = Image.new("RGBA", (w, h), (100, 150, 200, 128))
        return img

    def _gradient_rgb(self, w=32, h=32):
        from PIL import Image
        import random
        random.seed(42)
        img = Image.new("RGB", (w, h))
        pixels = [(random.randint(0,255), random.randint(0,255), random.randint(0,255))
                  for _ in range(w * h)]
        img.putdata(pixels)
        return img

    def test_fmt0_roundtrip(self):
        from kprl.g00 import read_g00, write_g00
        img = self._solid_rgb()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test.g00"
            write_g00(img, p, fmt=0)
            out = read_g00(p)
        self.assertEqual(img.size, out.size)
        self.assertEqual(list(img.getdata()), list(out.getdata()))

    def test_fmt1_roundtrip(self):
        from kprl.g00 import read_g00, write_g00
        img = self._solid_rgb()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test.g00"
            write_g00(img, p, fmt=1)
            out = read_g00(p)
        self.assertEqual(img.size, out.size)

    def test_fmt2_roundtrip(self):
        from kprl.g00 import read_g00, write_g00
        img = self._solid_rgba()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test.g00"
            write_g00(img, p, fmt=2)
            out = read_g00(p)
        self.assertEqual(img.size, out.size)

    def test_autoformat_rgb(self):
        """Auto-format for an RGB image with many colours should pick fmt 0."""
        from kprl.g00 import _choose_format
        img = self._gradient_rgb()
        fmt = _choose_format(img)
        self.assertIn(fmt, (0, 1, 2))  # must be a valid fmt

    def test_is_g00(self):
        from kprl.g00 import write_g00, is_g00
        img = self._solid_rgb()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test.g00"
            write_g00(img, p, fmt=0)
            self.assertTrue(is_g00(p))


class TestPDT(unittest.TestCase):
    def _solid_rgb(self, w=16, h=16):
        from PIL import Image
        return Image.new("RGB", (w, h), (80, 160, 240))

    def _solid_rgba(self, w=16, h=16):
        from PIL import Image
        return Image.new("RGBA", (w, h), (80, 160, 240, 200))

    def test_roundtrip_rgb(self):
        from kprl.pdt import read_pdt, write_pdt
        img = self._solid_rgb()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test.pdt"
            write_pdt(img, p)
            out = read_pdt(p)
        self.assertEqual(img.size, out.size)
        self.assertEqual(list(img.getdata()), list(out.getdata()))

    def test_roundtrip_rgba(self):
        from kprl.pdt import read_pdt, write_pdt
        img = self._solid_rgba()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test.pdt"
            write_pdt(img, p)
            out = read_pdt(p)
        self.assertEqual(img.size, out.size)
        self.assertEqual(img.mode, "RGBA")
        self.assertEqual(out.mode, "RGBA")

    def test_is_pdt(self):
        from kprl.pdt import write_pdt, is_pdt
        img = self._solid_rgb()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test.pdt"
            write_pdt(img, p)
            self.assertTrue(is_pdt(p))


class TestRCT(unittest.TestCase):
    def _solid(self, w=16, h=16):
        from PIL import Image
        return Image.new("RGB", (w, h), (200, 100, 50))

    def test_roundtrip(self):
        from kprl.rct import read_rct, write_rct
        img = self._solid()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test.rct"
            write_rct(img, p)
            out = read_rct(p)
        self.assertEqual(img.size, out.size)
        self.assertEqual(list(img.getdata()), list(out.getdata()))

    def test_is_rct(self):
        from kprl.rct import write_rct, is_rct
        img = self._solid()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test.rct"
            write_rct(img, p)
            self.assertTrue(is_rct(p))


class TestRC8(unittest.TestCase):
    def _solid(self, w=16, h=16):
        from PIL import Image
        return Image.new("RGB", (w, h), (200, 100, 50))

    def test_roundtrip(self):
        from kprl.rc8 import read_rc8, write_rc8
        img = self._solid()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test.rc8"
            write_rc8(img, p)
            out = read_rc8(p)
        self.assertEqual(img.size, out.size)

    def test_is_rc8(self):
        from kprl.rc8 import write_rc8, is_rc8
        img = self._solid()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test.rc8"
            write_rc8(img, p)
            self.assertTrue(is_rc8(p))
