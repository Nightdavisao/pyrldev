"""
__main__.py – CLI entry-point for the kprl Python package.

Usage:  python -m kprl <command> [options] <files…>

Commands
--------
break   SEEN.TXT [ranges]   Extract sub-files from an archive.
add     SEEN.TXT FILE…      Add/replace files in an archive.
remove  SEEN.TXT RANGE…     Remove sub-files from an archive.
list    SEEN.TXT [ranges]   List archive contents.
extract FILE…               Decompress individual bytecode files.
pack    FILE…               Compress individual bytecode files.

Range syntax (for break / remove / list)
-----------------------------------------
Comma-separated list of indices or inclusive ranges, e.g.:
  0,1,2        individual indices
  100-200      inclusive range
  0,5-10,42   mixed
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Range parsing (mirrors OCaml Archiver.process_archive range lexer)
# ---------------------------------------------------------------------------

def _parse_ranges(tokens: list[str]) -> set[int]:
    """Parse range tokens into a set of integer indices (0–9999)."""
    result: set[int] = set()
    for token in tokens:
        for part in token.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                lo_s, _, hi_s = part.partition("-")
                result.update(range(int(lo_s), int(hi_s) + 1))
            else:
                result.add(int(part))
    return result & set(range(10_000))


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def cmd_break(args: argparse.Namespace) -> int:
    from kprl.archive import break_archive, is_archive

    archive = Path(args.archive)
    if not is_archive(archive):
        print(f"Error: {archive.name} is not a valid RealLive archive",
              file=sys.stderr)
        return 1

    indices = _parse_ranges(args.ranges) if args.ranges else None
    outdir  = Path(args.outdir) if args.outdir else Path(".")
    written = break_archive(archive, outdir, verbose=args.verbose, indices=indices)
    if args.verbose:
        print(f"Extracted {len(written)} file(s).")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    from kprl.archive import add_to_archive

    try:
        add_to_archive(args.archive, args.files, verbose=args.verbose)
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    from kprl.archive import remove_from_archive

    if not args.ranges:
        print("Error: no indices specified", file=sys.stderr)
        return 1

    indices = _parse_ranges(args.ranges)
    try:
        remove_from_archive(args.archive, indices, verbose=args.verbose)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    from kprl.archive import is_archive, read_index
    from kprl.bytecode import read_full_header

    archive = Path(args.archive)
    if not is_archive(archive):
        print(f"Error: {archive.name} is not a valid RealLive archive",
              file=sys.stderr)
        return 1

    data    = archive.read_bytes()
    index   = read_index(data)
    indices = _parse_ranges(args.ranges) if args.ranges else set(range(10_000))

    for idx in sorted(index.keys()):
        if idx not in indices:
            continue
        off, ln = index[idx]
        blob = data[off: off + ln]
        try:
            hdr = read_full_header(blob)
            unc = hdr.uncompressed_size + hdr.data_offset
            if hdr.compressed_size is not None:
                cmp = hdr.compressed_size + hdr.data_offset
                ratio = cmp / unc * 100.0 if unc else 0.0
                print(
                    f"SEEN{idx:04d}.TXT: "
                    f"{unc / 1024:>10.2f} k -> {cmp / 1024:>10.2f} k  "
                    f"({ratio:.2f}%)"
                )
            else:
                print(f"SEEN{idx:04d}.TXT: {unc / 1024:>10.2f} k")
        except Exception:
            print(f"SEEN{idx:04d}.TXT: {ln} bytes (unreadable header)")

    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    """Decompress individual unarchived bytecode files (kprl -e equivalent)."""
    from kprl.archive  import is_archive, break_archive
    from kprl.bytecode import is_bytecode, read_file_header, uncompressed_header
    from kprl.rlcmp    import decompress_file

    outdir = Path(args.outdir) if args.outdir else Path(".")
    outdir.mkdir(parents=True, exist_ok=True)
    errors = 0

    first = Path(args.files[0])

    # If the first argument is an archive, break it then decompress each piece.
    if is_archive(first):
        broken = break_archive(first, outdir, verbose=False)
        targets = [Path(p) for p in broken]
    else:
        targets = [Path(f) for f in args.files]

    for fp in targets:
        blob = fp.read_bytes()
        if not is_bytecode(blob):
            print(f"Skipping {fp.name}: not a bytecode file")
            continue
        hdr = read_file_header(blob)
        if uncompressed_header(bytes(blob[:4])):
            print(f"Ignoring {fp.name} (not compressed)")
            continue
        out_path = outdir / (fp.name + ".uncompressed")
        if args.verbose:
            print(f"Decompressing {fp.name} to {out_path.name}")
        try:
            result = decompress_file(blob, use_xor2=(hdr.compiler_version == 110002))
            out_path.write_bytes(result)
        except Exception as exc:
            print(f"Error decompressing {fp.name}: {exc}", file=sys.stderr)
            errors += 1

    return 1 if errors else 0


def cmd_pack(args: argparse.Namespace) -> int:
    """Compress individual uncompressed bytecode files (kprl -p equivalent)."""
    from kprl.bytecode import is_bytecode, read_file_header, uncompressed_header
    from kprl.rlcmp    import compress as rl_compress

    outdir = Path(args.outdir) if args.outdir else Path(".")
    outdir.mkdir(parents=True, exist_ok=True)
    errors = 0

    for fp in (Path(f) for f in args.files):
        blob = fp.read_bytes()
        if not uncompressed_header(bytes(blob[:4])):
            print(f"Skipping {fp.name}: not an uncompressed bytecode file")
            continue
        # Strip .uncompressed suffix if present
        stem = fp.stem if fp.suffix == ".uncompressed" else fp.name
        out_path = outdir / stem
        if args.verbose:
            print(f"Compressing {fp.name} to {out_path.name}")
        try:
            hdr    = read_file_header(blob)
            result = rl_compress(blob, use_xor2=(hdr.compiler_version == 110002))
            out_path.write_bytes(result)
        except Exception as exc:
            print(f"Skipping {fp.name}: {exc}", file=sys.stderr)
            errors += 1

    return 1 if errors else 0


def cmd_assemble(args: argparse.Namespace) -> int:
    """Assemble Kepago assembly files (.ke) into binary bytecode."""
    from kprl.assemble import assemble_file

    outdir = Path(args.outdir) if args.outdir else Path(".")
    compress = getattr(args, "compress", False)
    errors = 0

    for fp in (Path(f) for f in args.files):
        if args.verbose:
            print(f"Assembling {fp.name}…")
        try:
            written = assemble_file(fp, outdir=outdir, compress=compress)
            if args.verbose:
                for wp in written:
                    print(f"  → {wp}")
        except Exception as exc:
            print(f"Error assembling {fp.name}: {exc}", file=sys.stderr)
            errors += 1

    return 1 if errors else 0


def cmd_disassemble(args: argparse.Namespace) -> int:
    """Disassemble bytecode files into Kepago assembly (.ke)."""
    from kprl.archive  import is_archive, break_archive
    from kprl.disasm   import disassemble_file

    outdir = Path(args.outdir) if args.outdir else Path(".")
    options = {
        "annotate":    getattr(args, "annotate", False),
        "single_file": getattr(args, "single_file", False),
        "encoding":    getattr(args, "encoding", "utf-8"),
    }
    errors = 0
    targets: list[Path] = []

    for fp in (Path(f) for f in args.files):
        if is_archive(fp):
            broken = break_archive(fp, outdir, verbose=False)
            targets.extend(Path(p) for p in broken)
        else:
            targets.append(fp)

    for fp in targets:
        if args.verbose:
            print(f"Disassembling {fp.name}…")
        try:
            written = disassemble_file(fp, outdir=outdir, options=options)
            if args.verbose:
                for wp in written:
                    print(f"  → {wp}")
        except Exception as exc:
            print(f"Error disassembling {fp.name}: {exc}", file=sys.stderr)
            errors += 1

    return 1 if errors else 0


# ---------------------------------------------------------------------------
# Image conversion helpers
# ---------------------------------------------------------------------------

_IMAGE_READERS = {
    ".g00": ("kprl.g00", "read_g00"),
    ".pdt": ("kprl.pdt", "read_pdt"),
    ".rct": ("kprl.rct", "read_rct"),
    ".rc8": ("kprl.rc8", "read_rc8"),
}

_IMAGE_WRITERS = {
    "g00": ("kprl.g00", "write_g00"),
    "pdt": ("kprl.pdt", "write_pdt"),
    "rct": ("kprl.rct", "write_rct"),
    "rc8": ("kprl.rc8", "write_rc8"),
}


def _read_any_image(path: Path):
    """Auto-detect and decode a supported image file."""
    import importlib
    ext = path.suffix.lower()
    if ext not in _IMAGE_READERS:
        raise ValueError(f"Unsupported image format: {ext}")
    modname, fname = _IMAGE_READERS[ext]
    mod = importlib.import_module(modname)
    return getattr(mod, fname)(path)


def cmd_img2png(args: argparse.Namespace) -> int:
    """Convert supported image files to PNG."""
    outdir = Path(args.outdir) if args.outdir else None
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)
    errors = 0
    for fp in (Path(f) for f in args.files):
        dest = (outdir or fp.parent) / (fp.stem + ".png")
        if args.verbose:
            print(f"Converting {fp.name} → {dest.name}")
        try:
            img = _read_any_image(fp)
            img.save(str(dest))
        except Exception as exc:
            print(f"Error converting {fp.name}: {exc}", file=sys.stderr)
            errors += 1
    return 1 if errors else 0


def cmd_png2img(args: argparse.Namespace) -> int:
    """Convert PNG files to a target image format."""
    import importlib
    from PIL import Image as PILImage

    fmt = args.format.lower()
    if fmt not in _IMAGE_WRITERS:
        print(f"Error: unsupported format '{fmt}'. Choices: {', '.join(_IMAGE_WRITERS)}",
              file=sys.stderr)
        return 1
    modname, fname = _IMAGE_WRITERS[fmt]
    mod = importlib.import_module(modname)
    writer = getattr(mod, fname)
    outdir = Path(args.outdir) if args.outdir else None
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)
    errors = 0
    for fp in (Path(f) for f in args.files):
        dest = (outdir or fp.parent) / (fp.stem + "." + fmt)
        if args.verbose:
            print(f"Converting {fp.name} → {dest.name}")
        try:
            img = PILImage.open(str(fp))
            writer(img, dest)
        except Exception as exc:
            print(f"Error converting {fp.name}: {exc}", file=sys.stderr)
            errors += 1
    return 1 if errors else 0


def cmd_ganxml(args: argparse.Namespace) -> int:
    """Convert .gan ↔ .ganxml files."""
    from kprl.gan import gan_to_ganxml, ganxml_to_gan
    outdir = Path(args.outdir) if args.outdir else None
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)
    errors = 0
    for fp in (Path(f) for f in args.files):
        ext = fp.suffix.lower()
        try:
            if ext == ".gan":
                dest = (outdir or fp.parent) / (fp.stem + ".ganxml")
                if args.verbose:
                    print(f"Converting {fp.name} → {dest.name}")
                gan_to_ganxml(fp, dest)
            elif ext == ".ganxml":
                dest = (outdir or fp.parent) / (fp.stem + ".gan")
                if args.verbose:
                    print(f"Converting {fp.name} → {dest.name}")
                ganxml_to_gan(fp, dest)
            else:
                print(f"Error: {fp.name}: expected .gan or .ganxml extension",
                      file=sys.stderr)
                errors += 1
        except Exception as exc:
            print(f"Error converting {fp.name}: {exc}", file=sys.stderr)
            errors += 1
    return 1 if errors else 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m kprl",
        description="RealLive SEEN.TXT archive pack/unpack tool (Python port of kprl).",
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print progress messages.")
    parser.add_argument("-o", "--outdir", metavar="DIR",
                        help="Output directory (default: current directory).")

    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    # break
    p_break = sub.add_parser("break", help="Extract sub-files from a SEEN.TXT archive.")
    p_break.add_argument("archive", metavar="SEEN.TXT")
    p_break.add_argument("ranges", nargs="*", metavar="RANGE",
                         help="Optional index ranges, e.g. 0-99,200")
    p_break.add_argument("-o", "--outdir", metavar="DIR",
                         help="Output directory (default: current directory).")

    # add
    p_add = sub.add_parser("add", help="Add/replace files in a SEEN.TXT archive.")
    p_add.add_argument("archive", metavar="SEEN.TXT")
    p_add.add_argument("files", nargs="+", metavar="SEENxxxx.TXT")

    # remove
    p_rem = sub.add_parser("remove", help="Remove sub-files from a SEEN.TXT archive.")
    p_rem.add_argument("archive", metavar="SEEN.TXT")
    p_rem.add_argument("ranges", nargs="+", metavar="RANGE")

    # list
    p_list = sub.add_parser("list", help="List archive contents.")
    p_list.add_argument("archive", metavar="SEEN.TXT")
    p_list.add_argument("ranges", nargs="*", metavar="RANGE")

    # extract
    p_ext = sub.add_parser("extract", help="Decompress individual bytecode files.")
    p_ext.add_argument("files", nargs="+", metavar="FILE")
    p_ext.add_argument("-o", "--outdir", metavar="DIR",
                       help="Output directory (default: current directory).")

    # pack
    p_pack = sub.add_parser("pack", help="Compress individual bytecode files.")
    p_pack.add_argument("files", nargs="+", metavar="FILE")
    p_pack.add_argument("-o", "--outdir", metavar="DIR",
                        help="Output directory (default: current directory).")

    # assemble
    p_asm = sub.add_parser("assemble",
                            help="Assemble Kepago assembly files (.ke) into binary bytecode.")
    p_asm.add_argument("files", nargs="+", metavar="FILE",
                       help=".ke assembly files to assemble.")
    p_asm.add_argument("-o", "--outdir", metavar="DIR",
                       help="Output directory (default: current directory).")
    p_asm.add_argument("--compress", action="store_true",
                       help="Compress the output bytecode with LZ77.")

    # disassemble
    p_dis = sub.add_parser("disassemble",
                            help="Disassemble bytecode files into Kepago assembly.")
    p_dis.add_argument("files", nargs="+", metavar="FILE",
                       help="Individual .TXT / .uncompressed files, or a SEEN.TXT archive.")
    p_dis.add_argument("-o", "--outdir", metavar="DIR",
                       help="Output directory (default: current directory).")
    p_dis.add_argument("--encoding", default="utf-8", metavar="ENC",
                       help="Output encoding name written in the file header (default: utf-8).")
    p_dis.add_argument("--annotate", action="store_true",
                       help="Add byte-offset annotations to every line.")
    p_dis.add_argument("--single-file", action="store_true", dest="single_file",
                       help="Write everything to the .ke file (suppress separate resource file).")

    # img2png
    p_img = sub.add_parser("img2png",
                            help="Convert G00/PDT/RCT/RC8 image files to PNG.")
    p_img.add_argument("files", nargs="+", metavar="FILE",
                       help="Image files (.g00, .pdt, .rct, .rc8) to convert.")
    p_img.add_argument("-o", "--outdir", metavar="DIR",
                       help="Output directory (default: same as input).")

    # png2img
    p_p2i = sub.add_parser("png2img",
                            help="Convert PNG files to a RealLive image format.")
    p_p2i.add_argument("files", nargs="+", metavar="FILE",
                       help="PNG files to convert.")
    p_p2i.add_argument("--format", required=True, metavar="FMT",
                       choices=["g00", "pdt", "rct", "rc8"],
                       help="Target format: g00, pdt, rct, or rc8.")
    p_p2i.add_argument("-o", "--outdir", metavar="DIR",
                       help="Output directory (default: same as input).")

    # ganxml
    p_gan = sub.add_parser("ganxml",
                            help="Convert GAN animation files ↔ XML (.gan ↔ .ganxml).")
    p_gan.add_argument("files", nargs="+", metavar="FILE",
                       help=".gan or .ganxml files to convert.")
    p_gan.add_argument("-o", "--outdir", metavar="DIR",
                       help="Output directory (default: same as input).")

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_COMMANDS = {
    "break":       cmd_break,
    "add":         cmd_add,
    "remove":      cmd_remove,
    "list":        cmd_list,
    "extract":     cmd_extract,
    "pack":        cmd_pack,
    "assemble":    cmd_assemble,
    "disassemble": cmd_disassemble,
    "img2png":     cmd_img2png,
    "png2img":     cmd_png2img,
    "ganxml":      cmd_ganxml,
}


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args   = parser.parse_args(argv)

    # Propagate global flags to sub-command namespace where needed
    if not hasattr(args, "verbose"):
        args.verbose = False
    if not hasattr(args, "outdir"):
        args.outdir = None

    return _COMMANDS[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
