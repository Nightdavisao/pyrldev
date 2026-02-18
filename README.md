# pyrldev: kprl

Python port of the RLdev toolchain for working with RealLive/AVG2000 visual novel game files.

> **⚠️ Heads up**
>
> This was written by an LLM. The whole point was to drag the project out of OCaml and
> away from a build system nobody can get running anymore. It works, the LLM tested it
> against real game files, and a human stepped in to fix things along the way (the image
> conversion code needed a few corrections), but there are still things that are
> probably not quite right, and the code is not very polished.
>
> I should also make it clear that this project's purpose is solely for translating *one* specific visual novel (the one I care about).
> It is not intended to be a general-purpose RLdev replacement, and it is not intended to be used by anyone else. If you want to use it for something else, or if you want to contribute to it, that's great, but just keep in mind that it was not designed with that in mind. Also, don't fill in more AI slop in this codebase than what already exists.
>
> Consider this a rough first pass. It's expected that I'll come in later and clean things up, but for now I just want to get something working.

Covers three of the four original RLdev tools (see [Not yet ported](#not-yet-ported) below):

| Original tool | What it does |
|---------------|--------------|
| `kprl`        | Pack/unpack `SEEN.TXT` archives; assemble/disassemble Kepago bytecode |
| `vaconv`      | Convert G00 / PDT / RCT / RC8 image files ↔ PNG |
| `rlxml`       | Convert GAN sprite-animation files ↔ XML |


## Installation

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

## Usage

All functionality is exposed through the `kprl` module:

```bash
python -m kprl <command> [options]
```

If installed via `uv` / pip you can also use the `kprl` entry point directly:

```bash
kprl <command> [options]
```

---

## Commands

### Archive (`SEEN.TXT`)

| Command | Description |
|---------|-------------|
| `break FILE [-o DIR]` | Extract all sub-files from a `SEEN.TXT` archive |
| `add FILE SUB... [-o DIR]` | Insert or replace sub-files in an archive |
| `remove FILE SLOT... [-o DIR]` | Remove sub-files by slot number |
| `list FILE` | List archive contents (slot, offset, size, compression) |

### Bytecode

| Command | Description |
|---------|-------------|
| `disassemble FILE... [-o DIR]` | Binary bytecode → `.ke` assembly + `.utf` resource file |
| `assemble FILE.ke... [-o DIR] [--compress]` | `.ke` assembly → binary bytecode |
| `extract FILE... [-o DIR]` | Decompress a KPRL-compressed file (no disassembly) |
| `pack FILE... [-o DIR]` | Compress a raw bytecode file with LZ77 |

### Images

| Command | Description |
|---------|-------------|
| `img2png FILE... [-o DIR]` | Convert G00 / PDT / RCT / RC8 → PNG |
| `png2img FILE... --format FMT [-o DIR]` | Convert PNG → `g00` / `pdt` / `rct` / `rc8` |

Supported image formats: `.g00` (G00 format 0/1/2), `.pdt` (PDT10/PDT11), `.rct` (Majiro true-colour), `.rc8` (Majiro 8-bit paletted).

### Animations

| Command | Description |
|---------|-------------|
| `ganxml FILE... [-o DIR]` | GAN binary ↔ XML (direction detected from file extension) |

---

## Quick examples

```bash
# Unpack a SEEN.TXT archive
python -m kprl break SEEN.TXT -o seenfiles/

# Disassemble all scripts
python -m kprl disassemble seenfiles/ -o ke/

# (edit ke/*.ke to translate the quoted strings)

# Reassemble and repack
python -m kprl assemble ke/*.ke -o out/ --compress
python -m kprl add SEEN.TXT out/*.uncompressed

# Convert all G00 images to PNG
python -m kprl img2png -o png/ *.g00

# Convert edited PNGs back to G00
python -m kprl png2img --format g00 -o g00/ png/*.png

# Convert a GAN animation to XML and back
python -m kprl ganxml sprite.gan      # → sprite.ganxml
python -m kprl ganxml sprite.ganxml   # → sprite.gan
```

For a full step-by-step translation workflow see [TRANSLATION_GUIDE.md](TRANSLATION_GUIDE.md).

---

## Running tests

```bash
uv run pytest tests/
```

---

## Not yet ported

| Original tool | Description |
|---------------|-------------|
| `rlc` | The Kepago **compiler** — compiles `.ke` source files written from scratch into bytecode. The current `assemble` command only reassembles bytecode that was first *disassembled* from an existing binary; it is not a full compiler. |

---

## Module overview

| Module | Description |
|--------|-------------|
| `archive.py` | `SEEN.TXT` binary archive read/write |
| `rlcmp.py` | KPRL LZ77 compression/decompression |
| `bytecode.py` | Low-level bytecode utilities |
| `kfn.py` | KFN header parser |
| `disasm.py` | Bytecode disassembler |
| `assemble.py` | Kepago assembler |
| `g00.py` | G00 image codec (formats 0, 1, 2) |
| `pdt.py` | PDT10 / PDT11 image codec |
| `rct.py` | Majiro RCT true-colour codec |
| `rc8.py` | Majiro RC8 paletted codec |
| `gan.py` | GAN animation binary ↔ XML |
