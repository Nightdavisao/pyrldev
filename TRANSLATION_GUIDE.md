# RealLive Translation Guide

This guide explains how to extract, edit, and repack a RealLive game's script for
translation using the Python `kprl` tool located in `src/python/`.

---

## Requirements

- Python 3.10 or later
- [Pillow](https://python-pillow.org/) (only needed for image conversion commands)

Install dependencies with [uv](https://docs.astral.sh/uv/):

```bash
cd src/python/
uv sync
```

Or with pip:

```bash
pip install pillow
```

Run all commands from the `src/python/` directory, or add it to your `PYTHONPATH`.

---

## Overview of the workflow

```
SEEN.TXT  ──break──►  SEENxxxx.TXT  ──disassemble──►  SEENxxxx.TXT.ke   ← edit text here
                                                       SEENxxxx.TXT.utf  ← character names here
                         ▲                                    │
                         │                               assemble
                         │                                    │
                         └──────────add──────────  SEENxxxx.TXT.uncompressed
```

1. **Break** the archive into individual script files.
2. **Disassemble** each file into human-readable `.ke` assembly.
3. **Edit** the text strings in `.ke` (and character names in `.utf`).
4. **Assemble** the edited `.ke` back into binary bytecode.
5. **Add** the new bytecode files back into the archive.

---

## Step-by-step

### 1. Break the archive

Extract every sub-file from `SEEN.TXT` into a directory:

```bash
python -m kprl break SEEN.TXT -o seenfiles/
```

This creates files named `SEENxxxx.TXT` (e.g. `SEEN0005.TXT`, `SEEN1009.TXT`, …).

> **Tip:** Make a backup of the original `SEEN.TXT` before doing anything else.

---

### 2. Disassemble the script files

Convert the binary bytecode into readable Kepago assembly (`.ke`):

```bash
python -m kprl disassemble seenfiles/ -o ke/
```

You can also disassemble a single file:

```bash
python -m kprl disassemble seenfiles/SEEN0005.TXT -o ke/
```

Or pass the original `SEEN.TXT` directly and it will disassemble every file inside:

```bash
python -m kprl disassemble SEEN.TXT -o ke/
```

For each input file you get:

| Output file | Contents |
|---|---|
| `SEENxxxx.TXT.ke` | Bytecode assembly — contains all the script logic and text |
| `SEENxxxx.TXT.utf` | Resource file — character (speaker) name table |

#### Useful options

| Option | Effect |
|---|---|
| `--annotate` | Adds hex byte-offset comments to every line (helpful for debugging) |
| `--single-file` | Merges the resource data into the `.ke` file (no separate `.utf`) |
| `--encoding ENC` | Records the encoding name in the file header comment (default: `utf-8`) |

---

### 3. Edit the text

Open a `.ke` file in any UTF-8 editor. Text strings are on lines beginning with a
single-quoted string:

```
  'ここには日本語のテキストが入っています。'
  '【カナコ】「こんにちは！」'
```

Replace those strings with your translation:

```
  'Here is where the Japanese text goes.'
  '【Kanako】「Hello!」'
```

**Rules:**
- Strings use **single quotes** `'...'`.  Escape a literal single quote as `\'`.
- Each string is one line of dialogue or narration — keep line breaks where the game
  expects them (the game engine wraps text automatically; do not add extra newlines
  unless the original had them).
- Do **not** modify the instruction names, variable names, label numbers (`@12`), or
  anything outside of quoted strings.

#### Character names (`.utf` file)

Character names used by the speaker-name overlay are in the companion `.utf` file:

```
// Resources for SEEN0009.TXT

#character 'カナコ'
#character '主人公'
```

Replace the names with your translations.  If you used `--single-file` during
disassembly these lines will be at the top of the `.ke` file instead.

---

### 4. Assemble back to bytecode

Convert the edited `.ke` files back to binary:

```bash
python -m kprl assemble ke/SEEN0005.TXT.ke -o out/
python -m kprl assemble ke/*.ke -o out/
```

This produces `SEENxxxx.TXT.uncompressed` files in `out/`.

#### Options

| Option | Effect |
|---|---|
| `--compress` | Apply LZ77 compression to the output (smaller files, same as original compressed files) |

> Most original RealLive archives store compressed data.  If you want the rebuilt
> archive to be the same size as the original, use `--compress`.

---

### 5. Add the new files back into the archive

```bash
python -m kprl add SEEN.TXT out/SEEN0005.TXT.uncompressed
```

To replace multiple files at once:

```bash
python -m kprl add SEEN.TXT out/SEEN*.TXT.uncompressed
```

The `add` command replaces any existing entry for that slot number.  The archive is
updated in-place.

---

## All CLI commands at a glance

### `break` — extract sub-files from archive

```
python -m kprl break SEEN.TXT [-o DIR]
```

Extracts every entry into separate `SEENxxxx.TXT` files.

---

### `add` — insert/replace files in archive

```
python -m kprl add SEEN.TXT FILE [FILE ...] [-o DIR]
```

Adds or replaces sub-files.  The slot number is taken from the filename (`SEEN0005` →
slot 5).

---

### `remove` — delete sub-files from archive

```
python -m kprl remove SEEN.TXT SLOT [SLOT ...] [-o DIR]
```

Removes entries by their four-digit slot number.

---

### `list` — show archive contents

```
python -m kprl list SEEN.TXT
```

Prints slot numbers, byte offsets, sizes, and whether each entry is compressed.

---

### `disassemble` — binary → human-readable assembly

```
python -m kprl disassemble FILE [FILE ...] [-o DIR]
                           [--annotate] [--single-file] [--encoding ENC]
```

Accepts individual `.TXT` / `.TXT.uncompressed` files, or a full `SEEN.TXT` archive.

---

### `assemble` — human-readable assembly → binary

```
python -m kprl assemble FILE.ke [FILE.ke ...] [-o DIR] [--compress]
```

Accepts one or more `.ke` files.  Use `--compress` if you need the output to be
LZ77-compressed (same as the original compressed files).

---

### `extract` — decompress individual bytecode files

```
python -m kprl extract FILE [FILE ...] [-o DIR]
```

Decompresses a `KPRL`-compressed `.TXT` file to its raw uncompressed form without
disassembling it.  Useful for inspecting the raw bytecode.

---

### `pack` — compress individual bytecode files

```
python -m kprl pack FILE [FILE ...] [-o DIR]
```

Compresses an uncompressed `.TXT.uncompressed` file with LZ77 (`KPRL` header).

---

## Full example: translate a single scene

```bash
# 1. Extract all scripts
python -m kprl break SEEN.TXT -o seenfiles/

# 2. Disassemble the scene you want to translate
python -m kprl disassemble seenfiles/SEEN0009.TXT -o ke/

# 3. Edit ke/SEEN0009.TXT.ke in your text editor (translate the quoted strings)
#    Edit ke/SEEN0009.TXT.utf for character names

# 4. Assemble back to bytecode
python -m kprl assemble ke/SEEN0009.TXT.ke -o out/ --compress

# 5. Inject back into the archive
python -m kprl add SEEN.TXT out/SEEN0009.TXT.uncompressed
```

Run the game — your translated scene should appear.

---

## Tips for translators

- **Work on one file at a time** and test in-game before moving on.
- **Keep the original files** — `break` produces the originals; never overwrite them.
- A `.ke` file is plain UTF-8 text.  You can use any diff/version-control tool (git,
  etc.) to track your translation progress.
- Lines beginning with `#` are directives (file name, entrypoints).  Do not edit them.
- Lines beginning with `@` followed by a number are jump labels.  Do not edit them.
- Lines beginning with `{-` are comments.  They are ignored by the assembler.
- If the assembler reports an error, check that all your edited strings still use
  single quotes and that you haven't accidentally deleted a closing `'`.

---

## Image conversion (vaconv / rlxml)

The `kprl` tool can also convert RealLive image files to and from PNG, and convert
GAN animation files to and from XML.

### Supported image formats

| Extension | Format | Description |
|-----------|--------|-------------|
| `.g00`    | G00    | Main RealLive image format (RGB, paletted, or RGBA+regions) |
| `.pdt`    | PDT    | AVG32 image format (PDT10 / PDT11) |
| `.rct`    | RCT    | Majiro true-colour image |
| `.rc8`    | RC8    | Majiro 8-bit paletted image |

### Convert images to PNG

```bash
# Single file
python -m kprl img2png logo.g00

# Multiple files
python -m kprl img2png *.g00 *.pdt

# Custom output directory
python -m kprl img2png -o png_output/ *.g00
```

Each input file produces a `.png` with the same stem in the output directory.

### Convert PNG back to an image format

```bash
# Convert to G00
python -m kprl png2img --format g00 logo.png

# Convert to PDT
python -m kprl png2img --format pdt logo.png

# Convert to RCT or RC8
python -m kprl png2img --format rct logo.png
python -m kprl png2img --format rc8 logo.png

# Custom output directory
python -m kprl png2img --format g00 -o g00_output/ *.png
```

**Notes:**
- G00 format is auto-detected: paletted images use format 1, opaque true-colour
  images use format 0, and images with transparency use format 2.
- RC8 will quantise the image to 256 colours if it has more.
- PDT encoding always produces PDT10 (uncompressed). PDT11 (palette-compressed)
  decoding is supported but encoding is not.

### GAN animation files (rlxml)

GAN files describe sprite animation sequences. They can be converted to/from XML
for inspection or editing.

```bash
# GAN → XML
python -m kprl ganxml sprite.gan
# Produces sprite.ganxml

# XML → GAN
python -m kprl ganxml sprite.ganxml
# Produces sprite.gan

# Custom output directory
python -m kprl ganxml -o out/ *.gan
```

The XML format (`<vas_gan>`) mirrors the original rlxml tool's output:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<vas_gan bitmap="SPRITE.G00">
  <set pattern="0" x="0" y="0" time="33" alpha="255" other="0">
    <frame />
    <frame x="10" />
    <frame x="20" />
  </set>
</vas_gan>
```

- The `bitmap` attribute names the G00 file used for this animation.
- Each `<set>` holds default attribute values for all its frames.
- Individual `<frame>` elements only list attributes that differ from the set defaults.
