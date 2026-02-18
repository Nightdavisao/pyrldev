"""
assemble.py - RealLive bytecode assembler.

Reads a Kepago assembly file (.ke) produced by disasm.py and reassembles it
into binary bytecode (.TXT / .TXT.uncompressed).

Entry point: ``assemble_file(ke_path, outdir='.', compress=False, options=None)``
"""

from __future__ import annotations

import re
import struct
import sys
from pathlib import Path
from typing import Optional

from .kfn import load_kfn, find_kfn_path
from .disasm import IVAR, SVAR


# ---------------------------------------------------------------------------
# Constant tables
# ---------------------------------------------------------------------------

# Reverse variable-name → byte lookups
_IVAR_REV: dict[str, int] = {v: k for k, v in IVAR.items()}
_SVAR_REV: dict[str, int] = {v: k for k, v in SVAR.items()}
_VAR_REV: dict[str, int] = {**_IVAR_REV, **_SVAR_REV}

# Binary operator text → byte (after \x5c)
_BINOP_BYTES: dict[str, int] = {
    '+':  0x00, '-':  0x01, '*':  0x02, '/':  0x03, '%':  0x04,
    '&':  0x05, '|':  0x06, '^':  0x07, '<<': 0x08, '>>': 0x09,
    '==': 0x28, '!=': 0x29, '<=': 0x2a, '<':  0x2b, '>=': 0x2c, '>':  0x2d,
    '&&': 0x3c, '||': 0x3d,
}

# Assignment operator text → byte (after \x5c)
_ASSIGN_OP_BYTES: dict[str, int] = {
    '+=': 0x14, '-=': 0x15, '*=': 0x16, '/=': 0x17, '%=': 0x18,
    '&=': 0x19, '|=': 0x1a, '^=': 0x1b, '<<=': 0x1c, '>>=': 0x1d, '=': 0x1e,
}

# Operator display-precedence (mirrors disasm._prec, used by Pratt parser)
_OP_PREC: dict[str, int] = {
    '||': 0, '&&': 1,
    '==': 2, '!=': 2,
    '<=': 3, '<':  3, '>=': 3, '>': 3,
    '+':  4, '-':  4, '|':  4, '^':  4,
    '*':  5, '/':  5, '%':  5, '&':  5,
    '<<': 6, '>>': 6,
}

# Hardcoded jump/gosub function info: name → (type, module, func, overload, has_cond)
_GOTO_FUNCS: dict[str, tuple] = {
    'goto':         (0, 1,  0, 0, False),
    'goto_if':      (0, 1,  1, 0, True),
    'goto_unless':  (0, 1,  2, 0, True),
    'gosub':        (0, 1,  5, 0, False),
    'gosub_if':     (0, 1,  6, 0, True),
    'gosub_unless': (0, 1,  7, 0, True),
    'ret':          (0, 1, 10, 0, False),
    'return':       (0, 1, 10, 0, False),
}

# Select function name → opcode function number (module 2)
_SELECT_FUNCS: dict[str, int] = {
    'select_w': 0, 'select': 1, 'select_s2': 2, 'select_s': 3, 'select_w2': 10,
}

# The SeeNEnd marker bytes
_SEEN_END_SJS = bytes.fromhex('827282858285828e8264828e8284')
_SEEN_END = _SEEN_END_SJS + b'\xff' * 44   # 58 bytes total


# ---------------------------------------------------------------------------
# Expression scanner / Pratt parser
# ---------------------------------------------------------------------------

class _ExprScan:
    """Character-level scanner for a single expression string."""

    def __init__(self, text: str, pos: int = 0, end: int = -1) -> None:
        self.text = text
        self.pos = pos
        self.end = len(text) if end < 0 else end

    def eof(self) -> bool:
        self._skip_ws()
        return self.pos >= self.end

    def peek(self) -> str:
        self._skip_ws()
        return self.text[self.pos] if self.pos < self.end else ''

    def advance(self) -> str:
        ch = self.text[self.pos]
        self.pos += 1
        return ch

    def expect(self, ch: str) -> None:
        self._skip_ws()
        if self.pos >= self.end or self.text[self.pos] != ch:
            got = self.text[self.pos] if self.pos < self.end else 'EOF'
            raise ValueError(f"expected {ch!r}, got {got!r} at pos {self.pos}")
        self.pos += 1

    def _skip_ws(self) -> None:
        while self.pos < self.end and self.text[self.pos] in ' \t\r\n':
            self.pos += 1

    def try_match(self, s: str) -> bool:
        """Try to match literal s; advance and return True if matched."""
        self._skip_ws()
        if self.text[self.pos: self.pos + len(s)] == s:
            # Make sure it's not a prefix of a longer token
            end = self.pos + len(s)
            if s[-1].isalpha() or s[-1] == '_':
                if end < self.end and (self.text[end].isalnum() or self.text[end] == '_'):
                    return False
            self.pos = end
            return True
        return False

    def read_positive_int(self) -> int:
        """Read one or more decimal digits as a non-negative integer."""
        self._skip_ws()
        start = self.pos
        while self.pos < self.end and self.text[self.pos].isdigit():
            self.pos += 1
        if self.pos == start:
            raise ValueError(f"expected integer at pos {self.pos}")
        return int(self.text[start: self.pos])

    def read_ident(self) -> str:
        """Read an identifier (letters, digits, underscores)."""
        self._skip_ws()
        start = self.pos
        if self.pos < self.end and (self.text[self.pos].isalpha() or self.text[self.pos] == '_'):
            self.pos += 1
            while self.pos < self.end and (self.text[self.pos].isalnum() or self.text[self.pos] == '_'):
                self.pos += 1
        if self.pos == start:
            raise ValueError(f"expected identifier at pos {self.pos}")
        return self.text[start: self.pos]

    def peek_binop(self) -> Optional[str]:
        """Return the next binary operator string (without consuming), or None."""
        self._skip_ws()
        if self.pos >= self.end:
            return None
        # Try multi-char operators first
        for op in ('||', '&&', '==', '!=', '<=', '>=', '<<', '>>'):
            if self.text[self.pos: self.pos + len(op)] == op:
                return op
        ch = self.text[self.pos]
        if ch in ('+', '-', '*', '/', '%', '&', '|', '^', '<', '>'):
            return ch
        return None

    def consume_binop(self, op: str) -> None:
        self._skip_ws()
        self.pos += len(op)


def _compile_expr(scan: _ExprScan) -> bytes:
    """Parse and compile a complete expression from *scan*."""
    return _pratt_parse(scan, 0)


def _pratt_parse(scan: _ExprScan, min_prec: int) -> bytes:
    """Pratt parser: parse expression with minimum precedence *min_prec*."""
    lhs = _parse_unary(scan)
    while True:
        op = scan.peek_binop()
        if op is None:
            break
        prec = _OP_PREC.get(op)
        if prec is None or prec < min_prec:
            break
        scan.consume_binop(op)
        # Left-associative: right side has prec+1
        rhs = _pratt_parse(scan, prec + 1)
        lhs = lhs + bytes([0x5c, _BINOP_BYTES[op]]) + rhs
    return lhs


def _parse_unary(scan: _ExprScan) -> bytes:
    """Parse a unary expression or primary."""
    scan._skip_ws()
    ch = scan.peek()

    if ch == '-':
        scan.advance()
        scan._skip_ws()
        # Negative integer literal
        if scan.pos < scan.end and scan.text[scan.pos].isdigit():
            n = scan.read_positive_int()
            return bytes([0x24, 0xff]) + struct.pack('<i', -n)
        # Unary negation of next atom
        inner = _parse_unary(scan)
        return bytes([0x5c, 0x01]) + inner

    if ch == '~':
        # Bitwise NOT: expand to (inner ^ -1)
        scan.advance()
        inner = _parse_unary(scan)
        neg1 = bytes([0x24, 0xff]) + struct.pack('<i', -1)
        return inner + bytes([0x5c, 0x07]) + neg1

    if ch == '!':
        # Logical NOT: expand to (inner == 0)
        scan.advance()
        inner = _parse_unary(scan)
        zero = bytes([0x24, 0xff]) + struct.pack('<i', 0)
        return inner + bytes([0x5c, 0x28]) + zero

    return _parse_primary(scan)


def _parse_primary(scan: _ExprScan) -> bytes:
    """Parse a primary expression (literal, variable, grouped expr)."""
    scan._skip_ws()
    ch = scan.peek()

    if ch == '(':
        # Parenthesised sub-expression → \x28 inner \x29
        scan.advance()
        inner = _compile_expr(scan)
        scan.expect(')')
        return bytes([0x28]) + inner + bytes([0x29])

    if ch and ch.isdigit():
        n = scan.read_positive_int()
        return bytes([0x24, 0xff]) + struct.pack('<i', n)

    if ch and (ch.isalpha() or ch == '_'):
        name = scan.read_ident()

        if name == 'store':
            return bytes([0x24, 0xc8])

        if name in _VAR_REV:
            var_byte = _VAR_REV[name]
            scan.expect('[')
            idx_bytes = _compile_expr(scan)
            scan.expect(']')
            return bytes([0x24, var_byte, 0x5b]) + idx_bytes + bytes([0x5d])

        raise ValueError(f"unknown identifier in expression: {name!r}")

    raise ValueError(f"unexpected character in expression: {ch!r} at pos {scan.pos}")


def compile_expr_text(text: str) -> bytes:
    """Compile a text expression string to bytecode bytes."""
    scan = _ExprScan(text.strip())
    result = _compile_expr(scan)
    if not scan.eof():
        pass  # trailing content — caller handles
    return result


# ---------------------------------------------------------------------------
# Ke text scanner
# ---------------------------------------------------------------------------

class _KEScan:
    """Scanner for Kepago assembly (.ke) text."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0

    def eof(self) -> bool:
        self._skip()
        return self.pos >= len(self.text)

    def peek(self) -> str:
        self._skip()
        return self.text[self.pos] if self.pos < len(self.text) else ''

    def advance(self) -> str:
        ch = self.text[self.pos]
        self.pos += 1
        return ch

    def _skip(self) -> None:
        """Skip whitespace and comments."""
        while self.pos < len(self.text):
            c = self.text[self.pos]
            if c in ' \t\r\n':
                self.pos += 1
            elif self.text[self.pos: self.pos + 2] == '{-':
                end = self.text.find('-}', self.pos + 2)
                self.pos = (end + 2) if end >= 0 else len(self.text)
            elif self.text[self.pos: self.pos + 2] == '//':
                end = self.text.find('\n', self.pos + 2)
                self.pos = (end + 1) if end >= 0 else len(self.text)
            else:
                break

    def read_ident(self) -> str:
        self._skip()
        start = self.pos
        while self.pos < len(self.text) and (
            self.text[self.pos].isalnum() or self.text[self.pos] in ('_', '?')
        ):
            self.pos += 1
        return self.text[start: self.pos]

    def read_int(self) -> int:
        self._skip()
        start = self.pos
        if self.pos < len(self.text) and self.text[self.pos] in '+-':
            self.pos += 1
        while self.pos < len(self.text) and self.text[self.pos].isdigit():
            self.pos += 1
        return int(self.text[start: self.pos])

    def read_positive_int(self) -> int:
        self._skip()
        start = self.pos
        while self.pos < len(self.text) and self.text[self.pos].isdigit():
            self.pos += 1
        return int(self.text[start: self.pos])

    def read_quoted_string(self) -> str:
        """Read a single-quoted string, handling backslash escapes."""
        self._skip()
        if self.pos >= len(self.text) or self.text[self.pos] != "'":
            raise ValueError(f"expected single quote at pos {self.pos}")
        self.pos += 1
        parts = []
        while self.pos < len(self.text) and self.text[self.pos] != "'":
            c = self.text[self.pos]
            if c == '\\' and self.pos + 1 < len(self.text):
                self.pos += 1
                nc = self.text[self.pos]
                if nc in ("'", '\\', '/', '<', '-'):
                    parts.append(nc)
                else:
                    parts.append('\\')
                    parts.append(nc)
                self.pos += 1
            else:
                parts.append(c)
                self.pos += 1
        if self.pos < len(self.text):
            self.pos += 1  # closing quote
        return ''.join(parts)

    def try_match(self, s: str) -> bool:
        """Try to match literal s; return True and advance if matched."""
        self._skip()
        if self.text[self.pos: self.pos + len(s)] == s:
            after = self.pos + len(s)
            # Ensure not a prefix of a longer identifier
            if s[-1:].isalpha() or s[-1:] == '_':
                if after < len(self.text) and (
                    self.text[after].isalnum() or self.text[after] == '_'
                ):
                    return False
            self.pos = after
            return True
        return False

    def expect(self, ch: str) -> None:
        self._skip()
        if self.pos >= len(self.text) or self.text[self.pos] != ch:
            got = self.text[self.pos] if self.pos < len(self.text) else 'EOF'
            raise ValueError(f"expected {ch!r}, got {got!r} at pos {self.pos}")
        self.pos += 1

    def read_to_eol(self) -> str:
        """Read raw text to end of current line."""
        start = self.pos
        while self.pos < len(self.text) and self.text[self.pos] != '\n':
            self.pos += 1
        return self.text[start: self.pos].strip()

    def scan_arg_text(self) -> str:
        """Scan one argument text (up to depth-0 comma or close-paren/brace).

        Does NOT consume the trailing comma, ), or }.
        """
        start = self.pos
        depth_paren = 0
        depth_bracket = 0
        depth_brace = 0
        in_sq = False

        while self.pos < len(self.text):
            c = self.text[self.pos]
            if in_sq:
                if c == '\\' and self.pos + 1 < len(self.text):
                    self.pos += 2
                    continue
                if c == "'":
                    in_sq = False
            elif c == "'":
                in_sq = True
            elif c == '(':
                depth_paren += 1
            elif c == ')':
                if depth_paren == 0 and depth_bracket == 0 and depth_brace == 0:
                    break
                depth_paren -= 1
            elif c == '[':
                depth_bracket += 1
            elif c == ']':
                depth_bracket -= 1
            elif c == '{':
                depth_brace += 1
            elif c == '}':
                if depth_brace == 0:
                    break
                depth_brace -= 1
            elif c == ',' and depth_paren == 0 and depth_bracket == 0 and depth_brace == 0:
                break
            self.pos += 1

        return self.text[start: self.pos].strip()


# ---------------------------------------------------------------------------
# Argument compilation helpers
# ---------------------------------------------------------------------------

def _compile_string_arg(text: str) -> bytes:
    """Compile a string argument (single-quoted) to CP932 bytes."""
    # Parse the quoted string
    if text.startswith("'") and text.endswith("'") and len(text) >= 2:
        inner = text[1:-1]
        # Un-escape backslash sequences
        result = []
        i = 0
        while i < len(inner):
            c = inner[i]
            if c == '\\' and i + 1 < len(inner):
                i += 1
                nc = inner[i]
                if nc in ("'", '\\', '/', '<', '-'):
                    result.append(nc)
                else:
                    result.append('\\')
                    result.append(nc)
            else:
                result.append(c)
            i += 1
        text = ''.join(result)
    return text.encode('cp932', errors='replace')


def _looks_like_string_arg(text: str) -> bool:
    """Return True if the argument text is a string literal."""
    t = text.strip()
    return t.startswith("'")


def _looks_like_complex_arg(text: str) -> bool:
    """Return True if the argument text is a complex (brace-enclosed) arg."""
    t = text.strip()
    return t.startswith('{') and t.endswith('}')


def _looks_like_special_named(text: str) -> bool:
    """Return True if the argument text looks like a named special: ident(...)."""
    t = text.strip()
    m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*\(', t)
    if m:
        name = m.group(1)
        # Must not be a known expression keyword
        if name not in _VAR_REV and name != 'store':
            return True
    return False


def _compile_arg_text(arg_text: str, ptype: str,
                       prototype_params, fndefs: dict,
                       special_map: dict) -> bytes:
    """Compile one argument based on its text representation.

    *ptype* is the KFN parameter type hint ('str', 'strC', 'int', 'intC', etc.)
    or 'unknown' if no prototype is available.
    *special_map* maps special-function names to (id, sub_param_types) from the
    parent function's special_defs.
    """
    t = arg_text.strip()

    # String argument
    if ptype in ('str', 'strC', 'strV', 'res') or (
        ptype == 'unknown' and _looks_like_string_arg(t)
    ):
        if t.startswith("'"):
            return _compile_string_arg(t)
        # Bare string without quotes — treat as raw text
        return t.encode('cp932', errors='replace')

    # Complex argument {a, b, ...} → \x28 ... \x29
    if ptype == 'complex' or _looks_like_complex_arg(t):
        inner = t[1:-1].strip() if (t.startswith('{') and t.endswith('}')) else t
        # Compile each sub-argument
        sub_args = _split_args_text(inner)
        out = bytearray([0x28])
        for sub in sub_args:
            sub_t = sub.strip()
            if _looks_like_string_arg(sub_t):
                out.extend(_compile_string_arg(sub_t))
            else:
                out.extend(compile_expr_text(sub_t))
        out.append(0x29)
        return bytes(out)

    # Special named argument funcname(...) → \x61 id \x28 ... \x29
    if ptype == 'special' or (ptype == 'unknown' and _looks_like_special_named(t)):
        # Handle __special[sid](args) fallback format
        m_special = re.match(r'^__special\[(\d+)\]\((.*)\)\s*$', t, re.DOTALL)
        if m_special:
            sid = int(m_special.group(1))
            inner_text = m_special.group(2)
            sub_args = _split_args_text(inner_text)
            out = bytearray([0x61, sid, 0x28])
            for sub in sub_args:
                sub_t = sub.strip()
                if sub_t.startswith("'"):
                    out.extend(_compile_string_arg(sub_t))
                else:
                    out.extend(compile_expr_text(sub_t))
            out.append(0x29)
            return bytes(out)

        m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)\s*$', t, re.DOTALL)
        if m:
            fname = m.group(1)
            inner_text = m.group(2)
            if fname in special_map:
                sid, sub_types = special_map[fname]
                sub_args = _split_args_text(inner_text)
                out = bytearray([0x61, sid, 0x28])
                for i, sub in enumerate(sub_args):
                    sub_t = sub.strip()
                    stype = sub_types[i] if i < len(sub_types) else 'unknown'
                    out.extend(_compile_arg_text(sub_t, stype, None, fndefs, {}))
                out.append(0x29)
                return bytes(out)

    # Default: integer expression
    if _looks_like_string_arg(t):
        # Fallback: string arg without prototype saying so
        return _compile_string_arg(t)

    return compile_expr_text(t)


def _looks_like_special_named_at(scan: '_KEScan') -> bool:
    """Return True if the scanner is positioned at a special named param (ident not in VAR_REV)."""
    pos = scan.pos
    text = scan.text
    if pos >= len(text) or not (text[pos].isalpha() or text[pos] == '_'):
        return False
    end = pos
    while end < len(text) and (text[end].isalnum() or text[end] == '_'):
        end += 1
    name = text[pos:end]
    if name in _VAR_REV or name == 'store':
        return False
    # Skip whitespace and check for '('
    e2 = end
    while e2 < len(text) and text[e2] in ' \t':
        e2 += 1
    return e2 < len(text) and text[e2] == '('


def _split_args_text(text: str) -> list[str]:
    args: list[str] = []
    depth = 0
    in_sq = False
    start = 0
    i = 0
    while i < len(text):
        c = text[i]
        if in_sq:
            if c == '\\' and i + 1 < len(text):
                i += 2
                continue
            if c == "'":
                in_sq = False
        elif c == "'":
            in_sq = True
        elif c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        elif c == ',' and depth == 0:
            arg = text[start:i].strip()
            if arg:
                args.append(arg)
            start = i + 1
        i += 1
    last = text[start:].strip()
    if last:
        args.append(last)
    return args


# ---------------------------------------------------------------------------
# Core assembler class
# ---------------------------------------------------------------------------

class _Assembler:
    """Two-pass assembler for a single .ke file."""

    def __init__(self, text: str, ke_path: Path,
                 fndefs: dict, module_names: dict) -> None:
        self.text = text
        self.ke_path = ke_path
        self.fndefs = fndefs
        self.module_names = module_names

        # Build reverse lookup: function name → list of (type, mod, func, overload)
        self._rev: dict[str, list] = {}
        for key, fd in fndefs.items():
            name = fd.ident
            if name:
                self._rev.setdefault(name, []).append(key)

        # Bytecode output
        self.bytecode = bytearray()

        # Label table: label_number → bytecode offset
        self.labels: dict[int, int] = {}

        # Pending label references: list of (bytecode_pos, label_number)
        self.pending: list[tuple[int, int]] = []

        # Kidoku state
        self.kidoku_table: list[int] = []
        self.kidoku_idx: int = 0

        # Entrypoint table (100 slots)
        self.entrypoints: list[int] = [0] * 100
        self.ep_defined: list[bool] = [False] * 100

        # Dramatis personae
        self.dramatis_personae: list[str] = []

        # Options
        self.compiler_version: int = 10002
        self.kidoku_char: int = 0x40  # '@' by default

        # Resource dictionary (for #res<NNNN> expansion)
        self.resources: dict[int, str] = {}

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    def _emit(self, b: bytes) -> None:
        self.bytecode.extend(b)

    def _emit_byte(self, b: int) -> None:
        self.bytecode.append(b)

    def _current_offset(self) -> int:
        return len(self.bytecode)

    def _emit_placeholder_label(self, label_num: int) -> None:
        """Emit 4 zero bytes as a placeholder for label *label_num*."""
        self.pending.append((self._current_offset(), label_num))
        self.bytecode.extend(b'\x00\x00\x00\x00')

    def _define_label(self, n: int) -> None:
        """Record that label @n is at the current bytecode offset.

        If a previous label was already defined at this exact offset, emit a
        ``\\x0a\\x00\\x00`` (line-number 0) marker first so the two labels sit
        at distinct offsets.  The disassembler suppresses line-number markers
        in its default output, so this is invisible after a round-trip while
        still keeping both labels addressable.
        """
        current = self._current_offset()
        # Check if any existing label is already at this offset
        for existing_offset in self.labels.values():
            if existing_offset == current:
                # Separate the two labels with a hidden line marker
                self._emit_line(0)
                break
        self.labels[n] = self._current_offset()

    def _resolve_labels(self) -> None:
        """Patch all label placeholders with resolved offsets."""
        for pos, lnum in self.pending:
            target = self.labels.get(lnum)
            if target is None:
                raise ValueError(f"undefined label @{lnum}")
            struct.pack_into('<i', self.bytecode, pos, target)

    # ------------------------------------------------------------------
    # Instruction emission
    # ------------------------------------------------------------------

    def _emit_halt(self) -> None:
        self._emit_byte(0x00)

    def _emit_eof(self) -> None:
        self._emit(_SEEN_END)

    def _emit_line(self, n: int) -> None:
        self.bytecode.append(0x0a)
        self.bytecode.extend(struct.pack('<h', n))

    def _emit_kidoku(self, idx: int) -> None:
        """Emit a kidoku/entrypoint marker byte sequence."""
        self.bytecode.append(self.kidoku_char)
        self.bytecode.extend(struct.pack('<H', idx))

    def _emit_textout(self, text: str) -> None:
        """Emit raw text output bytes (CP932)."""
        raw = text.encode('cp932', errors='replace')
        self.bytecode.extend(raw)

    def _emit_assignment(self, var_name: str, idx_bytes: bytes,
                          op_str: str, rhs_bytes: bytes) -> None:
        """Emit a variable assignment instruction from pre-compiled bytes."""
        var_byte = _VAR_REV.get(var_name)
        if var_byte is None:
            raise ValueError(f"unknown variable: {var_name!r}")
        op_byte = _ASSIGN_OP_BYTES.get(op_str)
        if op_byte is None:
            raise ValueError(f"unknown assignment operator: {op_str!r}")

        self._emit_byte(0x24)
        self._emit_byte(var_byte)
        self._emit_byte(0x5b)
        self._emit(idx_bytes)
        self._emit_byte(0x5d)
        self._emit_byte(0x5c)
        self._emit_byte(op_byte)
        self._emit(rhs_bytes)

    def _emit_function_header(self, op_type: int, op_module: int,
                               op_func: int, argc: int, op_overload: int) -> None:
        """Emit the 8-byte function call header."""
        self._emit_byte(0x23)
        self._emit_byte(op_type)
        self._emit_byte(op_module)
        self.bytecode.extend(struct.pack('<H', op_func))
        self.bytecode.extend(struct.pack('<H', argc))
        self._emit_byte(op_overload)

    def _build_special_map(self, prototype) -> dict[str, tuple[int, list]]:
        """Build a special-function-name → (id, [sub_types]) map from prototype."""
        smap: dict[str, tuple[int, list]] = {}
        if not prototype:
            return smap
        for param in prototype:
            if param.ptype == 'special':
                for sdef in param.special_defs:
                    sid, kind, name, sub_params, no_parens = sdef
                    if name and kind == 'named':
                        sub_types = [p.ptype for p in sub_params]
                        smap[name] = (sid, sub_types)
        return smap

    def _lookup_function(self, name: str, argc: int,
                          fixed_argc: int = -1) -> Optional[tuple]:
        """Look up a function by name and argument count.

        *argc* is the total arg count; *fixed_argc* is the number of
        non-special (regular) args (used to select the right overload for
        functions with ``special argc`` params).

        Returns ``(type, module, func, overload, fndef_or_None)`` or None.
        """
        if fixed_argc < 0:
            fixed_argc = argc
        # Check goto/gosub hardcoded table first
        if name in _GOTO_FUNCS:
            t, m, f, ov, has_cond = _GOTO_FUNCS[name]
            return (t, m, f, ov, None)

        # Select functions
        if name in _SELECT_FUNCS:
            fn = _SELECT_FUNCS[name]
            return (0, 2, fn, 0, None)

        # Select with index suffix (e.g. select_w[N])
        m = re.match(r'^([a-z_]+[a-z0-9_]*)\[', name)
        if m and m.group(1) in _SELECT_FUNCS:
            fn = _SELECT_FUNCS[m.group(1)]
            return (0, 2, fn, 0, None)

        # Parse op<type:mod:func, overload> fallback
        mo = re.match(r'^op<(\d+):([A-Za-z0-9]+):(\d+),\s*(\d+)>$', name)
        if mo:
            ot = int(mo.group(1))
            mod_name = mo.group(2)
            of = int(mo.group(3))
            ov = int(mo.group(4))
            # Find module number by name
            om = next((k for k, v in self.module_names.items() if v == mod_name), 0)
            return (ot, om, of, ov, None)

        # KFN lookup
        candidates = self._rev.get(name, [])
        if not candidates:
            return None

        # Group by (type, mod, func) to find the right set of overloads
        groups: dict[tuple, list] = {}
        for key in candidates:
            gkey = key[:3]
            groups.setdefault(gkey, []).append(key)

        # Pick the best group (usually only one; prefer lower type numbers)
        best_group = None
        for gkey, keys in sorted(groups.items()):
            best_group = keys
            break  # Use the first group

        if not best_group:
            return None

        # Find overload matching argc — prefer exact match, then best partial match
        best_key = None
        best_required = -1
        for key in sorted(best_group, key=lambda k: k[3]):
            fd = self.fndefs[key]
            proto = fd.prototypes[0] if fd.prototypes else None
            if proto is None:
                # No prototype — accept any argc
                if best_key is None:
                    best_key = key
                continue
            # Count non-fake, non-uncount, non-return params
            counted = [p for p in proto if not p.fake and not p.is_return]
            required = sum(1 for p in counted if not p.optional and not p.argc)
            has_argc_repeat = any(p.argc for p in counted)
            max_count = len(counted) if not has_argc_repeat else 9999

            # Use fixed_argc for matching when there are argc-repeat special params
            match_argc = fixed_argc if has_argc_repeat else argc

            if not has_argc_repeat:
                # Exact match preferred
                if required <= match_argc <= max_count:
                    if best_key is None or required > best_required:
                        best_key = key
                        best_required = required
            else:
                # argc-repeat: match if required <= fixed_argc, prefer largest required
                if match_argc >= required:
                    if best_key is None or required > best_required:
                        best_key = key
                        best_required = required

        if best_key is None:
            best_key = best_group[0]

        op_type, op_module, op_func, op_overload = best_key
        fndef = self.fndefs[best_key]
        return (op_type, op_module, op_func, op_overload, fndef)

    def _compile_fn_args(self, scan: _KEScan, prototype,
                          special_map: dict) -> tuple[bytes, int]:
        """Compile function arguments inside parens.

        Returns ``(arg_bytes, counted_argc)``.
        The counted_argc is the number of countable (non-fake, non-uncount) args.
        """
        scan._skip()
        if scan.peek() != '(':
            return b'', 0

        scan.advance()  # consume '('
        out = bytearray()
        arg_count = 0

        param_idx = 0
        first = True

        while True:
            scan._skip()
            if scan.eof() or scan.peek() == ')':
                break

            if not first:
                scan._skip()
                if scan.peek() == ',':
                    scan.advance()
                    scan._skip()
            first = False

            # Skip any fake params whose tags would appear in text
            ptype = 'unknown'
            is_uncount = False
            is_return = False
            is_argc_repeat = False
            if prototype and param_idx < len(prototype):
                while param_idx < len(prototype) and prototype[param_idx].fake:
                    # Fake param: it appears in text as tag but no binary output.
                    # Skip it in the text too.
                    fake_tag = prototype[param_idx].tag
                    if fake_tag:
                        scan._skip()
                        # Try to consume the fake tag if present
                        if scan.try_match(fake_tag):
                            scan._skip()
                            if scan.peek() == ',':
                                scan.advance()
                                scan._skip()
                    param_idx += 1

                if param_idx >= len(prototype):
                    break
                p = prototype[param_idx]
                ptype = p.ptype
                is_uncount = p.uncount
                is_return = p.is_return
                is_argc_repeat = p.argc

            scan._skip()
            if scan.eof() or scan.peek() == ')':
                break

            # Compile the argument based on type hint and syntax
            ch = scan.peek()

            if ptype in ('str', 'strC', 'strV', 'res') or (
                ptype == 'unknown' and ch == "'"
            ):
                # String arg: read quoted string directly
                s = scan.read_quoted_string()
                out.extend(s.encode('cp932', errors='replace'))

            elif ptype == 'complex' or (ptype == 'unknown' and ch == '{'):
                # Complex arg: {a, b, c} → \x28 compiled_sub_args \x29
                arg_text = scan.scan_arg_text()
                t = arg_text.strip()
                inner = t[1:-1] if (t.startswith('{') and t.endswith('}')) else t
                sub_args = _split_args_text(inner)
                out.append(0x28)
                for sub in sub_args:
                    sub_t = sub.strip()
                    if sub_t.startswith("'"):
                        out.extend(_compile_string_arg(sub_t))
                    else:
                        out.extend(compile_expr_text(sub_t))
                out.append(0x29)

            elif ptype == 'special' or (ptype == 'unknown' and
                                         ch and ch.isalpha() and
                                         _looks_like_special_named_at(scan)):
                # Special arg: funcname(...) → \x61 id \x28 args \x29
                arg_text = scan.scan_arg_text()
                compiled = _compile_arg_text(arg_text, 'special',
                                             prototype, self.fndefs, special_map)
                out.extend(compiled)

            else:
                # Expression arg: use ExprScan with shared position
                # But first check for __special[sid](...) fallback format
                if (scan.pos + 10 < len(scan.text) and
                        scan.text[scan.pos: scan.pos + 9] == '__special'):
                    arg_text = scan.scan_arg_text()
                    compiled = _compile_arg_text(arg_text, 'special',
                                                 prototype, self.fndefs, special_map)
                    out.extend(compiled)
                else:
                    expr_scan = _ExprScan(scan.text, pos=scan.pos)
                    expr_bytes = _compile_expr(expr_scan)
                    scan.pos = expr_scan.pos
                    out.extend(expr_bytes)

            if not is_uncount and not is_return:
                arg_count += 1

            if not is_argc_repeat:
                param_idx += 1

        scan._skip()
        if not scan.eof() and scan.peek() == ')':
            scan.advance()

        return bytes(out), arg_count

    def _emit_generic_function(self, scan: _KEScan, name: str,
                                store: bool = False) -> None:
        """Parse and emit a generic KFN function call."""
        scan._skip()
        has_parens = (scan.peek() == '(')

        # Pre-scan to count args (without consuming)
        total_argc = 0
        fixed_argc = 0
        if has_parens:
            save_pos = scan.pos
            total_argc, special_argc = self._count_args_at(scan)
            fixed_argc = total_argc - special_argc
            scan.pos = save_pos

        result = self._lookup_function(name, total_argc, fixed_argc)
        if result is None:
            # Unknown function: read args generically
            self._emit_unknown_function(scan, name, total_argc)
            return

        op_type, op_module, op_func, op_overload, fndef = result
        prototype = None
        special_map: dict = {}
        if fndef is not None:
            proto_idx = op_overload if op_overload < len(fndef.prototypes) else 0
            prototype = fndef.prototypes[proto_idx]
            special_map = self._build_special_map(prototype)
            is_goto = 'goto' in fndef.flags
        else:
            is_goto = name in _GOTO_FUNCS

        # Compile arguments
        if has_parens:
            arg_bytes, argc = self._compile_fn_args(scan, prototype, special_map)
        else:
            arg_bytes, argc = b'', 0

        # Determine argc for header
        header_argc = argc

        # Emit header
        self._emit_function_header(op_type, op_module, op_func, header_argc, op_overload)

        # Emit args in parens (if any)
        if arg_bytes:
            self._emit_byte(0x28)
            self._emit(arg_bytes)
            self._emit_byte(0x29)

        # Read label ref if goto-type
        if is_goto:
            scan._skip()
            if scan.peek() == '@':
                scan.advance()
                lnum = scan.read_positive_int()
                self._emit_placeholder_label(lnum)

    def _count_args_at(self, scan: _KEScan) -> tuple[int, int]:
        """Count args inside () at current position.

        Returns ``(total_argc, special_argc)`` where *special_argc* counts
        args that look like special params (funcname(...) or __special[...]).
        """
        if scan.peek() != '(':
            return 0, 0
        save = scan.pos
        scan.advance()  # consume '('

        depth = 0
        in_sq = False
        count = 0
        special_count = 0
        any_content = False
        arg_start = scan.pos
        is_special = False

        while not scan.eof():
            c = scan.text[scan.pos]
            if in_sq:
                if c == '\\' and scan.pos + 1 < len(scan.text):
                    scan.pos += 2
                    continue
                if c == "'":
                    in_sq = False
            elif c == "'":
                in_sq = True
            elif c in '([{':
                depth += 1
            elif c in ')]}':
                if depth == 0:
                    if any_content or count > 0:
                        count += 1
                        if is_special:
                            special_count += 1
                    break
                depth -= 1
            elif c == ',' and depth == 0:
                count += 1
                if is_special:
                    special_count += 1
                any_content = False
                is_special = False
                scan.pos += 1
                arg_start = scan.pos
                continue
            if c not in ' \t\r\n':
                if not any_content:
                    # Check if this arg starts like a special: ident(  or __special[
                    rest = scan.text[scan.pos:]
                    if (re.match(r'^__special\[', rest) or
                            (re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*\(', rest) and
                             not re.match(r'^(store|int[A-Za-z0-9]+|str[A-Za-z])\s*[\[(]', rest))):
                        is_special = True
                any_content = True
            scan.pos += 1

        scan.pos = save
        return count, special_count

    def _emit_unknown_function(self, scan: _KEScan, name: str,
                                argc: int) -> None:
        """Emit an unknown function call with raw arg compilation."""
        op_type, op_module, op_func, op_overload = 0, 0, 0, 0
        # Check op<...> format
        mo = re.match(r'^op<(\d+):([A-Za-z0-9]+):(\d+),\s*(\d+)>$', name)
        if mo:
            op_type = int(mo.group(1))
            mod_name = mo.group(2)
            op_func = int(mo.group(3))
            op_overload = int(mo.group(4))
            op_module = next(
                (k for k, v in self.module_names.items() if v == mod_name), 0
            )

        scan._skip()
        has_parens = (scan.peek() == '(')

        arg_bytes = b''
        if has_parens:
            arg_bytes, argc = self._compile_fn_args(scan, None, {})

        self._emit_function_header(op_type, op_module, op_func, argc, op_overload)
        if arg_bytes:
            self._emit_byte(0x28)
            self._emit(arg_bytes)
            self._emit_byte(0x29)

    # ------------------------------------------------------------------
    # Special instruction handlers
    # ------------------------------------------------------------------

    def _emit_goto_case_or_on(self, scan: _KEScan, name: str) -> None:
        """Emit goto_case / gosub_case / goto_on / gosub_on."""
        is_case = name in ('goto_case', 'gosub_case')
        is_gosub = name.startswith('gosub_')

        if is_case:
            op_func = 9 if is_gosub else 4
        else:
            op_func = 8 if is_gosub else 3

        op_type, op_module, op_overload = 0, 1, 0

        # Parse the selector expression using ExprScan (stops naturally at '{')
        scan._skip()
        expr_scan = _ExprScan(scan.text, pos=scan.pos)
        expr_bytes = _compile_expr(expr_scan)
        scan.pos = expr_scan.pos

        scan._skip()
        scan.expect('{')

        # Collect cases
        cases: list[tuple] = []   # (expr_bytes_or_None, label_num)

        while True:
            scan._skip()
            if scan.eof() or scan.peek() == '}':
                break
            if scan.peek() == ';':
                scan.advance()
                continue

            # Read case value: either "N:" or "_:" (scan until ':' at depth 0)
            cstart = scan.pos
            depth = 0
            while scan.pos < len(scan.text):
                c = scan.text[scan.pos]
                if c in '([{':
                    depth += 1
                elif c in ')]}':
                    depth -= 1
                elif c == ':' and depth == 0:
                    break
                scan.pos += 1
            case_text = scan.text[cstart: scan.pos].strip()
            scan.pos += 1  # consume ':'

            scan._skip()
            scan.expect('@')
            lnum = scan.read_positive_int()

            if case_text == '_':
                case_expr = None  # default case → empty parens
            else:
                case_expr = compile_expr_text(case_text)

            cases.append((case_expr, lnum))

        scan._skip()
        if not scan.eof() and scan.peek() == '}':
            scan.advance()

        argc = len(cases)

        # Emit header
        self._emit_function_header(op_type, op_module, op_func, argc, op_overload)

        if is_case:
            # Emit expr then { (expr) label ... }
            self._emit(expr_bytes)
            self._emit_byte(0x7b)
            for (ce, lnum) in cases:
                if ce is None:
                    # Default: ()
                    self._emit_byte(0x28)
                    self._emit_byte(0x29)
                else:
                    self._emit_byte(0x28)
                    self._emit(ce)
                    self._emit_byte(0x29)
                self._emit_placeholder_label(lnum)
            self._emit_byte(0x7d)
        else:
            # goto_on: expr { labels... }
            self._emit(expr_bytes)
            self._emit_byte(0x7b)
            for (_, lnum) in cases:
                self._emit_placeholder_label(lnum)
            self._emit_byte(0x7d)

    def _emit_select(self, scan: _KEScan, name: str) -> None:
        """Emit a select_w / select / select_s / etc. instruction."""
        # Extract bare name without index suffix
        base_name = re.sub(r'\[.*$', '', name)
        fn_idx = _SELECT_FUNCS.get(base_name, 1)

        # Optional selector index [expr]
        selector_bytes = b''
        m = re.match(r'\[(.+)\]$', name[len(base_name):])
        if m:
            selector_bytes = compile_expr_text(m.group(1))

        scan._skip()
        scan.expect('(')

        # Collect cases
        items: list[bytes] = []

        while True:
            scan._skip()
            if scan.eof() or scan.peek() == ')':
                break
            if scan.peek() == ',':
                scan.advance()
                continue

            # Check for condition prefix "cond: 'text'" — simplified handling
            arg_text = scan.scan_arg_text()
            if not arg_text:
                break

            # Basic: just text items
            t = arg_text.strip()
            if _looks_like_string_arg(t):
                items.append(_compile_string_arg(t))
            else:
                items.append(compile_expr_text(t))

        scan._skip()
        if not scan.eof() and scan.peek() == ')':
            scan.advance()

        argc = len(items)
        self._emit_function_header(0, 2, fn_idx, argc, 0)

        if selector_bytes:
            self._emit_byte(0x28)
            self._emit(selector_bytes)
            self._emit_byte(0x29)

        self._emit_byte(0x7b)
        for item in items:
            self._emit(item)
        self._emit_byte(0x7d)

    # ------------------------------------------------------------------
    # Main parse/emit loop
    # ------------------------------------------------------------------

    def _parse_and_emit(self) -> None:
        """Parse the entire .ke text and emit bytecode."""
        scan = _KEScan(self.text)

        while not scan.eof():
            ch = scan.peek()

            # Label definition
            if ch == '@':
                scan.advance()
                n = scan.read_positive_int()
                self._define_label(n)
                continue

            # Directive
            if ch == '#':
                scan.advance()
                name = scan.read_ident()
                self._handle_directive(scan, name)
                continue

            # Text output (single-quoted string)
            if ch == "'":
                text = scan.read_quoted_string()
                self._emit_textout(text)
                continue

            # Keyword / function / assignment
            if ch and (ch.isalpha() or ch == '_'):
                name = scan.read_ident()

                if name == 'halt':
                    self._emit_halt()
                    continue

                if name == 'eof':
                    self._emit_eof()
                    continue

                # store = funcname(args)
                scan._skip()
                if name == 'store' and scan.peek() == '=':
                    scan.advance()   # consume '='
                    scan._skip()
                    fn_name = scan.read_ident()
                    self._emit_generic_function(scan, fn_name, store=True)
                    continue

                # Check for goto_case / goto_on / gosub_case / gosub_on
                if name in ('goto_case', 'gosub_case', 'goto_on', 'gosub_on'):
                    self._emit_goto_case_or_on(scan, name)
                    continue

                # Check for select
                base = re.sub(r'\[.*', '', name)
                if base in _SELECT_FUNCS:
                    self._emit_select(scan, name)
                    continue

                # Check for assignment: name[idx] op rhs
                if name in _VAR_REV and scan.peek() == '[':
                    self._parse_assignment(scan, name)
                    continue

                # Generic function call
                # Handle op<type:mod:func, overload> format
                if name == 'op' and scan.peek() == '<':
                    # Read the full op<...> token
                    start = scan.pos  # points at '<'
                    depth = 1
                    scan.advance()  # consume '<'
                    end = scan.pos
                    while scan.pos < len(scan.text) and depth > 0:
                        c = scan.text[scan.pos]
                        if c == '<':
                            depth += 1
                        elif c == '>':
                            depth -= 1
                        scan.pos += 1
                        if depth == 0:
                            end = scan.pos  # capture end right after '>'
                    name = 'op' + scan.text[start: end]  # includes '<' and '>'

                self._emit_generic_function(scan, name)
                continue

            # Unknown character — skip
            if not scan.eof():
                scan.advance()

    def _handle_directive(self, scan: _KEScan, name: str) -> None:
        """Handle a #directive."""
        if name == 'entrypoint':
            n = scan.read_positive_int()
            offset = self._current_offset()
            self._emit_kidoku(self.kidoku_idx)
            self.entrypoints[n] = offset
            self.ep_defined[n] = True
            # Pad kidoku table to current index (with 0s for missing entries)
            while len(self.kidoku_table) < self.kidoku_idx:
                self.kidoku_table.append(0)
            self.kidoku_table.append(n + 1_000_000)
            self.kidoku_idx += 1

        elif name == 'line':
            n = scan.read_int()
            self._emit_line(n)

        elif name == 'character':
            if scan.peek() == "'":
                char_name = scan.read_quoted_string()
                self.dramatis_personae.append(char_name)

        elif name == 'target':
            scan._skip()
            tgt = scan.read_ident()
            # We only support RealLive format (no action needed)

        elif name == 'kidoku_type':
            n = scan.read_int()
            self.kidoku_char = 0x21 if n == 2 else 0x40

        elif name == 'file':
            if scan.peek() == "'":
                scan.read_quoted_string()  # informational, ignore

        elif name == 'resource':
            if scan.peek() == "'":
                res_name = scan.read_quoted_string()
                # Try to load resource file from same directory as ke_path
                res_path = self.ke_path.parent / res_name
                if res_path.exists():
                    self._load_resource(res_path)

        # All other directives ignored

    def _load_resource(self, path: Path) -> None:
        """Load a .utf resource file, populating self.resources and dramatis."""
        try:
            text = path.read_text(encoding='utf-8')
        except Exception:
            return
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            # #character 'name' directives
            m = re.match(r"#character\s+'(.*)'", line)
            if m:
                self.dramatis_personae.append(m.group(1))
                continue
            # <NNNN> text content
            m = re.match(r'<(\d{4})>\s*(.*)', line)
            if m:
                self.resources[int(m.group(1))] = m.group(2)

    def _parse_assignment(self, scan: _KEScan, var_name: str) -> None:
        """Parse and emit a variable assignment statement."""
        scan.expect('[')
        # Parse index expression using ExprScan with shared text position
        idx_scan = _ExprScan(scan.text, pos=scan.pos)
        idx_bytes = _compile_expr(idx_scan)
        scan.pos = idx_scan.pos
        scan.expect(']')
        scan._skip()

        # Determine assignment operator (could be multi-char)
        op_str = None
        for op in ('>>=', '<<=', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '='):
            if scan.try_match(op):
                op_str = op
                break

        if op_str is None:
            raise ValueError(f"expected assignment operator at pos {scan.pos}")

        # Parse RHS expression using ExprScan with shared text position
        scan._skip()
        rhs_scan = _ExprScan(scan.text, pos=scan.pos)
        rhs_bytes = _compile_expr(rhs_scan)
        scan.pos = rhs_scan.pos

        self._emit_assignment(var_name, idx_bytes, op_str, rhs_bytes)

    # ------------------------------------------------------------------
    # File header builder
    # ------------------------------------------------------------------

    def _build_file(self) -> bytes:
        """Build the complete binary file from bytecode and metadata."""
        bytecode = bytes(self.bytecode)

        # --- Dramatis personae table ---
        dramatis_data = bytearray()
        for name in self.dramatis_personae:
            raw = name.encode('shift-jis', errors='replace')
            dramatis_data.extend(struct.pack('<I', len(raw) + 1))
            dramatis_data.extend(raw)
            dramatis_data.append(0)   # null terminator
        dramatis_count = len(self.dramatis_personae)
        dramatis_size = len(dramatis_data)

        # --- Kidoku table ---
        kidoku_count = len(self.kidoku_table)
        kidoku_data = struct.pack(f'<{kidoku_count}i', *self.kidoku_table)

        # --- Header layout ---
        kidoku_offset = 0x1d0
        dramatis_offset = kidoku_offset + kidoku_count * 4
        bytecode_offset = dramatis_offset + dramatis_size

        # Entry points: fill unused slots with 0
        ep_table = list(self.entrypoints)

        # --- Build header (0x00..0x1cf) ---
        hdr = bytearray(bytecode_offset)

        # Magic + compiler version
        struct.pack_into('<I', hdr, 0x00, 0x1d0)          # uncompressed magic
        struct.pack_into('<I', hdr, 0x04, self.compiler_version)
        struct.pack_into('<I', hdr, 0x08, kidoku_offset)
        struct.pack_into('<I', hdr, 0x0c, kidoku_count)
        struct.pack_into('<I', hdr, 0x10, kidoku_count * 4)
        struct.pack_into('<I', hdr, 0x14, dramatis_offset)
        struct.pack_into('<I', hdr, 0x18, dramatis_count)
        struct.pack_into('<I', hdr, 0x1c, dramatis_size)
        struct.pack_into('<I', hdr, 0x20, bytecode_offset)
        struct.pack_into('<I', hdr, 0x24, len(bytecode))
        struct.pack_into('<I', hdr, 0x28, 0)   # compressed_length = 0
        struct.pack_into('<I', hdr, 0x2c, 0)   # val_0x2c
        struct.pack_into('<I', hdr, 0x30, 3)   # val_0x2c + 3

        # Entry point table (100 × 4 bytes at 0x34)
        for i, ep in enumerate(ep_table[:100]):
            struct.pack_into('<I', hdr, 0x34 + i * 4, ep)

        # 12 null bytes at 0x1c4 (already zero from bytearray init)

        # Kidoku table at 0x1d0
        if kidoku_data:
            hdr[kidoku_offset: kidoku_offset + len(kidoku_data)] = kidoku_data

        # Dramatis personae at dramatis_offset
        if dramatis_data:
            hdr[dramatis_offset: dramatis_offset + len(dramatis_data)] = dramatis_data

        return bytes(hdr) + bytecode

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def assemble(self) -> bytes:
        """Run the assembler and return the complete binary file."""
        # Substitute #res<NNNN> resource refs before parsing
        if self.resources:
            def _sub_res(m: re.Match) -> str:
                n = int(m.group(1))
                return self.resources.get(n, m.group(0))
            text = re.sub(r'#res<(\d{4})>', _sub_res, self.text)
            self.text = text

        self._parse_and_emit()
        self._resolve_labels()
        return self._build_file()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def assemble_file(ke_path: str | Path, outdir: str | Path = '.',
                  compress: bool = False,
                  options: dict | None = None) -> list[Path]:
    """Assemble a Kepago assembly file (.ke) to binary bytecode.

    Parameters
    ----------
    ke_path:
        Path to the ``.ke`` assembly file.
    outdir:
        Directory for output files (default: current directory).
    compress:
        If True, apply LZ77 compression to the output (default: False).
    options:
        Optional dict of assembler options (currently unused).

    Returns
    -------
    List of Path objects for the files written.
    """
    if options is None:
        options = {}

    ke_path = Path(ke_path)
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # Read ke file
    text = ke_path.read_text(encoding='utf-8')

    # Load KFN
    kfn_path = find_kfn_path()
    if kfn_path is not None:
        try:
            fndefs, module_names = load_kfn(kfn_path)
        except Exception as e:
            print(f'Warning: could not load {kfn_path}: {e}', file=sys.stderr)
            fndefs, module_names = {}, {}
    else:
        print('Warning: reallive.kfn not found; function lookup disabled',
              file=sys.stderr)
        fndefs, module_names = {}, {}

    # Run assembler
    asm = _Assembler(text, ke_path, fndefs, module_names)
    binary = asm.assemble()

    # Determine output filename
    stem = ke_path.name
    if stem.endswith('.ke'):
        stem = stem[:-3]   # remove .ke
    # stem is now e.g. SEEN0009.TXT

    written: list[Path] = []

    if compress:
        from .rlcmp import compress as rl_compress
        from .bytecode import read_file_header
        hdr = read_file_header(binary)
        xor2 = (hdr.compiler_version == 110002)
        compressed = rl_compress(binary, use_xor2=xor2)
        out_path = outdir / stem
        out_path.write_bytes(compressed)
        written.append(out_path)
    else:
        out_path = outdir / (stem + '.uncompressed')
        out_path.write_bytes(binary)
        written.append(out_path)

    return written
