"""
disasm.py - RealLive bytecode disassembler.

Port of src/kprl/disassembler.ml (OCaml) to Python.

Entry point: ``disassemble_file(path, outdir='.', options=None)``
"""

from __future__ import annotations

import os
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .bytecode import read_full_header, uncompressed_header, is_bytecode
from .kfn import load_kfn, find_kfn_path, FnDef, FnParam


# ---------------------------------------------------------------------------
# Variable name tables
# ---------------------------------------------------------------------------

IVAR: dict[int, str] = {
    0x00: 'intA',   0x01: 'intB',   0x02: 'intC',   0x03: 'intD',
    0x04: 'intE',   0x05: 'intF',   0x06: 'intG',   0x19: 'intZ',
    0x1a: 'intAb',  0x1b: 'intBb',  0x1c: 'intCb',  0x1d: 'intDb',
    0x1e: 'intEb',  0x1f: 'intFb',  0x20: 'intGb',  0x33: 'intZb',
    0x34: 'intA2b', 0x35: 'intB2b', 0x36: 'intC2b', 0x37: 'intD2b',
    0x38: 'intE2b', 0x39: 'intF2b', 0x3a: 'intG2b', 0x4d: 'intZ2b',
    0x4e: 'intA4b', 0x4f: 'intB4b', 0x50: 'intC4b', 0x51: 'intD4b',
    0x52: 'intE4b', 0x53: 'intF4b', 0x54: 'intG4b', 0x67: 'intZ4b',
    0x68: 'intA8b', 0x69: 'intB8b', 0x6a: 'intC8b', 0x6b: 'intD8b',
    0x6c: 'intE8b', 0x6d: 'intF8b', 0x6e: 'intG8b', 0x81: 'intZ8b',
}

SVAR: dict[int, str] = {
    0x0a: 'strK',
    0x0b: 'strL',
    0x0c: 'strM',
    0x12: 'strS',
}

# Operator strings indexed by op byte (0x00-0x09)
_OP_STR: list[str] = ['+', '-', '*', '/', '%', '&', '|', '^', '<<', '>>']

# Comparison operator strings (0x28-0x2d)
_CMP_STR: dict[int, str] = {
    0x28: '==', 0x29: '!=', 0x2a: '<=', 0x2b: '<', 0x2c: '>=', 0x2d: '>',
}

# Boolean operator strings
_BOOL_STR: dict[int, str] = {0x3c: '&&', 0x3d: '||'}

# Assignment op byte (0x5c, 0x14-0x1e)
_ASSIGN_OPS: dict[int, str] = {
    0x14: '+=', 0x15: '-=', 0x16: '*=', 0x17: '/=', 0x18: '%=',
    0x19: '&=', 0x1a: '|=', 0x1b: '^=', 0x1c: '<<=', 0x1d: '>>=', 0x1e: '=',
}

# Operator precedences
def _prec(op: int) -> int:
    if op <= 0x09:
        return [4, 4, 5, 5, 5, 5, 4, 4, 6, 6][op]
    if op <= 0x29:
        return 2
    if op <= 0x2d:
        return 3
    if op == 0x3c:
        return 1
    if op == 0x3d:
        return 0
    return 0


# ---------------------------------------------------------------------------
# seeNEnd marker (special text that signals end-of-file in SEEN scripts)
# ---------------------------------------------------------------------------

_SEEN_END_SJS = bytes.fromhex('827282858285828e8264828e8284')


# ---------------------------------------------------------------------------
# Command dataclass
# ---------------------------------------------------------------------------

@dataclass
class Command:
    """One disassembled bytecode command."""
    offset: int          # byte offset from start of data section
    text: str            # formatted Kepago text (with __PTR_XXXXXXXX__ placeholders)
    is_jump: bool = False   # this command ends control flow (halt, ret, goto…)
    hidden: bool = False    # debug marker — suppress unless verbose
    unhide: bool = False    # force unhide (used for #entrypoint markers)
    pointers: set = field(default_factory=set)  # pointer targets referenced


# Pointer placeholder helpers
_PTR_RE = re.compile(r'__PTR_([0-9A-Fa-f]{8})__')


def _ptr(offset: int) -> str:
    """Return a pointer placeholder for *offset*."""
    return f'__PTR_{offset:08X}__'


# ---------------------------------------------------------------------------
# ByteReader
# ---------------------------------------------------------------------------

class _Reader:
    """Byte-level reader over a bytes/bytearray region."""

    __slots__ = ('data', 'pos', 'end')

    def __init__(self, data: bytes | bytearray, start: int = 0, end: int | None = None) -> None:
        self.data = data
        self.pos  = start
        self.end  = end if end is not None else len(data)

    # ---- basic ops ----

    def eof(self) -> bool:
        return self.pos >= self.end

    def peek(self) -> int | None:
        return self.data[self.pos] if self.pos < self.end else None

    def read_byte(self) -> int:
        b = self.data[self.pos]
        self.pos += 1
        return b

    def rollback(self, n: int = 1) -> None:
        self.pos -= n

    def read_int16(self) -> int:
        """Read a signed 16-bit LE integer."""
        v = struct.unpack_from('<h', self.data, self.pos)[0]
        self.pos += 2
        return v

    def read_uint16(self) -> int:
        """Read an unsigned 16-bit LE integer."""
        v = struct.unpack_from('<H', self.data, self.pos)[0]
        self.pos += 2
        return v

    def read_int32(self) -> int:
        """Read a signed 32-bit LE integer."""
        v = struct.unpack_from('<i', self.data, self.pos)[0]
        self.pos += 4
        return v

    def expect(self, byte_val: int, context: str) -> None:
        """Read one byte and raise if it doesn't match *byte_val*."""
        if self.eof():
            raise ValueError(f'{context}: unexpected EOF, expected 0x{byte_val:02x}')
        b = self.read_byte()
        if b != byte_val:
            raise ValueError(f'{context}: expected 0x{byte_val:02x}, got 0x{b:02x}')

    def peek_is(self, byte_val: int) -> bool:
        return self.peek() == byte_val


# ---------------------------------------------------------------------------
# Expression parser
# ---------------------------------------------------------------------------

def _variable_name(b: int) -> str:
    """Return the variable name for byte *b*."""
    if b in IVAR:
        return IVAR[b]
    if b in SVAR:
        return SVAR[b]
    return f'VAR{b:02x}'


def _read_expr_token(r: _Reader) -> str:
    """Read a ``$``-token (integer literal, store, or variable reference)."""
    if r.eof():
        raise ValueError('unexpected EOF in _read_expr_token')
    b = r.read_byte()
    if b == 0xff:
        return str(r.read_int32())
    if b == 0xc8:
        return 'store'
    # Variable: byte is var-type, followed by '[' expr ']'
    name = _variable_name(b)
    r.expect(0x5b, '_read_expr_token')  # '['
    idx = _read_expression(r)
    r.expect(0x5d, '_read_expr_token')  # ']'
    return f'{name}[{idx}]'


def _read_expr_term(r: _Reader) -> tuple:
    """Parse an expression atom/term, returning an AST node."""
    if r.eof():
        raise ValueError('unexpected EOF in _read_expr_term')
    b = r.read_byte()
    if b == 0x24:   # '$'
        return ('atom', _read_expr_token(r))
    if b == 0x5c:   # '\'
        op = r.read_byte()
        if op == 0x00:
            return _read_expr_term(r)       # unary+ — ignore
        if op == 0x01:
            return ('neg', _read_expr_term(r))
        raise ValueError(f'unexpected unary op 0x{op:02x} in _read_expr_term')
    if b == 0x28:   # '('
        inner = _read_expr_bool(r)
        r.expect(0x29, '_read_expr_term')   # ')'
        return inner
    r.rollback()
    raise ValueError(f'expected [$\\(] in _read_expr_term, found 0x{b:02x}')


def _read_expr_arith(r: _Reader) -> tuple:
    """Parse arithmetic (with both high- and low-precedence operators)."""
    def loop_hi(tok: tuple) -> tuple:
        if r.eof():
            return tok
        p = r.peek()
        if p == 0x5c:
            r.read_byte()
            op = r.peek()
            if op is not None and 0x02 <= op <= 0x09:
                r.read_byte()
                rhs = _read_expr_term(r)
                return loop_hi(('binary', tok, op, rhs))
            r.rollback()
        return tok

    def loop_lo(tok: tuple) -> tuple:
        if r.eof():
            return tok
        p = r.peek()
        if p == 0x5c:
            r.read_byte()
            op = r.peek()
            if op is not None and 0x00 <= op <= 0x01:
                r.read_byte()
                rhs = loop_hi(_read_expr_term(r))
                return loop_lo(('binary', tok, op, rhs))
            r.rollback()
        return tok

    return loop_lo(loop_hi(_read_expr_term(r)))


def _read_expr_cond(r: _Reader) -> tuple:
    """Parse a comparison expression."""
    def loop(tok: tuple) -> tuple:
        if r.eof():
            return tok
        p = r.peek()
        if p == 0x5c:
            r.read_byte()
            op = r.peek()
            if op is not None and 0x28 <= op <= 0x2d:
                r.read_byte()
                rhs = _read_expr_arith(r)
                return loop(('binary', tok, op, rhs))
            r.rollback()
        return tok

    return loop(_read_expr_arith(r))


def _read_expr_bool(r: _Reader) -> tuple:
    """Parse a boolean (&&/||) expression."""
    def loop_and(tok: tuple) -> tuple:
        if r.eof():
            return tok
        p = r.peek()
        if p == 0x5c:
            r.read_byte()
            op = r.peek()
            if op == 0x3c:   # &&
                r.read_byte()
                rhs = _read_expr_cond(r)
                return loop_and(('binary', tok, 0x3c, rhs))
            r.rollback()
        return tok

    def loop_or(tok: tuple) -> tuple:
        if r.eof():
            return tok
        p = r.peek()
        if p == 0x5c:
            r.read_byte()
            op = r.peek()
            if op == 0x3d:   # ||
                r.read_byte()
                rhs = loop_and(_read_expr_cond(r))
                return loop_or(('binary', tok, 0x3d, rhs))
            r.rollback()
        return tok

    return loop_or(loop_and(_read_expr_cond(r)))


def _traverse(node: tuple) -> str:
    """Flatten an expression AST to a string."""
    kind = node[0]
    if kind == 'atom':
        return node[1]
    if kind == 'neg':
        inner = node[1]
        s = _traverse(inner)
        if inner[0] == 'atom':
            return f'-{s}'
        if inner[0] == 'neg':
            return _traverse(inner[1])
        return f'-({s})'
    if kind == 'binary':
        _, lhs, op, rhs = node
        a = _traverse(lhs)
        b = _traverse(rhs)
        op_s = _op_str(op)

        # Special reductions
        if op == 0x07 and b == '-1':   # XOR -1 → ~
            la = a if lhs[0] != 'binary' else f'({a})'
            return f'~{la}'
        if op == 0x28 and b == '0':   # == 0 → !
            la = a if lhs[0] != 'binary' else f'({a})'
            return f'!{la}'
        if op == 0x29 and b == '0':   # != 0 → identity
            return a

        # Parenthesise right side if needed
        b_par = b
        if rhs[0] == 'binary':
            if _prec(rhs[2]) <= _prec(op):
                b_par = b if b.startswith('~') else f'({b})'

        # Parenthesise left side if needed
        a_par = a
        if lhs[0] == 'binary':
            if _prec(lhs[2]) < _prec(op):
                a_par = f'({a})'

        return f'{a_par} {op_s} {b_par}'

    return '?'


def _op_str(op: int) -> str:
    if 0x00 <= op <= 0x09:
        return _OP_STR[op]
    if op in _CMP_STR:
        return _CMP_STR[op]
    if op in _BOOL_STR:
        return _BOOL_STR[op]
    return f'[op{op:02x}]'


def _read_expression(r: _Reader) -> str:
    """Read a complete expression and return its string representation."""
    ast = _read_expr_bool(r)
    return _traverse(ast)


# ---------------------------------------------------------------------------
# Data readers (strings and expressions)
# ---------------------------------------------------------------------------

_SJS1_RANGES = [(0x81, 0x9f), (0xe0, 0xef), (0xf0, 0xfc)]


def _is_sjs1(b: int) -> bool:
    """Return True if *b* is the first byte of a Shift-JIS 2-byte sequence."""
    return (0x81 <= b <= 0x9f) or (0xe0 <= b <= 0xfc)


def _is_data_str_start(b: int) -> bool:
    """Return True if *b* starts a string data item (vs an expression)."""
    return (
        b == 0x22                  # '"'
        or (0x41 <= b <= 0x5a)     # A-Z
        or (0x30 <= b <= 0x39)     # 0-9
        or b == 0x3f               # ?
        or b == 0x5f               # _
        or _is_sjs1(b)
    )


def _read_unquoted_string_bytes(r: _Reader) -> bytearray:
    """Read unquoted string bytes (SJS, A-Z, 0-9, ?, _) until something else."""
    buf = bytearray()
    while not r.eof():
        b = r.peek()
        if b is None:
            break
        if _is_sjs1(b):
            buf.append(r.read_byte())
            if not r.eof():
                buf.append(r.read_byte())
        elif (0x41 <= b <= 0x5a) or (0x30 <= b <= 0x39) or b == 0x3f or b == 0x5f:
            buf.append(r.read_byte())
        else:
            break
    return buf


def _read_string_data(r: _Reader, sep_str: bool = False) -> str:
    """Read a string parameter value (potentially quoted or unquoted SJS).

    Returns the string wrapped in single quotes, e.g. ``'text'``.
    """
    buf = bytearray()

    def read_unquoted() -> None:
        while not r.eof():
            b = r.peek()
            if b is None:
                break
            if b == 0x22:   # '"' → enter quoted mode
                r.read_byte()
                read_quoted()
                return
            if _is_sjs1(b):
                buf.append(r.read_byte())
                if not r.eof():
                    buf.append(r.read_byte())
            elif (0x41 <= b <= 0x5a) or (0x30 <= b <= 0x39) or b == 0x3f or b == 0x5f:
                buf.append(r.read_byte())
            else:
                break

    def read_quoted() -> None:
        while not r.eof():
            b = r.read_byte()
            if b == 0x22:   # '"' → exit quoted mode
                read_unquoted()
                return
            if b == 0x5c:   # '\'
                buf.append(b)
                if not r.eof():
                    buf.append(r.read_byte())
            elif _is_sjs1(b):
                buf.append(b)
                if not r.eof():
                    buf.append(r.read_byte())
            else:
                buf.append(b)

    read_unquoted()
    text = buf.decode('shift-jis', errors='replace')
    # Escape single quotes inside the string for Kepago
    text = text.replace("'", "\\'")
    return f"'{text}'"


def _read_data(r: _Reader, sep_str: bool = False) -> str:
    """Read one data item (string or expression), skipping debug commas/lines."""
    while not r.eof():
        b = r.peek()
        if b == 0x2c:   # ',' — debug comma
            r.read_byte()
            continue
        if b == 0x0a:   # line number
            r.read_byte()
            r.read_int16()
            continue
        break

    if r.eof():
        return ''

    b = r.peek()
    if b is None:
        return ''

    if _is_data_str_start(b):
        return _read_string_data(r, sep_str)

    # 0x61 = 'a' — special parameter dispatch (treat as expression fallback)
    if b == 0x61:
        r.read_byte()
        sid = r.read_byte()
        r.expect(0x28, '_read_data.special')   # '('
        buf = [f'__special[{sid}]({_read_data(r)}']
        while not r.eof() and r.peek() != 0x29:
            buf.append(f', {_read_data(r)}')
        r.expect(0x29, '_read_data.special')
        return ''.join(buf) + ')'

    return _read_expression(r)


# ---------------------------------------------------------------------------
# Text-output reader
# ---------------------------------------------------------------------------

_TEXTOUT_STOP = frozenset([0x00, 0x23, 0x24, 0x0a, 0x40, 0x21])


def _read_textout_bytes(r: _Reader) -> bytes:
    """Read raw text-output bytes until hitting a control byte.

    Handles SJS 2-byte sequences so we don't split them at control bytes.
    Skips ``,`` (0x2c) separators but doesn't include them.
    """
    buf = bytearray()

    while not r.eof():
        b = r.peek()
        if b is None:
            break
        if b in _TEXTOUT_STOP:
            break

        r.read_byte()

        if b == 0x22:   # '"' — enter quoted section
            while not r.eof():
                c = r.read_byte()
                if c == 0x22:
                    break
                if _is_sjs1(c):
                    buf.append(c)
                    if not r.eof():
                        buf.append(r.read_byte())
                else:
                    buf.append(c)
            continue

        if b == 0x2c:   # ',' — skip
            continue

        if _is_sjs1(b):
            buf.append(b)
            if not r.eof():
                buf.append(r.read_byte())
        else:
            buf.append(b)

    return bytes(buf)


def _escape_textout(text: str) -> str:
    """Escape special characters in a text-output string for Kepago output."""
    text = text.replace('\\', '\\\\')
    text = text.replace("'", "\\'")
    text = text.replace('{-', '{\\-')
    text = text.replace('//', '\\//') 
    text = text.replace('<', '\\<')
    return text


def _make_textout(raw: bytes) -> str:
    """Decode raw text output bytes and format as a Kepago string literal."""
    # Check for seeNEnd marker
    if raw.startswith(_SEEN_END_SJS):
        return 'eof'

    if not raw:
        return "''"

    text = raw.decode('shift-jis', errors='replace')
    text = _escape_textout(text)
    return f"'{text}'"


# ---------------------------------------------------------------------------
# Special-case function handlers
# ---------------------------------------------------------------------------

def _read_goto_case(r: _Reader, to_or_sub: str, argc: int) -> tuple[str, set]:
    """Read a goto_case / gosub_case instruction."""
    expr = _read_expression(r)
    r.expect(0x7b, 'read_goto_case')    # '{'
    parts = [f'go{to_or_sub}_case {expr} {{ ']
    ptrs: set[int] = set()
    for i in range(argc):
        b = r.peek()
        if b == 0x28:   # '('
            r.read_byte()
            b2 = r.peek()
            if b2 == 0x29:   # '()' — default case
                r.read_byte()
                label_txt = ('_:' if i == 0 else '; _:')
            else:
                e = _read_expression(r)
                r.expect(0x29, 'read_goto_case')
                label_txt = (f'{e}:' if i == 0 else f'; {e}:')
            target = r.read_int32()
            ptrs.add(target)
            parts.append(label_txt + _ptr(target))
        else:
            break
    r.expect(0x7d, 'read_goto_case')    # '}'
    parts.append(' }')
    return ''.join(parts), ptrs


def _read_goto_on(r: _Reader, to_or_sub: str, argc: int) -> tuple[str, set]:
    """Read a goto_on / gosub_on instruction."""
    expr = _read_expression(r)
    r.expect(0x7b, 'read_goto_on')    # '{'
    parts = [f'go{to_or_sub}_on {expr} {{ ']
    ptrs: set[int] = set()
    for i in range(argc):
        target = r.read_int32()
        ptrs.add(target)
        parts.append(('' if i == 0 else ', ') + _ptr(target))
    r.expect(0x7d, 'read_goto_on')    # '}'
    parts.append(' }')
    return ''.join(parts), ptrs


def _read_select(r: _Reader, opcode_func: int, argc: int, mode: str) -> str:
    """Read a select_* instruction."""
    fn_names = {0: 'select_w', 1: 'select', 2: 'select_s2', 3: 'select_s', 10: 'select_w2'}
    fn = fn_names.get(opcode_func, f'select_{opcode_func:05d}')

    # Optional expression selector [expr]
    if r.peek_is(0x28):   # '('
        r.read_byte()
        e = _read_expression(r)
        r.expect(0x29, 'read_select')
        fn = f'{fn}[{e}]'

    r.expect(0x7b, 'read_select')   # '{'

    def skip_debug_info() -> None:
        while not r.eof():
            b = r.peek()
            if b == 0x0a:
                r.read_byte()
                if mode == 'avg2000':
                    r.read_int32()
                else:
                    r.read_int16()
            elif b == 0x2c:
                r.read_byte()
            else:
                break

    has_conds = False
    cases: list[str] = []
    for _ in range(argc):
        skip_debug_info()
        cond = ''
        if r.peek_is(0x28):
            has_conds = True
            r.read_byte()
            cond_parts = []
            while not r.eof() and not r.peek_is(0x29):
                inner_cond = ''
                if r.peek_is(0x28):
                    r.read_byte()
                    ec = _read_expression(r)
                    r.expect(0x29, 'read_select.cond')
                    inner_cond = f' if {ec}'
                func_byte = r.read_byte()
                func_name_map = {0x30: 'colour', 0x31: 'title', 0x32: 'hide',
                                 0x33: 'blank', 0x34: 'cursor'}
                fspec = func_name_map.get(func_byte, f'fn{func_byte:02x}')
                need_arg = func_byte in (0x30, 0x31, 0x34)
                arg = ''
                if need_arg and not r.eof() and r.peek() != 0x29:
                    b = r.peek()
                    if not (0x30 <= b <= 0x39):  # not a digit
                        arg = f'({_read_expression(r)})'
                cond_parts.append(fspec + arg + inner_cond)
            r.expect(0x29, 'read_select.cond')
            cond = '; '.join(cond_parts) + ': '

        item = ''
        if r.peek_is(0x0a):
            item = "''"
        else:
            item = _read_data(r)

        cases.append(cond + item)

    skip_debug_info()
    r.expect(0x7d, 'read_select')   # '}'

    sep = (',\n    ' if has_conds else ', ')
    if has_conds:
        return f'{fn} (\n    {sep.join(cases)}\n)'
    else:
        return f'{fn} ({", ".join(cases)})'


# ---------------------------------------------------------------------------
# Complex / special parameter reading
# ---------------------------------------------------------------------------

def _read_complex_param(r: _Reader, params: list[FnParam],
                         with_parens: bool, opens: str) -> str:
    """Read a complex parameter group (list of sub-parameters)."""
    parts: list[str] = []
    param_iter = iter(params)
    for p in param_iter:
        # Stop on 0x61 ('a') or ')' if in-parens mode
        b = r.peek()
        if b == 0x61:
            break
        if b == 0x29 and with_parens:
            break
        e = _read_data(r)
        if parts and not (not parts and opens == '{' and e.startswith('-')):
            parts.append(', ')
        else:
            if parts or opens != '{' or not e.startswith('-'):
                if parts:
                    parts.append(', ')
        parts.append(e)
    return ''.join(parts)


def _read_special_param(r: _Reader, sdefs: list) -> str:
    """Read a ``special`` parameter (introduced by 0x61 'a' + id byte)."""
    r.expect(0x61, '_read_special_param')   # 'a'
    sid = r.read_byte()

    # Find matching sdef
    sdef = None
    for sd in sdefs:
        if sd[0] == sid:
            sdef = sd
            break

    if sdef is None:
        # Unknown special id — try to read it generically
        r.expect(0x28, '_read_special_param.unknown')
        parts = [_read_data(r)]
        while not r.eof() and not r.peek_is(0x29):
            parts.append(', ')
            parts.append(_read_data(r))
        r.expect(0x29, '_read_special_param.unknown')
        return f'__special[{sid}]({", ".join(parts)})'

    _, kind, name, params, no_parens = sdef

    if kind == 'named':
        r.expect(0x28, '_read_special_param.named')
        inner = _read_complex_param(r, params, with_parens=True, opens=f'{name}(')
        r.expect(0x29, '_read_special_param.named')
        return f'{name}({inner})'
    else:  # complex / AsComplex
        if no_parens:
            inner = _read_complex_param(r, params, with_parens=False, opens='')
            return f'{{{inner}}}'
        else:
            r.expect(0x28, '_read_special_param.complex')
            inner = _read_complex_param(r, params, with_parens=True, opens='{')
            r.expect(0x29, '_read_special_param.complex')
            return f'{{{inner}}}'


# ---------------------------------------------------------------------------
# General-case function call reader
# ---------------------------------------------------------------------------

def _read_unknown_function(r: _Reader, opstr: str, argc: int) -> tuple[str, set]:
    """Read argc data items for an unknown function."""
    if argc == 0:
        b = r.peek()
        if b != 0x28:
            return opstr, set()

    try:
        r.expect(0x28, '_read_unknown_function')
    except ValueError:
        return opstr, set()

    parts: list[str] = []
    remaining = argc
    while not r.eof():
        b = r.peek()
        if b == 0x29:
            r.read_byte()
            break
        if b == 0x0a:
            r.read_byte()
            r.read_int16()
            continue
        if b == 0x2c:
            r.read_byte()
            continue
        item = _read_data(r)
        parts.append(item)
        if remaining > 0:
            remaining -= 1

    params_str = ', '.join(parts)
    return f'{opstr} ({params_str})', set()


def _read_soft_function(r: _Reader, opcode_key: tuple[int, int, int, int],
                         argc: int, fndef: FnDef) -> tuple[str, set, bool]:
    """Read a function call using the prototype from *fndef*.

    Returns ``(text, pointers, is_jump)``.
    """
    overload_idx = opcode_key[3]
    if overload_idx >= len(fndef.prototypes):
        text, ptrs = _read_unknown_function(r, fndef.ident, argc)
        return text, ptrs, 'jump' in fndef.flags

    prototype = fndef.prototypes[overload_idx]
    is_jump = 'jump' in fndef.flags
    is_goto = 'goto' in fndef.flags
    has_store = 'store' in fndef.flags

    if prototype is None:
        text, ptrs = _read_unknown_function(r, fndef.ident, argc)
        return text, ptrs, is_jump

    params = prototype

    # ---- Case 1: no parameters given ----
    if argc == 0 and (not params or not r.peek_is(0x28)):
        fake_parts = [p.tag for p in params if p.fake]
        param_str = ', '.join(fake_parts)
        ptrs: set[int] = set()

        if is_goto:
            target = r.read_int32()
            ptrs.add(target)
            ptr_txt = _ptr(target)
        else:
            ptr_txt = ''

        if param_str:
            text = f'{fndef.ident} ({param_str}){ptr_txt}'
        elif ptr_txt:
            text = f'{fndef.ident}{ptr_txt}'
        else:
            text = fndef.ident

        if has_store:
            text = f'store = {text}'
        return text, ptrs, is_jump

    # ---- Case 2: parameters given ----
    try:
        r.expect(0x28, f'_read_soft_function({fndef.ident})')
    except ValueError:
        text, ptrs = _read_unknown_function(r, fndef.ident, argc)
        return text, ptrs, is_jump

    buf: list[str] = []
    pre = ''
    ptrs = set()
    remaining = argc
    param_list = list(params)
    i = 0

    while i < len(param_list):
        p = param_list[i]

        # Skip debug line numbers inside args
        while r.peek_is(0x0a):
            r.read_byte()
            r.read_int16()

        # Fake param — output tag without reading bytes
        if p.fake:
            if buf:
                buf.append(', ')
            buf.append(p.tag if p.tag else '')
            i += 1
            continue

        # Stop early if argc exhausted and param is optional or argc-repeat
        if remaining == 0 and (p.optional or p.argc):
            while r.peek_is(0x0a):
                r.read_byte()
                r.read_int16()
            break

        # Peek for early close paren
        if r.peek_is(0x29):
            r.read_byte()
            break

        # Warn if argc exhausted for non-uncount param
        if remaining == 0 and not p.uncount:
            pass   # warn but continue

        # Add comma separator (not before return values)
        if buf and not p.is_return:
            buf.append(', ')

        # Determine next index (for argc-repeat params)
        next_i = i if (p.argc and remaining > 1) else i + 1

        try:
            if p.ptype == 'complex':
                while r.peek_is(0x0a):
                    r.read_byte()
                    r.read_int16()
                r.expect(0x28, f'_read_soft_function.complex({fndef.ident})')
                inner = _read_complex_param(r, p.sub_params, with_parens=True, opens='{')
                r.expect(0x29, f'_read_soft_function.complex({fndef.ident})')
                buf.append(f'{{{inner}}}')
                if not p.uncount:
                    remaining -= 1

            elif p.ptype == 'special':
                part = _read_special_param(r, p.special_defs)
                buf.append(part)
                if not p.uncount:
                    remaining -= 1

            else:
                d = _read_data(r, sep_str=(p.ptype == 'res'))
                if p.is_return:
                    pre = f'{d} = '
                    if not p.uncount:
                        remaining -= 1
                    i += 1
                    continue
                else:
                    buf.append(d)
                    if not p.uncount:
                        remaining -= 1
        except (ValueError, struct.error) as e:
            # On parse error, stop reading params
            buf.append(f'[err:{e}]')
            # Try to find the closing paren
            while not r.eof() and not r.peek_is(0x29):
                r.read_byte()
            break

        i = next_i

    # Consume closing paren if not already consumed
    if not r.eof() and r.peek_is(0x29):
        r.read_byte()
    elif not r.eof() and r.peek_is(0x0a):
        r.read_byte()
        r.read_int16()
        if not r.eof() and r.peek_is(0x29):
            r.read_byte()

    # Read goto pointer if applicable
    ptr_txt = ''
    if is_goto:
        try:
            target = r.read_int32()
            ptrs.add(target)
            ptr_txt = _ptr(target)
        except (struct.error, ValueError):
            pass

    param_str = ''.join(buf)
    if param_str:
        text = f'{pre}{fndef.ident} ({param_str}){ptr_txt}'
    elif ptr_txt:
        text = f'{pre}{fndef.ident}{ptr_txt}'
    else:
        text = f'{pre}{fndef.ident}'

    if has_store:
        text = f'store = {text}'

    return text, ptrs, is_jump


# ---------------------------------------------------------------------------
# Strcpy / Strcat special cases
# ---------------------------------------------------------------------------

def _read_strcpy_strcat(r: _Reader, func: int, overload: int) -> tuple[str, set]:
    """Handle strcpy (func=0) and strcat (func=2) special cases."""
    r.expect(0x28, '_read_strcpy_strcat')
    a = _read_data(r)
    b = _read_data(r)
    if overload == 1:
        c = _read_data(r)
        r.expect(0x29, '_read_strcpy_strcat')
        return f'strcpy ({a}, {b}, {c})', set()
    r.expect(0x29, '_read_strcpy_strcat')
    op = '' if func == 0 else '+'
    return f'{a} {op}= {b}', set()


# ---------------------------------------------------------------------------
# Main function dispatcher
# ---------------------------------------------------------------------------

def _read_function(r: _Reader, offset: int, op_type: int, op_module: int,
                   op_func: int, op_overload: int, argc: int,
                   fndefs: dict, module_names: dict, mode: str) -> Command:
    """Dispatch a function call to the appropriate reader."""

    key = (op_type, op_module, op_func, op_overload)
    opstr = f'op<{op_type}:{module_names.get(op_module, f"{op_module:03d}")}:{op_func:05d}, {op_overload}>'

    ptrs: set[int] = set()
    is_jump = False
    text = opstr

    try:
        # Special cases by module/func
        if op_module == 1 and op_func == 3:    # GotoOn
            text, ptrs = _read_goto_on(r, 'to', argc)
            is_jump = True
        elif op_module == 1 and op_func == 4:  # GotoCase
            text, ptrs = _read_goto_case(r, 'to', argc)
            is_jump = True
        elif op_module == 1 and op_func == 8:  # GosubOn
            text, ptrs = _read_goto_on(r, 'sub', argc)
        elif op_module == 1 and op_func == 9:  # GosubCase
            text, ptrs = _read_goto_case(r, 'sub', argc)
        elif op_module == 5 and op_func == 3:  # PGotoOn
            text, ptrs = _read_goto_on(r, 'to', argc)
            is_jump = True
        elif op_module == 5 and op_func == 4:  # PGotoCase
            text, ptrs = _read_goto_case(r, 'to', argc)
            is_jump = True
        elif op_module == 5 and op_func == 8:  # PGosubOn
            text, ptrs = _read_goto_on(r, 'sub', argc)
        elif op_module == 5 and op_func == 9:  # PGosubCase
            text, ptrs = _read_goto_case(r, 'sub', argc)
        elif op_module == 2:    # Select
            text = _read_select(r, op_func, argc, mode)
            text = 'store = ' + text
        elif op_module == 3 and op_func == 120:  # Ruby
            text, ptrs = _read_unknown_function(r, 'ruby', argc)
        elif op_module == 10 and op_func == 0:   # Strcpy
            text, ptrs = _read_strcpy_strcat(r, 0, op_overload)
        elif op_module == 10 and op_func == 2:   # Strcat
            text, ptrs = _read_strcpy_strcat(r, 2, op_overload)
        elif key in fndefs:
            text, ptrs, is_jump = _read_soft_function(r, key, argc, fndefs[key])
        else:
            text, ptrs = _read_unknown_function(r, opstr, argc)

    except (ValueError, struct.error, IndexError) as e:
        text = f'{opstr} [parse error: {e}]'

    return Command(offset=offset, text=text, is_jump=is_jump, pointers=ptrs)


# ---------------------------------------------------------------------------
# Assignment reader
# ---------------------------------------------------------------------------

def _read_assignment(r: _Reader, offset: int) -> Command:
    """Read a ``$`` assignment expression."""
    try:
        lhs = _read_expr_token(r)
        b = r.read_byte()
        if b != 0x5c:
            raise ValueError(f'expected 0x5c, got 0x{b:02x}')
        op_b = r.read_byte()
        op_str = _ASSIGN_OPS.get(op_b, '=')
        rhs = _read_expression(r)

        # If rhs == 'store', look back and merge (handled by caller)
        return Command(offset=offset, text=f'{lhs} {op_str} {rhs}')
    except (ValueError, struct.error) as e:
        return Command(offset=offset, text=f'[assignment parse error: {e}]')


# ---------------------------------------------------------------------------
# Kidoku / entrypoint reader
# ---------------------------------------------------------------------------

def _read_kidoku(r: _Reader, offset: int, hdr, mode: str,
                  use_excl: list) -> Command:
    """Read a kidoku (``@`` or ``!``) marker."""
    b = r.peek()
    if b == 0x21:
        use_excl.append(True)
    r.read_byte()

    if mode == 'avg2000':
        idx = r.read_int32()
    else:
        idx = r.read_uint16()

    # Check if this is an entrypoint
    if 0 <= idx < len(hdr.kidoku_lnums):
        lnum = hdr.kidoku_lnums[idx]
        ep_idx = lnum - 1_000_000
        if ep_idx >= 0:
            return Command(offset=offset, text=f'#entrypoint {ep_idx:03d}',
                           hidden=False, unhide=True)

    # Regular kidoku (hidden by default)
    return Command(offset=offset, text=f'{{- kidoku {idx:03d} -}}', hidden=True)


# ---------------------------------------------------------------------------
# Main command reader
# ---------------------------------------------------------------------------

def _read_command(r: _Reader, hdr, fndefs: dict, module_names: dict,
                  mode: str, use_excl: list) -> Command | None:
    """Read one command from *r* and return a Command, or None on EOF."""
    if r.eof():
        return None

    offset = r.pos
    b = r.read_byte()

    if b == 0x00:   # halt
        return Command(offset=offset, text='halt', is_jump=True)

    if b == 0x23:   # '#' — function call
        op_type    = r.read_byte()
        op_module  = r.read_byte()
        op_func    = r.read_uint16()
        argc       = r.read_uint16()
        op_overload = r.read_byte()
        return _read_function(r, offset, op_type, op_module, op_func, op_overload,
                              argc, fndefs, module_names, mode)

    if b == 0x24:   # '$' — assignment
        return _read_assignment(r, offset)

    if b == 0x0a:   # '\n' — line number
        if mode == 'avg2000':
            ln = r.read_int32()
        else:
            ln = r.read_int16()
        return Command(offset=offset, text=f'#line {ln}', hidden=True)

    if b == 0x2c:   # ',' — debug comma
        return Command(offset=offset, text=',', hidden=True)

    if b in (0x40, 0x21):   # '@' or '!' — kidoku
        r.rollback()
        return _read_kidoku(r, offset, hdr, mode, use_excl)

    # Everything else: text output
    r.rollback()
    raw = _read_textout_bytes(r)
    txt = _make_textout(raw)
    is_jump = (txt == 'eof')
    return Command(offset=offset, text=txt, is_jump=is_jump)


# ---------------------------------------------------------------------------
# Disassembly loop
# ---------------------------------------------------------------------------

def _disassemble_all(data: bytes, hdr, fndefs: dict, module_names: dict
                      ) -> tuple[list[Command], bool]:
    """Disassemble the data section of a bytecode file.

    Returns ``(commands, uses_excl_kidoku)``.
    """
    mode = 'avg2000' if hdr.header_version == 1 else 'reallive'
    data_start = hdr.data_offset
    data_end = hdr.data_offset + hdr.uncompressed_size

    # Clamp to actual data length
    data_end = min(data_end, len(data))

    r = _Reader(data, start=data_start, end=data_end)
    commands: list[Command] = []
    use_excl: list = []

    while not r.eof():
        try:
            cmd = _read_command(r, hdr, fndefs, module_names, mode, use_excl)
        except (ValueError, struct.error, IndexError) as e:
            # On error, emit a comment and skip one byte
            cmd = Command(offset=r.pos, text=f'{{- parse error: {e} -}}', hidden=False)
            if not r.eof():
                r.read_byte()

        if cmd is not None:
            commands.append(cmd)

    return commands, bool(use_excl)


# ---------------------------------------------------------------------------
# Label resolution
# ---------------------------------------------------------------------------

def _collect_pointers(commands: list[Command]) -> set[int]:
    """Collect all pointer offsets referenced by any command."""
    ptrs: set[int] = set()
    for cmd in commands:
        ptrs.update(cmd.pointers)
        # Also scan text for __PTR_XXXXXXXX__ placeholders
        for m in _PTR_RE.finditer(cmd.text):
            ptrs.add(int(m.group(1), 16))
    return ptrs


def _resolve_labels(commands: list[Command], data_end: int) -> dict[int, int]:
    """Build a map from absolute offset → sequential label number (1-based)."""
    ptrs = _collect_pointers(commands)
    # Include data_end (the pointer after the last byte, used for 'end' labels)
    ptrs.discard(0)   # 0 is not a valid label
    sorted_ptrs = sorted(ptrs)
    return {offset: idx + 1 for idx, offset in enumerate(sorted_ptrs)}


def _apply_labels(text: str, labels: dict[int, int]) -> str:
    """Replace ``__PTR_XXXXXXXX__`` placeholders with `` @N`` labels."""
    def replace(m: re.Match) -> str:
        offset = int(m.group(1), 16)
        n = labels.get(offset)
        if n is not None:
            return f' @{n}'
        return f' @unknown_{m.group(1)}'
    return _PTR_RE.sub(replace, text)


# ---------------------------------------------------------------------------
# Output writer
# ---------------------------------------------------------------------------

def _write_output(commands: list[Command], labels: dict[int, int],
                  hdr, fname: str, oc,
                  rc, options: dict) -> None:
    """Write disassembled Kepago to open file objects *oc* (code) and *rc* (resources)."""
    annotate = options.get('annotate', False)
    data_offset = hdr.data_offset
    mode = 'avg2000' if hdr.header_version == 1 else 'reallive'

    # Header
    oc.write(f"{{-# cp utf-8 #- Disassembled with kprl.py -}}\n\n#file '{fname}'\n")

    if oc is not rc:
        rc.write(f'// Resources for {fname}\n\n')
        oc.write(f"#resource '{Path(rc.name).name}'\n")

    oc.write('\n')

    if mode == 'avg2000':
        oc.write('#target AVG2000\n')

    for name in hdr.dramatis_personae:
        rc.write(f"#character '{name}'\n")

    if rc is not oc and hdr.dramatis_personae:
        rc.write('\n')

    # Build offset-to-label map and set of offsets where labels appear
    pending_labels: set[int] = set(labels.keys())
    data_end_offset = hdr.uncompressed_size  # relative offset of end

    # Emit commands
    skipping = False
    for cmd in commands:
        rel_offset = cmd.offset - hdr.data_offset

        # Check if a label should be printed before this command
        if rel_offset in labels:
            lnum = labels[rel_offset]
            oc.write(f'\n  @{lnum}\n')
            pending_labels.discard(rel_offset)
            skipping = False

        # Un-hide if this is an entrypoint
        if cmd.unhide and skipping:
            skipping = False

        # Print the command if visible
        if not (skipping or cmd.hidden):
            line = _apply_labels(cmd.text, labels)
            if annotate:
                oc.write(f'{{-{rel_offset + data_offset:08x}-}} ')
            oc.write(f'  {line}\n')

        # If it's a jump, suppress subsequent commands until we hit a label
        # (suppress_uncalled is not enabled by default)

    # Emit any remaining labels that didn't correspond to commands
    for offset in sorted(pending_labels):
        if offset == data_end_offset:
            lnum = labels[offset]
            oc.write(f'\n  @{lnum}\n')


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def disassemble_file(path: str | Path,
                     outdir: str | Path = '.',
                     options: dict | None = None) -> list[Path]:
    """Disassemble a RealLive bytecode file (compressed or uncompressed).

    Parameters
    ----------
    path:
        Path to a ``.TXT`` (compressed) or ``.TXT.uncompressed`` bytecode file.
    outdir:
        Directory in which to write the output ``.ke`` (and optional ``.utf``) file.
    options:
        Optional dict with keys:
        - ``'annotate'``: bool — add offset annotations (default False)
        - ``'single_file'``: bool — suppress separate resource file (default True)
        - ``'encoding'``: str — output encoding name, used in header comment

    Returns
    -------
    List of Path objects for the files written.
    """
    if options is None:
        options = {}

    path = Path(path)
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # Read file
    raw = path.read_bytes()

    # Parse header first to determine layout
    hdr_tmp = read_full_header(raw)
    expected_unc_size = hdr_tmp.data_offset + hdr_tmp.uncompressed_size

    # Detect whether the payload is already decompressed.
    # A file is already decompressed when its total size equals
    # data_offset + uncompressed_size (i.e. no LZ block present).
    already_decompressed = (
        hdr_tmp.compressed_size is None
        or len(raw) == expected_unc_size
        or uncompressed_header(raw[:4])
    )

    if already_decompressed:
        data = raw
    else:
        from .rlcmp import decompress_file as _decompress
        use_xor2 = (hdr_tmp.compiler_version == 110002)
        data = _decompress(raw, use_xor2=use_xor2)

    # Parse header
    hdr = read_full_header(data)

    # Determine base filename for output
    stem = path.name
    if stem.endswith('.uncompressed'):
        stem = stem[:-len('.uncompressed')]
    base = Path(stem).stem    # strip .TXT

    ke_path  = outdir / (base + '.TXT.ke')
    res_path = outdir / (base + '.TXT.utf')

    # Load KFN function definitions
    kfn_path = find_kfn_path()
    if kfn_path is not None:
        try:
            fndefs, module_names = load_kfn(kfn_path)
        except Exception as e:
            print(f'Warning: could not load {kfn_path}: {e}', file=sys.stderr)
            fndefs, module_names = {}, {}
    else:
        print('Warning: reallive.kfn not found; function names will be numeric',
              file=sys.stderr)
        fndefs, module_names = {}, {}

    # Disassemble
    commands, uses_excl = _disassemble_all(data, hdr, fndefs, module_names)

    # Build label table
    data_end = hdr.data_offset + hdr.uncompressed_size
    data_end_rel = hdr.uncompressed_size
    labels = _resolve_labels(commands, data_end_rel)

    # Write output
    single_file = options.get('single_file', True)

    written: list[Path] = []
    with open(ke_path, 'w', encoding='utf-8') as oc:
        if single_file or not commands:
            rc = oc
        else:
            rc_file = open(res_path, 'w', encoding='utf-8')
            rc = rc_file

        try:
            _write_output(commands, labels, hdr, stem, oc, rc, options)
            written.append(ke_path)
            if rc is not oc:
                written.append(res_path)
        finally:
            if rc is not oc:
                rc.close()

    return written
