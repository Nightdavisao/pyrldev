"""
kfn.py - Parser for RealLive function definition (.kfn) files.

Parses ``lib/reallive.kfn`` to build a lookup table mapping
(op_type, op_module, op_func, op_overload) → FnDef.

Grammar reference: src/common/kfnParser.mly
Type definitions:  src/common/kfnTypes.ml
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class FnParam:
    """A single parameter in a function prototype."""
    ptype: str          # 'int', 'intC', 'intV', 'str', 'strC', 'strV',
                        # 'res', 'complex', 'special', 'any'
    tag: str = ''       # parameter tag (from STRING in grammar)
    optional: bool = False    # '?' prefix
    uncount: bool = False     # '<' prefix — not counted in argc
    is_return: bool = False   # '>' prefix — return value
    fake: bool = False        # '=' prefix — don't read, just print tag
    argc: bool = False        # '+' postfix — repeated until argc runs out
    text_obj: bool = False    # '#' prefix — #-codes valid
    sub_params: list = field(default_factory=list)    # for complex: list[FnParam]
    special_defs: list = field(default_factory=list)  # for special: list of (id, kind, params, flags)


@dataclass
class FnDef:
    """A function definition from the KFN file."""
    ident: str
    flags: frozenset        # {'jump', 'goto', 'store', 'textout', 'nobrace', 'lbr', 'cond'}
    ccode: str              # control-code name (empty if none)
    prototypes: list        # list of (list[FnParam] | None) — one per overload


# ---------------------------------------------------------------------------
# Tokeniser
# ---------------------------------------------------------------------------

# Token type constants
_TT_MODULE  = 'MODULE'
_TT_FUN     = 'FUN'
_TT_VER     = 'VER'
_TT_END     = 'END'
_TT_INT     = 'INT'
_TT_INTC    = 'INTC'
_TT_INTV    = 'INTV'
_TT_STR     = 'STR'
_TT_STRC    = 'STRC'
_TT_STRV    = 'STRV'
_TT_RES     = 'RES'
_TT_SPECIAL = 'SPECIAL'
_TT_IDENT   = 'IDENT'
_TT_INTEGER = 'INTEGER'
_TT_STRING  = 'STRING'
_TT_EOF     = 'EOF'
# Punctuation
_TT_LT  = 'LT'   # <
_TT_GT  = 'GT'   # >
_TT_EQ  = 'EQ'   # =
_TT_CM  = 'CM'   # ,
_TT_LP  = 'LP'   # (
_TT_RP  = 'RP'   # )
_TT_LBR = 'LBR'  # {
_TT_RBR = 'RBR'  # }
_TT_LSQ = 'LSQ'  # [
_TT_RSQ = 'RSQ'  # ]
_TT_QU  = 'QU'   # ?
_TT_ST  = 'ST'   # *
_TT_PL  = 'PL'   # +
_TT_CO  = 'CO'   # :
_TT_PT  = 'PT'   # .
_TT_HA  = 'HA'   # #

_KEYWORDS: dict[str, str] = {
    'module':  _TT_MODULE,
    'fun':     _TT_FUN,
    'ver':     _TT_VER,
    'end':     _TT_END,
    'int':     _TT_INT,
    'intC':    _TT_INTC,
    'intV':    _TT_INTV,
    'str':     _TT_STR,
    'strC':    _TT_STRC,
    'strV':    _TT_STRV,
    'res':     _TT_RES,
    'special': _TT_SPECIAL,
}

_PUNCT: dict[str, str] = {
    '<': _TT_LT, '>': _TT_GT, '=': _TT_EQ, ',': _TT_CM,
    '(': _TT_LP, ')': _TT_RP, '{': _TT_LBR, '}': _TT_RBR,
    '[': _TT_LSQ, ']': _TT_RSQ, '?': _TT_QU, '*': _TT_ST,
    '+': _TT_PL, ':': _TT_CO, '.': _TT_PT, '#': _TT_HA,
}


def _tokenize(text: str) -> list[tuple[str, object]]:
    """Tokenise a KFN source file into a list of (type, value) tuples."""
    tokens: list[tuple[str, object]] = []
    pos = 0
    length = len(text)

    while pos < length:
        # Comment
        if text[pos:pos+2] == '//':
            nl = text.find('\n', pos)
            pos = nl + 1 if nl >= 0 else length
            continue

        # Whitespace
        if text[pos].isspace():
            pos += 1
            continue

        # Quoted string (single or double quotes)
        if text[pos] in ('"', "'"):
            quote = text[pos]
            end = text.find(quote, pos + 1)
            if end < 0:
                end = length
            tokens.append((_TT_STRING, text[pos+1:end]))
            pos = end + 1
            continue

        # Integer
        if text[pos].isdigit():
            end = pos + 1
            while end < length and text[end].isdigit():
                end += 1
            tokens.append((_TT_INTEGER, int(text[pos:end])))
            pos = end
            continue

        # Identifier or keyword (note: intC/intV/strC/strV must be matched before int/str)
        # '?' is allowed inside (not at start of) identifiers, e.g. '__Debugging?'
        if text[pos].isalpha() or text[pos] == '_':
            end = pos + 1
            while end < length and (text[end].isalnum() or text[end] in ('_', '?')):
                end += 1
            word = text[pos:end]
            tt = _KEYWORDS.get(word, _TT_IDENT)
            tokens.append((tt, word))
            pos = end
            continue

        # Punctuation
        ch = text[pos]
        if ch in _PUNCT:
            tokens.append((_PUNCT[ch], ch))
            pos += 1
            continue

        # Unknown — skip silently
        pos += 1

    tokens.append((_TT_EOF, None))
    return tokens


# ---------------------------------------------------------------------------
# Recursive-descent parser
# ---------------------------------------------------------------------------

class _Parser:
    """Recursive-descent KFN parser.

    After parsing, ``fndefs`` maps ``(type, module, func, overload) → FnDef``
    and ``module_names`` maps ``module_number → name``.
    """

    def __init__(self, tokens: list[tuple[str, object]]) -> None:
        self._tokens = tokens
        self._pos = 0
        self._modules: dict[str, int] = {}   # name → number
        self.module_names: dict[int, str] = {}  # number → name
        self.fndefs: dict[tuple[int, int, int, int], FnDef] = {}

    # ------------------------------------------------------------------
    # Token access helpers
    # ------------------------------------------------------------------

    def _peek(self) -> tuple[str, object]:
        return self._tokens[self._pos]

    def _peek_type(self) -> str:
        return self._tokens[self._pos][0]

    def _consume(self, expected: str | None = None) -> tuple[str, object]:
        tok = self._tokens[self._pos]
        if expected is not None and tok[0] != expected:
            raise ValueError(
                f'KFN parse error: expected {expected}, got {tok[0]!r} ({tok[1]!r})'
            )
        self._pos += 1
        return tok

    def _check(self, *types: str) -> bool:
        return self._tokens[self._pos][0] in types

    def _optional(self, tt: str) -> bool:
        """Consume token of type *tt* if present; return True if consumed."""
        if self._peek_type() == tt:
            self._consume()
            return True
        return False

    # ------------------------------------------------------------------
    # Top-level
    # ------------------------------------------------------------------

    def parse(self) -> None:
        while not self._check(_TT_EOF):
            if self._check(_TT_MODULE):
                self._parse_module_def()
            elif self._check(_TT_VER):
                self._parse_ver_block()
            elif self._check(_TT_FUN):
                fd = self._parse_fun_def()
                self._register_fun(fd, ver_constraint=None)
            else:
                # Skip unknown tokens gracefully
                self._consume()

    # ------------------------------------------------------------------
    # Module definition
    # ------------------------------------------------------------------

    def _parse_module_def(self) -> None:
        self._consume(_TT_MODULE)
        _, num = self._consume(_TT_INTEGER)
        if self._optional(_TT_EQ):
            _, name = self._consume(_TT_IDENT)
            self._modules[name] = num
            self.module_names[num] = name

    # ------------------------------------------------------------------
    # Version block
    # ------------------------------------------------------------------

    def _parse_ver_block(self) -> None:
        self._consume(_TT_VER)
        ver_constraint = self._parse_versions()
        fun_defs = []
        while self._check(_TT_FUN):
            fun_defs.append(self._parse_fun_def())
        self._consume(_TT_END)
        for fd in fun_defs:
            self._register_fun(fd, ver_constraint)

    def _parse_versions(self) -> list:
        """Parse a comma-separated version constraint list (informational)."""
        versions = [self._parse_version()]
        while self._optional(_TT_CM):
            versions.append(self._parse_version())
        return versions

    def _parse_version(self) -> object:
        if self._check(_TT_IDENT):
            _, name = self._consume(_TT_IDENT)
            return ('class', name.lower())
        # >= / <= / > / <
        if self._optional(_TT_GT):
            if self._optional(_TT_EQ):
                stamp = self._parse_vstamp()
                return ('>=', stamp)
            stamp = self._parse_vstamp()
            return ('>', stamp)
        if self._optional(_TT_LT):
            if self._optional(_TT_EQ):
                stamp = self._parse_vstamp()
                return ('<=', stamp)
            stamp = self._parse_vstamp()
            return ('<', stamp)
        return ('any',)

    def _parse_vstamp(self) -> tuple:
        _, a = self._consume(_TT_INTEGER)
        if not self._optional(_TT_PT):
            return (a, 0, 0, 0)
        _, b = self._consume(_TT_INTEGER)
        if not self._optional(_TT_PT):
            return (a, b, 0, 0)
        _, c = self._consume(_TT_INTEGER)
        if not self._optional(_TT_PT):
            return (a, b, c, 0)
        _, d = self._consume(_TT_INTEGER)
        return (a, b, c, d)

    # ------------------------------------------------------------------
    # Function definition
    # ------------------------------------------------------------------

    def _parse_fun_def(self) -> tuple:
        """Parse one ``fun`` definition.

        Returns ``(ident, ccode_str, flags, op_type, op_module, op_func, overloads, prototypes)``.
        """
        self._consume(_TT_FUN)
        ident1, ident2 = self._parse_ident()
        ccode_str, ccode_flags = self._parse_ccode()
        fun_flags = self._parse_fun_flags()

        self._consume(_TT_LT)
        _, op_type = self._consume(_TT_INTEGER)
        self._consume(_TT_CO)
        op_module = self._parse_module_id()
        self._consume(_TT_CO)
        _, op_func = self._consume(_TT_INTEGER)
        self._consume(_TT_CM)
        _, overloads = self._consume(_TT_INTEGER)
        self._consume(_TT_GT)

        prototypes = self._parse_prototypes()

        all_flags = frozenset(ccode_flags + fun_flags)
        # Disassembler uses the second ident if two are given
        ident = ident2 if ident2 else ident1

        return (ident, ccode_str, all_flags, op_type, op_module, op_func, overloads, prototypes)

    def _parse_ident(self) -> tuple[str, str]:
        """Parse 0, 1, or 2 identifiers.  Returns (first, second) — either may be empty."""
        # 'end' keyword can appear as an ident due to grammar note
        if self._check(_TT_END):
            self._consume()
            return ('end', 'end')
        if not self._check(_TT_IDENT):
            return ('', '')
        _, first = self._consume(_TT_IDENT)
        if self._check(_TT_IDENT):
            _, second = self._consume(_TT_IDENT)
            return (first, second)
        return (first, first)

    def _parse_ccode(self) -> tuple[str, list]:
        """Parse optional control-code spec ``{...}``.

        Returns ``(ccode_name, extra_flags)``.
        """
        if not self._optional(_TT_LBR):
            return ('', [])

        textout_flag = False
        nobrace_flag = False
        lbr_flag = False

        # Flags before the name
        if self._optional(_TT_ST):          # *
            textout_flag = True
        if self._optional(_TT_EQ):          # =
            nobrace_flag = True
            if self._check(_TT_IDENT):
                pass  # name follows

        # Name
        if self._check(_TT_RBR):
            # {} — unnamed
            self._consume(_TT_RBR)
            extra = []
            if textout_flag:
                extra.append('textout')
            if nobrace_flag:
                extra.append('nobrace')
                if lbr_flag:
                    extra.append('lbr')
            return ('__unnamed__', extra)
        elif self._check(_TT_IDENT):
            _, name = self._consume(_TT_IDENT)
            self._consume(_TT_RBR)
            extra = []
            if textout_flag:
                extra.append('textout')
            if nobrace_flag:
                extra.append('nobrace')
                if lbr_flag:
                    extra.append('lbr')
            return (name, extra)
        else:
            # Handle {*=IDENT} — already consumed * (and maybe =)
            # Try reading the remaining part
            if self._check(_TT_EQ) and not nobrace_flag:
                self._consume(_TT_EQ)
                nobrace_flag = True
                lbr_flag = True
            if self._check(_TT_IDENT):
                _, name = self._consume(_TT_IDENT)
            else:
                name = ''
            self._consume(_TT_RBR)
            extra = []
            if textout_flag:
                extra.append('textout')
            if nobrace_flag:
                extra.append('nobrace')
            if lbr_flag:
                extra.append('lbr')
            return (name, extra)

    def _parse_fun_flags(self) -> list[str]:
        """Parse optional ``(flag1 flag2 ...)`` list."""
        if not self._optional(_TT_LP):
            return []
        flags = []
        while not self._check(_TT_RP, _TT_EOF):
            _, name = self._consume(_TT_IDENT)
            mapping = {
                'store': 'store',
                'jump':  'jump',
                'goto':  'goto',
                'if':    'cond',
            }
            flags.append(mapping.get(name.lower(), name.lower()))
        self._consume(_TT_RP)
        return flags

    def _parse_module_id(self) -> int:
        """Parse a module reference (integer or identifier)."""
        if self._check(_TT_INTEGER):
            _, num = self._consume(_TT_INTEGER)
            return num
        _, name = self._consume(_TT_IDENT)
        num = self._modules.get(name)
        if num is None:
            # Unknown module — use 0 as fallback
            return 0
        return num

    # ------------------------------------------------------------------
    # Prototypes
    # ------------------------------------------------------------------

    def _parse_prototypes(self) -> list:
        """Parse one or more prototypes (``?`` or ``(params)``)."""
        protos = []
        while self._check(_TT_QU, _TT_LP):
            if self._optional(_TT_QU):
                protos.append(None)
            else:
                self._consume(_TT_LP)
                params = self._parse_parameters()
                protos.append(params)
        return protos

    def _parse_parameters(self) -> list[FnParam]:
        """Parse a comma-separated parameter list until ``)``.  Consumes the ``)``."""
        params: list[FnParam] = []
        if self._optional(_TT_RP):
            return params
        params.append(self._parse_param())
        while self._optional(_TT_CM):
            params.append(self._parse_param())
        self._consume(_TT_RP)
        return params

    def _parse_param(self) -> FnParam:
        """Parse a single parameter with optional pre/post flags."""
        pre = self._parse_preparm()
        # Determine type — could be a bare STRING (tagged intC shorthand)
        if self._check(_TT_STRING):
            _, tag = self._consume(_TT_STRING)
            post = self._parse_postparm()
            p = FnParam(ptype='intC', tag=tag)
        else:
            ptype, sub_params, special_defs = self._parse_typedef()
            post = self._parse_postparm()
            p = FnParam(ptype=ptype, sub_params=sub_params, special_defs=special_defs)
        # Apply flags
        for f in pre + post:
            if f == 'optional':
                p.optional = True
            elif f == 'uncount':
                p.uncount = True
            elif f == 'return':
                p.is_return = True
            elif f == 'fake':
                p.fake = True
            elif f == 'textobj':
                p.text_obj = True
            elif f == 'argc':
                p.argc = True
            elif f.startswith('tag:'):
                p.tag = f[4:]
        return p

    def _parse_preparm(self) -> list[str]:
        """Parse zero or more prefix flags (stackable)."""
        flags = []
        while True:
            if self._optional(_TT_HA):   # #
                flags.append('textobj')
            elif self._optional(_TT_QU):  # ?
                flags.append('optional')
            elif self._optional(_TT_LT):  # <
                flags.append('uncount')
            elif self._optional(_TT_GT):  # >
                flags.append('return')
            elif self._optional(_TT_EQ):  # =
                flags.append('fake')
            else:
                break
        return flags

    def _parse_postparm(self) -> list[str]:
        """Parse zero or more postfix flags."""
        flags = []
        while True:
            if self._optional(_TT_PL):   # +
                flags.append('argc')
            elif self._check(_TT_STRING):
                _, tag = self._consume(_TT_STRING)
                flags.append(f'tag:{tag}')
            else:
                break
        return flags

    def _parse_typedef(self) -> tuple[str, list, list]:
        """Parse a type specifier.  Returns ``(ptype, sub_params, special_defs)``."""
        tt = self._peek_type()

        if tt == _TT_INT:
            self._consume()
            return ('int', [], [])
        if tt == _TT_INTC:
            self._consume()
            return ('intC', [], [])
        if tt == _TT_INTV:
            self._consume()
            return ('intV', [], [])
        if tt == _TT_STR:
            self._consume()
            return ('str', [], [])
        if tt == _TT_STRC:
            self._consume()
            return ('strC', [], [])
        if tt == _TT_STRV:
            self._consume()
            return ('strV', [], [])
        if tt == _TT_RES:
            self._consume()
            return ('res', [], [])

        if tt == _TT_SPECIAL:
            self._consume()
            self._consume(_TT_LP)
            sdefs = self._parse_special()
            self._consume(_TT_RP)
            return ('special', [], sdefs)

        if tt == _TT_LP:
            self._consume()
            sub = self._parse_complex()
            self._consume(_TT_RP)
            return ('complex', sub, [])

        # Fallback — treat as intC
        return ('intC', [], [])

    def _parse_complex(self) -> list[FnParam]:
        """Parse a complex type: ``compdef (, compdef)*``."""
        params = [self._parse_compdef()]
        while self._optional(_TT_CM):
            params.append(self._parse_compdef())
        return params

    def _parse_compdef(self) -> FnParam:
        """Parse one component of a complex type."""
        if self._check(_TT_STRING):
            _, tag = self._consume(_TT_STRING)
            return FnParam(ptype='intC', tag=tag)
        ptype, sub_params, special_defs = self._parse_typedef()
        tag = ''
        if self._check(_TT_STRING):
            _, tag = self._consume(_TT_STRING)
        return FnParam(ptype=ptype, tag=tag, sub_params=sub_params, special_defs=special_defs)

    def _parse_special(self) -> list:
        """Parse a special type definition list.

        Returns list of ``(id, kind, params, flags)`` where kind is
        ``'named'`` or ``'complex'`` and params is a list of FnParam.
        """
        sdefs = [self._parse_specdef()]
        while self._optional(_TT_CM):
            sdefs.append(self._parse_specdef())
        return sdefs

    def _parse_specdef(self) -> tuple:
        """Parse one specdef: ``INTEGER : [#] IDENT(complex) | [#] {complex}``."""
        _, sid = self._consume(_TT_INTEGER)
        self._consume(_TT_CO)

        # Optional '#' → NoParens flag
        no_parens = self._optional(_TT_HA)

        if self._check(_TT_IDENT):
            _, name = self._consume(_TT_IDENT)
            self._consume(_TT_LP)
            params = self._parse_complex()
            self._consume(_TT_RP)
            return (sid, 'named', name, params, no_parens)
        elif self._optional(_TT_LBR):   # '{' ... '}'
            params = self._parse_complex()
            self._consume(_TT_RBR)
            return (sid, 'complex', '', params, no_parens)
        else:
            return (sid, 'complex', '', [], no_parens)

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def _register_fun(self, fun_def: tuple, ver_constraint: object) -> None:
        """Register all overloads of a function definition into ``self.fndefs``."""
        ident, ccode_str, all_flags, op_type, op_module, op_func, overloads, prototypes = fun_def

        expected = overloads + 1
        if len(prototypes) != expected:
            # Silently pad or truncate rather than hard-failing
            if len(prototypes) < expected:
                prototypes = prototypes + [None] * (expected - len(prototypes))
            else:
                prototypes = prototypes[:expected]

        # Resolve ccode name
        if ccode_str == '__unnamed__':
            ccode = ident
        else:
            ccode = ccode_str

        fndef = FnDef(
            ident=ident if ident else '',
            flags=all_flags,
            ccode=ccode,
            prototypes=prototypes,
        )

        for i, proto in enumerate(prototypes):
            key = (op_type, op_module, op_func, i)
            existing = self.fndefs.get(key)
            if ver_constraint is None:
                # Unconditional → overrides everything
                fndef_i = FnDef(
                    ident=fndef.ident,
                    flags=fndef.flags,
                    ccode=fndef.ccode,
                    prototypes=[proto],
                )
                self.fndefs[key] = fndef_i
            else:
                # Version-constrained → only add if not already present
                if existing is None:
                    fndef_i = FnDef(
                        ident=fndef.ident,
                        flags=fndef.flags,
                        ccode=fndef.ccode,
                        prototypes=[proto],
                    )
                    self.fndefs[key] = fndef_i
                # else: keep existing (most-general wins)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_kfn(path: str | Path) -> tuple[dict, dict]:
    """Parse *path* (a ``.kfn`` file) and return ``(fndefs, module_names)``.

    *fndefs* maps ``(op_type, op_module, op_func, op_overload) → FnDef``.
    *module_names* maps ``module_number → name``.
    """
    text = Path(path).read_text(encoding='latin-1')
    tokens = _tokenize(text)
    parser = _Parser(tokens)
    parser.parse()
    return parser.fndefs, parser.module_names


def find_kfn_path() -> Optional[Path]:
    """Try to auto-locate ``reallive.kfn`` in standard locations.

    Search order:
    1. ``$RLDEV/lib/reallive.kfn``
    2. Repo root ``lib/reallive.kfn`` (relative to this file)
    3. Current working directory ``reallive.kfn``
    """
    import os

    # Environment variable
    rldev = os.environ.get('RLDEV')
    if rldev:
        candidate = Path(rldev) / 'lib' / 'reallive.kfn'
        if candidate.exists():
            return candidate

    # Relative to this file: src/python/kprl/kfn.py → ../../../../lib/reallive.kfn
    here = Path(__file__).parent
    for up in range(5):
        candidate = here / 'lib' / 'reallive.kfn'
        if candidate.exists():
            return candidate
        here = here.parent

    # CWD
    candidate = Path('reallive.kfn')
    if candidate.exists():
        return candidate

    return None
