"""
Take a Bash command apart into the pieces the gate has to judge separately.

A gate that only looks at the first word of a command misses almost everything
that matters: the write lives in `> file`, the delete lives after `&&`, the
secret lives in `$(cat ~/.ssh/id_rsa)`. So a command is decomposed into
simple commands (segments), each with

  words         argv after quote removal, with flags per word: did it contain
                a command substitution (dynamic), an unquoted glob, an unquoted
                brace expression, which variables it expands
  assignments   NAME=value words in front of the program
  redirects     > >> >| &> &>> >& (writes), < <> (reads), <& >& n (fd dups),
                << <<- (heredocs), <<< (here-strings)
  depth         0 for the top level; command substitutions ($(...), `...`)
                and process substitutions (<(...), >(...)) are parsed
                recursively and their commands become segments of their own

Separators are ; ;; & && || | |& ( ) and newlines, outside quotes.

Heredoc bodies are stdin DATA, never commands: they are kept on the segment
that opens them and are not split into segments. An unquoted heredoc
delimiter (<<EOF, as opposed to <<'EOF') lets the shell expand $VAR and run
$(...) inside the body, so those are still recorded. In such a body the shell
also joins a line ending in a backslash with the next one before looking for
the delimiter, so where the body ends depends on that joining: a body line
ending in a backslash is refused (ParseError).

Anything this parser cannot take apart (unbalanced quotes or parentheses, a
heredoc without its terminator, ANSI-C strings with escapes, nesting deeper
than MAX_DEPTH) raises ParseError, and the gate denies the call.

Pure: no I/O, no configuration.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_DEPTH = 8
MAX_BRACE_RESULTS = 256

# Redirection targets that are not files on disk.
NULL_SINKS = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"})

# Reserved words that may start a segment and are not programs.
KEYWORDS = frozenset({"!", "{", "}", "then", "do", "else", "elif", "if", "while",
                      "until", "fi", "done", "esac", "time"})

# Keywords that end a compound command; redirections after them apply to it.
_CLOSERS = frozenset({"}", "done", "fi", "esac"})

SEPARATORS = frozenset({";", ";;", "&", "&&", "||", "|", "|&", "(", ")"})
REDIRECTS = ("<<<", "<<-", "&>>", ">>", "<<", ">|", "<>", ">&", "<&", "&>", "<", ">")
_OPERATOR_CHARS = set(";&|()<>")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=")
_SPECIAL_PARAMS = set("0123456789@*#?-$!")
SUBST = "\x00"   # stands in for a substitution inside Word.text


class ParseError(ValueError):
    """The command could not be taken apart; the caller must deny it."""


@dataclass
class Word:
    text: str                     # after quote removal; SUBST marks a substitution
    mask: tuple = ()              # per character of text: True when it was quoted
    dynamic: bool = False         # contains $(...), `...`, $((...)) or $1/$@/...
    expansions: list = field(default_factory=list)   # variable names expanded

    @property
    def quoted(self) -> bool:
        return any(self.mask)

    def _unquoted(self, chars: str) -> bool:
        return any(c in chars and not q for c, q in zip(self.text, self.mask))

    @property
    def glob(self) -> bool:
        """Unquoted * ? [ : the shell will expand it against the filesystem."""
        return self._unquoted("*?[")

    @property
    def brace(self) -> bool:
        """Unquoted {a,b} or {a..b}: the shell will expand it into several words."""
        return len(expand_braces(self)) > 1

    def __str__(self) -> str:
        return self.text


@dataclass
class Heredoc:
    delimiter: str
    quoted: bool                  # <<'EOF': the body is literal
    strip_tabs: bool              # <<-EOF
    body: str = ""


@dataclass
class Redirect:
    op: str
    fd: str = ""
    target: Word | None = None
    heredoc: Heredoc | None = None

    @property
    def kind(self) -> str:
        """write | read | dup | heredoc | herestring"""
        if self.op in ("<<", "<<-"):
            return "heredoc"
        if self.op == "<<<":
            return "herestring"
        if self.op in (">&", "<&"):
            t = self.target.text if self.target else ""
            if t == "-" or t.isdigit():
                return "dup"
            return "write" if self.op == ">&" else "read"
        if self.op in ("<", "<>"):
            return "read" if self.op == "<" else "write"
        return "write"


@dataclass
class Segment:
    words: list = field(default_factory=list)          # list[Word]
    assignments: list = field(default_factory=list)    # list[Word]
    redirects: list = field(default_factory=list)      # list[Redirect]
    depth: int = 0
    closes: bool = False          # follows `)`, `}`, `done`, `fi` or `esac`: its
                                  # redirections apply to that compound command

    @property
    def argv(self) -> list[str]:
        return [w.text for w in self.words]

    @property
    def heredocs(self) -> list[Heredoc]:
        return [r.heredoc for r in self.redirects if r.heredoc is not None]

    def targets(self, kind: str) -> list[Word]:
        """Redirect targets of one kind ("write" or "read"), null sinks removed."""
        out = []
        for r in self.redirects:
            if r.kind == kind and r.target is not None:
                if r.target.text in NULL_SINKS or r.target.text.startswith("/dev/fd/"):
                    continue
                out.append(r.target)
        return out


@dataclass
class Parsed:
    source: str
    segments: list = field(default_factory=list)       # list[Segment], in source order
    expansions: list = field(default_factory=list)     # every variable name expanded


# ── public entry points ──────────────────────────────────────────────────────

def parse(command: str) -> Parsed:
    """Decompose a command. Raises ParseError when it cannot."""
    if not isinstance(command, str):
        raise ParseError("command is not a string")
    result = Parsed(source=command)
    _Lexer(command, 0, result).run()
    return result


def split(command: str) -> list[list[str]]:
    """The argv of every segment, nested ones included."""
    return [s.argv for s in parse(command).segments]


def expand_braces(word: Word) -> list[str]:
    """Brace expansion of the unquoted {a,b} and {1..3} parts of a word.

    Returns [word.text] when there is nothing to expand. Raises ParseError when
    the expansion would produce more than MAX_BRACE_RESULTS words.
    """
    results = _expand(word.text, list(word.mask))
    if len(results) > MAX_BRACE_RESULTS:
        raise ParseError("brace expansion too large")
    return results


# ── brace expansion ──────────────────────────────────────────────────────────

def _expand(text: str, mask: list) -> list[str]:
    # find the first unquoted "{" that has a matching unquoted "}" with a
    # top-level "," or a ".." range inside
    for start, ch in enumerate(text):
        if ch != "{" or mask[start]:
            continue
        depth, commas, end = 0, [], -1
        for j in range(start, len(text)):
            if mask[j]:
                continue
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    end = j
                    break
            elif text[j] == "," and depth == 1:
                commas.append(j)
        if end < 0:
            continue
        pre, post = text[:start], text[end + 1:]
        pre_m, post_m = mask[:start], mask[end + 1:]
        if commas:
            bounds = [start] + commas + [end]
            alts = [(text[a + 1:b], mask[a + 1:b]) for a, b in zip(bounds, bounds[1:])]
        else:
            inner = text[start + 1:end]
            items = _range(inner) if not any(mask[start + 1:end]) else None
            if items is None:
                continue
            alts = [(s, [True] * len(s)) for s in items]
        out: list[str] = []
        for alt, alt_m in alts:
            for tail in _expand(alt + post, list(alt_m) + list(post_m)):
                out.append(pre + tail)
                if len(out) > MAX_BRACE_RESULTS:
                    raise ParseError("brace expansion too large")
        # the prefix may itself hold an earlier, non-expanding "{"; it is literal
        return out
    return [text]


def _range(inner: str):
    m = re.fullmatch(r"(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?", inner)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        step = abs(int(m.group(3) or 1)) or 1
        if abs(b - a) // step > MAX_BRACE_RESULTS:
            raise ParseError("brace expansion too large")
        rng = range(a, b + 1, step) if a <= b else range(a, b - 1, -step)
        return [str(i) for i in rng]
    m = re.fullmatch(r"([A-Za-z])\.\.([A-Za-z])", inner)
    if m:
        a, b = ord(m.group(1)), ord(m.group(2))
        rng = range(a, b + 1) if a <= b else range(a, b - 1, -1)
        return [chr(i) for i in rng]
    return None


# ── lexer ────────────────────────────────────────────────────────────────────

class _WordBuilder:
    def __init__(self) -> None:
        self.chars: list[str] = []
        self.mask: list[bool] = []
        self.dynamic = False
        self.expansions: list[str] = []
        self.started = False

    def add(self, text: str, quoted: bool) -> None:
        self.started = True
        self.chars.extend(text)
        self.mask.extend([quoted] * len(text))

    def word(self) -> Word:
        return Word("".join(self.chars), tuple(self.mask), self.dynamic, self.expansions)


class _Lexer:
    def __init__(self, src: str, depth: int, result: Parsed) -> None:
        if depth > MAX_DEPTH:
            raise ParseError("command nesting too deep")
        self.s = src
        self.i = 0
        self.depth = depth
        self.result = result
        self.tokens: list[tuple] = []
        self.pending: list[Heredoc] = []

    # -- helpers ------------------------------------------------------------
    def _expansion(self, name: str, wb: _WordBuilder | None) -> None:
        self.result.expansions.append(name)
        if wb is not None:
            wb.expansions.append(name)

    def _nested(self, body: str) -> None:
        _Lexer(body, self.depth + 1, self.result).run()

    # -- main loop ----------------------------------------------------------
    def run(self) -> None:
        s = self.s
        while self.i < len(s):
            c = s[self.i]
            if c in " \t\r":
                self.i += 1
            elif c == "\\" and s[self.i + 1:self.i + 2] == "\n":
                self.i += 2
            elif c == "#":
                while self.i < len(s) and s[self.i] != "\n":
                    self.i += 1
            elif c == "\n":
                self.i += 1
                self.tokens.append(("sep", "\n"))
                if self.pending:
                    self._read_heredoc_bodies()
            elif c in "<>" and s[self.i + 1:self.i + 2] == "(":
                self._word()                     # process substitution
            elif c in _OPERATOR_CHARS or (c.isdigit() and re.match(r"\d+[<>]", s[self.i:])):
                self._operator()
            else:
                self._word()
        if self.pending:
            raise ParseError(f"heredoc without its terminator: {self.pending[0].delimiter}")
        self._group()

    def _operator(self) -> None:
        s = self.s
        fd = ""
        m = re.match(r"\d+", s[self.i:])
        if m and s[self.i + len(m.group()):self.i + len(m.group()) + 1] in ("<", ">"):
            fd = m.group()
            self.i += len(fd)
        for op in REDIRECTS:
            if s.startswith(op, self.i):
                self.i += len(op)
                self.tokens.append(("redir", op, fd))
                return
        for op in (";;", "&&", "||", "|&", ";", "&", "|", "(", ")"):
            if s.startswith(op, self.i):
                self.i += len(op)
                self.tokens.append(("sep", op))
                return
        raise ParseError(f"unexpected character {s[self.i]!r}")

    def _word(self) -> None:
        s = self.s
        wb = _WordBuilder()
        while self.i < len(s):
            c = s[self.i]
            if c in " \t\r\n":
                break
            if c in "<>" and s[self.i + 1:self.i + 2] == "(":
                end = _find_close(s, self.i + 2)
                self._nested(s[self.i + 2:end])
                wb.add(SUBST, False)
                wb.dynamic = True
                self.i = end + 1
                continue
            if c in _OPERATOR_CHARS:
                break
            if c == "\\":
                nxt = s[self.i + 1:self.i + 2]
                if nxt == "\n":
                    self.i += 2
                    continue
                if not nxt:
                    raise ParseError("trailing backslash")
                wb.add(nxt, True)
                self.i += 2
            elif c == "'":
                end = s.find("'", self.i + 1)
                if end < 0:
                    raise ParseError("unbalanced single quote")
                wb.add(s[self.i + 1:end], True)
                wb.started = True
                self.i = end + 1
            elif c == '"':
                self.i += 1
                self._double_quoted(wb)
            elif c == "$":
                self._dollar(wb, quoted=False)
            elif c == "`":
                self._backtick(wb)
            else:
                wb.add(c, False)
                self.i += 1
        if wb.started:
            self.tokens.append(("word", wb.word()))
            if self.tokens[-2:-1] and self.tokens[-2][0] == "redir" \
                    and self.tokens[-2][1] in ("<<", "<<-"):
                w = self.tokens[-1][1]
                hd = Heredoc(w.text, w.quoted, self.tokens[-2][1] == "<<-")
                self.pending.append(hd)
                self.tokens[-1] = ("word", w, hd)

    def _double_quoted(self, wb: _WordBuilder) -> None:
        """Read up to the closing quote; self.i is just past the opening one."""
        s = self.s
        wb.started = True
        while True:
            if self.i >= len(s):
                raise ParseError("unbalanced double quote")
            c = s[self.i]
            if c == '"':
                self.i += 1
                return
            if c == "\\" and self.i + 1 < len(s):
                nxt = s[self.i + 1]
                if nxt == "\n":
                    self.i += 2
                    continue
                if nxt in '$`"\\':
                    wb.add(nxt, True)
                    self.i += 2
                    continue
                wb.add("\\", True)
                self.i += 1
            elif c == "$":
                self._dollar(wb, quoted=True)
            elif c == "`":
                self._backtick(wb)
            else:
                wb.add(c, True)
                self.i += 1

    def _backtick(self, wb: _WordBuilder) -> None:
        s = self.s
        j = self.i + 1
        body: list[str] = []
        while True:
            if j >= len(s):
                raise ParseError("unbalanced backtick")
            c = s[j]
            if c == "\\" and j + 1 < len(s) and s[j + 1] in "`$\\":
                body.append(s[j + 1])
                j += 2
                continue
            if c == "`":
                break
            body.append(c)
            j += 1
        self._nested("".join(body))
        wb.add(SUBST, False)
        wb.dynamic = True
        self.i = j + 1

    def _dollar(self, wb: _WordBuilder, quoted: bool) -> None:
        s = self.s
        i = self.i
        nxt = s[i + 1:i + 2]
        if nxt == "(":
            end = _find_close(s, i + 2)          # closes the "(" of "$("
            if s[i + 2:i + 3] == "(" and _find_close(s, i + 3) == end - 1:
                # $(( arithmetic )): every name in it is a variable read
                body = s[i + 3:end - 1]
                for name in _NAME.findall(body):
                    self._expansion(name, wb)
            else:
                self._nested(s[i + 2:end])
            wb.add(SUBST, False)
            wb.dynamic = True
            self.i = end + 1
        elif nxt == "{":
            end = _find_brace_close(s, i + 2)
            inner = s[i + 2:end]
            m = re.match(r"[!#]?([A-Za-z_][A-Za-z0-9_]*)", inner)
            if m:
                self._expansion(m.group(1), wb)
            elif not inner or inner.lstrip("!#")[:1] not in _SPECIAL_PARAMS:
                raise ParseError("unreadable ${...} expansion")
            if "$(" in inner or "`" in inner:
                self._nested(re.sub(r"^[^$`]*", "", inner))
            wb.add(SUBST, False)
            wb.dynamic = True
            self.i = end + 1
        elif nxt == "'" and not quoted:
            end = s.find("'", i + 2)
            if end < 0:
                raise ParseError("unbalanced $'...' string")
            body = s[i + 2:end]
            if "\\" in body:
                raise ParseError("$'...' string with escapes")
            wb.add(body, True)
            self.i = end + 1
        elif nxt == '"' and not quoted:
            self.i = i + 2
            self._double_quoted(wb)
        elif nxt and _NAME.match(nxt):
            m = _NAME.match(s, i + 1)
            self._expansion(m.group(), wb)
            wb.add(SUBST, False)
            wb.dynamic = True
            self.i = m.end()
        elif nxt and nxt in _SPECIAL_PARAMS:
            wb.add(SUBST, False)
            wb.dynamic = True
            self.i = i + 2
        else:
            wb.add("$", quoted)
            self.i = i + 1

    def _read_heredoc_bodies(self) -> None:
        s = self.s
        for hd in self.pending:
            lines: list[str] = []
            while True:
                if self.i >= len(s):
                    raise ParseError(f"heredoc without its terminator: {hd.delimiter}")
                end = s.find("\n", self.i)
                line = s[self.i:] if end < 0 else s[self.i:end]
                self.i = len(s) if end < 0 else end + 1
                check = line.lstrip("\t") if hd.strip_tabs else line
                if check == hd.delimiter:
                    break
                if not hd.quoted and check.endswith("\\"):
                    raise ParseError("unquoted heredoc with a line ending in a backslash: "
                                     "the shell joins it with the next line")
                lines.append(check)
            hd.body = "\n".join(lines)
            if not hd.quoted:
                _scan_expanding_text(hd.body, self)
        self.pending = []

    # -- grouping -----------------------------------------------------------
    def _group(self) -> None:
        seg = Segment(depth=self.depth)
        toks = self.tokens
        k = 0
        open_parens = 0               # a `)` without one is a case pattern, not a subshell
        while k < len(toks):
            t = toks[k]
            if t[0] == "sep":
                self._finish(seg)
                closes = t[1] == ")" and open_parens > 0
                open_parens += {"(": 1, ")": -1 if closes else 0}.get(t[1], 0)
                seg = Segment(depth=self.depth, closes=closes)
            elif t[0] == "redir":
                if k + 1 >= len(toks) or toks[k + 1][0] != "word":
                    raise ParseError(f"redirection {t[1]} without a target")
                nxt = toks[k + 1]
                seg.redirects.append(Redirect(t[1], t[2], nxt[1], nxt[2] if len(nxt) > 2 else None))
                k += 1
            else:
                seg.words.append(t[1])
            k += 1
        self._finish(seg)

    def _finish(self, seg: Segment) -> None:
        words = seg.words
        changed = True
        while changed:
            changed = False
            while words and not words[0].quoted and words[0].text in KEYWORDS:
                if words[0].text in _CLOSERS:
                    seg.closes = True
                words.pop(0)
                changed = True
                if words and words[0].text == "-p" and not words[0].quoted:
                    words.pop(0)      # time -p
            while words and _ASSIGN.match(words[0].text) \
                    and not any(words[0].mask[:words[0].text.index("=")]):
                seg.assignments.append(words.pop(0))
                changed = True
        if words and not words[-1].quoted and words[-1].text == "}":
            words.pop()
            if not words:
                seg.closes = True
        if seg.words or seg.redirects or seg.assignments:
            self.result.segments.append(seg)


def _scan_expanding_text(text: str, lexer: _Lexer) -> None:
    """Record expansions and parse substitutions in an unquoted heredoc body."""
    # The body behaves like the inside of a double-quoted string, except that a
    # double quote is literal: \$ \` \\ escape, $ and ` expand.
    sub = _Lexer(text, lexer.depth, lexer.result)
    wb = _WordBuilder()
    while sub.i < len(text):
        c = text[sub.i]
        if c == "\\":
            sub.i += 2
        elif c == "$":
            sub._dollar(wb, quoted=True)
        elif c == "`":
            sub._backtick(wb)
        else:
            sub.i += 1


# ── bracket matching (quote- and heredoc-aware) ──────────────────────────────

def _find_close(s: str, i: int) -> int:
    """Index of the ")" that closes the "(" just before position i."""
    depth = 1
    pending: list[tuple[str, bool]] = []
    at_word_start = True
    while i < len(s):
        c = s[i]
        if c == "\\":
            i += 2
            at_word_start = False
            continue
        if c == "'":
            end = s.find("'", i + 1)
            if end < 0:
                raise ParseError("unbalanced single quote")
            i = end + 1
            at_word_start = False
            continue
        if c == '"':
            i = _skip_double(s, i + 1)
            at_word_start = False
            continue
        if c == "`":
            end = i + 1
            while end < len(s) and s[end] != "`":
                end += 2 if s[end] == "\\" else 1
            if end >= len(s):
                raise ParseError("unbalanced backtick")
            i = end + 1
            continue
        if c == "#" and at_word_start:
            while i < len(s) and s[i] != "\n":
                i += 1
            continue
        if c == "<" and s.startswith("<<", i) and not s.startswith("<<<", i):
            j = i + 2
            strip = s[j:j + 1] == "-"
            if strip:
                j += 1
            while j < len(s) and s[j] in " \t":
                j += 1
            m = re.match(r"""(['"]?)([^\s;&|()<>'"]+)\1""", s[j:])
            if not m:
                raise ParseError("heredoc without a delimiter")
            pending.append((m.group(2), strip))
            i = j + len(m.group())
            continue
        if c == "\n" and pending:
            i += 1
            for delim, strip in pending:
                while True:
                    if i >= len(s):
                        raise ParseError(f"heredoc without its terminator: {delim}")
                    end = s.find("\n", i)
                    line = s[i:] if end < 0 else s[i:end]
                    i = len(s) if end < 0 else end + 1
                    if (line.lstrip("\t") if strip else line) == delim:
                        break
            pending = []
            at_word_start = True
            continue
        if c == "$" and s[i + 1:i + 2] == "(":
            i = _find_close(s, i + 2) + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        at_word_start = c in " \t\n;&|("
        i += 1
    raise ParseError("unbalanced parenthesis")


def _skip_double(s: str, i: int) -> int:
    """Index just past the closing double quote; i is just past the opening one."""
    while i < len(s):
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i + 1
        if c == "$" and s[i + 1:i + 2] == "(":
            i = _find_close(s, i + 2) + 1
            continue
        if c == "`":
            end = i + 1
            while end < len(s) and s[end] != "`":
                end += 2 if s[end] == "\\" else 1
            i = end + 1
            continue
        i += 1
    raise ParseError("unbalanced double quote")


def _find_brace_close(s: str, i: int) -> int:
    depth = 1
    while i < len(s):
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "'":
            end = s.find("'", i + 1)
            if end < 0:
                raise ParseError("unbalanced single quote")
            i = end + 1
            continue
        if c == '"':
            i = _skip_double(s, i + 1)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ParseError("unbalanced ${")
