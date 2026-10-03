"""
The outbound contract: what an answer must look like before it reaches the phone.

Every reply goes through the same steps, in this order:

  1. scrub      secrets and personal data are replaced by a placeholder:
                credentials inside URLs (https://user:token@host), private
                key blocks, API keys and bot tokens and JWTs (the same
                patterns sancho.recall keeps out of its index), e-mail
                addresses, phone numbers, card-like numbers (Luhn-valid),
                US social security numbers, long digit ids (8+ digits), plus
                any extra regexes in config "outbound".
                The permission gate is the first line of defence; this is the
                second net, for data that reached the model legitimately.
  2. detable    Markdown tables become one readable line per row. A phone
                cannot show a table; it can show a list.
  3. plain      heading hashes, bold markers and code fences are removed, so
                the text reads cleanly without any parse mode.
  4. cut        the first N lines (default 10) go out. The full text is stored
                in state_dir("detail")/<id>.md and a "More" button, or /more,
                sends the rest.
  5. chunk      each message stays under Telegram's 4096-character limit.

The cut is enforced mechanically, not requested politely in a prompt.

Configuration ("outbound" section):
  max_lines        lines sent before the "More" button             default 10
  scrub_patterns   extra regexes whose matches are redacted        default []
"""
from __future__ import annotations

import os
import re
import secrets as _random
from dataclasses import dataclass

from sancho import config
from sancho.recall import _PHONE as _PHONE_GROUPED
from sancho.recall import _SECRET
from sancho.telegram import MAX_MESSAGE, split_text

DEFAULT_MAX_LINES = 10
KEEP_DETAILS = 50               # detail files kept on disk; older ones are pruned
DETAIL_ID = re.compile(r"^[0-9a-f]{12}$")

_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_CARD = re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])")
_PHONE_INTL = re.compile(r"(?<![\w+])\+\d(?:[\s().-]*\d){6,14}(?!\d)")
_PHONE_LOCAL = re.compile(r"(?<!\d)\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)")
_LONG_ID = re.compile(r"(?<![\w])\d{8,}(?![\w])")
_URL_CREDENTIALS = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@]+@")
_PRIVATE_KEY = re.compile(r"-{4,}\s*BEGIN[ A-Z]*PRIVATE KEY(?: BLOCK)?\s*-{4,}.*?"
                          r"(?:-{4,}\s*END[ A-Z]*PRIVATE KEY(?: BLOCK)?\s*-{4,}|\Z)",
                          re.S | re.I)
_SSN = re.compile(r"(?<![\w-])\d{3}([- ])\d{2}\1\d{4}(?![\w-])")

_ROW = re.compile(r"^\s*\|(.+)\|\s*$")
_SEPARATOR = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")
_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(.*?)\s*#*\s*$")
_FENCE = re.compile(r"^\s*```.*$")


# ── 1. scrub ─────────────────────────────────────────────────────────────────

def _luhn_ok(digits: str) -> bool:
    total, double = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if double:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
        double = not double
    return total % 10 == 0


def _extra_patterns() -> list[re.Pattern]:
    compiled = []
    for pattern in config.get("outbound", "scrub_patterns", []):
        try:
            compiled.append(re.compile(str(pattern)))
        except re.error:
            continue            # a broken pattern in config must not mute the bot
    return compiled


def scrub(text: str) -> str:
    """Replace secrets and personal data with placeholders."""
    text = text or ""
    text = _URL_CREDENTIALS.sub(r"\1[credentials]@", text)
    text = _PRIVATE_KEY.sub("[private key]", text)
    text = _SECRET.sub("[secret]", text)
    text = _EMAIL.sub("[email]", text)

    def card(m: re.Match) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        return "[card]" if 13 <= len(digits) <= 19 and _luhn_ok(digits) else m.group(0)

    text = _CARD.sub(card, text)
    text = _PHONE_INTL.sub("[phone]", text)
    text = _PHONE_LOCAL.sub("[phone]", text)
    text = _PHONE_GROUPED.sub("[phone]", text)
    text = _SSN.sub("[ssn]", text)
    text = _LONG_ID.sub("[id]", text)
    for pattern in _extra_patterns():
        text = pattern.sub("[redacted]", text)
    return text


# ── 2. detable ───────────────────────────────────────────────────────────────

def _cells(line: str) -> list[str]:
    return [c.strip() for c in _ROW.match(line).group(1).split("|")]


def _table(rows: list[str]) -> list[str]:
    header, body = None, rows
    if len(rows) > 1 and _SEPARATOR.match(rows[1]):
        header, body = _cells(rows[0]), rows[2:]
    out = []
    for row in body:
        if _SEPARATOR.match(row):
            continue
        cells = _cells(row)
        first, rest = cells[0], cells[1:]
        if header and len(header) >= 3:
            labelled = [f"{h}: {v}" for h, v in zip(header[1:], rest) if v]
            out.append(f"• {first} — " + " · ".join(labelled) if labelled else f"• {first}")
        else:
            out.append(" — ".join([f"• {first}"] + [v for v in rest if v]))
    return out


def detable(text: str) -> str:
    """Markdown tables → one bullet per row. With three or more columns the
    header names travel with the values, since a row alone loses its meaning."""
    lines = (text or "").split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        if _ROW.match(lines[i]):
            j = i
            while j < len(lines) and (_ROW.match(lines[j]) or _SEPARATOR.match(lines[j])):
                j += 1
            out.extend(_table(lines[i:j]))
            i = j
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


# ── 3. plain ─────────────────────────────────────────────────────────────────

def plain(text: str) -> str:
    """Strip the Markdown that would show up as literal symbols."""
    out = []
    for line in (text or "").split("\n"):
        if _FENCE.match(line):
            continue
        m = _HEADING.match(line)
        if m:
            line = m.group(1)
        line = re.sub(r"^(\s*)[-*+]\s+", r"\1• ", line)
        line = line.replace("**", "").replace("__", "")
        out.append(line.rstrip())
    return re.sub(r"\n{3,}", "\n\n", "\n".join(out)).strip()


# ── 4. cut ───────────────────────────────────────────────────────────────────

def max_lines() -> int:
    return max(1, config.get("outbound", "max_lines", DEFAULT_MAX_LINES))


def _split_lines(text: str, limit: int) -> tuple[str, str]:
    lines = text.split("\n")
    return "\n".join(lines[:limit]), "\n".join(lines[limit:]).strip("\n")


def detail_dir() -> str:
    return config.state_dir("detail")


def _prune() -> None:
    folder = detail_dir()
    files = sorted((os.path.join(folder, f) for f in os.listdir(folder) if f.endswith(".md")),
                   key=os.path.getmtime, reverse=True)
    for old in files[KEEP_DETAILS:]:
        try:
            os.remove(old)
        except OSError:
            pass


def store_detail(text: str) -> str:
    detail_id = _random.token_hex(6)
    path = os.path.join(detail_dir(), f"{detail_id}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    _prune()
    return detail_id


def rest_of(detail_id: str) -> str | None:
    """The part of a stored answer that was not sent, or None if unknown."""
    if not DETAIL_ID.match(detail_id or ""):
        return None
    try:
        with open(os.path.join(detail_dir(), f"{detail_id}.md"), encoding="utf-8") as f:
            full = f.read()
    except OSError:
        return None
    return _split_lines(full, max_lines())[1] or None


def latest_detail_id() -> str | None:
    folder = detail_dir()
    files = [f for f in os.listdir(folder) if f.endswith(".md") and DETAIL_ID.match(f[:-3])]
    if not files:
        return None
    return max(files, key=lambda f: os.path.getmtime(os.path.join(folder, f)))[:-3]


@dataclass
class Reply:
    head: str                   # what goes out now
    detail_id: str | None       # set when there is more to send on request


def prepare(text: str) -> Reply:
    """Run the whole contract on one answer."""
    clean = plain(detable(scrub(text)))
    head, rest = _split_lines(clean, max_lines())
    if not rest:
        return Reply(clean, None)
    return Reply(head + "\n…", store_detail(clean))


# ── 5. chunk ─────────────────────────────────────────────────────────────────

def chunks(text: str, limit: int = MAX_MESSAGE) -> list[str]:
    return split_text(text, min(limit, MAX_MESSAGE))
