"""
Recall: full-text search over past Claude Code sessions, without opening them.

Claude Code keeps every session as a JSON-lines transcript under
`~/.claude/projects/<encoded-cwd>/<session-id>.jsonl`. Those files are the best
record of "where did we leave X" — and also raw, unfiltered text. This module is
the only door to them: it builds a local SQLite FTS5 index and answers queries
with a timestamp, a project label and a short, redacted snippet. It never
returns a whole turn and never returns a transcript path.

Privacy rules, enforced in code:

  * Files and working directories matched by `recall.exclude_globs` are never
    read, and rows already indexed from them are purged on the next refresh.
    Search results are filtered against the same globs as a second net, so a
    newly added glob takes effect immediately.
  * Emails, phone numbers, card-like numbers, long digit ids and common API-key
    shapes are redacted BEFORE text is written to the index, and snippets are
    redacted again on the way out. What is never stored cannot leak later.
  * Only what was said is indexed: user and assistant text blocks. Tool output,
    hidden reasoning and harness notices are skipped.

Indexing is incremental: a file is re-read only when its size or mtime changed.

Configuration (`config.json`, section "recall"; every key optional):

  transcripts_root  "~/.claude/projects"  where the .jsonl transcripts live
  exclude_globs     []                    fnmatch patterns; see `is_excluded`
  project_roots     []                    folders whose direct children are
                                          "projects" (improves project labels)
  snippet_chars     240                   snippet length
  min_chars         15                    shorter turns ("ok", "go on") are skipped

CLI:
  python3 -m sancho.recall "query words"        search (refreshes the index first)
  python3 -m sancho.recall --project NAME QUERY
  python3 -m sancho.recall --index              refresh the index and print stats
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sqlite3
import sys
from typing import Iterator

from sancho import config

SCHEMA_VERSION = 1

# Harness plumbing that shows up as "user" turns. Indexing it buries what was
# actually said under reminders and notifications.
NOISE_MARKERS = (
    "<system-reminder>", "<task-notification>", "<command-name>",
    "<local-command-stdout>", "hook feedback", "[Request interrupted",
)

# ── redaction ────────────────────────────────────────────────────────────────
# This filter guards what goes INTO the index. The outbound filter reuses
# _SECRET and _PHONE, so a secret kept out of the index is also kept off the
# phone.

# No \b: a key glued to a letter or "_" (my_sk-..., bot123:AA... in a URL) must
# still match, so only alphanumerics in front block a match.
_SECRET = re.compile(r"""(?x)
      (?<![A-Za-z0-9])sk-[A-Za-z0-9_\-]{20,}                  # common LLM API keys
    | (?<![A-Za-z0-9])[sr]k_(?:live|test)_[A-Za-z0-9]{10,}     # payment API keys
    | (?<![A-Za-z0-9])(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}
    | (?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])       # cloud access key ids
    | AIza[0-9A-Za-z_\-]{35}                                  # cloud API keys
    | (?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}
    | \d{8,10}:AA[A-Za-z0-9_\-]{30,}                          # chat-bot tokens
    | eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]*   # JWT, maybe unsigned
    | (?<![A-Za-z0-9])(?:hf_|glpat-|r8_|npm_)[A-Za-z0-9]{20,}
    | (?<![A-Za-z0-9])SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}  # mail API keys
    | (?i:-{4,}\s*BEGIN[ A-Z]*PRIVATE\ KEY(?:\ BLOCK)?\s*-{4,})
""")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
# Masked card notation: 411111XXXXXX0000, ****0000, "ending in 0000".
_MASKED_CARD = re.compile(
    r"(?i)\b\d{4,6}[X*\u2022]{4,8}\d{4}\b|\*{3,}\s?\d{4}\b|\bending\s+in\s+\d{3,}\b")
# 13-19 contiguous digits, or the usual printed groupings (4-4-4-4, 4-6-5).
# Groups must be regular so that two adjacent dates are not taken for a card.
_CARD = re.compile(r"""(?x)(?<![\w-])(?:
      \d{13,19}
    | \d{4}([ -])\d{4}\1\d{4}\1\d{1,7}
    | \d{4}([ -])\d{6}\2\d{5}
)(?![\w-])""")
# International (+CC ...) or grouped local numbers: (555) 010-0000, 555-010-0000.
# Dates (2024-01-31) and times do not match: the middle group needs 3+ digits.
_PHONE = re.compile(r"""(?x)
      (?<![\w+])\+\d{1,3}(?:[\s-]?\(?\d{1,4}\)?){2,5}(?!\w)
    | (?<![\w-])(?:\(\d{2,4}\)\s?|\d{3,4}[\s-])\d{3,4}[\s-]\d{3,4}(?![\w-])
""")
_LONG_DIGITS = re.compile(r"(?<![\w-])\d{7,}(?![\w-])")

_REDACTIONS = (
    (_SECRET, "[secret]"),
    (_EMAIL, "[email]"),
    (_MASKED_CARD, "[card]"),
    (_CARD, "[card]"),
    (_PHONE, "[phone]"),
    (_LONG_DIGITS, "[number]"),
)


def redact(text: str) -> str:
    """Replace secrets, emails, card numbers, phones and long digit ids."""
    for pattern, marker in _REDACTIONS:
        text = pattern.sub(marker, text)
    return text


# ── configuration helpers ────────────────────────────────────────────────────

def transcripts_root() -> str:
    return config.expand(config.get("recall", "transcripts_root", "~/.claude/projects"))


def db_path() -> str:
    return os.path.join(config.state_dir("recall"), "recall.db")


def _exclude_globs() -> list[str]:
    globs = config.get("recall", "exclude_globs", [])
    return [g for g in globs if isinstance(g, str) and g.strip()]


def is_excluded(path: str, globs: list[str] | None = None) -> bool:
    """True when `path` matches any exclude glob.

    Each glob is tried against the absolute path (with `~` expanded in the
    glob), against the path relative to the transcripts root, and against every
    single path component. `*` also crosses `/`, so `*client-data*` excludes any
    path that contains that fragment anywhere. Matching is case-sensitive, like
    the filesystem paths it guards.
    """
    globs = _exclude_globs() if globs is None else globs
    if not globs or not path:
        return False
    absolute = os.path.abspath(os.path.expanduser(path))
    root = transcripts_root()
    rel = os.path.relpath(absolute, root) if absolute.startswith(root + os.sep) else None
    parts = [p for p in absolute.split(os.sep) if p]
    for glob in globs:
        expanded = os.path.expanduser(glob)
        if fnmatch.fnmatchcase(absolute, expanded):
            return True
        if rel is not None and fnmatch.fnmatchcase(rel, glob):
            return True
        if any(fnmatch.fnmatchcase(part, glob) for part in parts):
            return True
    return False


# ── transcript parsing ───────────────────────────────────────────────────────

def _text_of(content) -> str:
    """Only spoken text: plain strings and `text` blocks; no tool I/O, no thinking."""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    out = []
    for block in content:
        if isinstance(block, str):
            out.append(block)
        elif isinstance(block, dict) and block.get("type") == "text":
            out.append(str(block.get("text") or ""))
    return "\n".join(out)


def project_label(cwd: str, folder: str) -> str:
    """A human project name: the first folder under a configured project root,
    else the basename of the session's working directory, else the folder name."""
    cwd = (cwd or "").rstrip(os.sep)
    if cwd:
        for root in config.get("recall", "project_roots", []):
            if not isinstance(root, str):
                continue
            root = config.expand(root).rstrip(os.sep)
            if cwd.startswith(root + os.sep):
                return cwd[len(root) + 1:].split(os.sep)[0]
        return os.path.basename(cwd) or cwd
    return folder


def iter_turns(path: str, globs: list[str] | None = None) -> Iterator[dict]:
    """Indexable turns of one transcript, already redacted."""
    globs = _exclude_globs() if globs is None else globs
    min_chars = config.get("recall", "min_chars", 15)
    folder = os.path.basename(os.path.dirname(path))
    default_session = os.path.splitext(os.path.basename(path))[0]
    title = ""
    turns = []
    try:
        fh = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return
    with fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except ValueError:
                continue  # one corrupt line must not sink the whole file
            if not isinstance(rec, dict):
                continue
            kind = rec.get("type")
            if kind == "custom-title":
                title = str(rec.get("customTitle") or "")[:120]
                continue
            if kind == "summary" and not title:
                title = str(rec.get("summary") or "")[:120]
                continue
            if kind not in ("user", "assistant"):
                continue
            cwd = str(rec.get("cwd") or "")
            if cwd and is_excluded(cwd, globs):
                continue
            msg = rec.get("message")
            body = _text_of(msg.get("content") if isinstance(msg, dict) else "")
            body = re.sub(r"\s+", " ", body).strip()
            if len(body) < min_chars or any(m in body for m in NOISE_MARKERS):
                continue
            turns.append({
                "session": str(rec.get("sessionId") or default_session),
                "project": project_label(cwd, folder),
                "timestamp": str(rec.get("timestamp") or ""),
                "role": kind,
                "body": redact(body),
            })
    for turn in turns:
        turn["title"] = redact(title)
        yield turn


# ── index ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    path  TEXT PRIMARY KEY,
    mtime REAL NOT NULL,
    size  INTEGER NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS turns USING fts5(
    body, title, project,
    session UNINDEXED, timestamp UNINDEXED, role UNINDEXED, path UNINDEXED,
    tokenize = 'unicode61 remove_diacritics 2'
);
"""


def _connect(path: str | None = None) -> sqlite3.Connection:
    con = sqlite3.connect(path or db_path(), timeout=30)
    if con.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
        con.executescript("DROP TABLE IF EXISTS files; DROP TABLE IF EXISTS turns;")
        con.executescript(_SCHEMA)
        con.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        con.commit()
    return con


def _transcript_files(root: str) -> Iterator[str]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            if name.endswith(".jsonl"):
                yield os.path.join(dirpath, name)


def index() -> dict:
    """Bring the index up to date. Returns counts of what changed."""
    root = transcripts_root()
    globs = _exclude_globs()
    stats = {"scanned": 0, "indexed": 0, "unchanged": 0, "removed": 0, "turns": 0}
    con = _connect()
    try:
        known = {p: (m, s) for p, m, s in con.execute("SELECT path, mtime, size FROM files")}
        seen = set()
        if os.path.isdir(root):
            for path in _transcript_files(root):
                if is_excluded(path, globs):
                    continue
                stats["scanned"] += 1
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                seen.add(path)
                if known.get(path) == (st.st_mtime, st.st_size):
                    stats["unchanged"] += 1
                    continue
                with con:
                    con.execute("DELETE FROM turns WHERE path = ?", (path,))
                    con.executemany(
                        "INSERT INTO turns(body, title, project, session, timestamp, role, path)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?)",
                        [(t["body"], t["title"], t["project"], t["session"],
                          t["timestamp"], t["role"], path) for t in iter_turns(path, globs)])
                    con.execute("INSERT OR REPLACE INTO files(path, mtime, size) VALUES (?, ?, ?)",
                                (path, st.st_mtime, st.st_size))
                stats["indexed"] += 1
        # Deleted files, and files that became excluded, leave the index.
        for path in set(known) - seen:
            with con:
                con.execute("DELETE FROM turns WHERE path = ?", (path,))
                con.execute("DELETE FROM files WHERE path = ?", (path,))
            stats["removed"] += 1
        stats["turns"] = con.execute("SELECT count(*) FROM turns").fetchone()[0]
    finally:
        con.close()
    return stats


# ── search ───────────────────────────────────────────────────────────────────

_FTS_OPERATORS = {"AND", "OR", "NOT", "NEAR"}


def _terms(query: str) -> list[str]:
    words = re.findall(r"\w[\w.\-]*", query or "", re.UNICODE)
    return [w for w in words if w.upper() not in _FTS_OPERATORS][:12]


def _strip_markup(text: str) -> str:
    """A snippet is a quotation; stray Markdown from a mid-word cut is noise."""
    text = re.sub(r"```+|~~~+", " ", text)
    text = re.sub(r"\*\*|__|~~|`", "", text)
    text = re.sub(r"(?<![\w*])\*(?!\s)", "", text)
    text = re.sub(r"(^|\s)#{1,6}\s+", r"\1", text)
    text = re.sub(r"<[^>\n]{1,80}>", " ", text)
    return re.sub(r"\s{2,}", " ", text).strip()


def make_snippet(body: str, terms: list[str], width: int | None = None) -> str:
    """A window of `width` characters around the first matching term, redacted."""
    width = width or config.get("recall", "snippet_chars", 240)
    lower = body.lower()
    start = 0
    for term in terms:
        i = lower.find(term.lower())
        if i >= 0:
            start = max(0, i - width // 3)
            break
    piece = _strip_markup(body[start:start + width])
    prefix = "..." if start > 0 else ""
    suffix = "..." if start + width < len(body) else ""
    return redact(prefix + piece + suffix)


def search(query: str, limit: int = 5, project: str | None = None,
           refresh: bool = True) -> list[dict]:
    """Best matches for `query`: all terms first, newest first; if nothing
    matches every term, any term, ranked by relevance.

    Each result: {"session", "project", "timestamp", "title", "snippet"}.
    """
    terms = _terms(query)
    if not terms or limit <= 0:
        return []
    if refresh:
        index()
    elif not os.path.exists(db_path()):
        return []
    globs = _exclude_globs()
    quoted = ['"' + t.replace('"', '""') + '"' for t in terms]
    attempts = ((" ".join(quoted), "timestamp DESC"),
                (" OR ".join(quoted), "bm25(turns), timestamp DESC"))
    where = "turns MATCH ?"
    params_extra: list = []
    if project:
        where += " AND lower(project) = lower(?)"
        params_extra.append(project)
    results: list[dict] = []
    con = _connect()
    try:
        for match, order in attempts:
            try:
                rows = con.execute(
                    f"SELECT session, project, timestamp, title, body, path FROM turns "
                    f"WHERE {where} ORDER BY {order} LIMIT ?",
                    (match, *params_extra, limit * 4)).fetchall()
            except sqlite3.OperationalError:
                rows = []
            for session, proj, ts, title, body, path in rows:
                if is_excluded(path, globs):
                    continue
                results.append({"session": session, "project": proj, "timestamp": ts,
                                "title": title, "snippet": make_snippet(body, terms)})
                if len(results) >= limit:
                    break
            if results:
                break
    finally:
        con.close()
    return results


# ── CLI ──────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m sancho.recall",
                                     description="Search past Claude Code sessions.")
    parser.add_argument("query", nargs="*", help="words to look for")
    parser.add_argument("--project", help="only this project label")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--index", action="store_true", help="refresh the index and exit")
    args = parser.parse_args(argv)

    if args.index:
        s = index()
        print(f"{s['turns']} turns indexed · {s['indexed']} files updated · "
              f"{s['unchanged']} unchanged · {s['removed']} removed")
        return 0
    query = " ".join(args.query)
    if not _terms(query):
        parser.print_usage(sys.stderr)
        return 2
    hits = search(query, limit=args.limit, project=args.project)
    if not hits:
        print(f"Nothing about \"{query}\" in past sessions.")
        return 0
    for h in hits:
        header = f"{h['timestamp'][:16].replace('T', ' ')} · {h['project']}"
        if h["title"]:
            header += f" · {h['title']}"
        print(header)
        print(f"  {h['snippet']}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
