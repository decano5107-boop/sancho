"""
Held tool calls and their one-time approval codes.

When the gate holds a call it stores one record per call, as a JSON file under
state_dir("pending"). A record carries two identifiers:

  pending_id   Public reference. The model sees it in the denial reason; the
               listener uses it in button payloads. Knowing it grants nothing.
  code         Secret, four characters from an alphabet without look-alikes.
               It exists only in the record and in the message to the owner's
               phone. Nothing the model can read ever contains it.

Lifecycle:

  pending ──approve(code, thread)──▶ approved ──consume_approved(call)──▶ deleted
     │                                  │
     └──────────reject(code)────────────┴──▶ rejected (swept later)

A record also dies when it expires (config "gate": ok_ttl_minutes, default 10);
approving it starts a fresh window of the same length.
`consume_approved` matches on a SHA-256 hash of the canonical JSON of
{tool, input}, with cosmetic fields such as a Bash description left out, so
only the exact call that was shown to the owner can run, and only once: the
record is deleted before the call is allowed.

Every mutation happens under an exclusive lock on the directory, so the gate
(one process per tool call) and the listener never interleave a read and a
write. Files are written atomically (temp file + os.replace) with mode 0600.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import time
from typing import Iterator

from sancho import config

# No 0/O, 1/I/L: the code is read off a phone screen and typed back.
ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
CODE_LENGTH = 4
DEFAULT_TTL_MINUTES = 10

PENDING = "pending"
APPROVED = "approved"
REJECTED = "rejected"
LIVE = (PENDING, APPROVED)

_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_LOCK_NAME = ".lock"
_TMP_SUFFIX = ".tmp"


# ── helpers ──────────────────────────────────────────────────────────────────

def _now() -> float:
    return time.time()


def _dir() -> str:
    path = config.state_dir(PENDING)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def ttl_seconds() -> float:
    minutes = config.get("gate", "ok_ttl_minutes", DEFAULT_TTL_MINUTES)
    if isinstance(minutes, bool) or not isinstance(minutes, (int, float)) or minutes <= 0:
        minutes = DEFAULT_TTL_MINUTES
    return float(minutes) * 60.0


# Input fields that describe a call without changing what it does. The model may
# reword them when it repeats an approved call, so they are left out of the hash.
# Everything else (the command, its timeout, background mode) stays in.
COSMETIC_FIELDS = {"Bash": frozenset({"description"})}


def call_hash(tool: str, tool_input: dict) -> str:
    """Stable identity of a tool call: key order, whitespace and cosmetic fields
    cannot change it. Anything that is not plain JSON raises, so the caller
    fails closed. Used by both create() and consume_approved()."""
    if not isinstance(tool_input, dict):
        raise ValueError("tool_input must be a dict")
    drop = COSMETIC_FIELDS.get(tool, frozenset())
    canonical = {k: v for k, v in tool_input.items() if k not in drop}
    blob = json.dumps({"tool": tool, "input": canonical}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _new_code() -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH))


def _new_id() -> str:
    return secrets.token_urlsafe(6)          # 8 url-safe characters


def _normalize_code(code: object) -> str:
    return str(code or "").strip().upper()


@contextlib.contextmanager
def _locked() -> Iterator[str]:
    d = _dir()
    fd = os.open(os.path.join(d, _LOCK_NAME), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield d
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _path(d: str, pending_id: str) -> str:
    return os.path.join(d, pending_id + ".json")


def _write(d: str, record: dict) -> None:
    final = _path(d, record["pending_id"])
    tmp = f"{final}.{secrets.token_hex(4)}{_TMP_SUFFIX}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(record, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, final)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _read(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _records(d: str) -> list[tuple[str, dict]]:
    out = []
    for name in os.listdir(d):
        if name.endswith(".json"):
            path = os.path.join(d, name)
            record = _read(path)
            if record is not None:
                out.append((path, record))
    return out


def _unlink(path: str) -> None:
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)


def _expired(record: dict, now: float) -> bool:
    try:
        return float(record.get("expires_at", 0)) <= now
    except (TypeError, ValueError):
        return True


def _live(record: dict, now: float) -> bool:
    return record.get("status") in LIVE and not _expired(record, now)


# ── public API ───────────────────────────────────────────────────────────────

def create(tool: str, tool_input: dict, thread: str, summary: str, full_text: str,
           truncated: bool) -> dict:
    """Hold one call. Returns the stored record (which includes the secret code:
    callers that talk to the model must never print the record)."""
    if not isinstance(tool, str) or not tool:
        raise ValueError("tool must be a non-empty string")
    if not isinstance(tool_input, dict):
        raise ValueError("tool_input must be a dict")
    if not isinstance(thread, str) or not thread:
        raise ValueError("thread must be a non-empty string")
    digest = call_hash(tool, tool_input)
    summary, full_text = str(summary or ""), str(full_text or "")
    visible = f"{summary}\n{full_text}".upper()
    with _locked() as d:
        now = _now()
        live_codes = {r.get("code") for _, r in _records(d) if _live(r, now)}
        while True:
            code = _new_code()
            # The code must never show up in anything the model sees: the id and
            # the summary go into the denial reason.
            if code not in live_codes and code not in visible:
                break
        while True:
            pending_id = _new_id()
            if code not in pending_id.upper() and not os.path.exists(_path(d, pending_id)):
                break
        record = {
            "pending_id": pending_id,
            "code": code,
            "hash": digest,
            "tool": tool,
            "input": tool_input,
            "thread": thread,
            "summary": summary,
            "full_text": full_text,
            "truncated": bool(truncated),
            "created_at": now,
            "expires_at": now + ttl_seconds(),
            "status": PENDING,
        }
        _write(d, record)
    return record


def get(pending_id: str) -> dict | None:
    """The record as stored, whatever its status, or None. The id comes from a
    button payload, so anything that is not a plain id is refused."""
    if not isinstance(pending_id, str) or not _ID.match(pending_id):
        return None
    return _read(_path(_dir(), pending_id))


def list_for_thread(thread: str, status: str = PENDING,
                    since: float | None = None) -> list[dict]:
    """Unexpired records of one thread with the given status, oldest first.
    `since` keeps only records created at or after that timestamp."""
    now = _now()
    out = [r for _, r in _records(_dir())
           if r.get("thread") == thread and r.get("status") == status
           and not _expired(r, now)
           and (since is None or float(r.get("created_at", 0)) >= since)]
    out.sort(key=lambda r: float(r.get("created_at", 0)))
    return out


def approve(code: str, thread: str) -> dict | None:
    """Mark a held call approved. The code must exist, be pending, unexpired and
    belong to `thread`. Returns the updated record, or None."""
    code = _normalize_code(code)
    if not code or not thread:
        return None
    with _locked() as d:
        now = _now()
        for _, record in _records(d):
            if record.get("code") != code:
                continue
            if (record.get("status") != PENDING or record.get("thread") != thread
                    or _expired(record, now)):
                return None
            record["status"] = APPROVED
            record["approved_at"] = now
            # A fresh window, so a busy queue does not let the approval lapse.
            record["expires_at"] = now + ttl_seconds()
            _write(d, record)
            return record
    return None


def reject(code: str) -> dict | None:
    """Refuse a held call (pending, or approved but not yet run). Returns the
    updated record, or None when no live record has this code."""
    code = _normalize_code(code)
    if not code:
        return None
    with _locked() as d:
        now = _now()
        for _, record in _records(d):
            if record.get("code") == code and _live(record, now):
                record["status"] = REJECTED
                record["rejected_at"] = now
                _write(d, record)
                return record
    return None


def consume_approved(tool: str, tool_input: dict, thread: str) -> bool:
    """True exactly once for the call whose hash matches an approved, unexpired
    record of `thread`. The record is deleted before True is returned, so a
    replay (or a racing second process) finds nothing."""
    if not thread:
        return False
    digest = call_hash(tool, tool_input)
    with _locked() as d:
        now = _now()
        for path, record in _records(d):
            if (record.get("status") == APPROVED and record.get("thread") == thread
                    and record.get("hash") == digest and not _expired(record, now)):
                os.unlink(path)
                return True
    return False


def sweep() -> int:
    """Remove expired and finished records and stray temp files. Returns how many."""
    removed = 0
    with _locked() as d:
        now = _now()
        for path, record in _records(d):
            if not _live(record, now):
                _unlink(path)
                removed += 1
        for name in os.listdir(d):
            path = os.path.join(d, name)
            if name.endswith(_TMP_SUFFIX):
                with contextlib.suppress(OSError):
                    if now - os.path.getmtime(path) > 60:
                        os.unlink(path)
                        removed += 1
            elif name.endswith(".json") and _read(path) is None:
                _unlink(path)
                removed += 1
    return removed
