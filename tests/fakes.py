"""
Stand-ins shared by the listener and runner tests.

`install_stubs()` registers placeholder `sancho.pending` / `sancho.tiers`
modules only when the real ones are absent, so these tests import cleanly on
their own. The tests never depend on the real modules' behaviour: they patch
in `FakePending` and a fixed tool list.
"""
from __future__ import annotations

import importlib.util
import sys
import time
import types


def install_stubs() -> None:
    if "sancho.pending" not in sys.modules and importlib.util.find_spec("sancho.pending") is None:
        stub = types.ModuleType("sancho.pending")
        for name in ("get", "approve", "reject", "list_for_thread"):
            setattr(stub, name, lambda *a, **k: None)
        sys.modules["sancho.pending"] = stub
        import sancho
        sancho.pending = stub
    if "sancho.tiers" not in sys.modules and importlib.util.find_spec("sancho.tiers") is None:
        stub = types.ModuleType("sancho.tiers")
        stub.allowed_tools = lambda: ["Read", "Grep"]
        sys.modules["sancho.tiers"] = stub
        import sancho
        sancho.tiers = stub


class FakePending:
    """In-memory pending store with the semantics the listener relies on:
    a code approves once, only for its own thread, only before it expires."""

    def __init__(self) -> None:
        self.records: dict[str, dict] = {}

    def add(self, pending_id: str, code: str, thread: str, summary: str = "write notes.md",
            ttl: float = 600, **extra) -> dict:
        now = time.time()
        rec = {"pending_id": pending_id, "code": code, "summary": summary,
               "truncated": False, "thread": thread, "created_at": now,
               "expires_at": now + ttl, "status": "pending", **extra}
        self.records[pending_id] = rec
        return rec

    def get(self, pending_id: str) -> dict | None:
        rec = self.records.get(pending_id)
        return dict(rec) if rec else None

    def approve(self, code: str, thread: str) -> dict | None:
        for rec in self.records.values():
            if rec["code"] == code:
                if rec["status"] != "pending" or rec["thread"] != thread \
                        or rec["expires_at"] < time.time():
                    return None
                rec["status"] = "approved"
                return dict(rec)
        return None

    def list_for_thread(self, thread: str, status: str = "pending",
                        since: float | None = None) -> list[dict]:
        now = time.time()
        out = [dict(r) for r in self.records.values()
               if r["thread"] == thread and r["status"] == status and r["expires_at"] > now
               and (since is None or r["created_at"] >= since)]
        return sorted(out, key=lambda r: r["created_at"])

    def reject(self, code: str) -> None:
        for rec in self.records.values():
            if rec["code"] == code and rec["status"] == "pending":
                rec["status"] = "rejected"


class FakeBot:
    """Records everything the listener would send."""

    bot_id = "999"

    def __init__(self) -> None:
        self.sent: list[tuple[str, dict | None]] = []
        self.callbacks: list[str] = []
        self.downloads: list[tuple[str, str]] = []
        self.photos: list[str] = []
        self.voices: list[str] = []

    def send_message(self, chat_id, text, reply_markup=None):
        self.sent.append((text, reply_markup))

    def answer_callback(self, callback_id, text=None):
        self.callbacks.append(callback_id)

    def send_photo(self, chat_id, path, caption=None):
        self.photos.append(path)

    def send_voice(self, chat_id, path, caption=None):
        self.voices.append(path)

    def send_chat_action(self, chat_id, action="typing"):
        pass

    def download(self, file_id, dest, max_bytes=0):
        self.downloads.append((file_id, dest))
        with open(dest, "wb") as f:
            f.write(b"audio")
        return dest

    def texts(self) -> list[str]:
        return [t for t, _ in self.sent]
