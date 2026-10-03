"""
The router: which project folder a question runs in.

A project is a direct subfolder of one of the configured roots that contains a
marker file (README.md, CLAUDE.md or STATUS.md by default). The user picks one
explicitly with `/p <name>`; the choice is sticky per chat until changed.

The router never lets the model guess the project. A wrong guess would run the
question against the wrong folder's instructions, memory and tools, and the
user, reading a short answer on a phone, would not notice. So a name either
resolves to exactly one folder, or the bot asks.

Config ("projects"):
  roots     list of folders to scan            default ["~/Projects"]
  markers   file names that make a project     default ["README.md", "CLAUDE.md", "STATUS.md"]
  exclude   project names never offered        default []
"""
from __future__ import annotations

import difflib
import json
import os
import re
import time

from sancho import config

DEFAULT_ROOTS = ["~/Projects"]
DEFAULT_MARKERS = ["README.md", "CLAUDE.md", "STATUS.md"]


def normalize(name: str) -> str:
    """`My Project`, `my_project` and `my-project` are the same name: the
    separator depends on how the name was typed or spoken."""
    return re.sub(r"[\s_-]+", "-", (name or "").strip().lower())


def roots() -> list[str]:
    return [config.expand(r) for r in config.get("projects", "roots", DEFAULT_ROOTS)
            if isinstance(r, str) and r.strip()]


def _excluded() -> set[str]:
    return {normalize(n) for n in config.get("projects", "exclude", []) if isinstance(n, str)}


def is_excluded(name: str) -> bool:
    return normalize(name) in _excluded()


def list_projects() -> dict[str, str]:
    """name → absolute path, for every folder that qualifies. When two roots
    hold a folder with the same name, the first root wins."""
    markers = [m for m in config.get("projects", "markers", DEFAULT_MARKERS) if isinstance(m, str)]
    excluded = _excluded()
    found: dict[str, str] = {}
    for root in roots():
        try:
            entries = sorted(os.listdir(root))
        except OSError:
            continue
        for name in entries:
            path = os.path.join(root, name)
            if name.startswith(".") or name in found or normalize(name) in excluded:
                continue
            if not os.path.isdir(path):
                continue
            if any(os.path.isfile(os.path.join(path, m)) for m in markers):
                found[name] = path
    return found


def resolve(name: str) -> tuple[str | None, list[str]]:
    """(path, []) for exactly one match; (None, candidates) otherwise.

    Order: exact name, unique prefix, unique substring, then close spellings
    as suggestions only — a fuzzy match is offered, never taken."""
    wanted = normalize(name)
    if not wanted or wanted in _excluded():
        return None, []
    projects = list_projects()
    by_norm = {normalize(n): n for n in projects}
    if wanted in by_norm:
        return projects[by_norm[wanted]], []
    for test in (lambda n: n.startswith(wanted), lambda n: wanted in n):
        hits = sorted(by_norm[n] for n in by_norm if test(n))
        if len(hits) == 1:
            return projects[hits[0]], []
        if hits:
            return None, hits
    close = difflib.get_close_matches(wanted, list(by_norm), n=4, cutoff=0.6)
    return None, [by_norm[c] for c in close]


def resolve_with_rest(text: str, max_words: int = 4) -> tuple[str | None, str, list[str]]:
    """`/p my project what changed today?` → (path, "what changed today?", []).

    Project names can have several words, so the longest prefix that resolves
    wins; whatever follows is the question. Nothing resolves → (None, "", hints)."""
    words = (text or "").split()
    hints: list[str] = []
    for n in range(min(max_words, len(words)), 0, -1):
        path, candidates = resolve(" ".join(words[:n]))
        if path:
            return path, " ".join(words[n:]).strip(), []
        hints = hints or candidates
    return None, "", hints


# ── sticky selection, per chat ───────────────────────────────────────────────

def _current_file() -> str:
    return os.path.join(config.state_dir(), "current_project.json")


def _load_current() -> dict:
    try:
        with open(_current_file(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def current(chat_id: str | int) -> str | None:
    """The project this chat last chose, if it still exists."""
    entry = _load_current().get(str(chat_id)) or {}
    path = entry.get("path")
    return path if path and os.path.isdir(path) else None


def set_current(chat_id: str | int, path: str) -> None:
    data = _load_current()
    data[str(chat_id)] = {"path": path, "at": time.time()}
    tmp = _current_file() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, _current_file())


def display_name(path: str | None) -> str:
    return os.path.basename((path or "").rstrip(os.sep)) or "(none)"
