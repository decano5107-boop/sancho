"""
Filesystem policy: which paths the assistant may reach at all.

Rules, in the order they are applied:

  1. Never-paths, unconditional, whatever the configuration says: Sancho's
     state directory, Sancho's own code (the repository, which also holds
     config.json and .env), the config and .env files wherever they live,
     Claude Code's own settings (~/.claude, ~/.claude.json), and in every
     folder the project-level Claude Code configuration (any `.claude` folder
     and any `.mcp.json`), because it sets the hooks, environment and
     permissions of the next run. CLAUDE.md is not on this list: editing it is
     ordinary work and needs an OK like any other write.
  2. Denied globs (config "gate.denied_globs" + "gate.extra_denied"). Denied
     wins over allowed.
  3. Allowed roots (config "gate.allowed_roots") and scratch roots
     ("gate.scratch_roots"). Anything outside them is unreachable.

A path is judged by where it really is: `~`, `..` and symlinks are resolved,
so a symlink planted inside an allowed folder cannot reach ~/.ssh. Any other
tilde form (`~+`, `~-`, `~2`, `~user`) is refused: a shell would expand it to
a folder this module does not compute. The name
as written is judged too, so a file called `.env` is denied even when it is a
link to something harmless. Denied matching ignores case (the default macOS
filesystem does too: ~/.SSH is ~/.ssh); allowed matching does not.

Glob syntax for denied patterns:
  a pattern without "/"   matches any path component (".env", "*.pem", "id_rsa*")
  a pattern with "/"      matches the whole path; "~" expands to the home folder;
                          a relative one ("**/credentials") matches at any depth
  "**" crosses folders, "*" and "?" do not, "[...]" is a character class.
Every pattern also covers everything below what it matches, so "~/.ssh/**"
and "~/.ssh" both deny the folder and its contents.

Known limit: a hard link to a secret, made before Sancho ran, looks like an
ordinary file. The gate refuses to create one (`ln` needs both paths to pass).
"""
from __future__ import annotations

import fnmatch
import os
import re
import tempfile

from sancho import config

DEFAULT_ALLOWED_ROOTS = ["~/Projects", "~/Documents", "~/Downloads", "~/Desktop"]
DEFAULT_DENIED_GLOBS = [
    ".env", ".env.*", ".envrc",
    "~/.claude.json", "~/.claude/**",
    "~/.aws/**", "~/.ssh/**", "~/.config/**", "~/Library/Keychains/**",
    "**/credentials", "*.pem", "*.key", "id_rsa*",
]
DEFAULT_RECURSIVE_SCAN_LIMIT = 20000
# Denied in every folder, whatever denied_globs says (see rule 1 above).
UNCONDITIONAL_GLOBS = ["**/.claude", "**/.mcp.json"]


def default_scratch_roots() -> list[str]:
    return [os.path.join(tempfile.gettempdir(), "sancho")]


# ── resolution ───────────────────────────────────────────────────────────────

def home() -> str:
    return os.path.expanduser("~")


def literal(path: str, cwd: str | None = None) -> str:
    """Absolute and normalised (`~` and `..` handled), symlinks NOT resolved."""
    p = os.path.expanduser(str(path))
    if not os.path.isabs(p):
        p = os.path.join(cwd or os.getcwd(), p)
    return os.path.normpath(p)


def real(path: str, cwd: str | None = None) -> str:
    """Absolute, with symlinks resolved (also for paths that do not exist yet)."""
    p = os.path.expanduser(str(path))
    if not os.path.isabs(p):
        p = os.path.join(cwd or os.getcwd(), p)
    try:
        return os.path.realpath(p)
    except (OSError, ValueError):
        return os.path.normpath(p)


def _under(path: str, root: str, fold: bool = False) -> bool:
    if fold:
        path, root = path.lower(), root.lower()
    root = root.rstrip(os.sep) or os.sep
    return path == root or path.startswith(root if root == os.sep else root + os.sep)


def _config_roots(key: str, default: list[str]) -> list[str]:
    value = config.get("gate", key, default)
    return [os.path.realpath(config.expand(r)) for r in value if isinstance(r, str) and r]


def allowed_roots() -> list[str]:
    return _config_roots("allowed_roots", DEFAULT_ALLOWED_ROOTS)


def scratch_roots() -> list[str]:
    return _config_roots("scratch_roots", default_scratch_roots())


def never_roots() -> list[str]:
    """Unconditional never-paths, as written and as resolved."""
    h = home()
    raw = [config.state_dir(), config.REPO_DIR, config.config_path(),
           config.env_file_path(), os.path.join(h, ".claude"),
           os.path.join(h, ".claude.json")]
    out: list[str] = []
    for p in raw:
        for form in (os.path.normpath(os.path.abspath(p)), real(p)):
            if form not in out:
                out.append(form)
    return out


# ── denied globs ─────────────────────────────────────────────────────────────

def denied_patterns() -> list[str]:
    base = config.get("gate", "denied_globs", DEFAULT_DENIED_GLOBS)
    extra = config.get("gate", "extra_denied", [])
    return [p for p in list(base) + list(extra) if isinstance(p, str) and p]


def _translate(pat: str) -> str:
    out, i = [], 0
    while i < len(pat):
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif pat[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            out.append("[^/]")
            i += 1
        elif pat[i] == "[" and pat.find("]", i + 1) > i + 1:
            j = pat.find("]", i + 1)
            cls = pat[i + 1:j]
            if cls.startswith("!"):
                cls = "^" + cls[1:]
            out.append("[" + cls.replace("\\", "\\\\") + "]")
            i = j + 1
        else:
            out.append(re.escape(pat[i]))
            i += 1
    return "".join(out)


def _compile(pattern: str) -> tuple[str, re.Pattern]:
    """("name", regex for one component) or ("path", regex for a whole path)."""
    if "/" not in pattern:
        return "name", re.compile(_translate(pattern), re.IGNORECASE)
    p = pattern
    if p.startswith("~"):
        p = os.path.expanduser(p)
    while p.endswith("/**"):
        p = p[:-3]
    body = _translate(p)
    if not p.startswith("/"):
        body = "(?:.*/)?" + body.removeprefix("(?:.*/)?")
    return "path", re.compile(body + "(?:/.*)?", re.IGNORECASE)


def _glob_match(abs_path: str, compiled: list) -> str | None:
    parts = [c for c in abs_path.split(os.sep) if c]
    for pattern, (kind, rx) in compiled:
        if kind == "name":
            if any(rx.fullmatch(c) for c in parts):
                return pattern
        elif rx.fullmatch(abs_path):
            return pattern
    return None


def _compiled() -> list:
    return [(p, _compile(p)) for p in denied_patterns()]


def _unconditional() -> list:
    return [(p, _compile(p)) for p in UNCONDITIONAL_GLOBS]


def _never_match(abs_path: str, roots: list[str]) -> str | None:
    for r in roots:
        if _under(abs_path, r, fold=True):
            return r
    return None


def denied_reason(path: str, cwd: str | None = None) -> str | None:
    """Why this path is denied, or None. Checks the written and the real location."""
    roots = never_roots()
    compiled = _compiled()
    always = _unconditional()
    for form in dict.fromkeys((literal(path, cwd), real(path, cwd))):
        hit = _never_match(form, roots)
        if hit:
            return f"{form} is Sancho's own code, configuration or state, or Claude Code's settings"
        pattern = _glob_match(form, always)
        if pattern:
            return (f"{form} is project-level Claude Code configuration (matches {pattern}); "
                    "it changes the hooks, environment or permissions of the next run")
        pattern = _glob_match(form, compiled)
        if pattern:
            return f"{form} is a protected path (matches {pattern})"
    return None


def is_denied(path: str, cwd: str | None = None) -> bool:
    return denied_reason(path, cwd) is not None


# ── allowed roots ────────────────────────────────────────────────────────────

def is_scratch(path: str, cwd: str | None = None) -> bool:
    p = real(path, cwd)
    return any(_under(p, r) for r in scratch_roots())


def in_allowed(path: str, cwd: str | None = None) -> bool:
    """Inside an allowed or scratch root, by real location (denial not checked)."""
    p = real(path, cwd)
    return any(_under(p, r) for r in allowed_roots() + scratch_roots())


def judge(path: str, cwd: str | None = None) -> tuple[bool, str]:
    """(ok, reason). ok is False when the path is denied or outside the roots."""
    text = str(path)
    if text.startswith("~") and text != "~" and not text.startswith("~/"):
        # ~+, ~-, ~N, ~user and zsh named directories: a shell expands them,
        # literal() does not, so the gate would judge a different folder.
        return False, f"{text} starts with a tilde form the gate does not expand"
    why = denied_reason(path, cwd)
    if why:
        return False, why
    if not in_allowed(path, cwd):
        return False, f"{real(path, cwd)} is outside the allowed folders"
    return True, ""


# ── what a recursive operation would reach ───────────────────────────────────

def _static_prefix(pattern: str) -> str | None:
    if "/" not in pattern:
        return None
    p = os.path.expanduser(pattern) if pattern.startswith("~") else pattern
    if not p.startswith("/"):
        return None
    keep = []
    for part in p.split("/"):
        if any(ch in part for ch in "*?["):
            break
        keep.append(part)
    return "/".join(keep) or None


def contains_never(path: str, cwd: str | None = None) -> str | None:
    """A never-path or fixed denied location strictly inside `path`, or None.

    Cheap (no disk walk): used for recursive reads and for moves, copies and
    deletes of a folder that holds something protected.
    """
    root = real(path, cwd)
    candidates = never_roots() + [p for p in (_static_prefix(g) for g in denied_patterns()) if p]
    for c in candidates:
        if _under(c, root, fold=True) and c.lower() != root.lower():
            return c
    return None


def include_matcher(globs) -> "re.Pattern | None":
    """One case-insensitive regex for include globs, tested against a file's
    basename and its path relative to the searched folder. Broader than any
    real tool's matching on purpose: a denied file that might be included is
    treated as included. A glob is tried whole and by its last component
    alone ("*/.env" also selects a top-level .env), and a glob the gate cannot
    read with confidence ({ } ! \\) selects everything (returns None)."""
    parts = []
    for g in globs:
        g = g.strip().lstrip("/")
        while g.startswith("./"):
            g = g[2:]
        if not g:
            continue
        if any(ch in g for ch in "{}!\\"):
            return None
        body = _translate(g)
        parts.append("(?:.*/)?" + body.removeprefix("(?:.*/)?") + "(?:/.*)?")
        last = g.rstrip("/").split("/")[-1]
        if last and last != "**":
            parts.append(_translate(last))
        else:
            return None
    if not parts:
        return None
    return re.compile("|".join(f"(?:{p})" for p in parts), re.IGNORECASE)


def scan_tree(path: str, cwd: str | None = None, *, include_hidden: bool = True,
              only: tuple = (), exclude: tuple = (), exclude_dirs: tuple = (),
              limit: int | None = None) -> tuple[str, str]:
    """Would reading everything under `path` touch a protected file?

    Returns ("clean", ""), ("denied", <what>) or ("too_big", <limit>). Symlinks
    are not followed; a symlink pointing at a protected or outside location
    counts as denied. `only`, `exclude` and `exclude_dirs` are basename globs
    (the --include / --exclude / --exclude-dir of grep, the glob of the Grep
    tool) so an explicit exclusion keeps a search free. `only` may hold path
    globs ("**/.env"); it is matched case-insensitively against the basename
    and the relative path. Exclusions are matched case-sensitively, so they
    can only ever exclude less.
    """
    hit = contains_never(path, cwd)
    if hit:
        return "denied", hit
    root = real(path, cwd)
    if not os.path.isdir(root):
        return "clean", ""
    if limit is None:
        limit = config.get("gate", "recursive_scan_limit", DEFAULT_RECURSIVE_SCAN_LIMIT)
    compiled = _compiled() + _unconditional()
    roots = never_roots()
    only_rx = include_matcher(only)
    count = 0
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for e in entries:
            count += 1
            if count > limit:
                return "too_big", str(limit)
            name = e.name
            if not include_hidden and name.startswith("."):
                continue
            try:
                is_link = e.is_symlink()
                is_dir = e.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if is_dir and any(fnmatch.fnmatchcase(name, g) for g in exclude_dirs):
                continue
            if not is_dir and exclude and any(fnmatch.fnmatchcase(name, g) for g in exclude):
                continue
            full = e.path
            if not is_dir and only_rx is not None and not (is_link and os.path.isdir(full)):
                rel = os.path.relpath(full, root)
                if not (only_rx.fullmatch(name) or only_rx.fullmatch(rel)):
                    continue
            if _glob_match(full, compiled) or _never_match(full, roots):
                return "denied", full
            if is_link:
                if denied_reason(full) or not in_allowed(full):
                    return "denied", f"{full} (a link to {real(full)})"
                continue
            if is_dir:
                stack.append(full)
    return "clean", ""
