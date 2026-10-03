"""
The three permission tiers, decided from the tool call and nothing else.

  free       runs
  needs_ok   held until the user approves it from the phone
  never      denied, with the reason

The gate never reads the conversation: what a file, a web page or an MCP
result says does not matter, only what the model then tries to do. A call
reaches "free" only by matching an allowlist, by tool and, for Bash, by program
AND flags; a chained command takes the highest tier among its parts; anything
the parser cannot take apart is "never".

Configuration: section "gate" of config.json. Every key is optional.

  allowed_roots          folders the assistant may reach at all
                         default ["~/Projects", "~/Documents", "~/Downloads", "~/Desktop"]
  scratch_roots          throw-away folders, reachable like allowed roots; the
                         only place where `rm` of one plain file can be approved
                         default [<system temp dir>/sancho]
  denied_globs           protected paths, denied even inside allowed roots
                         (syntax in sancho/paths.py); setting it REPLACES
                         this list, so use extra_denied to add to it
                         default [".env", ".env.*", ".envrc", "~/.claude.json",
                         "~/.claude/**", "~/.aws/**", "~/.ssh/**", "~/.config/**",
                         "~/Library/Keychains/**", "**/credentials", "*.pem",
                         "*.key", "id_rsa*"]
  extra_denied           more protected paths, added to denied_globs   default []
  net_allow_hosts        hosts that curl, wget, ssh, scp, rsync, nc, ftp,
                         sftp and telnet may reach (then "needs_ok", never
                         "free"); "example.com" matches that host only,
                         ".example.com" or "*.example.com" also its subdomains
                         default []
  safe_scripts           exact paths of scripts or binaries you trust; running
                         one is "free" (listing a script trusts all it does)
                         default []
  free_commands_extra    more read-only program names, judged like `cat`
                         (every operand must be a reachable path). They cannot
                         override the deletion, network, environment, wrapper
                         and interpreter rules.                  default []
  web_search_tier        tier of the WebSearch tool: "free", "needs_ok" or
                         "never"; a query can carry data out, at low bandwidth
                         default "free"
  mcp_never_patterns     MCP tool names (fnmatch, case-insensitive) that are
                         never allowed
                         default ["*delete*", "*trash*", "*remove*", "*purge*",
                         "*drop*", "*destroy*", "*wipe*", "*erase*", "*clear*",
                         "*revoke*", "*terminate*"]
  mcp_needs_ok_patterns  MCP tool names that need an OK
                         default ["*send*", "*create_event*", "*draft*", "*update*"]
  mcp_free_patterns      MCP tool names that run freely (checked after the two
                         lists above; any other MCP tool needs an OK)  default []
  recursive_scan_limit   files a recursive search (grep -r, rg, the Grep tool)
                         may walk while checking it cannot reach a protected
                         file; a larger tree needs an OK          default 20000

Unconditional, whatever the configuration says: Sancho's state directory,
Sancho's own code, config.json and .env, ~/.claude and ~/.claude.json, and any
project's `.claude` folder and `.mcp.json` are "never" for every tool.
`sudo`, `doas` and `su` are "never" even around a safe script.

Programs that run other commands. A program the gate knows to run commands
it is handed (shells with -c, eval, source, xargs, env, nohup, nice, timeout,
time, watch, caffeinate, script, trap, osascript, launchctl, at, crontab,
`find -exec`, `git submodule foreach`, `git bisect run`, `git rebase --exec`,
`pwsh -c`, `uv run python -c`, `npx -c`, `npm exec -c`, `expect -c`, sqlite3
dot-commands such as .shell, editors started with a command such as `vim -c`,
`open -a Terminal`) is "never", unless it only wraps a safe script. A program
the gate does not know defaults to "needs_ok": the full command is shown
before you approve it, but the gate cannot tell whether it runs other
commands. Read the summary.

MCP tools: besides the name patterns, every string in the input is checked.
A value under a key that names a path (path, file, dir, folder, filename,
uri) or a value that looks like one (/…, ~…, ./…, ../…, file://…) is judged
like any other path: protected or outside the allowed folders is "never".

Known limits:
  - Paths are checked on arguments, not on repository history: free
    `git show`, `git log -p` and `git grep` print committed content, so a
    secret that was ever committed is readable through them.
  - Environment variables are never expanded, so `$HOME/x` is denied even
    when it would be harmless. For the same reason any tilde form other than
    `~` and `~/` (`~+`, `~-`, `~2`, `~user`, zsh named directories) and zsh's
    `=name` expansion are "never".
  - Pattern expansion has a time budget (GLOB_SECONDS); a pattern that cannot
    be expanded within it is "never".
  - A program the gate does not know is "needs_ok"; a recursive or forced
    delete handed to it is "never" only when it is visible in its arguments
    (`tool rm -rf x`, `tool -c 'rm -rf x'`). One it builds itself is not seen:
    read the summary before approving.

Pure apart from reading configuration and looking at the filesystem (symlink
resolution, glob expansion, the bounded walk of recursive searches).
"""
from __future__ import annotations

import fnmatch
import glob as _glob
import itertools
import json
import os
import re
import shutil
import threading
import time
import unicodedata
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit

from sancho import config, paths
from sancho.shellparse import NULL_SINKS, ParseError, Segment, Word, expand_braces, parse

FREE, NEEDS_OK, NEVER = "free", "needs_ok", "never"
TIERS = (FREE, NEEDS_OK, NEVER)
_RANK = {FREE: 0, NEEDS_OK: 1, NEVER: 2}
SUMMARY_LIMIT = 300
GLOB_CAP = 2000     # glob matches checked per word; more needs an OK
GLOB_SECONDS = 5.0  # time budget for all pattern expansion in one command

DEFAULT_MCP_NEVER = ["*delete*", "*trash*", "*remove*", "*purge*", "*drop*", "*destroy*",
                     "*wipe*", "*erase*", "*clear*", "*revoke*", "*terminate*"]
DEFAULT_MCP_NEEDS_OK = ["*send*", "*create_event*", "*draft*", "*update*"]


@dataclass
class Verdict:
    tier: str        # "free" | "needs_ok" | "never"
    summary: str     # one line for the phone, built from tool_input
    full_text: str   # the complete command / path / URL / content summary
    truncated: bool  # True when summary had to shorten full_text
    reason: str      # why this tier


def _worse(a: tuple[str, str], b: tuple[str, str]) -> tuple[str, str]:
    return b if _RANK[b[0]] > _RANK[a[0]] else a


def _gate(key: str, default):
    return config.get("gate", key, default)


# ── public API ───────────────────────────────────────────────────────────────

def classify(tool_name: str, tool_input: dict, cwd: str | None = None) -> Verdict:
    """The tier of one tool call. Never raises: an internal error is "never"."""
    if not isinstance(tool_input, dict):
        tool_input = {}
    tool_name = str(tool_name or "")
    try:
        summary_line, full_text = _describe(tool_name, tool_input, cwd)
    except Exception as e:  # noqa: BLE001 - the description must never break the gate
        summary_line, full_text = f"{tool_name}: (unreadable input)", f"{type(e).__name__}"
    try:
        tier, reason = _classify(tool_name, tool_input, cwd or os.getcwd())
    except _GlobBudget:
        tier, reason = NEVER, (f"a pattern could not be expanded and checked within "
                               f"{GLOB_SECONDS:g} seconds; unchecked means denied")
    except ParseError as e:
        tier, reason = NEVER, f"the command could not be parsed ({e}); unreadable means denied"
    except Exception as e:  # noqa: BLE001 - fail closed
        tier, reason = NEVER, f"the gate could not classify this call ({type(e).__name__})"
    one_line = reveal_invisible(re.sub(r"\s*\n\s*", " ⏎ ", summary_line).strip())
    truncated = len(one_line) > SUMMARY_LIMIT
    if truncated:
        one_line = one_line[:SUMMARY_LIMIT - 1].rstrip() + "…"
    return Verdict(tier, one_line, reveal_invisible(full_text), truncated, reason)


def reveal_invisible(text: str) -> str:
    """Format and control characters (bidi overrides, zero-width marks, ...)
    shown as <U+XXXX>, so what the phone displays is what will run. Newlines
    and tabs are kept."""
    return "".join(f"<U+{ord(ch):04X}>" if ch not in "\n\t" and unicodedata.category(ch) in
                   ("Cf", "Cc", "Co", "Cs", "Zl", "Zp") else ch for ch in str(text or ""))


FREE_TOOLS = ("Read", "Glob", "Grep", "LS", "NotebookRead", "TodoWrite")
ALLOWED_BASH_PROGRAMS = ("ls", "cat", "head", "tail", "wc", "grep", "egrep", "fgrep",
                         "stat", "du", "df", "pwd", "which", "date", "uname",
                         "basename", "dirname")
ALLOWED_GIT = ("status", "rev-parse", "ls-files", "blame")


def allowed_tools() -> list[str]:
    """Claude Code --allowedTools entries for the free tier, narrowest form.

    Only programs that cannot be escalated by a flag are listed: `find`,
    `sed`, `sort`, `awk`, `rg`, `echo`, `git diff/log/show/branch` are free for
    the gate but left out here, because `Bash(find:*)` would also pre-approve
    `find -delete`. The gate still lets those run when they are read-only.
    """
    tools = list(FREE_TOOLS)
    if _gate("web_search_tier", FREE) == FREE:
        tools.append("WebSearch")
    names = list(ALLOWED_BASH_PROGRAMS)
    for extra in _gate("free_commands_extra", []):
        if isinstance(extra, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", extra) \
                and not _dangerous_name(extra) and extra not in names:
            names.append(extra)
    tools += [f"Bash({n}:*)" for n in names]
    tools += [f"Bash(git {s}:*)" for s in ALLOWED_GIT]
    return tools


# ── descriptions (built from the call, never from a model-written description) ─

def _describe(tool: str, ti: dict, cwd: str | None) -> tuple[str, str]:
    def s(key: str) -> str:
        v = ti.get(key)
        return v if isinstance(v, str) else ""

    if tool == "Bash":
        cmd = s("command")
        return f"Run: {cmd}", cmd
    if tool == "Read":
        line = f"Read {s('file_path')}"
        return line, line
    if tool == "NotebookRead":
        line = f"Read notebook {s('notebook_path')}"
        return line, line
    if tool == "LS":
        line = f"List {s('path')}"
        return line, line
    if tool == "Glob":
        line = f"Find files {s('pattern')} in {s('path') or cwd or '.'}"
        return line, line
    if tool == "Grep":
        line = f"Search {s('pattern')!r} in {s('path') or cwd or '.'}"
        if s("glob"):
            line += f" (files {s('glob')})"
        return line, line
    if tool == "Write":
        content = s("content")
        line = f"Write {s('file_path')} ({len(content)} characters)"
        return line, f"{line}\n\n{content}"
    if tool == "Edit":
        old, new = s("old_string"), s("new_string")
        line = f"Edit {s('file_path')}: replace {len(old)} characters with {len(new)}"
        if ti.get("replace_all"):
            line += " (every occurrence)"
        return line, f"{line}\n\n--- old\n{old}\n+++ new\n{new}"
    if tool == "MultiEdit":
        edits = ti.get("edits") if isinstance(ti.get("edits"), list) else []
        line = f"Edit {s('file_path')}: {len(edits)} changes"
        parts = [line]
        for e in edits:
            if isinstance(e, dict):
                parts.append(f"--- old\n{e.get('old_string', '')}\n+++ new\n{e.get('new_string', '')}")
        return line, "\n\n".join(parts)
    if tool == "NotebookEdit":
        line = (f"Edit notebook {s('notebook_path')} "
                f"({s('edit_mode') or 'replace'} cell {s('cell_id') or '?'})")
        return line, f"{line}\n\n{s('new_source')}"
    if tool == "WebFetch":
        line = f"Fetch {s('url')}"
        return line, s("url")
    if tool == "WebSearch":
        line = f"Search the web: {s('query')}"
        return line, line
    if tool.startswith("mcp__"):
        parts = tool.split("__", 2)
        name = f"{parts[1]} / {parts[2]}" if len(parts) == 3 else tool
    else:
        name = tool
    # shortest values first, so recipients and ids survive the truncation
    items = sorted(ti.items(), key=lambda kv: len(json.dumps(kv[1], default=str)))
    compact = json.dumps(dict(items), ensure_ascii=False, default=str)
    return f"{name}: {compact}", f"{name}\n{json.dumps(ti, ensure_ascii=False, indent=2, default=str)}"


# ── dispatch by tool ─────────────────────────────────────────────────────────

def _classify(tool: str, ti: dict, cwd: str) -> tuple[str, str]:
    if tool == "Bash":
        cmd = ti.get("command")
        if not isinstance(cmd, str) or not cmd.strip():
            return NEVER, "empty or missing command"
        return _classify_bash(cmd, cwd)
    if tool in ("Read", "NotebookRead", "LS"):
        key = {"Read": "file_path", "NotebookRead": "notebook_path", "LS": "path"}[tool]
        return _tool_read(ti.get(key), cwd, tool)
    if tool == "Glob":
        return _tool_glob(ti, cwd)
    if tool == "Grep":
        return _tool_grep(ti, cwd)
    if tool == "TodoWrite":
        return FREE, "the assistant's own task list"
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        key = "notebook_path" if tool == "NotebookEdit" else "file_path"
        target = ti.get(key)
        if not isinstance(target, str) or not target:
            return NEVER, f"{tool} without a path"
        return _write_target(target, [cwd], f"{tool} changes {target}")
    if tool == "WebFetch":
        url = ti.get("url")
        if not isinstance(url, str) or not url.lower().startswith(("http://", "https://")):
            return NEVER, "WebFetch without an http(s) URL"
        if not _host(url):
            return NEVER, "WebFetch without a readable host"
        return NEEDS_OK, "fetching a URL sends data to a host the model chose"
    if tool == "WebSearch":
        tier = _gate("web_search_tier", FREE)
        tier = tier if tier in TIERS else NEEDS_OK
        return tier, f"web search is configured as {tier}"
    if tool.startswith("mcp__"):
        path_verdict = _mcp_paths(ti, cwd)
        return path_verdict if path_verdict[0] == NEVER else _classify_mcp(tool)
    return NEEDS_OK, f"{tool} is not a tool the gate knows; it needs your OK"


def _tool_read(path, cwd: str, tool: str) -> tuple[str, str]:
    if not isinstance(path, str) or not path:
        if tool == "LS":
            path = cwd
        else:
            return NEVER, f"{tool} without a path"
    ok, why = paths.judge(path, cwd)
    return (FREE, "reading inside the allowed folders") if ok else (NEVER, why)


def _tool_glob(ti: dict, cwd: str) -> tuple[str, str]:
    base = ti.get("path") if isinstance(ti.get("path"), str) and ti.get("path") else cwd
    ok, why = paths.judge(base, cwd)
    if not ok:
        return NEVER, why
    pattern = ti.get("pattern") if isinstance(ti.get("pattern"), str) else ""
    static: list[str] = []
    wild = False
    for part in pattern.split("/"):
        if any(ch in part for ch in "*?[{"):
            wild = True
        elif part == ".." and wild:
            return NEVER, "a `..` after a wildcard can climb out of the folder being listed"
        elif not wild:
            static.append(part)
    prefix = "/".join(static)
    if pattern.startswith("/"):
        start = prefix or "/"
    elif pattern.startswith("~"):
        start = os.path.expanduser(prefix)
    else:
        start = os.path.join(paths.literal(base, cwd), prefix)
    ok, why = paths.judge(start, cwd)
    if not ok:
        return NEVER, why
    return FREE, "listing file names inside the allowed folders"


def _tool_grep(ti: dict, cwd: str) -> tuple[str, str]:
    base = ti.get("path") if isinstance(ti.get("path"), str) and ti.get("path") else cwd
    ok, why = paths.judge(base, cwd)
    if not ok:
        return NEVER, why
    only = tuple(g for g in _brace_list(ti.get("glob"))) if isinstance(ti.get("glob"), str) else ()
    status, what = paths.scan_tree(base, cwd, include_hidden=True, only=only)
    if status == "denied":
        return NEVER, f"the search would read a protected path: {what}"
    if status == "too_big":
        return NEEDS_OK, f"the search walks more than {what} files; it could not be checked"
    return FREE, "searching inside the allowed folders"


def _brace_list(g: str) -> list[str]:
    try:
        return expand_braces(Word(g, tuple([False] * len(g))))
    except ParseError:
        return [g]


def _classify_mcp(tool: str) -> tuple[str, str]:
    parts = tool.split("__", 2)
    short = parts[2] if len(parts) == 3 else tool

    def hit(key: str, default: list) -> str | None:
        for p in _gate(key, default):
            if isinstance(p, str) and (fnmatch.fnmatch(short.lower(), p.lower())
                                       or fnmatch.fnmatch(tool.lower(), p.lower())):
                return p
        return None

    p = hit("mcp_never_patterns", DEFAULT_MCP_NEVER)
    if p:
        return NEVER, f"MCP tool {short} matches the never pattern {p}"
    p = hit("mcp_needs_ok_patterns", DEFAULT_MCP_NEEDS_OK)
    if p:
        return NEEDS_OK, f"MCP tool {short} matches {p} and needs your OK"
    p = hit("mcp_free_patterns", [])
    if p:
        return FREE, f"MCP tool {short} matches the free pattern {p}"
    return NEEDS_OK, f"MCP tool {short} is not on a free list; it needs your OK"


_PATH_KEY = re.compile(r"path|file|dir|folder|uri", re.IGNORECASE)


def _strings(value, key: str = "", depth: int = 0):
    """(key, string) pairs anywhere inside an MCP input."""
    if depth > 20:
        return
    if isinstance(value, str):
        yield key, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(v, str(k), depth + 1)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v, key, depth + 1)


def _mcp_paths(ti: dict, cwd: str) -> tuple[str, str]:
    """Path policy for the path-like values of an MCP call."""
    for key, value in _strings(ti):
        v = value.strip()
        if not v or "\n" in v or len(v) > 4096:
            continue
        if v.lower().startswith("file://"):
            v = unquote(urlsplit(v).path) or "/"
        elif "://" in v:
            continue
        rooted = v.startswith(("/", "~", "./", "../")) or "/../" in v or v == ".."
        if rooted:
            ok, why = paths.judge(v, cwd)
            if not ok:
                return NEVER, f"the MCP call names a path it may not reach: {why}"
        elif _PATH_KEY.search(key):
            why = paths.denied_reason(v, cwd)
            if why:
                return NEVER, f"the MCP call names a protected path: {why}"
    return FREE, ""


def _host(url: str) -> str:
    try:
        text = url if "://" in url else "//" + url
        return (urlsplit(text).hostname or "").lower()
    except ValueError:
        return ""


# ── Bash ─────────────────────────────────────────────────────────────────────

DELETERS = {"rm", "unlink", "rmdir", "shred", "srm", "truncate", "dd", "trash"}
ENV_PRINTERS = {"printenv", "env", "export", "declare", "typeset", "set", "ps"}
NEVER_PROGRAMS = {"security": "`security` reads the Keychain",
                  "sudo": "`sudo` runs a command with more privilege",
                  "doas": "`doas` runs a command with more privilege",
                  "su": "`su` runs a command as another user",
                  "socat": "`socat` opens network connections the gate cannot read",
                  "http": "HTTPie requests are not readable by the gate",
                  "https": "HTTPie requests are not readable by the gate",
                  "trap": "`trap` runs a command later, when a signal arrives",
                  "osascript": "`osascript` runs AppleScript, which can run any command",
                  "launchctl": "`launchctl` reads the session environment and starts jobs",
                  "at": "`at` schedules a command to run later",
                  "batch": "`batch` schedules a command to run later",
                  "crontab": "`crontab` schedules commands",
                  "ed": "`ed` takes editing commands, including `!` shell commands",
                  "ex": "`ex` takes editing commands, including `!` shell commands"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "csh", "tcsh"}
WRAPPERS = {"eval", "source", ".", "exec", "xargs", "nohup", "nice", "timeout",
            "gtimeout", "stdbuf", "builtin", "watch", "parallel", "script",
            "caffeinate", "flock", "chroot", "unbuffer", "arch", "command", "env",
            "time", "gtime"}
INTERPRETERS = {
    # program: flags that carry inline code
    "python": {"-c"}, "python2": {"-c"}, "python3": {"-c"}, "pythonw": {"-c"},
    "node": {"-e", "--eval", "-p", "--print"}, "nodejs": {"-e", "--eval", "-p", "--print"},
    "perl": {"-e", "-E"}, "ruby": {"-e"}, "php": {"-r"},
    "lua": {"-e"}, "Rscript": {"-e"}, "bun": {"-e", "--eval", "-p", "--print"},
    "deno": {"eval"}, "tclsh": set(), "wish": set(),
}
NETWORK = {"curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "rsync", "ftp",
           "sftp", "telnet"}
FREE_READERS = {"ls", "cat", "head", "tail", "wc", "stat", "file", "du", "df"}
FREE_NO_PATHS = {"pwd", "which", "uname", "basename", "dirname", "true", "false",
                 ":", "sleep", "exit", "return", "break", "continue", "wait", "shift",
                 "popd"}
FILE_OPS = {"mv", "cp", "mkdir", "touch", "ln", "tee", "lpr", "chmod", "chown",
            "chgrp", "chflags", "xattr", "install", "zip", "unzip", "tar", "gzip",
            "gunzip", "ditto"}
HEADERS = {"for", "select", "case", "in", "function"}
EDITORS = {"vim", "vi", "nvim", "view", "gvim", "mvim", "vimdiff", "nano", "pico", "emacs",
           "emacsclient", "micro", "kak", "hx"}
PAGERS = {"less", "more", "most"}
# Shell variables that change what later commands run or where they look.
# PWD, OLDPWD and DIRSTACK feed the tilde forms ~+, ~- and ~N; NULLCMD and
# READNULLCMD are what zsh runs for a redirection without a command; FPATH
# holds autoloaded functions; BASH_CMDS and zsh's `commands`, `aliases`,
# `functions` and `nameddirs` arrays change what a name runs or where ~name
# points; TMPPREFIX is where zsh writes its temporary files.
DANGEROUS_VARS = re.compile(
    r"PATH|IFS|BASH_ENV|ENV|PROMPT_COMMAND|CDPATH|HOME|ZDOTDIR|TMPDIR|SHELLOPTS|BASHOPTS"
    r"|PS4|PAGER|EDITOR|VISUAL|BROWSER|LESSOPEN|LESSCLOSE|MANPAGER|LD_\w*|DYLD_\w*"
    r"|PYTHON\w*|NODE_OPTIONS|NODE_PATH|PERL5\w*|PERLLIB|RUBY\w*|GIT_\w*|SSH_\w*"
    r"|PWD|OLDPWD|DIRSTACK|NULLCMD|READNULLCMD|FPATH|MODULE_PATH|TMPPREFIX|BASH_\w*"
    r"|COMMANDS|ALIASES|GALIASES|SALIASES|FUNCTIONS|BUILTINS|NAMEDDIRS|USERDIRS"
    r"|OPTIONS|PARAMETERS|DIS_\w*|HISTFILE|ZSH_\w*",
    re.IGNORECASE)
SYSTEM_BIN = ("/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/local/bin",
              "/opt/homebrew/bin", "/usr/libexec")

VALUE_FLAGS = {
    "head": {"-n", "-c"}, "tail": {"-n", "-c", "-b"},
    "stat": {"-f", "-c", "-t", "--format", "--printf"},
    "file": {"-m", "-f", "-F", "-e", "-P", "--magic-file", "--files-from", "--separator"},
    "du": {"-d", "-B", "-t", "-I", "-X", "--max-depth", "--block-size", "--exclude-from"},
    "df": {"-t", "-B", "-x", "--type", "--exclude-type", "--block-size"},
    "ls": {"-I", "-w", "-T", "--ignore", "--hide", "--width", "--tabsize"},
    "grep": {"-e", "-f", "-m", "-A", "-B", "-C", "-D", "-d", "--regexp", "--file",
             "--max-count", "--context", "--after-context", "--before-context",
             "--include", "--exclude", "--exclude-dir", "--exclude-from", "--label",
             "--devices", "--directories", "--binary-files"},
    "rg": {"-e", "-f", "-g", "-t", "-T", "-m", "-A", "-B", "-C", "-j", "-M", "-r",
           "-E", "-d", "--type", "--type-not", "--glob", "--iglob", "--regexp", "--file",
           "--replace", "--max-count", "--max-depth", "--context", "--after-context",
           "--before-context", "--encoding", "--ignore-file", "--pre", "--pre-glob",
           "--threads", "--max-columns", "--sort", "--sortr", "--type-add", "--colors",
           "--color", "--path-separator", "--max-filesize", "--context-separator",
           "--field-match-separator", "--field-context-separator", "--engine"},
    "sort": {"-k", "-t", "-o", "-T", "-S", "--key", "--field-separator", "--output",
             "--temporary-directory", "--buffer-size", "--parallel", "--batch-size",
             "--files0-from", "--compress-program", "--random-source"},
    "awk": {"-F", "-v", "-f", "-e", "--source", "--field-separator", "--assign",
            "--file", "-i", "--include", "-l", "--load"},
    "date": {"-r", "-d", "-f", "-v", "-j", "--reference", "--date", "--file"},
}
# flag values that name a file to read, whatever they look like
FILE_VALUE_FLAGS = {"-f", "--file", "--exclude-from", "--ignore-file", "--files0-from",
                    "-X", "--magic-file", "--files-from", "-m", "-r", "--reference"}


class _GlobBudget(Exception):
    """Pattern expansion or checking ran past GLOB_SECONDS."""


def _expand_glob(pattern: str, deadline: float) -> list[str]:
    """Up to GLOB_CAP + 1 matches of a pattern, or _GlobBudget when the
    expansion does not finish before the deadline (a deep pattern can walk a
    large tree without yielding a single match)."""
    left = deadline - time.monotonic()
    if left <= 0:
        raise _GlobBudget()
    box: dict = {}

    def work() -> None:
        try:
            box["matches"] = list(itertools.islice(_glob.iglob(pattern), GLOB_CAP + 1))
        except BaseException as e:  # noqa: BLE001 - reported to the caller below
            box["error"] = e

    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    worker.join(left)
    if worker.is_alive():
        raise _GlobBudget()
    if "error" in box:
        raise box["error"]
    return box["matches"]


class _Bash:
    """State while judging one command: where relative paths may resolve."""

    def __init__(self, cwd: str) -> None:
        self.cwds = [paths.real(cwd)]
        self.capped = False         # the last candidates() hit GLOB_CAP
        self.deadline = time.monotonic() + GLOB_SECONDS

    def tick(self) -> None:
        if time.monotonic() > self.deadline:
            raise _GlobBudget()

    # -- words to paths ----------------------------------------------------
    def candidates(self, word: Word | str):
        """(path text, cwd) pairs a word can stand for: braces and globs
        expanded. The fixed folder in front of every pattern comes first, so a
        caller that stops at the first refusal never expands a pattern under a
        folder it may not reach."""
        if isinstance(word, str):
            texts = [word]
            is_glob = any(ch in word for ch in "*?[")
        else:
            texts = expand_braces(word)
            is_glob = word.glob
        self.capped = False
        for cwd in self.cwds:
            for t in texts:
                yield (_static_dir(t) if is_glob else t, cwd)
        if not is_glob:
            return
        for cwd in self.cwds:
            for t in texts:
                pattern = os.path.join(cwd, os.path.expanduser(t))
                matches = _expand_glob(pattern, self.deadline)
                if len(matches) > GLOB_CAP:
                    self.capped = True
                    matches = matches[:GLOB_CAP]
                for m in matches:
                    self.tick()
                    yield (m, cwd)

    def _cap_verdict(self) -> tuple[str, str]:
        if self.capped:
            return NEEDS_OK, (f"a pattern matches more than {GLOB_CAP} files; "
                              "they could not all be checked")
        return FREE, ""

    def read(self, word: Word | str, what: str = "") -> tuple[str, str]:
        if isinstance(word, Word) and word.dynamic:
            return NEVER, (f"an argument{what} is computed when the command runs "
                           "($(...) or `...`); the gate cannot see which file it names")
        for text, cwd in self.candidates(word):
            ok, why = paths.judge(text, cwd)
            if not ok:
                return NEVER, why
        return self._cap_verdict()

    def scan(self, word: Word | str, **opts) -> tuple[str, str]:
        verdict = self.read(word)
        if verdict[0] != FREE:
            return verdict
        cands = list(self.candidates(word))
        verdict = self._cap_verdict()
        for text, cwd in cands:
            self.tick()
            status, what = paths.scan_tree(text, cwd, **opts)
            if status == "denied":
                return NEVER, f"a recursive read would reach a protected path: {what}"
            if status == "too_big":
                return NEEDS_OK, (f"a recursive read walks more than {what} files; "
                                  "it could not be checked for protected files")
        return verdict

    def write(self, word: Word | str, reason: str) -> tuple[str, str]:
        if isinstance(word, Word) and word.dynamic:
            return NEVER, "a write target is computed when the command runs; the gate cannot see it"
        for text, cwd in self.candidates(word):
            verdict = _write_target(text, [cwd], reason)
            if verdict[0] == NEVER:
                return verdict
        return _worse((NEEDS_OK, reason), self._cap_verdict())

    def cwd_readable(self) -> tuple[str, str]:
        for cwd in self.cwds:
            ok, why = paths.judge(cwd)
            if not ok:
                return NEVER, f"the working directory is not reachable: {why}"
        return FREE, ""

    def loose(self, words: list[Word]) -> tuple[str, str]:
        """For programs whose operands are not all paths: check the ones that
        clearly are (rooted, ~, ./, ../, `..` inside, a protected name)."""
        verdict = (FREE, "")
        for w in words:
            for text in _embedded(w.text) + [w.text]:
                if not text or w.dynamic:
                    continue
                if _looks_like_path(text):
                    verdict = _worse(verdict, self.read(text if text != w.text else w))
                    if verdict[0] == NEVER:
                        return verdict
        return verdict


def _static_dir(pattern: str) -> str:
    keep = []
    for part in pattern.split("/"):
        if any(ch in part for ch in "*?["):
            break
        keep.append(part)
    joined = "/".join(keep)
    if not joined:
        return "/" if pattern.startswith("/") else "."
    return joined


def _looks_like_path(t: str) -> bool:
    if t.startswith(("/", "~", "./", "../")) or t in (".", ".."):
        return True
    if "/../" in t or t.endswith("/..") or "/proc/" in t:
        return True
    return bool(paths._glob_match("/" + t, paths._compiled()))


def _embedded(flag: str) -> list[str]:
    """A path hidden inside a flag: --file=~/x, -f/etc/x."""
    if not flag.startswith("-"):
        return []
    if "=" in flag:
        return [flag.split("=", 1)[1]]
    for i, ch in enumerate(flag):
        if ch in "/~" and i > 1:
            return [flag[i:]]
    return []


def _write_target(target: str, cwds: list[str], reason: str) -> tuple[str, str]:
    for cwd in cwds:
        ok, why = paths.judge(target, cwd)
        if not ok:
            return NEVER, why
        inner = paths.contains_never(target, cwd)
        if inner:
            return NEVER, f"{paths.real(target, cwd)} contains a protected path ({inner})"
    return NEEDS_OK, reason


_ENVIRON = re.compile(r"/proc/[^/\s]*/environ")


def _classify_bash(command: str, cwd: str) -> tuple[str, str]:
    parsed = parse(command)
    if parsed.expansions:
        names = ", ".join(f"${n}" for n in dict.fromkeys(parsed.expansions))
        return NEVER, (f"the command expands {names}; environment variables can hold "
                       "secrets, so no variable expansion is allowed")
    if _ENVIRON.search(command):
        return NEVER, "reads a process environment (/proc/*/environ)"
    if not parsed.segments:
        return NEVER, "nothing to run"
    for seg in parsed.segments:
        why = _unexpanded_forms(seg)
        if why:
            return NEVER, why
    state = _Bash(cwd)
    verdict = (FREE, "")
    for seg in parsed.segments:
        verdict = _worse(verdict, _segment(seg, state))
        if verdict[0] == NEVER:
            break
    if verdict[0] == FREE and not verdict[1]:
        verdict = (FREE, "read-only commands inside the allowed folders")
    return verdict


# An unquoted ~ that the gate does not expand: ~+ ($PWD), ~- ($OLDPWD), ~N and
# ~+N/~-N (the directory stack), ~name (a user's home, or in zsh any named
# directory, including a variable that holds a path).
_TILDE_FORM = re.compile(r"~(?!/|$)")
# zsh equals expansion: =name becomes the full path of the command `name`.
_EQUALS_FORM = re.compile(r"=[^=\s]")


def _unexpanded_forms(seg: Segment) -> str:
    """Why a word of this segment would be expanded by the shell into a path
    the gate never sees, or ""."""
    words = list(seg.words) + list(seg.assignments) + [
        r.target for r in seg.redirects if r.target is not None and r.heredoc is None]
    for w in words:
        text, mask = w.text, w.mask
        for m in _TILDE_FORM.finditer(text):
            i = m.start()
            if not mask[i] and (i == 0 or (text[i - 1] in "=:" and not mask[i - 1])):
                return (f"`{text}` uses a tilde form (~+, ~-, ~N, ~name) that the shell "
                        "expands to a folder the gate cannot see")
        if _EQUALS_FORM.match(text) and not mask[0]:
            return f"`{text}`: zsh expands =name to the path of a program the gate cannot see"
    return ""


def _segment(seg: Segment, st: _Bash) -> tuple[str, str]:
    verdict = (FREE, "")
    if not seg.words and not seg.closes and any(
            r.kind in ("read", "heredoc", "herestring") for r in seg.redirects):
        return NEVER, ("an input redirection without a command: zsh runs $READNULLCMD "
                       "or $NULLCMD on it, a program the gate cannot see")
    if seg.assignments and seg.words:
        return NEVER, ("the command runs with changed environment variables "
                       "(NAME=value cmd), which can change what it executes")
    for a in seg.assignments:
        name = re.split(r"[+\[=]", a.text, maxsplit=1)[0]
        if DANGEROUS_VARS.fullmatch(name):
            return NEVER, f"setting {name} changes what later commands run or where they look"
    if seg.words and os.path.basename(seg.words[0].text) in ("sqlite3", "sqlite"):
        fed = [h.body for h in seg.heredocs] + [r.target.text for r in seg.redirects
                                                if r.kind == "herestring" and r.target]
        if any(_SQLITE_SHELL.search(t) for t in fed):
            return NEVER, "sqlite3 is fed a .shell/.system/.load command"
    for target in seg.targets("write"):
        verdict = _worse(verdict, st.write(target, f"writes to {target.text}"))
        if verdict[0] == NEVER:
            return verdict
    for target in seg.targets("read"):
        verdict = _worse(verdict, st.read(target, " (input redirection)"))
        if verdict[0] == NEVER:
            return verdict
    if not seg.words:
        return verdict
    return _worse(verdict, _program(seg.words[0], seg.words[1:], st))


def _dangerous_name(base: str) -> bool:
    return (base in DELETERS or base in ENV_PRINTERS or base in NEVER_PROGRAMS
            or base in SHELLS or base in WRAPPERS or _interpreter(base) is not None
            or base in NETWORK or base in _RUNNERS or base in EDITORS or base in PAGERS)


_INTERPRETERS_FOLDED = {k.lower(): k for k in INTERPRETERS}


def _canonical(base: str) -> str:
    """The default macOS filesystem ignores case, so `RM` runs rm: a name that
    is dangerous once lowercased is judged in lowercase."""
    low = base.lower()
    if low != base and (_dangerous_name(low) or low == "git" or low in _HANDLERS):
        return low
    return base


def _interpreter(base: str) -> str | None:
    if base in INTERPRETERS:
        return base
    if base.lower() in _INTERPRETERS_FOLDED:
        return _INTERPRETERS_FOLDED[base.lower()]
    m = re.fullmatch(r"(python|pypy|ruby|perl|node|php|lua)(\d+(\.\d+)*)?", base)
    if m:
        return {"python": "python3", "pypy": "python3"}.get(m.group(1), m.group(1))
    return None


def _safe_scripts() -> set[str]:
    return {os.path.realpath(config.expand(p)) for p in _gate("safe_scripts", [])
            if isinstance(p, str) and p}


def _is_safe(word: Word, st: _Bash) -> bool:
    if word.dynamic or word.glob:
        return False
    safe = _safe_scripts()
    if not safe:
        return False
    text = word.text
    if "/" not in text:
        found = shutil.which(text)
        return bool(found) and os.path.realpath(found) in safe and not paths.is_denied(found)
    return all(paths.real(text, cwd) in safe and not paths.is_denied(text, cwd)
               for cwd in st.cwds)


def _run_safe(word: Word, args: list[Word], st: _Bash) -> tuple[str, str]:
    verdict = st.loose(args)
    if verdict[0] == NEVER:
        return verdict
    return _worse((FREE, f"{word.text} is on the safe-scripts list"), verdict)


def _program(prog: Word, args: list[Word], st: _Bash) -> tuple[str, str]:
    if prog.dynamic or prog.glob:
        return NEVER, "the program name is computed when the command runs"
    name = prog.text
    base = _canonical(os.path.basename(name))
    if _is_safe(prog, st):
        return _run_safe(prog, args, st)
    if "/" in name:
        # judged by what it really is: ./cat may be a link to /bin/rm
        resolved = [paths.real(name, cwd) for cwd in st.cwds]
        real_bases = {_canonical(os.path.basename(r)) for r in resolved}
        written_folder = os.path.dirname(paths.literal(name, st.cwds[0]))
        system = all(os.path.dirname(r) in SYSTEM_BIN for r in resolved) \
            or written_folder in SYSTEM_BIN
        dangerous = [b for b in real_bases if _dangerous_name(b)]
        if dangerous:
            base = dangerous[0]
        elif system and len(real_bases) == 1:
            base = real_bases.pop()
        elif _dangerous_name(base):
            pass
        else:
            return _run_script(prog, args, st)
    if base in HEADERS:
        return FREE, ""
    if base in DELETERS:
        return _delete(base, args, st)
    if base in NEVER_PROGRAMS:
        return NEVER, NEVER_PROGRAMS[base]
    if base in ENV_PRINTERS:
        return _env_printer(base, args, st)
    if base in SHELLS:
        return _shell(base, args, st)
    if base == "command":
        return _command(base, args, st)
    if base in WRAPPERS:
        return _wrapper(base, args, st)
    if _interpreter(base):
        return _interpret(_interpreter(base), args, st)
    if base in NETWORK:
        return _network(base, args, st)
    if base in _RUNNERS:
        return _RUNNERS[base](base, args, st)
    if base in EDITORS:
        return _editor(base, args, st)
    if base in PAGERS:
        return _pager(base, args, st)
    if base == "git":
        return _git(args, st)
    handler = _HANDLERS.get(base)
    if handler:
        return handler(base, args, st)
    extras = {e for e in _gate("free_commands_extra", []) if isinstance(e, str)}
    if base in FREE_READERS or base in extras:
        return _reader(base, args, st)
    if base in FREE_NO_PATHS:
        if any(a.dynamic for a in args):
            return NEEDS_OK, f"{base} with an argument computed at run time"
        return FREE, ""
    if base in FILE_OPS:
        return _file_op(base, args, st)
    verdict = _passed_delete(args) or st.loose(args)
    if verdict[0] == NEVER:
        return verdict
    return _worse((NEEDS_OK, f"`{base}` is not on the read-only list; running it needs your OK"),
                  verdict)


_DELETE_FLAG = re.compile(r"-[A-Za-z]*[rRf][A-Za-z]*|--(recursive|force)(=.*)?", re.S)


_DELETE_IN_TEXT = re.compile(
    r"(?:^|[\s;&|(`/])(?:%s)\s+(?:\S+\s+){0,4}?(?:-[A-Za-z]*[rRf]|--recursive|--force)\b"
    % "|".join(sorted(DELETERS)), re.IGNORECASE)


def _passed_delete(args: list[Word]) -> tuple[str, str] | None:
    """A program the gate cannot read may run its arguments: a delete program
    among them with a recursive or force flag after it, or a whole delete
    command inside one argument (`tool -c 'rm -rf .'`), is "never"."""
    for k, a in enumerate(args):
        if os.path.basename(a.text).lower() in DELETERS and any(
                _DELETE_FLAG.fullmatch(b.text) for b in args[k + 1:]):
            return NEVER, (f"`{a.text}` with a recursive or forced flag is passed to another "
                           "program, which may run it; deletes are never allowed")
        if _DELETE_IN_TEXT.search(a.text):
            return NEVER, (f"the argument `{a.text}` holds a recursive or forced delete "
                           "that another program may run; deletes are never allowed")
    return None


# -- argument splitting ------------------------------------------------------

def _split(args: list[Word], value_flags: set) -> tuple[list[tuple[str, Word | None]], list[Word]]:
    """(flags with their values, operands)."""
    flags: list[tuple[str, Word | None]] = []
    ops: list[Word] = []
    i, end = 0, False
    while i < len(args):
        w = args[i]
        t = w.text
        if end or t == "-" or not t.startswith("-") or len(t) < 2:
            ops.append(w)
        elif t == "--":
            end = True
        elif t.startswith("--"):
            if "=" in t:
                k, v = t.split("=", 1)
                flags.append((k, Word(v, tuple([True] * len(v)), w.dynamic)))
            elif t in value_flags and i + 1 < len(args):
                flags.append((t, args[i + 1]))
                i += 1
            else:
                flags.append((t, None))
        else:
            value: Word | None = None
            for j in range(1, len(t)):
                if "-" + t[j] in value_flags:
                    rest = t[j + 1:]
                    if rest:
                        value = Word(rest, tuple([True] * len(rest)), w.dynamic)
                    elif i + 1 < len(args):
                        value = args[i + 1]
                        i += 1
                    flags.append(("-" + t[j], value))
                    break
                flags.append(("-" + t[j], None))
        i += 1
    return flags, ops


def _check_flag_values(flags, st: _Bash) -> tuple[str, str]:
    verdict = (FREE, "")
    for k, v in flags:
        if v is None:
            continue
        if v.dynamic:
            return NEVER, f"the value of {k} is computed when the command runs"
        if k in FILE_VALUE_FLAGS or _looks_like_path(v.text):
            verdict = _worse(verdict, st.read(v))
            if verdict[0] == NEVER:
                return verdict
    return verdict


def _reads(words: list[Word], st: _Bash) -> tuple[str, str]:
    verdict = (FREE, "")
    for w in words:
        verdict = _worse(verdict, st.read(w))
        if verdict[0] == NEVER:
            return verdict
    return verdict


def _flag_set(flags) -> set[str]:
    return {k for k, _ in flags}


# -- read-only programs ------------------------------------------------------

def _reader(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    flags, ops = _split(args, VALUE_FLAGS.get(base, set()))
    verdict = _check_flag_values(flags, st)
    if verdict[0] == NEVER:
        return verdict
    if base == "file" and _flag_set(flags) & {"-C", "--compile"}:
        verdict = _worse(verdict, (NEEDS_OK, "file -C writes a compiled magic file"))
    if not ops and base in ("ls", "du"):
        verdict = _worse(verdict, st.cwd_readable())
    return _worse(verdict, _reads(ops, st))


def _grep(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    flags, ops = _split(args, VALUE_FLAGS["grep"])
    verdict = _check_flag_values([(k, v) for k, v in flags
                                  if k not in ("--include", "--exclude", "--exclude-dir")], st)
    if verdict[0] == NEVER:
        return verdict
    names = _flag_set(flags)
    if not names & {"-e", "--regexp", "-f", "--file"} and ops:
        ops = ops[1:]                               # the pattern is not a path
    recursive = bool(names & {"-r", "-R", "--recursive", "--dereference-recursive"}) or any(
        k in ("-d", "--directories") and v is not None and v.text == "recurse" for k, v in flags)
    if not recursive:
        return _worse(verdict, _reads(ops, st))
    opts = dict(only=tuple(v.text for k, v in flags if k == "--include" and v),
                exclude=tuple(v.text for k, v in flags if k == "--exclude" and v),
                exclude_dirs=tuple(v.text for k, v in flags if k == "--exclude-dir" and v))
    for w in ops or [Word(".", (False,))]:
        verdict = _worse(verdict, st.scan(w, **opts))
        if verdict[0] == NEVER:
            return verdict
    return verdict


def _rg(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    flags, ops = _split(args, VALUE_FLAGS["rg"])
    names = _flag_set(flags)
    if names & {"--pre"}:
        return NEVER, "rg --pre runs a program on every file it searches"
    verdict = _check_flag_values([(k, v) for k, v in flags
                                  if k not in ("-g", "--glob", "--iglob", "-r", "--replace")], st)
    if verdict[0] == NEVER:
        return verdict
    if not names & {"-e", "--regexp", "-f", "--file", "--files", "--type-list"} and ops:
        ops = ops[1:]
    globs = [g for k, v in flags if k in ("-g", "--glob", "--iglob") and v
             for g in _brace_list(v.text)]
    hidden = bool(globs) or any(n in ("--hidden", "-.", "-u", "--unrestricted")
                                or n.startswith("--no-ignore") for n in names)
    opts = dict(include_hidden=hidden,
                only=tuple(g for g in globs if not g.startswith("!")),
                exclude=tuple(g[1:] for g in globs if g.startswith("!")))
    for w in ops or [Word(".", (False,))]:
        verdict = _worse(verdict, st.scan(w, **opts))
        if verdict[0] == NEVER:
            return verdict
    return verdict


FIND_NEVER = {"-delete": "find -delete deletes files",
              "-exec": "find -exec runs another command", "-execdir": "find -execdir runs another command",
              "-ok": "find -ok runs another command", "-okdir": "find -okdir runs another command"}
FIND_WRITES = {"-fprint", "-fprint0", "-fprintf", "-fls"}


def _find(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    i = 0
    starts: list[Word] = []
    while i < len(args) and args[i].text in ("-H", "-L", "-P", "-E", "-X", "-d", "-s", "-x", "-f"):
        if args[i].text == "-f" and i + 1 < len(args):
            starts.append(args[i + 1])
            i += 1
        i += 1
    while i < len(args) and not args[i].text.startswith(("-", "(", "!", ")")):
        starts.append(args[i])
        i += 1
    verdict = (FREE, "")
    expr = args[i:]
    for k, w in enumerate(expr):
        if w.text in FIND_NEVER:
            return NEVER, FIND_NEVER[w.text]
        if w.text in FIND_WRITES:
            if k + 1 >= len(expr):
                return NEVER, f"find {w.text} without a file"
            verdict = _worse(verdict, st.write(expr[k + 1], f"find {w.text} writes {expr[k + 1].text}"))
        if w.dynamic:
            return NEVER, "a find expression is computed when the command runs"
    if not starts:
        verdict = _worse(verdict, st.cwd_readable())
    return _worse(verdict, _reads(starts, st))


def _sed(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    in_place = False
    scripts: list[Word] = []
    script_files: list[Word] = []
    ops: list[Word] = []
    i, end = 0, False
    while i < len(args):
        w = args[i]
        t = w.text
        if end or not t.startswith("-") or t == "-":
            ops.append(w)
        elif t == "--":
            end = True
        elif t.startswith("--"):
            k, _, v = t.partition("=")
            if k == "--in-place":
                in_place = True
            elif k in ("--expression", "--file"):
                if not v and i + 1 < len(args):
                    i += 1
                    val = args[i]
                else:
                    val = Word(v, tuple([True] * len(v)), w.dynamic)
                (scripts if k == "--expression" else script_files).append(val)
        else:
            for j in range(1, len(t)):
                ch = t[j]
                if ch in "iI":
                    in_place = True
                    if t == "-i" and i + 1 < len(args) and (
                            args[i + 1].text == "" or re.fullmatch(r"\.[\w.~-]*", args[i + 1].text)):
                        i += 1                    # BSD: -i '' / -i .bak
                    break
                if ch in "ef":
                    rest = t[j + 1:]
                    if rest:
                        val = Word(rest, tuple([True] * len(rest)), w.dynamic)
                    elif i + 1 < len(args):
                        i += 1
                        val = args[i]
                    else:
                        return NEVER, "sed -e/-f without a value"
                    (scripts if ch == "e" else script_files).append(val)
                    break
                if ch == "l":
                    if not t[j + 1:]:
                        i += 1
                    break
        i += 1
    if not scripts and not script_files:
        if not ops:
            return NEVER, "sed without a script"
        scripts, ops = [ops[0]], ops[1:]
    verdict = (FREE, "")
    for sw in scripts:
        if sw.dynamic:
            return NEVER, "the sed script is computed when the command runs"
        try:
            reads, writes, executes = _sed_script(sw.text)
        except ValueError as e:
            return NEVER, f"the sed script could not be read ({e}); unreadable means denied"
        if executes:
            return NEVER, "the sed script runs shell commands (the e command or s///e)"
        for r in reads:
            verdict = _worse(verdict, st.read(r))
        for w_ in writes:
            verdict = _worse(verdict, st.write(w_, f"the sed script writes {w_}"))
        if verdict[0] == NEVER:
            return verdict
    for f in script_files:
        verdict = _worse(verdict, st.read(f))
        verdict = _worse(verdict, (NEEDS_OK, "sed runs a script file the gate has not read"))
    verdict = _worse(verdict, _reads(ops, st))
    if in_place:
        if not ops:
            return NEVER, "sed -i without a file"
        for f in ops:
            verdict = _worse(verdict, st.write(f, f"sed -i rewrites {f.text}"))
    return verdict


def _sed_script(script: str) -> tuple[list[str], list[str], bool]:
    """(files read, files written, runs commands) for a sed script. ValueError
    when it cannot be read."""
    reads: list[str] = []
    writes: list[str] = []
    s, i, n = script, 0, len(script)

    def to_eol(k: int) -> tuple[str, int]:
        e = s.find("\n", k)
        e = n if e < 0 else e
        return s[k:e].strip(), e

    def delimited(k: int, d: str) -> int:
        while k < n:
            if s[k] == "\\":
                k += 2
                continue
            if s[k] == "\n" and d != "\n":
                raise ValueError("unterminated expression")
            if s[k] == d:
                return k + 1
            k += 1
        raise ValueError("unterminated expression")

    def address(k: int) -> int:
        if k < n and s[k] == "/":
            return delimited(k + 1, "/")
        if k < n and s[k] == "\\" and k + 1 < n:
            return delimited(k + 2, s[k + 1])
        m = re.match(r"\d+(~\d+)?|\$", s[k:])
        return k + (len(m.group()) if m else 0)

    while i < n:
        c = s[i]
        if c in " \t\n;}":
            i += 1
            continue
        i = address(i)
        if i < n and s[i] == ",":
            i = address(i + 1)
            if i < n and s[i] in "+~":
                m = re.match(r"[+~]\d+", s[i:])
                i += len(m.group()) if m else 1
        while i < n and s[i] in " \t!":
            i += 1
        if i >= n:
            break
        c = s[i]
        i += 1
        if c == "{" or c in ";\n}":
            continue
        if c == "s":
            if i >= n:
                raise ValueError("s without a delimiter")
            d = s[i]
            i = delimited(i + 1, d)
            i = delimited(i, d)
            m = re.match(r"[gpiImMe0-9]*", s[i:])
            fl = m.group()
            i += len(fl)
            if "e" in fl:
                return reads, writes, True
            if i < n and s[i] == "w":
                name, i = to_eol(i + 1)
                if not name:
                    raise ValueError("w without a file")
                if name not in ("/dev/stdout", "/dev/stderr"):
                    writes.append(name)
        elif c == "y":
            if i >= n:
                raise ValueError("y without a delimiter")
            d = s[i]
            i = delimited(delimited(i + 1, d), d)
        elif c in "aic":
            _, i = to_eol(i)
        elif c in "rRwW":
            name, i = to_eol(i)
            if not name:
                raise ValueError(f"{c} without a file")
            if name in ("/dev/stdout", "/dev/stderr", "/dev/stdin"):
                continue
            (reads if c in "rR" else writes).append(name)
        elif c == "e":
            return reads, writes, True
        elif c in ":btT":
            m = re.match(r"[^;\n]*", s[i:])
            i += len(m.group())
        elif c in "qQlL":
            m = re.match(r"\s*\d*", s[i:])
            i += len(m.group())
        elif c in "=dDgGhHnNpPxzF#":
            if c == "#":
                _, i = to_eol(i)
        else:
            raise ValueError(f"unknown sed command {c!r}")
    return reads, writes, False


def _sort(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    flags, ops = _split(args, VALUE_FLAGS["sort"])
    verdict = (FREE, "")
    for k, v in flags:
        if k == "--compress-program":
            return NEVER, "sort --compress-program runs another program"
        if v is None:
            continue
        if v.dynamic:
            return NEVER, f"the value of {k} is computed when the command runs"
        if k in ("-o", "--output"):
            verdict = _worse(verdict, st.write(v, f"sort -o writes {v.text}"))
        elif k in ("-T", "--temporary-directory", "--files0-from", "--random-source"):
            verdict = _worse(verdict, st.read(v))
        if verdict[0] == NEVER:
            return verdict
    return _worse(verdict, _reads(ops, st))


_AWK_NEVER = [
    (re.compile(r"\bsystem\s*\("), "awk system() runs a shell command"),
    (re.compile(r"\b(ENVIRON|SYMTAB|PROCINFO|FUNCTAB)\b"),
     "awk reads the environment or its own symbol table"),
    (re.compile(r"\|&|(?<!\|)\|(?!\|)"), "awk runs a command through a pipe"),
    (re.compile(r"@"), "awk loads code or calls a function by name (@)"),
]
_AWK_KEYWORDS_BEFORE_REGEX = {"print", "printf", "return", "in", "case", "if", "while",
                              "for", "do", "else", "getline"}


def _awk_strip(prog: str) -> str:
    """The program with string and regex literals emptied and comments removed,
    so a `;`, `}`, `>` or `|` inside a literal cannot hide or fake a statement.
    ValueError when a literal is not closed or parentheses do not balance."""
    out: list[str] = []
    i, n = 0, len(prog)
    last = ""          # last significant character emitted
    word = ""          # last identifier emitted
    while i < n:
        c = prog[i]
        if c == '"':
            j = i + 1
            while j < n and prog[j] != '"':
                if prog[j] == "\n":
                    raise ValueError("string not closed")
                j += 2 if prog[j] == "\\" else 1
            if j >= n:
                raise ValueError("string not closed")
            out.append('""')
            last, word = '"', ""
            i = j + 1
            continue
        if c == "/" and (not last or last in "(,{};!~&|=<>+-*%^?:\n[" or
                         word in _AWK_KEYWORDS_BEFORE_REGEX):
            j = i + 1
            in_class = False
            while j < n:
                ch = prog[j]
                if ch == "\n":
                    raise ValueError("regex not closed")
                if ch == "\\":
                    j += 2
                    continue
                if ch == "[":
                    in_class = True
                elif ch == "]":
                    in_class = False
                elif ch == "/" and not in_class:
                    break
                j += 1
            if j >= n:
                raise ValueError("regex not closed")
            out.append("//")
            last, word = "/", ""
            i = j + 1
            continue
        if c == "#":
            while i < n and prog[i] != "\n":
                i += 1
            continue
        out.append(c)
        if c.isalnum() or c == "_":
            word = word + c if (last.isalnum() or last == "_") else c
        elif not c.isspace():
            word = ""
        if not c.isspace() or c == "\n":
            last = c
        i += 1
    text = "".join(out)
    depth = 0
    for ch in text:
        depth += {"(": 1, ")": -1}.get(ch, 0)
        if depth < 0:
            raise ValueError("unbalanced parentheses")
    if depth:
        raise ValueError("unbalanced parentheses")
    return text


def _awk_statement_has(text: str, keyword: str, chars: str) -> bool:
    """Does a `keyword` statement contain one of `chars` outside parentheses?"""
    for m in re.finditer(rf"\b{keyword}\b", text):
        depth = 0
        for ch in text[m.end():]:
            if ch in "([":
                depth += 1
            elif ch in ")]":
                depth -= 1
                if depth < 0:
                    break
            elif depth == 0 and ch in ";}\n":
                break
            elif depth == 0 and ch in chars:
                return True
    return False


def _awk_program(prog: str) -> tuple[str, str]:
    try:
        text = _awk_strip(prog)
    except ValueError as e:
        return NEVER, f"the awk program could not be read ({e}); unreadable means denied"
    for rx, why in _AWK_NEVER:
        if rx.search(text):
            return NEVER, why
    if _awk_statement_has(text, "getline", "<"):
        return NEVER, "awk getline < reads a file the gate cannot see"
    if _awk_statement_has(text, "printf?", ">"):
        return NEEDS_OK, "awk print > writes to a file"
    return FREE, ""


def _awk(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    flags, ops = _split(args, VALUE_FLAGS["awk"])
    verdict = (FREE, "")
    programs: list[Word] = []
    for k, v in flags:
        if v is not None and v.dynamic:
            return NEVER, f"the value of {k} is computed when the command runs"
        if k in ("-f", "--file"):
            if v is None:
                return NEVER, "awk -f without a file"
            verdict = _worse(verdict, st.read(v))
            verdict = _worse(verdict, (NEEDS_OK, "awk runs a program file the gate has not read"))
        elif k in ("-e", "--source"):
            if v is not None:
                programs.append(v)
        elif k in ("-F", "--field-separator", "-v", "--assign"):
            continue
        else:
            verdict = _worse(verdict, (NEEDS_OK, f"awk {k} is not a read-only option the gate knows"))
    if not programs and not any(k in ("-f", "--file") for k, _ in flags):
        if not ops:
            return NEVER, "awk without a program"
        programs, ops = [ops[0]], ops[1:]
    for p in programs:
        if p.dynamic:
            return NEVER, "the awk program is computed when the command runs"
        verdict = _worse(verdict, _awk_program(p.text))
        if verdict[0] == NEVER:
            return verdict
    files = [w for w in ops if not re.match(r"[A-Za-z_]\w*=", w.text)]
    return _worse(verdict, _reads(files, st))


def _cd(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    ops = [a for a in args if not a.text.startswith("-") or a.text == "-"]
    target: Word | str = ops[0] if ops else paths.home()
    if isinstance(target, Word) and target.text == "-":
        return NEVER, "cd - goes to a folder the gate cannot see"
    verdict = st.read(target)
    if verdict[0] == NEVER:
        return verdict
    new = []
    for text, cwd in st.candidates(target):
        r = paths.real(text, cwd)
        if r not in new:
            new.append(r)
    st.cwds = list(dict.fromkeys(st.cwds + new))
    return FREE, ""


def _echo(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    if any(a.dynamic or a.glob for a in args):
        return NEEDS_OK, "echo of text computed when the command runs"
    return FREE, ""


def _date(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    flags, _ = _split(args, VALUE_FLAGS["date"])
    if _flag_set(flags) & {"-s", "--set"}:
        return NEEDS_OK, "date -s sets the clock"
    for k, v in flags:
        if k in ("-r", "--reference", "-f", "--file") and v is not None:
            verdict = st.read(v)
            if verdict[0] == NEVER:
                return verdict
    return FREE, ""


def _command(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    if args and args[0].text in ("-v", "-V"):
        return FREE, ""
    return _wrapper(base, args, st)


def _type(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    return FREE, ""


_HANDLERS = {
    "grep": _grep, "egrep": _grep, "fgrep": _grep, "rg": _rg, "find": _find,
    "sed": _sed, "gsed": _sed, "sort": _sort, "awk": _awk, "gawk": _awk,
    "mawk": _awk, "nawk": _awk, "cd": _cd, "pushd": _cd, "echo": _echo,
    "date": _date, "type": _type,
}


# -- deletes -----------------------------------------------------------------

def _delete(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    if base not in ("rm", "unlink"):
        return NEVER, f"`{base}` destroys data; deletes are never allowed"
    flags = [a for a in args if a.text.startswith("-") and a.text != "-"]
    ops = [a for a in args if a not in flags]
    for f in flags:
        t = f.text
        if t.startswith("--"):
            if t not in ("--verbose", "--interactive"):
                return NEVER, f"rm {t}: recursive or forced deletes are never allowed"
        elif set(t[1:]) - set("iv"):
            return NEVER, f"rm {t}: recursive or forced deletes are never allowed"
    if len(ops) != 1:
        return NEVER, "rm of several files at once is never allowed"
    w = ops[0]
    if w.dynamic or w.glob or w.brace:
        return NEVER, "rm with a pattern or a computed name is never allowed"
    for cwd in st.cwds:
        if paths.is_denied(w.text, cwd) or not paths.is_scratch(w.text, cwd) \
                or os.path.isdir(paths.real(w.text, cwd)):
            return NEVER, ("deletes are never allowed, except one plain file inside "
                           "a scratch folder")
    return NEEDS_OK, f"deletes one scratch file: {w.text}"


# -- environment -------------------------------------------------------------

def _env_printer(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    if base == "printenv":
        return NEVER, "printenv prints the environment, where tokens live"
    if base in ("export", "declare", "typeset"):
        return NEVER, f"`{base}` prints or changes the environment"
    if base == "set":
        if not args:
            return NEVER, "set without arguments prints every variable"
        if all(re.fullmatch(r"[-+][euxvfhnCbmBHPTo]+|pipefail|errexit|nounset|xtrace|--?", a.text)
               for a in args):
            return FREE, ""
        return NEEDS_OK, "set with arguments the gate does not recognise"
    if base == "ps":
        if any(re.search(r"[eE]", a.text) for a in args if not a.text.isdigit()):
            return NEVER, "ps with e/E shows the environment of processes"
        return NEEDS_OK, "ps lists processes; it needs your OK"
    # env
    rest = [a for a in args if not (a.text.startswith("-") or "=" in a.text)]
    if not rest:
        return NEVER, "env without a command prints the environment"
    return _wrapper(base, args, st)


# -- wrappers, shells, interpreters -----------------------------------------

def _wrapper(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    if base == "eval":
        text = " ".join(a.text for a in args)
        if any(a.dynamic for a in args):
            return NEVER, "eval of computed text"
        return _inner_command(base, text, st)
    if base in ("source", "."):
        if args and _is_safe(args[0], st):
            return _run_safe(args[0], args[1:], st)
        return NEVER, f"`{base}` runs a file inside the shell, hidden from the gate"
    # the first word that is not an option, an assignment or a number
    for k, a in enumerate(args):
        t = a.text
        if t.startswith("-") or re.fullmatch(r"[A-Za-z_]\w*=.*", t, re.S) \
                or re.fullmatch(r"[\d.]+[smhd]?", t):
            continue
        if _is_safe(a, st):
            return _run_safe(a, args[k + 1:], st)
        break
    return NEVER, f"`{base}` runs another command and hides it from the gate"


def _inner_command(base: str, text: str, st: _Bash) -> tuple[str, str]:
    """`bash -c TEXT`, `eval TEXT`: allowed only when TEXT runs one safe script."""
    try:
        inner = parse(text)
    except ParseError:
        return NEVER, f"`{base}` hides a command the gate cannot parse"
    segs = inner.segments
    if (not inner.expansions and len(segs) == 1 and segs[0].words and not segs[0].assignments
            and not segs[0].redirects and _is_safe(segs[0].words[0], st)):
        return _run_safe(segs[0].words[0], segs[0].words[1:], st)
    return NEVER, f"`{base}` hides a command from the gate (only a safe script may run this way)"


def _shell(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    i = 0
    while i < len(args) and args[i].text.startswith(("-", "+")) and args[i].text not in ("-", "--"):
        t = args[i].text
        if not t.startswith("--") and "c" in t[1:]:
            if i + 1 >= len(args) or args[i + 1].dynamic:
                return NEVER, f"{base} -c with a computed command"
            return _inner_command(f"{base} -c", args[i + 1].text, st)
        if not t.startswith("--") and "s" in t[1:]:
            return NEVER, f"{base} -s reads commands from standard input, hidden from the gate"
        if t in ("-o", "+o", "--rcfile", "--init-file"):
            i += 1
        i += 1
    if i < len(args) and args[i].text == "--":
        i += 1
    if i >= len(args) or args[i].text == "-":
        return NEVER, f"{base} without a script reads commands from standard input, hidden from the gate"
    return _run_script(args[i], args[i + 1:], st)


def _interpret(lang: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    inline = INTERPRETERS.get(lang, set())
    value_flags = {"python3": {"-W", "-X", "-Q"}, "node": {"-r", "--require", "--import",
                   "--loader", "--experimental-loader"}, "ruby": {"-r", "-I", "-C"},
                   "perl": {"-I", "-M", "-m"}}.get(lang, set())
    if lang == "deno":
        if args and args[0].text in inline:
            return NEVER, "deno eval runs inline code"
        return _unknown_runner(lang, args, st)
    if lang == "bun":
        if any(a.text in inline for a in args):
            return NEVER, "bun -e runs inline code"
        return _unknown_runner(lang, args, st)
    i = 0
    while i < len(args):
        t = args[i].text
        if t == "--":
            i += 1
            break
        if t == "-" or not t.startswith("-"):
            break
        if t in inline or t.split("=", 1)[0] in inline:
            return NEVER, f"{lang} {t} runs inline code the gate cannot judge"
        if not t.startswith("--"):
            letters = t[1:]
            for flag in inline:
                if flag.startswith("-") and not flag.startswith("--") and flag[1] in letters:
                    return NEVER, f"{lang} {t} runs inline code the gate cannot judge"
        if lang == "python3" and (t == "-m" or t.startswith("-m")):
            return _unknown_runner(lang, args, st, f"{lang} -m runs a module")
        if t in value_flags:
            i += 1
        i += 1
    if i >= len(args) or args[i].text == "-":
        return NEVER, f"{lang} without a script reads code from standard input, hidden from the gate"
    return _run_script(args[i], args[i + 1:], st)


def _run_script(script: Word, args: list[Word], st: _Bash) -> tuple[str, str]:
    if script.dynamic or script.glob:
        return NEVER, "the script to run is computed when the command runs"
    if _is_safe(script, st):
        return _run_safe(script, args, st)
    verdict = _passed_delete(args) or st.read(script)
    if verdict[0] == NEVER:
        return verdict
    verdict = _worse(verdict, st.loose(args))
    if verdict[0] == NEVER:
        return verdict
    return _worse(verdict, (NEEDS_OK, f"runs {script.text}, which is not on the safe-scripts list"))


def _unknown_runner(lang: str, args: list[Word], st: _Bash, why: str = "") -> tuple[str, str]:
    verdict = _passed_delete(args) or st.loose(args)
    if verdict[0] == NEVER:
        return verdict
    return _worse(verdict, (NEEDS_OK, why or f"`{lang}` runs code; it needs your OK"))


# -- other known command-runners --------------------------------------------

_SQLITE_SHELL = re.compile(r"(^|[\n;])\s*\.(shell|system|load|sh)\b|^\s*!", re.MULTILINE)


def _pwsh(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    for a in args:
        t = a.text.lower()
        if t in ("-", "/c") or not t.startswith("-"):
            if t in ("-", "/c"):
                return NEVER, f"{base} reads or runs an inline command"
            break
        flag = t.lstrip("-")
        if flag and ("command".startswith(flag) or "encodedcommand".startswith(flag)
                     or flag in ("e", "ec", "enc")):
            return NEVER, f"{base} {a.text} runs an inline command the gate cannot judge"
    if not any(not a.text.startswith("-") for a in args) and not any(
            a.text.lower().lstrip("-") in ("file", "f") for a in args):
        return NEVER, f"{base} without a script reads commands from standard input"
    return _unknown_runner(base, args, st)


_UV_VALUES = {"--with", "--python", "-p", "--from", "--directory", "--project", "--env-file",
              "--index", "--extra", "--group", "--package", "--with-requirements", "-w",
              "--index-url", "--extra-index-url"}


def _uv(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    rest = list(args)
    if base == "uv":
        while rest and rest[0].text.startswith("-"):
            rest.pop(0)
        if not rest or rest[0].text not in ("run", "tool", "x"):
            return _unknown_runner(base, args, st)
        if rest[0].text == "tool":
            rest = rest[1:]
            if not rest or rest[0].text != "run":
                return _unknown_runner(base, args, st)
        rest = rest[1:]
    verdict = (NEEDS_OK, f"`{base}` runs a program; it needs your OK")
    i = 0
    while i < len(rest) and rest[i].text.startswith("-") and rest[i].text != "--":
        k = rest[i].text.split("=", 1)[0]
        if k == "--env-file":
            value = rest[i].text.split("=", 1)[1] if "=" in rest[i].text else (
                rest[i + 1].text if i + 1 < len(rest) else "")
            verdict = _worse(verdict, st.read(value))
        if k in _UV_VALUES and "=" not in rest[i].text:
            i += 1
        i += 1
    if i < len(rest) and rest[i].text == "--":
        i += 1
    if i < len(rest):
        verdict = _worse(verdict, _program(rest[i], rest[i + 1:], st))
    return verdict


def _npx(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    texts = [a.text for a in args]
    if base in ("npm", "pnpm", "yarn") and not (texts and texts[0] in ("exec", "x", "dlx")):
        return _unknown_runner(base, args, st)
    for t in texts:
        if t in ("-c", "--call", "--shell") or t.startswith(("--call=", "-c=")):
            return NEVER, f"{base} {t} runs an inline shell command"
    return _unknown_runner(base, args, st)


def _expect(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    for a in args:
        if a.text == "-c" or (a.text.startswith("-") and not a.text.startswith("--")
                              and "c" in a.text[1:]):
            return NEVER, "expect -c runs an inline script"
    if not any(not a.text.startswith("-") for a in args) or any(a.text == "-" for a in args):
        return NEVER, "expect without a script reads commands from standard input"
    return _unknown_runner(base, args, st)


def _sqlite(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    for a in args:
        if a.dynamic:
            return NEVER, "sqlite3 with an argument computed when the command runs"
        if _SQLITE_SHELL.search(a.text):
            return NEVER, "sqlite3 .shell/.system/.load (or a ! command) runs other programs"
    return _unknown_runner(base, args, st)


_TERMINAL_APPS = re.compile(r"terminal|iterm|warp|kitty|alacritty|ghostty|wezterm|hyper"
                            r"|script ?editor|automator|shortcuts", re.IGNORECASE)
_RUNNABLE = re.compile(r"\.(command|tool|sh|zsh|bash|csh|app|workflow|scpt|scptd|applescript"
                       r"|terminal|action|shortcut|pkg|mpkg)/?$", re.IGNORECASE)


def _open(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    for k, a in enumerate(args):
        t = a.text
        if a.dynamic:
            return NEVER, "open with an argument computed when the command runs"
        if t in ("-a", "-b") and k + 1 < len(args) and _TERMINAL_APPS.search(args[k + 1].text):
            return NEVER, f"open {t} {args[k + 1].text} starts a terminal or script runner"
        if _RUNNABLE.search(t) and "://" not in t:
            return NEVER, f"open {t} runs a script or an application"
    return _unknown_runner(base, args, st)


def _compgen(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    texts = [a.text for a in args]
    for k, t in enumerate(texts):
        if t.startswith("-") and not t.startswith("--") and set(t[1:]) & set("ve"):
            return NEVER, "compgen -v/-e lists variables"
        if t == "-A" and k + 1 < len(texts) and texts[k + 1] in ("variable", "export", "arrayvar"):
            return NEVER, "compgen -A variable/export lists variables"
    return _unknown_runner(base, args, st)


def _local(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    if base == "readonly" and not [a for a in args if not a.text.startswith("-")]:
        return NEVER, "readonly without names prints variables"
    for a in args:
        name = re.split(r"[+\[=]", a.text, maxsplit=1)[0]
        if DANGEROUS_VARS.fullmatch(name):
            return NEVER, f"setting {name} changes what later commands run or where they look"
    return _unknown_runner(base, args, st)


def _editor(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    for a in args:
        t = a.text
        if t.startswith("+") or t in ("-c", "--cmd", "-S", "-s", "-e", "-E", "-x", "-l", "-f",
                                      "--eval", "-eval", "--load", "--funcall", "--batch",
                                      "-batch", "--script", "-script", "--exec") \
                or t.startswith(("--eval=", "--load=", "--funcall=", "--script=", "--cmd=")):
            return NEVER, f"{base} {t} runs editor commands, which can run shell commands"
    return _unknown_runner(base, args, st)


def _pager(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    for a in args:
        if a.text.startswith("+") or "!" in a.text:
            return NEVER, f"{base} {a.text} runs pager commands, which can run shell commands"
    return _unknown_runner(base, args, st)


_RUNNERS = {
    "pwsh": _pwsh, "powershell": _pwsh, "uv": _uv, "uvx": _uv, "npx": _npx, "npm": _npx,
    "pnpm": _npx, "yarn": _npx, "expect": _expect, "sqlite3": _sqlite, "sqlite": _sqlite,
    "open": _open, "compgen": _compgen, "local": _local, "readonly": _local,
}


# -- file operations ---------------------------------------------------------

def _file_op(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    flags, ops = _split(args, {"-t", "--target-directory", "-S", "--suffix", "-m", "--mode",
                               "-o", "-g", "-f", "-C"} if base in ("install", "tar", "cp", "mv", "ln") else set())
    verdict = (FREE, "")
    for k, v in flags:
        if v is not None:
            if v.dynamic:
                return NEVER, f"the value of {k} is computed when the command runs"
            if _looks_like_path(v.text) or k in ("-t", "--target-directory", "-f", "-C"):
                verdict = _worse(verdict, st.write(v, f"{base} writes {v.text}"))
    for w in ops:
        if base == "tee" and w.text in NULL_SINKS:
            continue
        verdict = _worse(verdict, st.write(w, f"`{base}` changes files"))
        if verdict[0] == NEVER:
            return verdict
    return _worse(verdict, (NEEDS_OK, f"`{base}` changes files"))


# -- network -----------------------------------------------------------------

def _net_allowed(host: str) -> bool:
    host = host.lower().rstrip(".")
    for entry in _gate("net_allow_hosts", []):
        if not isinstance(entry, str) or not entry:
            continue
        e = entry.lower().rstrip(".")
        if e.startswith("*."):
            e = e[1:]
        if e.startswith("."):
            if host == e[1:] or host.endswith(e):
                return True
        elif host == e:
            return True
    return False


_CURL_NEVER = {"-x", "--proxy", "--preproxy", "-K", "--config", "--resolve", "--connect-to",
               "--unix-socket", "--abstract-unix-socket", "--doh-url", "-:", "--next"}
_CURL_VALUES = {"-H", "-A", "-X", "-u", "-o", "-d", "-F", "-T", "-e", "-b", "-c", "-K", "-x",
                "-m", "-w", "-r", "-E", "-D", "-Y", "-y", "-z", "-C", "-U", "-Q",
                "--header", "--user-agent", "--request", "--user", "--output", "--data",
                "--data-binary", "--data-raw", "--data-ascii", "--data-urlencode", "--form",
                "--form-string", "--upload-file", "--referer", "--cookie", "--cookie-jar",
                "--config", "--proxy", "--max-time", "--connect-timeout", "--write-out",
                "--range", "--cert", "--key", "--cacert", "--capath", "--dump-header",
                "--retry", "--retry-delay", "--retry-max-time", "--limit-rate", "--url",
                "--resolve", "--connect-to", "--json", "--trace", "--trace-ascii", "--stderr",
                "--output-dir", "--proxy-user", "--oauth2-bearer", "--time-cond",
                "--continue-at", "--max-filesize", "--speed-limit", "--speed-time",
                "--interface", "--local-port", "--ciphers", "--libcurl", "--netrc-file",
                "--unix-socket", "--preproxy", "--doh-url", "--variable", "--expand-url"}
_CURL_WRITES = {"-o", "--output", "-D", "--dump-header", "-c", "--cookie-jar", "--trace",
                "--trace-ascii", "--stderr", "--libcurl", "--output-dir"}
_CURL_DATA = {"-d", "--data", "--data-binary", "--data-ascii", "--data-urlencode", "-F",
              "--form", "--json", "-T", "--upload-file", "-b", "--cookie", "--cert", "--key",
              "--netrc-file", "-E", "--variable", "-K"}

_WGET_NEVER = {"-e", "--execute", "-i", "--input-file", "--use-askpass", "--config"}
_WGET_VALUES = {"-O", "-o", "-a", "-P", "-U", "-t", "-T", "-w", "-Q", "-l", "-A", "-R", "-D",
                "-e", "-i", "--output-document", "--output-file", "--append-output",
                "--directory-prefix", "--user-agent", "--header", "--post-data", "--post-file",
                "--body-data", "--body-file", "--user", "--password", "--tries", "--timeout",
                "--wait", "--quota", "--level", "--method", "--load-cookies", "--save-cookies",
                "--execute", "--input-file", "--config", "--referer", "--certificate",
                "--private-key", "--ca-certificate", "--domains"}
_WGET_WRITES = {"-O", "--output-document", "-o", "--output-file", "-a", "--append-output",
                "-P", "--directory-prefix", "--save-cookies"}
_WGET_READS = {"--post-file", "--body-file", "--load-cookies", "--certificate",
               "--private-key", "--ca-certificate"}

_SSH_NEVER = {"-o", "-F", "-J", "-D", "-L", "-R", "-W", "-w", "-S", "-E", "-P",
              "-e", "--rsh", "--rsync-path", "-l"}


def _network(base: str, args: list[Word], st: _Bash) -> tuple[str, str]:
    if any(a.dynamic for a in args):
        return NEVER, f"{base} with an argument computed when the command runs"
    if not _gate("net_allow_hosts", []) and base not in ("scp", "rsync"):
        return NEVER, f"`{base}` reaches the network, and no host is allowed (gate.net_allow_hosts)"
    hosts: list[str] = []
    verdict = (FREE, "")

    if base in ("curl", "wget"):
        never, values = (_CURL_NEVER, _CURL_VALUES) if base == "curl" else (_WGET_NEVER, _WGET_VALUES)
        flags, ops = _split(args, values)
        for k, v in flags:
            if k in never:
                return NEVER, f"{base} {k} sends traffic or reads settings the gate cannot see"
            if v is None:
                if base == "curl" and k in ("-O", "--remote-name", "-J", "--remote-header-name"):
                    verdict = _worse(verdict, st.write(".", f"{base} saves a file here"))
                continue
            if k == "--url":
                ops.append(v)
            elif k in (_CURL_WRITES if base == "curl" else _WGET_WRITES):
                verdict = _worse(verdict, st.write(v, f"{base} writes {v.text}"))
            elif base == "curl" and k in _CURL_DATA:
                for f in _curl_files(k, v.text):
                    verdict = _worse(verdict, st.read(f))
            elif base == "wget" and k in _WGET_READS:
                verdict = _worse(verdict, st.read(v))
            if verdict[0] == NEVER:
                return verdict
        hosts = [_host(o.text) for o in ops]
    elif base == "ssh":
        flags, ops = _split(args, {"-b", "-c", "-e", "-I", "-i", "-l", "-m", "-O", "-p", "-Q",
                                   "-o", "-F", "-J", "-D", "-L", "-R", "-W", "-w", "-S", "-E"})
        for k, v in flags:
            if k in _SSH_NEVER - {"-l", "-e", "-P"}:
                return NEVER, f"ssh {k} opens tunnels, proxies or runs local commands"
            if k == "-i" and v is not None:
                verdict = _worse(verdict, st.read(v))
        if not ops:
            return NEVER, "ssh without a host"
        hosts = [_host(ops[0].text)]
    elif base in ("scp", "rsync"):
        vals = {"-c", "-i", "-l", "-P", "-o", "-F", "-J", "-S"} if base == "scp" else \
               {"-e", "--rsh", "--rsync-path", "--exclude", "--include", "--exclude-from",
                "--include-from", "--files-from", "-f", "--filter", "--port", "-T",
                "--temp-dir", "--log-file", "--password-file", "--bwlimit"}
        flags, ops = _split(args, vals)
        for k, v in flags:
            if k in ("-o", "-F", "-J", "-S", "-e", "--rsh", "--rsync-path") or k.startswith("--delete") \
                    or k == "--remove-source-files":
                return NEVER, f"{base} {k} runs commands, uses a proxy or deletes files"
        for o in ops:
            t = o.text
            m = re.match(r"(?:(?:scp|rsync)://)?(?:[^@/:]+@)?(\[[^\]]+\]|[^/:@]+)::?(?!//)", t)
            if t.startswith(("rsync://", "scp://")) or (m and not t.startswith(("/", ".", "~"))):
                hosts.append(_host(t) if "://" in t else m.group(1).strip("[]").lower())
            else:
                verdict = _worse(verdict, st.read(o))
                verdict = _worse(verdict, _write_target(t, st.cwds, f"{base} copies {t}"))
                if verdict[0] == NEVER:
                    return verdict
    else:  # nc, ncat, netcat, telnet, ftp, sftp
        for a in args:
            t = a.text
            if t in ("-e", "-c", "--exec", "--sh-exec", "--lua-exec", "-l", "--listen", "-x",
                     "-X", "--proxy") or (t.startswith("-") and not t.startswith("--")
                                          and base in ("nc", "ncat", "netcat")
                                          and set(t[1:]) & set("eclxX")):
                return NEVER, f"{base} {t} runs commands, listens or uses a proxy"
        ops = [a for a in args if not a.text.startswith("-")]
        if not ops:
            return NEVER, f"{base} without a host"
        hosts = [_host(ops[0].text)]
    if base in ("scp", "rsync") and not hosts:
        return _worse((NEEDS_OK, f"{base} copies files locally"), verdict)
    if not hosts or not all(hosts):
        return NEVER, f"{base} without a destination the gate can read"
    bad = [h for h in hosts if not _net_allowed(h)]
    if bad:
        return NEVER, f"{base} reaches {', '.join(bad)}, which is not in gate.net_allow_hosts"
    return _worse((NEEDS_OK, f"{base} reaches {', '.join(dict.fromkeys(hosts))}"), verdict)


def _curl_files(flag: str, value: str) -> list[str]:
    """Local files a curl data or upload option reads."""
    if flag in ("-T", "--upload-file", "-b", "--cookie", "--cert", "--key", "--netrc-file",
                "-E", "-K"):
        return [value] if value and value != "-" and ("=" not in value or flag in ("-T", "--upload-file")) else []
    out = []
    for m in re.finditer(r"[@<]([^;,]+)", value):
        f = m.group(1)
        if f and f != "-":
            out.append(f)
    return out


# -- git ---------------------------------------------------------------------

GIT_FREE = {"status", "log", "diff", "show", "branch", "rev-parse", "ls-files", "blame",
            "version", "help", "remote", "grep", "config"}
GIT_NEEDS_OK = {"add", "commit", "push", "checkout", "switch", "merge", "stash", "fetch",
                "pull", "tag", "restore", "rebase", "cherry-pick", "revert", "init", "mv",
                "rm", "clone", "am", "apply", "worktree", "reset", "notes", "bisect", "gc",
                "submodule"}
GIT_NEVER = {"clean": "git clean deletes untracked files",
             "filter-branch": "git filter-branch rewrites history",
             "filter-repo": "git filter-repo rewrites history",
             "prune": "git prune deletes unreachable objects",
             "credential": "git credential handles stored credentials",
             "update-ref": "git update-ref rewrites references directly",
             "restore": "git restore discards uncommitted work"}
_CONFIG_READ = {"--get", "--get-all", "--get-regexp", "-l", "--list", "--show-origin",
                "--show-scope", "--name-only", "-z", "--null", "--local", "--global",
                "--system", "--worktree", "--includes", "--no-includes", "--bool", "--int",
                "--path", "--bool-or-int", "--expiry-date", "--type", "--default", "-f",
                "--file", "--all", "--regexp", "--value", "--fixed-value"}
_BRANCH_LIST = {"-a", "-r", "-v", "-vv", "-l", "--list", "--all", "--remotes", "--verbose",
                "--show-current", "--merged", "--no-merged", "--contains", "--no-contains",
                "--points-at", "--sort", "--format", "--color", "--no-color", "--column",
                "--no-column", "-i", "--ignore-case", "--abbrev", "--no-abbrev"}
_GIT_SAFE_GLOBAL = {"--no-pager", "-P", "--paginate", "-p", "--bare", "--no-replace-objects",
                    "--literal-pathspecs", "--no-optional-locks", "--glob-pathspecs",
                    "--noglob-pathspecs", "--icase-pathspecs", "--no-lazy-fetch"}


def _git(args: list[Word], st: _Bash) -> tuple[str, str]:
    verdict = (FREE, "")
    i = 0
    git_cwds = list(st.cwds)
    while i < len(args) and args[i].text.startswith("-"):
        w = args[i]
        k, eq, v = w.text.partition("=")
        if w.dynamic:
            return NEVER, "a git option is computed when the command runs"
        if k in ("-c", "--config-env"):
            return NEVER, "git -c sets configuration for this call, which can run any program"
        if k == "--exec-path":
            return NEVER, "git --exec-path changes which programs git runs"
        if k in ("-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--attr-source"):
            if not eq:
                i += 1
                if i >= len(args):
                    return NEVER, f"git {k} without a value"
                v = args[i].text
                if args[i].dynamic:
                    return NEVER, f"git {k} with a computed value"
            if k in ("-C", "--git-dir", "--work-tree"):
                for cwd in git_cwds:
                    ok, why = paths.judge(v, cwd)
                    if not ok:
                        return NEVER, f"git {k}: {why}"
                if k == "-C":
                    git_cwds = [paths.real(v, c) for c in git_cwds]
        elif k not in _GIT_SAFE_GLOBAL:
            verdict = _worse(verdict, (NEEDS_OK, f"git option {k} is not one the gate knows"))
        i += 1
    if i >= len(args):
        return _worse(verdict, (FREE, ""))
    sub_w, rest = args[i], args[i + 1:]
    if sub_w.dynamic:
        return NEVER, "the git subcommand is computed when the command runs"
    sub = sub_w.text
    for cwd in git_cwds:
        ok, why = paths.judge(cwd)
        if not ok:
            return NEVER, f"git runs in a folder that is not reachable: {why}"
    texts = [a.text for a in rest]

    if sub in GIT_NEVER:
        return NEVER, GIT_NEVER[sub]
    if sub == "push":
        for t in texts:
            if t in ("-f", "--force", "--mirror", "--delete", "-d", "--prune", "--force-if-includes") \
                    or t.startswith(("--force-with-lease", "--force=")) \
                    or (t.startswith("-") and not t.startswith("--") and set(t[1:]) & set("fd")) \
                    or (not t.startswith("-") and (t.startswith(("+", ":")) or ":+" in t)):
                return NEVER, "git push that forces, mirrors or deletes is never allowed"
        if any(a.dynamic for a in rest):
            return NEVER, "git push with a computed argument"
    if sub == "reset" and ("--hard" in texts or "--merge" in texts):
        return NEVER, "git reset --hard discards work"
    if sub == "reflog" and rest and texts[0] in ("expire", "delete"):
        return NEVER, "git reflog expire/delete removes the last way back"
    if sub == "stash" and rest and texts[0] in ("drop", "clear"):
        return NEVER, "git stash drop/clear discards saved work"
    if sub == "checkout":
        if any(t in ("-f", "--force", "--", "--ours", "--theirs", "-p", "--patch",
                     "--pathspec-from-file") or t.startswith("--pathspec-from-file=")
               for t in texts):
            return NEVER, "git checkout of paths discards uncommitted work"
        for a in rest:
            t = a.text
            if t.startswith("-") or a.dynamic:
                continue
            if t in (".", "..") or any(ch in t for ch in "*?[") or any(
                    os.path.lexists(os.path.join(c, t)) for c in git_cwds):
                return NEVER, f"git checkout {t} names a path: it discards uncommitted work"
    if sub == "switch" and any(t in ("-f", "--force", "--discard-changes") for t in texts):
        return NEVER, "git switch --discard-changes discards uncommitted work"
    if sub == "submodule" and "foreach" in texts:
        return NEVER, "git submodule foreach runs a shell command in every submodule"
    if sub == "bisect" and texts[:1] == ["run"]:
        return NEVER, "git bisect run runs a command"
    if sub == "rebase" and any(t in ("-x", "--exec") or t.startswith("--exec=") or
                               (t.startswith("-x") and len(t) > 2) for t in texts):
        return NEVER, "git rebase --exec runs a shell command"
    if sub in ("difftool", "mergetool") and any(t in ("-x", "--extcmd") or t.startswith("--extcmd=")
                                                 for t in texts):
        return NEVER, f"git {sub} --extcmd runs a command"
    if sub == "grep" and any(t in ("-O", "--open-files-in-pager") or t.startswith(
            ("-O", "--open-files-in-pager=")) for t in texts):
        return NEVER, "git grep -O runs a pager program"
    if sub == "rm" and any(t in ("-f", "--force") or (t.startswith("-") and not t.startswith("--")
                                                      and "f" in t) for t in texts):
        return NEVER, "git rm --force deletes files with unsaved changes"
    if sub == "branch" and any(t == "-D" or (t.startswith("-") and not t.startswith("--")
                                             and "D" in t) or t in ("-f", "--force") for t in texts):
        return NEVER, "git branch -D/--force deletes or overwrites a branch"
    if sub == "config":
        if not _git_config_read(texts):
            return NEVER, "git config changes settings that can make git run any program"
        flags = {t.split("=", 1)[0] for t in texts if t.startswith("-")}
        if flags & {"--global", "--system", "--includes"} or not flags & {
                "--local", "--worktree", "-f", "--file"}:
            verdict = _worse(verdict, (NEEDS_OK, "git config without --local also reads the "
                                                 "global and system settings, which can hold "
                                                 "tokens"))

    # path operands: checked for every subcommand, after brace expansion; a
    # pattern (expanded by the shell, or by git itself when quoted) is judged
    # by every file under its fixed folder that it could select
    for a in rest:
        if a.dynamic:
            continue
        t = a.text
        if t.startswith(":") and t[1:2] in ("(", "!", "^", "/"):
            verdict = _worse(verdict, (NEEDS_OK, f"git pathspec magic {t} is not read by the gate"))
            continue
        texts_a = _embedded(t) if t.startswith("-") else expand_braces(a)
        for c in texts_a:
            if not t.startswith("-") and ":" in c and sub in ("show", "diff", "log", "blame",
                                                               "cat-file"):
                c = c.split(":", 1)[1]
            if not c:
                continue
            if not t.startswith("-") and any(ch in c for ch in "*?["):
                verdict = _worse(verdict, _git_pattern(c, git_cwds, st))
                if verdict[0] == NEVER:
                    return verdict
            elif _looks_like_path(c) or "/" in c or c.startswith("."):
                for cwd in git_cwds:
                    ok, why = paths.judge(c, cwd)
                    if not ok:
                        return NEVER, why

    if sub in GIT_FREE:
        if any(a.dynamic for a in rest):
            return NEVER, f"git {sub} with an argument computed when the command runs"
        if sub == "grep" and any(t in ("--untracked", "--no-index", "--no-exclude-standard")
                                 for t in texts):
            for cwd in git_cwds:
                status, what = paths.scan_tree(cwd)
                if status == "denied":
                    return NEVER, f"a search of untracked files would reach a protected path: {what}"
                if status == "too_big":
                    verdict = _worse(verdict, (NEEDS_OK, "the untracked search could not be checked"))
        if sub in ("log", "diff", "show"):
            for t in texts:
                if t == "--output" or t.startswith("--output="):
                    target = t.split("=", 1)[1] if "=" in t else ""
                    if not target:
                        idx = texts.index(t)
                        target = texts[idx + 1] if idx + 1 < len(texts) else ""
                    if not target:
                        return NEVER, f"git {sub} --output without a file"
                    verdict = _worse(verdict, _write_target(target, git_cwds,
                                                            f"git {sub} --output writes {target}"))
                elif t == "--ext-diff":
                    verdict = _worse(verdict, (NEEDS_OK, f"git {sub} --ext-diff runs an external diff program"))
            return _worse(verdict, (FREE, ""))
        if sub == "branch":
            flags = [t for t in texts if t.startswith("-")]
            listing = "--list" in texts or "-l" in texts
            bad = [f for f in flags if f.split("=", 1)[0] not in _BRANCH_LIST]
            operands = []
            skip = False
            for t in texts:
                if skip:
                    skip = False
                    continue
                if t in ("--contains", "--no-contains", "--merged", "--no-merged", "--points-at",
                         "--sort", "--format"):
                    skip = True
                    continue
                if not t.startswith("-"):
                    operands.append(t)
            if bad or (operands and not listing):
                return _worse(verdict, (NEEDS_OK, "git branch that creates, renames or deletes a branch"))
            return _worse(verdict, (FREE, ""))
        if sub == "remote":
            if not rest or all(t in ("-v", "--verbose") for t in texts) or (texts and texts[0] in ("show", "get-url")):
                return _worse(verdict, (FREE, ""))
            return _worse(verdict, (NEEDS_OK, "git remote that changes remotes"))
        return _worse(verdict, (FREE, ""))
    if sub in GIT_NEEDS_OK:
        return _worse(verdict, (NEEDS_OK, f"git {sub} changes the repository or talks to a remote"))
    return _worse(verdict, (NEEDS_OK, f"git {sub} is not on the read-only list; it needs your OK"))


def _git_pattern(pattern: str, cwds: list[str], st: _Bash) -> tuple[str, str]:
    """A git path operand with * ? [: its fixed folder must be reachable, and
    no protected file under it may be one the pattern could select. Git's own
    pathspec `*` also crosses folders, so the whole tree below is checked."""
    static = _static_dir(pattern)
    rest = pattern if static == "." else pattern[len(static):].lstrip("/")
    for cwd in cwds:
        st.tick()
        ok, why = paths.judge(static, cwd)
        if not ok:
            return NEVER, why
        status, what = paths.scan_tree(static, cwd, include_hidden=True, only=(rest,))
        if status == "denied":
            return NEVER, f"the pattern {pattern} could select a protected path: {what}"
        if status == "too_big":
            return NEEDS_OK, f"the pattern {pattern} covers more than {what} files; it could not be checked"
    return FREE, ""


def _git_config_read(texts: list[str]) -> bool:
    """True when `git config ...` only reads: known read flags, and no value."""
    ops: list[str] = []
    mode = ""
    skip = False
    for k, t in enumerate(texts):
        if skip:
            skip = False
            continue
        if t.startswith("-"):
            flag = t.split("=", 1)[0]
            if flag not in _CONFIG_READ:
                return False
            if flag in ("--get", "--get-all", "--get-regexp"):
                mode = "get"
            elif flag in ("-l", "--list"):
                mode = "list"
            elif flag in ("--type", "--default", "-f", "--file", "--value") and "=" not in t:
                skip = True
            continue
        ops.append(t)
    if ops[:1] in (["get"], ["list"]) and not mode:
        mode, ops = ops[0], ops[1:]
    elif ops[:1] and ops[0] in ("set", "unset", "rename-section", "remove-section", "edit"):
        return False
    limit = {"get": 2, "list": 0}.get(mode, 1)
    return len(ops) <= limit
