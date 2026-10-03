"""
Configuration and secrets, in one place.

Two sources, kept apart on purpose:

  config.json   Behaviour: which folders the assistant may reach, where projects
                live, timeouts. Safe to show; lives next to the code (gitignored)
                or wherever $SANCHO_CONFIG points.
  .env          Secrets only: the Telegram bot token, the allowed chat id, the
                Claude Code OAuth token. Never in config.json, never in git, and
                never readable by the assistant itself (the gate denies .env).

Every module reads its settings through `get(section, key, default)` and keeps
its own defaults, so a missing or partial config.json is never an error.

Configuration ("sancho" section):
  state_dir   runtime state: threads, held approvals, the Telegram offset, long
              replies                                    default "~/.sancho/state"
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOME = os.path.expanduser("~")

_CONFIG: dict | None = None


def config_path() -> str:
    return os.environ.get("SANCHO_CONFIG") or os.path.join(REPO_DIR, "config.json")


def load() -> dict:
    """The whole config.json as a dict, or {} when absent or malformed."""
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = {}
        try:
            with open(config_path(), encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                _CONFIG = data
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"sancho: could not read {config_path()}: {e}", file=sys.stderr)
    return _CONFIG


def reload() -> dict:
    """Forget the cached config (tests use this after writing a new file)."""
    global _CONFIG
    _CONFIG = None
    return load()


def get(section: str, key: str, default: Any) -> Any:
    """`config.json[section][key]`, or `default` when absent or of the wrong type."""
    value = (load().get(section) or {}).get(key, default)
    if default is not None and not isinstance(value, type(default)):
        return default
    return value


def expand(path: str) -> str:
    """`~` and environment variables expanded, then made absolute."""
    return os.path.abspath(os.path.expandvars(os.path.expanduser(path)))


def state_dir(*parts: str) -> str:
    """Runtime state (threads, pending approvals, offsets, logs). Created on demand."""
    base = expand(get("sancho", "state_dir", "~/.sancho/state"))
    path = os.path.join(base, *parts)
    os.makedirs(path, exist_ok=True)
    return path


# ── secrets ──────────────────────────────────────────────────────────────────

def env_file_path() -> str:
    return os.environ.get("SANCHO_ENV_FILE") or os.path.join(REPO_DIR, ".env")


def secrets() -> dict[str, str]:
    """KEY=value pairs from the .env file, overridden by the real environment.

    Recognised keys: TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, CLAUDE_CODE_OAUTH_TOKEN.
    """
    values: dict[str, str] = {}
    try:
        with open(env_file_path(), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    values[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    for key in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "CLAUDE_CODE_OAUTH_TOKEN"):
        if os.environ.get(key):
            values[key] = os.environ[key]
    return values
