#!/usr/bin/env python3
"""
PreToolUse permission gate. Claude Code runs this before every tool call and
passes the call as JSON on stdin.

  SANCHO_GATE != "1"   Exit 0, print nothing: the hook is inert outside the
                       child processes the runner starts, so installing it
                       anywhere never affects other sessions.
  free                 Exit 0, print nothing: the normal permission rules apply.
  never                Deny, with the policy's reason.
  needs_ok             If the owner approved this exact call in this thread,
                       allow it once. Otherwise hold it (sancho.pending), deny
                       with "HELD_FOR_APPROVAL <id> — <summary>", and let the
                       listener carry the secret code to the phone.

Fail closed: Claude Code lets a call through when a hook crashes, so any
exception, unreadable input or unknown verdict ends in exit status 2 (a
blocking error) or an explicit deny. The approval code is never printed.
"""
from __future__ import annotations

import json
import os
import sys

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_DIR not in sys.path:
    sys.path.insert(0, REPO_DIR)

EVENT = "PreToolUse"
MARKER = "HELD_FOR_APPROVAL"
MARKER_SUMMARY_MAX = 300
STOP_SENTENCE = (
    "Stop here and do not retry or work around this call: tell the user this action is "
    f"waiting for their approval on the phone, and quote the {MARKER} line above verbatim."
)


class GateError(Exception):
    """Input the gate cannot judge; ends in a blocking error."""


def decision(kind: str, reason: str) -> str:
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": EVENT,
        "permissionDecision": kind,
        "permissionDecisionReason": reason,
    }}, ensure_ascii=False)


def one_line(text: str, limit: int) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def held_reason(pending_id: str, summary: str) -> str:
    return f"{MARKER} {pending_id} — {one_line(summary, MARKER_SUMMARY_MAX)}\n{STOP_SENTENCE}"


def read_event(raw: str) -> tuple[str, dict, str | None]:
    try:
        event = json.loads(raw)
    except ValueError as e:
        raise GateError(f"unreadable hook input ({e.__class__.__name__})") from None
    if not isinstance(event, dict):
        raise GateError("hook input is not a JSON object")
    tool = event.get("tool_name")
    if not isinstance(tool, str) or not tool:
        raise GateError("hook input has no tool_name")
    tool_input = event.get("tool_input", {})
    if tool_input is None:
        tool_input = {}
    if not isinstance(tool_input, dict):
        raise GateError("tool_input is not a JSON object")
    cwd = event.get("cwd")
    return tool, tool_input, cwd if isinstance(cwd, str) and cwd else None


def judge(raw: str, env: dict) -> str | None:
    """The decision JSON to print, or None for "no opinion" (exit 0, silent)."""
    tool, tool_input, cwd = read_event(raw)
    from sancho import pending

    thread = env.get("SANCHO_THREAD", "")
    if not thread:
        return decision("deny", "Blocked: the permission gate has no thread id (SANCHO_THREAD).")

    from sancho import tiers

    verdict = tiers.classify(tool, tool_input, cwd=cwd)
    tier = getattr(verdict, "tier", None)
    if tier == "free":
        return None
    if tier == "never":
        reason = one_line(getattr(verdict, "reason", "") or "", 500) or "not permitted"
        return decision("deny", f"Blocked by policy: {reason}")
    if tier == "needs_ok":
        # The working directory is part of what was approved: the same relative
        # command means something else in another folder.
        held_input = dict(tool_input, _cwd=cwd or "")
        if pending.consume_approved(tool, held_input, thread):
            return decision("allow", "Approved once by the user from the phone.")
        try:
            pending.sweep()
        except Exception:
            pass                      # housekeeping must never stop a hold
        summary = str(getattr(verdict, "summary", "") or tool)
        record = pending.create(tool, held_input, thread, summary,
                                str(getattr(verdict, "full_text", "") or ""),
                                bool(getattr(verdict, "truncated", False)))
        return decision("deny", held_reason(record["pending_id"], summary))
    return decision("deny", "Blocked: the permission policy returned no usable verdict.")


def main() -> int:
    if os.environ.get("SANCHO_GATE") != "1":
        return 0
    try:
        out = judge(sys.stdin.read(), dict(os.environ))
        if out is not None:
            sys.stdout.write(out + "\n")
            sys.stdout.flush()
        return 0
    except BaseException as e:           # fail closed, whatever happened
        if isinstance(e, GateError):
            detail = str(e)
        else:
            detail = e.__class__.__name__
        try:
            sys.stderr.write(f"sancho gate: blocked, internal error ({detail}). "
                             "The call did not run.\n")
            sys.stderr.flush()
        except BaseException:
            pass
        return 2


if __name__ == "__main__":
    sys.exit(main())
