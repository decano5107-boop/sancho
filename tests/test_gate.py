"""The PreToolUse gate, run as a real subprocess.

The policy module is replaced by a small wrapper script written to the test's
temp directory: it installs a fake `sancho.tiers` with a fixed verdict, then
calls the gate's own main(). Nothing in the gate itself can be switched to a
test mode.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

from helpers import REPO, SanchoTestCase
from fakes import install_stubs

install_stubs()

from sancho import pending, runner  # noqa: E402

GATE = os.path.join(REPO, "hooks", "gate.py")
THREAD = "thread-a"
CALL = {"tool_name": "Bash",
        "tool_input": {"command": "git push origin main", "description": "push"},
        "cwd": "/work/project", "hook_event_name": "PreToolUse", "session_id": "s-1"}

WRAPPER = r'''
import importlib.util, json, sys, types
REPO, GATE, VERDICT_FILE, CALLS_FILE = sys.argv[1:5]
sys.path.insert(0, REPO)
import sancho

def classify(tool_name, tool_input, cwd=None):
    with open(CALLS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps({"tool": tool_name, "input": tool_input, "cwd": cwd}) + "\n")
    with open(VERDICT_FILE, encoding="utf-8") as f:
        verdict = json.load(f)
    if verdict.get("raise"):
        raise RuntimeError("policy exploded")
    return types.SimpleNamespace(**verdict)

fake = types.ModuleType("sancho.tiers")
fake.classify = classify
sys.modules["sancho.tiers"] = fake
sancho.tiers = fake
spec = importlib.util.spec_from_file_location("sancho_gate_under_test", GATE)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
sys.exit(gate.main())
'''


def verdict(tier: str, summary: str = "Bash: git push origin main", reason: str = "",
            full_text: str = "", truncated: bool = False) -> dict:
    return {"tier": tier, "summary": summary, "full_text": full_text or summary,
            "truncated": truncated, "reason": reason}


class GateTest(SanchoTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.wrapper = self.make_file("gate_wrapper.py", WRAPPER)
        self.verdict_file = os.path.join(self.tmp, "verdict.json")
        self.calls_file = os.path.join(self.tmp, "calls.jsonl")
        self.set_verdict(verdict("free"))

    def set_verdict(self, data: dict) -> None:
        with open(self.verdict_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def env(self, **extra) -> dict:
        env = {k: v for k, v in os.environ.items() if k not in ("SANCHO_GATE", "SANCHO_THREAD")}
        env.update({"SANCHO_GATE": "1", "SANCHO_THREAD": THREAD})
        env.update(extra)
        return {k: v for k, v in env.items() if v is not None}

    def gate(self, event=None, raw: str | None = None, env: dict | None = None,
             wrapped: bool = True) -> subprocess.CompletedProcess:
        stdin = raw if raw is not None else json.dumps(event or CALL)
        cmd = ([sys.executable, self.wrapper, REPO, GATE, self.verdict_file, self.calls_file]
               if wrapped else [sys.executable, GATE])
        return subprocess.run(cmd, input=stdin, capture_output=True, text=True,
                              env=env if env is not None else self.env(),
                              cwd=self.tmp, timeout=60)

    def decision(self, proc: subprocess.CompletedProcess) -> dict:
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)["hookSpecificOutput"]
        self.assertEqual(out["hookEventName"], "PreToolUse")
        return out

    def all_records(self) -> list[dict]:
        d = os.path.join(self.tmp, "state", "pending")
        if not os.path.isdir(d):
            return []
        out = []
        for name in os.listdir(d):
            if name.endswith(".json"):
                with open(os.path.join(d, name), encoding="utf-8") as f:
                    out.append(json.load(f))
        return out

    # ── inert / fail closed ──────────────────────────────────────────────────

    def test_inactive_without_switch(self):
        for value in (None, "0", "", "true"):
            proc = self.gate(env=self.env(SANCHO_GATE=value), wrapped=False)
            self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, "", ""))
        proc = self.gate(raw="not json", env=self.env(SANCHO_GATE=None), wrapped=False)
        self.assertEqual((proc.returncode, proc.stdout), (0, ""))
        self.assertFalse(os.path.exists(self.calls_file))

    def test_missing_thread_denies(self):
        proc = self.gate(env=self.env(SANCHO_THREAD=None))
        out = self.decision(proc)
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertEqual(self.all_records(), [])

    def test_garbage_stdin_blocks(self):
        for raw in ("", "not json", "[1, 2]", '{"tool_input": {}}',
                    '{"tool_name": "Bash", "tool_input": "rm"}'):
            proc = self.gate(raw=raw, wrapped=False)
            self.assertEqual(proc.returncode, 2, raw)
            self.assertEqual(proc.stdout, "")
            self.assertIn("blocked", proc.stderr)

    def test_exception_in_classify_blocks(self):
        self.set_verdict({"raise": True})
        proc = self.gate()
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, "")
        self.assertIn("RuntimeError", proc.stderr)

    def test_unknown_tier_denies(self):
        self.set_verdict(verdict("maybe"))
        self.assertEqual(self.decision(self.gate())["permissionDecision"], "deny")

    # ── tiers ────────────────────────────────────────────────────────────────

    def test_free_is_silent(self):
        proc = self.gate()
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, "", ""))
        with open(self.calls_file, encoding="utf-8") as f:
            seen = json.loads(f.readline())
        self.assertEqual(seen, {"tool": "Bash", "input": CALL["tool_input"],
                                "cwd": "/work/project"})

    def test_never_denies_with_reason(self):
        self.set_verdict(verdict("never", reason="reads the secrets file"))
        out = self.decision(self.gate())
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("reads the secrets file", out["permissionDecisionReason"])
        self.assertEqual(self.all_records(), [])

    def test_needs_ok_holds_without_leaking_code(self):
        self.set_verdict(verdict("needs_ok", full_text="git push origin main\nsecond line"))
        proc = self.gate()
        out = self.decision(proc)
        self.assertEqual(out["permissionDecision"], "deny")
        reason = out["permissionDecisionReason"]
        records = self.all_records()
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertTrue(reason.startswith(
            f"HELD_FOR_APPROVAL {rec['pending_id']} — Bash: git push origin main\n"), reason)
        self.assertIn("approval", reason.split("\n", 1)[1])
        self.assertNotIn(rec["code"], (proc.stdout + proc.stderr).upper())
        self.assertEqual(rec["thread"], THREAD)
        self.assertEqual(rec["tool"], "Bash")
        self.assertEqual(rec["input"], dict(CALL["tool_input"], _cwd=CALL["cwd"]),
                         "the working directory is part of what is approved")
        self.assertEqual(rec["full_text"], "git push origin main\nsecond line")
        # The runner recognises the marker and strips it from the answer.
        ids, rest = runner.held_ids("I need your OK.\n" + reason.split("\n")[0])
        self.assertEqual((ids, rest), ([rec["pending_id"]], "I need your OK."))

    def test_approved_call_runs_exactly_once(self):
        self.set_verdict(verdict("needs_ok"))
        self.assertEqual(self.decision(self.gate())["permissionDecision"], "deny")
        rec = self.all_records()[0]
        self.assertIsNotNone(pending.approve(rec["code"].lower(), THREAD))

        # An edited call does not match the approved hash, and is held anew.
        edited = json.loads(json.dumps(CALL))
        edited["tool_input"]["command"] = "git push --force origin main"
        out = self.decision(self.gate(edited))
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("HELD_FOR_APPROVAL", out["permissionDecisionReason"])

        # The same relative command from another folder is a different call.
        elsewhere = dict(CALL, cwd="/work/other")
        out = self.decision(self.gate(elsewhere))
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("HELD_FOR_APPROVAL", out["permissionDecisionReason"])

        # Another thread cannot spend this thread's approval.
        out = self.decision(self.gate(env=self.env(SANCHO_THREAD="thread-b")))
        self.assertEqual(out["permissionDecision"], "deny")

        proc = self.gate()
        out = self.decision(proc)
        self.assertEqual(out["permissionDecision"], "allow")
        self.assertNotIn(rec["code"], (proc.stdout + proc.stderr).upper())
        self.assertIsNone(pending.get(rec["pending_id"]))

        # Replay: the same call is held again, never allowed twice.
        out = self.decision(self.gate())
        self.assertEqual(out["permissionDecision"], "deny")
        self.assertIn("HELD_FOR_APPROVAL", out["permissionDecisionReason"])

    def test_runs_from_any_cwd_with_absolute_path(self):
        proc = subprocess.run([sys.executable, GATE], input=json.dumps(CALL),
                              capture_output=True, text=True,
                              env=self.env(SANCHO_THREAD=None), cwd="/", timeout=60)
        out = self.decision(proc)
        self.assertEqual(out["permissionDecision"], "deny")

    def test_reworded_description_still_matches_the_approval(self):
        self.set_verdict(verdict("needs_ok"))
        self.decision(self.gate())
        rec = self.all_records()[0]
        pending.approve(rec["code"], THREAD)
        repeat = json.loads(json.dumps(CALL))
        repeat["tool_input"]["description"] = "Push main to the remote"
        self.assertEqual(self.decision(self.gate(repeat))["permissionDecision"], "allow")
