"""Runner: the exact command line, environment and settings file handed to
`claude`, thread rotation, fail-open, timeouts, the daily counter and held-call
markers. `subprocess.Popen` is replaced; Claude never runs."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from unittest import mock

from helpers import SanchoTestCase
from fakes import install_stubs

install_stubs()

from sancho import config, runner  # noqa: E402

TOOLS = ["Read", "Grep", "Bash(git status:*)"]


class FakePopen:
    """Stands in for the child. `script` is a list of (stdout, stderr, code) or
    the string "timeout", consumed one per spawn."""
    script: list = []
    calls: list = []

    def __init__(self, args, **kwargs):
        self.args, self.kwargs = args, kwargs
        self.pid = 4242
        self.returncode = None
        self.stdin_text = None
        self._step = FakePopen.script.pop(0)
        FakePopen.calls.append(self)

    def communicate(self, input=None, timeout=None):
        if input is not None:
            self.stdin_text = input
            self.timeout = timeout
        if self._step == "timeout" and self.returncode is None:
            self.returncode = -9
            raise subprocess.TimeoutExpired(self.args, timeout)
        if self._step == "timeout":
            return "", ""
        out, err, code = self._step
        self.returncode = code
        return out, err

    def poll(self):
        return self.returncode

    def kill(self):
        self.returncode = -9


def reply(text: str, session: str = "sess-1", **extra) -> tuple[str, str, int]:
    return json.dumps({"type": "result", "result": text, "session_id": session,
                       "is_error": False, **extra}), "", 0


class RunnerTest(SanchoTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.project = os.path.join(self.home, "Projects", "alpha")
        os.makedirs(self.project)
        with open(os.environ["SANCHO_ENV_FILE"], "w") as f:
            f.write("TELEGRAM_BOT_TOKEN=123:tg-secret\nTELEGRAM_CHAT_ID=77\n"
                    "CLAUDE_CODE_OAUTH_TOKEN=oauth-test-value\n")
        FakePopen.script, FakePopen.calls = [], []
        for target, value in (("sancho.runner.subprocess.Popen", FakePopen),
                              ("sancho.runner.tiers.allowed_tools", lambda: list(TOOLS)),
                              ("sancho.runner.os.killpg", lambda pid, sig: None)):
            patcher = mock.patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        # Parent variables that must not leak into the child. Only these keys are
        # restored afterwards, so the base class's HOME handling is untouched.
        for key, value in (("CLAUDE_CODE_ENTRYPOINT", "cli"), ("SANCHO_OK", "stale"),
                           ("ANTHROPIC_API_KEY", "sk-x"), ("TELEGRAM_BOT_TOKEN", "123:tg-secret")):
            self.addCleanup(self._restore_env, key, os.environ.get(key))
            os.environ[key] = value

    @staticmethod
    def _restore_env(key, value):
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value

    def run_once(self, *steps, prompt="what changed?", **kw) -> runner.Result:
        FakePopen.script = list(steps)
        return runner.run(prompt, self.project, **kw)

    def threads(self) -> dict:
        with open(os.path.join(config.state_dir(), "threads.json")) as f:
            return json.load(f)

    # ── command line ─────────────────────────────────────────────────────────

    def test_exact_command_line(self):
        self.run_once(reply("ok"))
        call = FakePopen.calls[0]
        settings = os.path.join(config.state_dir("runtime"), "child-settings.json")
        self.assertEqual(call.args, [
            "claude", "-p",
            "--output-format", "json",
            "--permission-mode", "dontAsk",
            "--settings", settings,
            "--allowedTools", *TOOLS,
            "--append-system-prompt", runner.GATE_PROMPT,
        ])
        self.assertEqual(call.stdin_text, "what changed?", "the prompt travels on stdin")
        self.assertNotIn("what changed?", call.args)
        self.assertEqual(call.kwargs["cwd"], self.project)
        self.assertTrue(call.kwargs["start_new_session"])
        self.assertEqual(call.timeout, 300)

    def test_never_a_permissive_mode(self):
        self.run_once(reply("ok"))
        args = FakePopen.calls[0].args
        for bad in ("bypassPermissions", "acceptEdits", "auto", "--dangerously-skip-permissions"):
            self.assertNotIn(bad, args)

    def test_second_turn_resumes_the_session(self):
        self.run_once(reply("one", session="sess-A"))
        self.run_once(reply("two", session="sess-A"))
        self.assertNotIn("--resume", FakePopen.calls[0].args)
        self.assertEqual(FakePopen.calls[1].args[-2:], ["--resume", "sess-A"])

    def test_settings_file_wires_only_the_gate(self):
        self.run_once(reply("ok"))
        path = FakePopen.calls[0].args[FakePopen.calls[0].args.index("--settings") + 1]
        with open(path) as f:
            settings = json.load(f)
        self.assertEqual(list(settings), ["hooks"])
        hook = settings["hooks"]["PreToolUse"][0]
        self.assertEqual(hook["matcher"], "*")
        self.assertEqual(hook["hooks"][0]["type"], "command")
        self.assertEqual(hook["hooks"][0]["command"],
                         f"{sys.executable} {os.path.join(config.REPO_DIR, 'hooks', 'gate.py')}")

    def test_child_environment(self):
        self.write_config({"runner": {"extra_env": {"MY_FLAG": "1", "SANCHO_GATE": "0"},
                                      "project_env": {"alpha": {"PROJECT_FLAG": "yes"}}}})
        result = self.run_once(reply("ok"))
        env = FakePopen.calls[0].kwargs["env"]
        self.assertEqual(env["SANCHO_GATE"], "1", "config cannot switch the gate off")
        self.assertEqual(env["SANCHO_THREAD"], result.thread_id)
        self.assertEqual(env["CLAUDE_CODE_OAUTH_TOKEN"], "oauth-test-value")
        self.assertEqual(env["MY_FLAG"], "1")
        self.assertEqual(env["PROJECT_FLAG"], "yes")
        self.assertEqual(env["SANCHO_CONFIG"], self.config_path,
                         "the gate judges by the same policy file as the listener")
        for gone in ("SANCHO_OK", "CLAUDE_CODE_ENTRYPOINT", "ANTHROPIC_API_KEY",
                     "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
            self.assertNotIn(gone, env)
        self.assertNotIn("tg-secret", json.dumps(env))

    def test_custom_timeout_and_binary(self):
        self.write_config({"runner": {"timeout_seconds": 60, "claude_bin": "/opt/bin/claude",
                                      "append_system_prompt": "Be brief."}})
        self.run_once(reply("ok"))
        call = FakePopen.calls[0]
        self.assertEqual(call.args[0], "/opt/bin/claude")
        self.assertEqual(call.timeout, 60)
        self.assertEqual(call.args[call.args.index("--append-system-prompt") + 1],
                         runner.GATE_PROMPT + "\n\nBe brief.")

    # ── threads ──────────────────────────────────────────────────────────────

    def test_turns_are_counted_and_rotate_at_the_limit(self):
        self.write_config({"runner": {"max_turns": 2}})
        first = self.run_once(reply("1", session="s1"))
        self.run_once(reply("2", session="s1"))
        self.assertEqual(self.threads()[self.project]["turns"], 2)
        third = self.run_once(reply("3", session="s2"))
        self.assertNotIn("--resume", FakePopen.calls[2].args)
        self.assertNotEqual(first.thread_id, third.thread_id)
        self.assertEqual(self.threads()[self.project]["turns"], 1)

    def test_idle_thread_rotates(self):
        first = self.run_once(reply("1", session="s1"))
        data = self.threads()
        data[self.project]["last_at"] = time.time() - 25 * 3600
        with open(os.path.join(config.state_dir(), "threads.json"), "w") as f:
            json.dump(data, f)
        second = self.run_once(reply("2", session="s2"))
        self.assertNotIn("--resume", FakePopen.calls[1].args)
        self.assertNotEqual(first.thread_id, second.thread_id)

    def test_dead_session_falls_open_to_a_new_thread(self):
        first = self.run_once(reply("1", session="gone"))
        result = self.run_once(("", "No conversation found with session ID: gone", 1),
                               reply("fresh", session="s-new"))
        self.assertEqual(result.text, "fresh")
        self.assertIsNone(result.error)
        self.assertEqual(FakePopen.calls[1].args[-2:], ["--resume", "gone"])
        self.assertNotIn("--resume", FakePopen.calls[2].args)
        self.assertNotEqual(result.thread_id, first.thread_id)
        self.assertEqual(self.threads()[self.project]["session_id"], "s-new")

    def test_pinned_thread_runs_only_on_that_thread(self):
        first = self.run_once(reply("1", session="s1"))
        again = self.run_once(reply("done", session="s1"), thread_id=first.thread_id)
        self.assertEqual(again.text, "done")
        self.assertEqual(FakePopen.calls[1].args[-2:], ["--resume", "s1"])
        self.assertEqual(FakePopen.calls[1].kwargs["env"]["SANCHO_THREAD"], first.thread_id)
        moved = runner.run("x", self.project, thread_id="not-the-thread")
        self.assertEqual(moved.error, "thread-moved")
        self.assertEqual(len(FakePopen.calls), 2, "nothing ran")

    def test_pinned_thread_does_not_fail_open(self):
        first = self.run_once(reply("1", session="s1"))
        result = self.run_once(("", "boom", 1), thread_id=first.thread_id)
        self.assertEqual(result.error, "boom")
        self.assertEqual(len(FakePopen.calls), 2)

    # ── errors ───────────────────────────────────────────────────────────────

    def test_timeout(self):
        result = self.run_once("timeout")
        self.assertEqual(result.error, "timeout")
        self.assertEqual(len(FakePopen.calls), 1, "a timeout is not retried")

    def test_auth_failure(self):
        out = json.dumps({"result": "", "is_error": True, "api_error_status": 401})
        self.assertEqual(self.run_once((out, "", 1)).error, "auth")

    def test_cancel(self):
        self.assertFalse(runner.cancel(), "nothing to cancel")
        proc = FakePopen.__new__(FakePopen)
        proc.returncode, proc.pid = None, 1
        runner._current = proc
        try:
            self.assertTrue(runner.cancel())
        finally:
            runner._current = None

    # ── counters and markers ─────────────────────────────────────────────────

    def test_daily_counter_alerts_once_at_the_threshold(self):
        self.write_config({"runner": {"daily_alert": 3}})
        alerts = [self.run_once(reply("x")).alert for _ in range(4)]
        self.assertEqual(alerts, [False, False, True, False])
        self.assertEqual(runner.today_count(), 4)

    def test_held_markers_are_parsed_and_removed(self):
        text = ("I need your approval for this.\n"
                "HELD_FOR_APPROVAL p-1a2b3c — write notes.md in alpha\n"
                "HELD_FOR_APPROVAL p-1a2b3c — write notes.md in alpha\n"
                "HELD_FOR_APPROVAL p-9z — push to origin")
        result = self.run_once(reply(text))
        self.assertEqual(result.held, ["p-1a2b3c", "p-9z"])
        self.assertEqual(result.text, "I need your approval for this.")
