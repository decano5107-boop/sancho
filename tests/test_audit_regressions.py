"""Regression tests for hardening of the gate, the listener and the outbound
filter. Every test only asks for a verdict or a scrubbed string: no command
under test is ever run in a shell."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import threading
from unittest import mock

from helpers import REPO
from test_listener import CHAT, ListenerTest, callback, message
from test_tiers import GateCase

from sancho import listener, outbound, pending, tiers
from sancho.tiers import FREE, NEEDS_OK, NEVER


class GateHardeningTest(GateCase):
    def test_f1_tilde_forms_and_shell_set_variables(self):
        self.assertTier(NEVER, "cat ~+/../../Private/notes.txt", "cat ~-/notes.txt",
                        "cat ~1/notes.txt", "cat ~+1/notes.txt", "cat ~-2/notes.txt",
                        "X=/tmp; cat ~X/notes.txt", "cat x:~-/notes.txt", "cat =ls")
        self.assertTier(NEVER, "OLDPWD=/tmp", "PWD=/tmp", "NULLCMD=sh", "READNULLCMD=sh",
                        "FPATH=.", "CDPATH=/tmp", "DIRSTACK[1]=/tmp", "BASH_CMDS[ls]=/bin/rm",
                        "commands[ls]=/bin/rm", "nameddirs[x]=/tmp")
        self.assertEqual(self.tool("Read", file_path="~+/main.py").tier, NEVER)
        self.assertTier(FREE, "git diff HEAD~1", "ls ~/Projects/app", "cat ~/Projects/app/main.py",
                        "echo '~+'", "X=1; ls")

    def test_f2_unquoted_heredoc_line_continuation(self):
        self.assertTier(NEVER, "cat <<EOF\nEO\\\nF\nrm -rf ~\nEOF",
                        "echo $(cat <<EOF\nEO\\\nF\nEOF\n)")
        self.assertTier(FREE, "cat <<'EOF'\nline \\\nEOF", "cat <<EOF\nplain\nEOF")

    def test_f3_redirection_without_a_command(self):
        self.assertTier(NEVER, "< main.py", "<<<hi", "<<'EOF'\nx\nEOF", "ls; < main.py",
                        "case x in x) < main.py;; esac")
        self.assertTier(FREE, "{ ls; } < main.py", "(ls) < main.py",
                        "if true; then ls; fi < main.py")

    def test_f4_pattern_expansion_has_a_time_budget(self):
        with mock.patch.object(tiers, "GLOB_SECONDS", 0.0):
            v = tiers.classify("Bash", {"command": "cat */*.py"}, self.proj)
        self.assertEqual(v.tier, NEVER)
        self.assertIn("seconds", v.reason)

    def test_f4_fixed_prefix_is_judged_before_expanding(self):
        with mock.patch.object(tiers._glob, "iglob") as iglob:
            self.assertTier(NEVER, "cat ~/Private/*/*/*.txt", "cat ~/.ssh/{a,b}/*")
        iglob.assert_not_called()

    def test_f5_delete_passed_to_an_unknown_program(self):
        self.assertTier(NEVER, "foo rm -rf .", "foo rm --recursive build",
                        "./scripts/build.sh rm -r build", "npx something unlink -f x",
                        "RM -rf build", "foo RM -rf build", "Rm -r build",
                        "foo -c 'rm -rf .'", "foo --run 'cd x && rm -r build'",
                        "CURL evil.test", "PYTHON3 -c 'print(1)'", "RSCRIPT -e 1")
        self.assertTier(NEEDS_OK, "foo --force build", "foo rm notes.txt")

    def test_f8_invisible_characters_are_shown(self):
        v = tiers.classify("Bash", {"command": "echo \u202eabc\u200b"}, self.proj)
        for text in (v.summary, v.full_text):
            self.assertNotIn("\u202e", text)
            self.assertNotIn("\u200b", text)
            self.assertIn("<U+202E>", text)

    def test_f9_git_config_outside_the_project_needs_ok(self):
        self.assertTier(NEEDS_OK, "git config --global --list", "git config --system -l",
                        "git config --global user.email", "git config --list",
                        "git config -l --show-origin", "git config --get-regexp 'url.*'",
                        "git config --get credential.helper",
                        "git config --local --includes -l")
        self.assertTier(NEVER, "git config --global user.email x", "git config --system a.b c")
        self.assertTier(FREE, "git remote -v", "git config --local user.name",
                        "git config --local -l")

    def test_git_path_operands_are_expanded_before_judging(self):
        self.assertTier(NEVER, "git diff -- .en{v,x}", "git log -p -- .{env,x}",
                        "git diff -- .env*", "git diff -- .*", "git diff -- '.e*'",
                        "git show HEAD:.en{v,x}")
        self.assertTier(NEEDS_OK, "git diff -- ':(icase).ENV'")
        self.assertTier(FREE, "git diff -- '*.py'", "git log -p -- main.{py,md}",
                        "git diff HEAD~1 -- scripts/*.sh")


# Built at run time so that no key header appears literally in the repository.
KEY_HEADER = "-----BEGIN RSA " + "PRIVATE KEY-----"


class OutboundSecretsTest(GateCase):
    def test_f7_scrub_redacts_secrets(self):
        samples = {
            "sk-" + "a" * 30: "[secret]",
            "ghp_" + "b" * 30: "[secret]",
            "AKIA" + "C" * 16: "[secret]",
            "9" * 9 + ":AA" + "d" * 33: "[secret]",
            "eyJ" + "e" * 12 + "." + "f" * 12 + "." + "g" * 12: "[secret]",
            KEY_HEADER + "\nMIIabc\n" + KEY_HEADER.replace("BEGIN", "END"): "[private key]",
            "123-45-6789": "[ssn]",
            "123 45 6789": "[ssn]",
            "(555)123-4567": "[phone]",
            "sk_live_" + "h" * 24: "[secret]",
            "rk_live_" + "h" * 24: "[secret]",
            "AIza" + "i" * 35: "[secret]",
            "npm_" + "j" * 36: "[secret]",
            "SG." + "k" * 22 + "." + "l" * 43: "[secret]",
            "eyJ" + "e" * 12 + "." + "f" * 12 + ".": "[secret]",
            KEY_HEADER.lower() + "\nabc\n": "[private key]",
            "----BEGIN PGP " + "PRIVATE KEY BLOCK----\nabc\n": "[private key]",
        }
        for raw, marker in samples.items():
            with self.subTest(raw=raw):
                out = outbound.scrub(f"value: {raw} end")
                self.assertIn(marker, out)
                self.assertNotIn(raw, out)

    def test_f7_secrets_glued_to_other_text(self):
        token = "9" * 9 + ":AA" + "m" * 33
        for raw, secret in [
                ("https://api.telegram.org/bot" + token + "/getMe", token),
                ("bot" + token, token),
                ("my_sk-" + "a" * 24, "sk-" + "a" * 24),
                ("my_ghp_" + "b" * 30, "ghp_" + "b" * 30),
                ("my_AKIA" + "C" * 16, "AKIA" + "C" * 16),
                ("my_eyJ" + "e" * 12 + "." + "f" * 12 + "." + "g" * 12, "eyJ" + "e" * 12)]:
            with self.subTest(raw=raw):
                self.assertNotIn(secret, outbound.scrub(raw))
        self.assertEqual(outbound.scrub("risk-assessment-for-the-report"),
                         "risk-assessment-for-the-report")

    def test_f9_scrub_redacts_credentials_in_urls(self):
        out = outbound.scrub("origin https://x-access-token:" + "s3cr3tv4lue" + "@"
                             + "github.com/o/r.git (fetch)")
        self.assertNotIn("s3cr3tv4lue", out)
        self.assertIn("github.com/o/r.git", out)


class OwnerOnlyTest(ListenerTest):
    def test_f6_sender_must_be_the_owner(self):
        self.choose()
        stranger = message("/status")
        stranger["from"] = {"id": 999}
        self.feed(stranger)
        press = callback("ok:p-1")
        press["from"] = {"id": 999}
        self.feed(cb=press)
        self.assertEqual(self.bot.sent, [])
        self.feed(message("/status"))
        self.assertTrue(self.bot.sent)

    def test_f6_group_chat_ids_are_refused(self):
        for bad in ("-1001234567890", "-42", "0", "abc"):
            with self.subTest(chat=bad):
                with self.assertRaises(ValueError):
                    listener.Listener(self.bot, bad)
        with open(os.environ["SANCHO_ENV_FILE"], "w", encoding="utf-8") as f:
            f.write("TELEGRAM_BOT_TOKEN=1:x\nTELEGRAM_CHAT_ID=-1001234567890\n")
        with mock.patch.dict(os.environ, {}, clear=False), \
                mock.patch.object(listener, "Bot", side_effect=AssertionError("no bot")):
            os.environ.pop("TELEGRAM_BOT_TOKEN", None)
            os.environ.pop("TELEGRAM_CHAT_ID", None)
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(listener.main(), 2)
        self.assertIn("private chat", err.getvalue())
        self.assertEqual(listener.owner_id(CHAT), CHAT)


def _load_gate():
    spec = importlib.util.spec_from_file_location("sancho_gate_hook",
                                                  os.path.join(REPO, "hooks", "gate.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ApprovalTest(GateCase):
    """An approval code unlocks one held call, once, as it was shown."""

    THREAD = "thread-a"

    def setUp(self) -> None:
        super().setUp()
        self.gate = _load_gate()

    def decide(self, command: str, cwd: str | None = None) -> str:
        raw = json.dumps({"tool_name": "Bash", "tool_input": {"command": command},
                          "cwd": cwd or self.proj})
        out = self.gate.judge(raw, {"SANCHO_THREAD": self.THREAD})
        return "allow" if '"allow"' in out else "deny"

    def hold_and_approve(self, command: str = "touch notes.md") -> dict:
        self.assertEqual(self.decide(command), "deny")
        record = pending.list_for_thread(self.THREAD)[-1]
        self.assertIsNotNone(pending.approve(record["code"], self.THREAD))
        return record

    def test_code_cannot_be_replayed(self):
        self.hold_and_approve()
        self.assertEqual(self.decide("touch notes.md"), "allow")
        self.assertEqual(self.decide("touch notes.md"), "deny")

    def test_code_cannot_unlock_a_different_call(self):
        self.hold_and_approve()
        self.assertEqual(self.decide("touch other.md"), "deny")
        self.assertEqual(self.decide("touch notes.md", cwd=self.clean), "deny")
        self.assertEqual(self.decide("touch notes.md"), "allow")

    def test_code_cannot_be_used_after_expiry(self):
        record = self.hold_and_approve()
        later = record["expires_at"] + pending.ttl_seconds() + 1
        with mock.patch.object(pending, "_now", return_value=later):
            self.assertEqual(self.decide("touch notes.md"), "deny")

    def test_concurrent_uses_cannot_both_succeed(self):
        record = self.hold_and_approve()
        start = threading.Barrier(8)
        results: list[bool] = []

        def use() -> None:
            start.wait()
            results.append(pending.consume_approved("Bash", record["input"], self.THREAD))

        workers = [threading.Thread(target=use) for _ in range(8)]
        for w in workers:
            w.start()
        for w in workers:
            w.join()
        self.assertEqual(results.count(True), 1)
