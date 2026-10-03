"""The pending store: one held call, one secret code, one execution."""
from __future__ import annotations

import json
import os
import stat
from unittest import mock

from helpers import SanchoTestCase

from sancho import config, pending

CALL = ("Bash", {"command": "git push origin main", "description": "push"})
THREAD = "thread-a"


class PendingTest(SanchoTestCase):
    def hold(self, tool=CALL[0], tool_input=None, thread=THREAD, summary="git push origin main",
             full_text="", truncated=False) -> dict:
        return pending.create(tool, dict(tool_input or CALL[1]), thread, summary,
                              full_text, truncated)

    # ── create / get ─────────────────────────────────────────────────────────

    def test_create_record_shape(self):
        rec = self.hold()
        for key in ("pending_id", "code", "hash", "tool", "input", "thread", "summary",
                    "full_text", "truncated", "created_at", "expires_at", "status"):
            self.assertIn(key, rec)
        self.assertEqual(rec["status"], "pending")
        self.assertEqual(len(rec["code"]), 4)
        self.assertTrue(set(rec["code"]) <= set(pending.ALPHABET))
        self.assertRegex(rec["pending_id"], r"^[A-Za-z0-9_-]{8}$")
        self.assertNotIn(rec["code"], rec["pending_id"].upper())
        self.assertAlmostEqual(rec["expires_at"] - rec["created_at"], 600, delta=1)
        self.assertEqual(pending.get(rec["pending_id"]), rec)

    def test_ttl_from_config(self):
        self.write_config({"gate": {"ok_ttl_minutes": 3}})
        rec = self.hold()
        self.assertAlmostEqual(rec["expires_at"] - rec["created_at"], 180, delta=1)

    def test_files_are_private(self):
        rec = self.hold()
        d = config.state_dir("pending")
        path = os.path.join(d, rec["pending_id"] + ".json")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700)
        pending.approve(rec["code"], THREAD)        # rewrite keeps the mode
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        leftovers = [n for n in os.listdir(d) if n.endswith(".tmp")]
        self.assertEqual(leftovers, [])

    def test_codes_unique_among_live_records(self):
        codes = iter(["AAAA", "AAAA", "BBBB"])
        with mock.patch.object(pending, "_new_code", lambda: next(codes)):
            first = self.hold()
            second = self.hold()
        self.assertEqual(first["code"], "AAAA")
        self.assertEqual(second["code"], "BBBB")

    def test_code_never_inside_visible_text(self):
        codes = iter(["PUSH", "K7M3"])
        with mock.patch.object(pending, "_new_code", lambda: next(codes)):
            rec = self.hold(summary="git push")
        self.assertEqual(rec["code"], "K7M3")

    def test_get_refuses_path_like_ids(self):
        self.hold()
        for bad in ("../x", "a/b", "", None, "x" * 65, ".lock"):
            self.assertIsNone(pending.get(bad))

    def test_hash_ignores_key_order(self):
        a = pending.call_hash("Bash", {"command": "ls", "description": "d"})
        b = pending.call_hash("Bash", {"description": "d", "command": "ls"})
        self.assertEqual(a, b)
        self.assertNotEqual(a, pending.call_hash("Bash", {"command": "ls ", "description": "d"}))
        self.assertNotEqual(a, pending.call_hash("Write", {"command": "ls", "description": "d"}))

    def test_hash_ignores_bash_description_only(self):
        base = {"command": "git push origin main", "description": "push the branch",
                "timeout": 60000, "run_in_background": False}
        reworded = dict(base, description="Push main to the remote")
        self.assertEqual(pending.call_hash("Bash", base), pending.call_hash("Bash", reworded))
        self.assertEqual(pending.call_hash("Bash", base),
                         pending.call_hash("Bash", {k: v for k, v in base.items()
                                                    if k != "description"}))
        for key, value in (("command", "git push --force origin main"), ("timeout", 1),
                           ("run_in_background", True)):
            self.assertNotEqual(pending.call_hash("Bash", base),
                                pending.call_hash("Bash", dict(base, **{key: value})), key)
        # The exemption is Bash's alone: other tools keep every field.
        other = {"file_path": "/x", "description": "a"}
        self.assertNotEqual(pending.call_hash("Write", other),
                            pending.call_hash("Write", dict(other, description="b")))

    def test_consume_matches_despite_reworded_description(self):
        rec = self.hold()
        pending.approve(rec["code"], THREAD)
        changed = dict(CALL[1], command="git push --force origin main")
        self.assertFalse(pending.consume_approved("Bash", changed, THREAD))
        reworded = dict(CALL[1], description="Push the main branch")
        self.assertTrue(pending.consume_approved("Bash", reworded, THREAD))
        self.assertFalse(pending.consume_approved("Bash", reworded, THREAD))

    # ── approve ──────────────────────────────────────────────────────────────

    def test_approve_case_insensitive(self):
        rec = self.hold()
        got = pending.approve(" " + rec["code"].lower() + " ", THREAD)
        self.assertIsNotNone(got)
        self.assertEqual(got["status"], "approved")
        self.assertEqual(pending.get(rec["pending_id"])["status"], "approved")

    def test_approve_wrong_thread_fails(self):
        rec = self.hold()
        self.assertIsNone(pending.approve(rec["code"], "thread-b"))
        self.assertEqual(pending.get(rec["pending_id"])["status"], "pending")

    def test_approve_unknown_code_fails(self):
        rec = self.hold()
        other = "2222" if rec["code"] != "2222" else "3333"
        self.assertIsNone(pending.approve(other, THREAD))
        self.assertIsNone(pending.approve("", THREAD))
        self.assertIsNone(pending.approve(rec["code"], ""))

    def test_approve_expired_fails(self):
        rec = self.hold()
        with mock.patch.object(pending, "_now", return_value=rec["expires_at"] + 1):
            self.assertIsNone(pending.approve(rec["code"], THREAD))
        self.assertEqual(pending.get(rec["pending_id"])["status"], "pending")

    def test_approval_gets_a_fresh_window(self):
        rec = self.hold()
        late = rec["expires_at"] - 30             # approved with 30 s left
        with mock.patch.object(pending, "_now", return_value=late):
            got = pending.approve(rec["code"], THREAD)
        self.assertAlmostEqual(got["expires_at"], late + 600, delta=0.01)
        self.assertEqual(pending.get(rec["pending_id"])["expires_at"], got["expires_at"])
        # A busy queue: the run starts after the original deadline, within the new one.
        with mock.patch.object(pending, "_now", return_value=rec["expires_at"] + 300):
            self.assertEqual(len(pending.list_for_thread(THREAD, "approved")), 1)
            self.assertTrue(pending.consume_approved(*CALL, THREAD))

    def test_fresh_window_still_ends(self):
        rec = self.hold()
        with mock.patch.object(pending, "_now", return_value=rec["created_at"] + 60):
            got = pending.approve(rec["code"], THREAD)
        with mock.patch.object(pending, "_now", return_value=got["expires_at"] + 1):
            self.assertFalse(pending.consume_approved(*CALL, THREAD))

    def test_approve_twice_fails(self):
        rec = self.hold()
        self.assertIsNotNone(pending.approve(rec["code"], THREAD))
        self.assertIsNone(pending.approve(rec["code"], THREAD))

    def test_approve_rejected_fails(self):
        rec = self.hold()
        self.assertIsNotNone(pending.reject(rec["code"].lower()))
        self.assertEqual(pending.get(rec["pending_id"])["status"], "rejected")
        self.assertIsNone(pending.approve(rec["code"], THREAD))

    def test_approve_used_fails(self):
        rec = self.hold()
        pending.approve(rec["code"], THREAD)
        self.assertTrue(pending.consume_approved(*CALL, THREAD))
        self.assertIsNone(pending.approve(rec["code"], THREAD))
        self.assertIsNone(pending.get(rec["pending_id"]))

    # ── consume ──────────────────────────────────────────────────────────────

    def test_consume_requires_approval(self):
        self.hold()
        self.assertFalse(pending.consume_approved(*CALL, THREAD))

    def test_consume_once_then_replay_fails(self):
        rec = self.hold()
        pending.approve(rec["code"], THREAD)
        self.assertTrue(pending.consume_approved(CALL[0], dict(reversed(CALL[1].items())), THREAD))
        self.assertFalse(pending.consume_approved(*CALL, THREAD))

    def test_consume_different_call_fails(self):
        rec = self.hold()
        pending.approve(rec["code"], THREAD)
        edited = {"command": "git push --force origin main", "description": "push"}
        self.assertFalse(pending.consume_approved("Bash", edited, THREAD))
        self.assertFalse(pending.consume_approved("Write", CALL[1], THREAD))
        self.assertFalse(pending.consume_approved(*CALL, "thread-b"))
        self.assertFalse(pending.consume_approved(*CALL, ""))
        self.assertTrue(pending.consume_approved(*CALL, THREAD))   # still intact

    def test_consume_expired_fails(self):
        rec = self.hold()
        pending.approve(rec["code"], THREAD)
        with mock.patch.object(pending, "_now", return_value=rec["expires_at"] + 1):
            self.assertFalse(pending.consume_approved(*CALL, THREAD))

    def test_consume_rejected_after_approval_fails(self):
        rec = self.hold()
        pending.approve(rec["code"], THREAD)
        self.assertIsNotNone(pending.reject(rec["code"]))
        self.assertFalse(pending.consume_approved(*CALL, THREAD))

    def test_reject_unknown_returns_none(self):
        self.assertIsNone(pending.reject("ZZZZ"))
        self.assertIsNone(pending.reject(""))

    # ── list / sweep ─────────────────────────────────────────────────────────

    def test_list_for_thread_filters(self):
        times = iter([1000.0, 1001.0, 1002.0, 1003.0])
        with mock.patch.object(pending, "_now", side_effect=lambda: next(times)):
            a = self.hold(summary="first")
            b = self.hold(summary="second")
            self.hold(thread="thread-b", summary="other thread")
            c = self.hold(summary="third")
        with mock.patch.object(pending, "_now", return_value=1100.0):
            pending.approve(b["code"], THREAD)
        with mock.patch.object(pending, "_now", return_value=1200.0):
            self.assertEqual([r["pending_id"] for r in pending.list_for_thread(THREAD)],
                             [a["pending_id"], c["pending_id"]])
            self.assertEqual([r["pending_id"] for r in pending.list_for_thread(THREAD, since=1002.5)],
                             [c["pending_id"]])
            self.assertEqual([r["pending_id"] for r in pending.list_for_thread(THREAD, "approved")],
                             [b["pending_id"]])
            self.assertEqual(len(pending.list_for_thread("thread-b")), 1)
            self.assertEqual(pending.list_for_thread("nobody"), [])
        with mock.patch.object(pending, "_now", return_value=a["expires_at"] + 0.5):
            self.assertEqual([r["pending_id"] for r in pending.list_for_thread(THREAD)],
                             [c["pending_id"]])

    def test_sweep_removes_expired_and_finished(self):
        live = self.hold(summary="live")
        rejected = self.hold(summary="rejected")
        pending.reject(rejected["code"])
        old = self.hold(summary="old")
        d = config.state_dir("pending")
        path = os.path.join(d, old["pending_id"] + ".json")
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        data["expires_at"] = 0
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        self.assertEqual(pending.sweep(), 2)
        self.assertIsNotNone(pending.get(live["pending_id"]))
        self.assertIsNone(pending.get(rejected["pending_id"]))
        self.assertIsNone(pending.get(old["pending_id"]))
        self.assertEqual(pending.sweep(), 0)

    def test_create_rejects_bad_input(self):
        with self.assertRaises(ValueError):
            pending.create("Bash", "not a dict", THREAD, "s", "", False)
        with self.assertRaises(ValueError):
            pending.create("Bash", {}, "", "s", "", False)
        with self.assertRaises(ValueError):
            pending.create("Bash", {"x": float("nan")}, THREAD, "s", "", False)
