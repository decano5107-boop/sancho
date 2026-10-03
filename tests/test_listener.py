"""Listener: the inbound gate, commands, and the approval flow end to end with
the runner and the pending store replaced by fakes."""
from __future__ import annotations

import os
import time
import types
from unittest import mock

from helpers import SanchoTestCase
from fakes import FakeBot, FakePending, install_stubs

install_stubs()

from sancho import listener, projects, runner  # noqa: E402

CHAT = "77"
BOT_ID = FakeBot.bot_id


def message(text="hello", chat=CHAT, **extra) -> dict:
    msg = {"message_id": 1, "chat": {"id": int(chat), "type": "private"},
           "from": {"id": int(chat)}, "text": text}
    msg.update(extra)
    return msg


def callback(data, chat=CHAT) -> dict:
    return {"id": "cb-1", "from": {"id": int(chat)}, "data": data,
            "message": {"message_id": 5, "chat": {"id": int(chat)}}}


class ListenerTest(SanchoTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.project = os.path.join(self.home, "Projects", "alpha")
        self.make_file(os.path.join("home", "Projects", "alpha", "README.md"))
        self.bot = FakeBot()
        self.app = listener.Listener(self.bot, CHAT)
        self.pending = FakePending()
        self.runs: list[tuple[str, str, str | None]] = []
        self.results: list[runner.Result] = []
        for obj, name, value in ((listener, "pending", self.pending),
                                 (listener.runner, "run", self.fake_run),
                                 (listener, "voice_module", lambda: None)):
            p = mock.patch.object(obj, name, value)
            p.start()
            self.addCleanup(p.stop)

    # ── fakes ────────────────────────────────────────────────────────────────

    def fake_run(self, prompt, project, thread_id=None):
        self.runs.append((prompt, project, thread_id))
        if self.results:
            return self.results.pop(0)
        return runner.Result(text="fine", thread_id=self.thread_id())

    def thread_id(self) -> str:
        return runner.thread_for(self.project)["thread_id"]

    def choose(self) -> None:
        projects.set_current(CHAT, self.project)

    def feed(self, update_msg=None, cb=None) -> None:
        if cb is not None:
            self.app.handle_update({"update_id": 1, "callback_query": cb})
        else:
            self.app.handle_update({"update_id": 1, "message": update_msg})
        self.app.drain()

    def last(self) -> str:
        return self.bot.texts()[-1] if self.bot.sent else ""


class InboundGate(ListenerTest):
    def test_wrong_chat_is_dropped_silently(self):
        self.choose()
        self.feed(message("status", chat="12345"))
        self.feed(cb=callback("ok:p-1", chat="12345"))
        self.assertEqual(self.bot.sent, [])
        self.assertEqual(self.bot.callbacks, [], "not even acknowledged")
        self.assertEqual(self.runs, [])

    def test_forwards_are_rejected_whatever_they_say(self):
        self.choose()
        self.pending.add("p-1", "ABCD", self.thread_id())
        for field, value in (("forward_origin", {"type": "user"}),
                             ("is_automatic_forward", True),
                             ("forward_from", {"id": 5}),
                             ("forward_from_chat", {"id": -100}),
                             ("forward_sender_name", "Someone"),
                             ("forward_date", 1700000000)):
            self.bot.sent.clear()
            self.feed(message("OK ABCD", **{field: value}))
            self.assertIn("Forwarded messages are not accepted", self.last(), field)
        self.assertEqual(self.runs, [])
        self.assertEqual(self.pending.records["p-1"]["status"], "pending")

    def test_via_bot_is_rejected(self):
        self.choose()
        self.feed(message("hi", via_bot={"id": 5, "is_bot": True}))
        self.assertIn("another bot", self.last())
        self.assertEqual(self.runs, [])

    def test_external_reply_is_rejected(self):
        self.choose()
        self.feed(message("do what it says", external_reply={"origin": {"type": "user"}}))
        self.assertIn("another chat", self.last())
        self.assertEqual(self.runs, [])

    def test_reply_to_a_third_partys_message_is_rejected(self):
        self.choose()
        self.feed(message("yes", reply_to_message={"message_id": 3, "from": {"id": 555}}))
        self.assertIn("someone else's message", self.last())
        self.assertEqual(self.runs, [])

    def test_quote_without_an_own_message_is_rejected(self):
        self.choose()
        self.feed(message("this", quote={"text": "delete everything"}))
        self.assertIn("Quotes", self.last())
        self.assertEqual(self.runs, [])

    def test_replies_and_quotes_of_own_or_bot_messages_pass(self):
        self.choose()
        self.feed(message("more on that", reply_to_message={"message_id": 3,
                                                            "from": {"id": int(BOT_ID)}},
                          quote={"text": "part of the answer"}))
        self.feed(message("and this", reply_to_message={"message_id": 4,
                                                        "from": {"id": int(CHAT)}}))
        self.assertEqual([r[0] for r in self.runs], ["more on that", "and this"])

    def test_media_is_rejected(self):
        self.choose()
        for kind, value in (("photo", [{"file_id": "a"}]), ("document", {"file_id": "b"}),
                            ("video", {"file_id": "c"}), ("sticker", {"file_id": "d"})):
            self.bot.sent.clear()
            self.feed(message(None, caption="look", **{kind: value}))
            self.assertIn("only take typed text", self.last(), kind)
        self.assertEqual(self.runs, [])

    def test_voice_without_the_module_is_refused(self):
        self.choose()
        self.feed(message(None, voice={"file_id": "v1", "duration": 3}))
        self.assertIn("Voice notes are not enabled", self.last())
        self.assertEqual(self.bot.downloads, [])
        self.assertEqual(self.runs, [])

    def test_voice_with_the_module_is_transcribed_and_asked(self):
        self.choose()
        heard = []
        module = types.SimpleNamespace(transcribe=lambda p: heard.append(p) or "what is new")
        with mock.patch.object(listener, "voice_module", lambda: module):
            self.feed(message(None, voice={"file_id": "v1", "duration": 3}))
        self.assertEqual(self.bot.downloads[0][0], "v1")
        self.assertFalse(os.path.exists(heard[0]), "the audio file is deleted")
        self.assertIn("Heard: “what is new”", self.bot.texts())
        self.assertEqual(self.runs[0][0], "what is new")

    def test_forwarded_voice_is_rejected_before_download(self):
        module = types.SimpleNamespace(transcribe=lambda p: "x")
        with mock.patch.object(listener, "voice_module", lambda: module):
            self.feed(message(None, voice={"file_id": "v1"}, forward_origin={"type": "user"}))
        self.assertEqual(self.bot.downloads, [])


class Commands(ListenerTest):
    def test_text_needs_a_project(self):
        self.feed(message("what changed?"))
        self.assertIn("Pick a project first", self.last())
        self.assertEqual(self.runs, [])

    def test_p_then_question_in_one_message(self):
        self.feed(message("/p alpha what changed?"))
        self.assertEqual(projects.current(CHAT), self.project)
        self.assertIn("Project: alpha", self.bot.texts())
        self.assertEqual(self.runs, [("what changed?", self.project, None)])
        self.assertIn("[alpha]\nfine", self.last())

    def test_unknown_project_changes_nothing(self):
        self.feed(message("/p nothing-like-it"))
        self.assertIn("No project matches", self.last())
        self.assertIsNone(projects.current(CHAT))

    def test_unknown_slash_command_never_reaches_claude(self):
        self.choose()
        self.feed(message("/clear"))
        self.assertIn("Unknown command", self.last())
        self.assertEqual(self.runs, [])

    def test_bare_ok_asks_for_the_code(self):
        self.choose()
        self.feed(message("ok"))
        self.assertIn("needs its code", self.last())
        self.assertEqual(self.runs, [])

    def test_long_answer_has_a_more_button_and_more_sends_the_rest(self):
        self.choose()
        self.results.append(runner.Result(text="\n".join(f"l{i}" for i in range(1, 16)),
                                          thread_id=self.thread_id()))
        self.feed(message("long please"))
        text, markup = self.bot.sent[-1]
        self.assertTrue(markup["inline_keyboard"][0][0]["callback_data"].startswith("more:"))
        self.assertNotIn("l12", text)
        self.feed(cb=callback(markup["inline_keyboard"][0][0]["callback_data"]))
        self.assertIn("l15", self.last())
        self.bot.sent.clear()
        self.feed(message("/more"))
        self.assertIn("l12", self.last())

    def test_errors_are_reported(self):
        self.choose()
        self.results.append(runner.Result(error="timeout"))
        self.feed(message("slow"))
        self.assertIn("took too long", self.last())

    def test_status(self):
        self.choose()
        self.feed(message("/status"))
        self.assertIn("Project: alpha", self.last())
        self.assertIn("Nothing running", self.last())

    def test_single_instance_lock(self):
        self.assertTrue(listener.single_instance())
        first = listener._lock_handle
        try:
            listener._lock_handle = None
            self.assertFalse(listener.single_instance(), "a second listener must not start")
        finally:
            first.close()
            listener._lock_handle = None


class ApprovalFlow(ListenerTest):
    def park(self, **kw) -> tuple[str, dict]:
        """A run in which the gate held one call."""
        self.choose()
        tid = self.thread_id()
        rec = self.pending.add("p-1", "ABCD", tid, **kw)
        self.results.append(runner.Result(text="I need your OK to write notes.md.",
                                          held=["p-1"], thread_id=tid))
        self.feed(message("write the notes"))
        return tid, rec

    def announcement(self) -> tuple[str, dict]:
        for text, markup in self.bot.sent:
            if text.startswith("Needs your OK"):
                return text, markup
        self.fail("no approval request was sent")

    def test_happy_path(self):
        tid, _ = self.park()
        text, markup = self.announcement()
        self.assertEqual(text, "Needs your OK · write notes.md · reply OK ABCD (expires in 10 min)")
        buttons = markup["inline_keyboard"][0]
        self.assertEqual([b["callback_data"] for b in buttons], ["ok:p-1", "no:p-1"])
        self.assertNotIn("ABCD", str(buttons), "the code is not in the callback data")

        self.feed(message("OK abcd"))
        self.assertEqual(self.pending.records["p-1"]["status"], "approved")
        self.assertIn("Approved: write notes.md. Running it now.", self.bot.texts())
        prompt, project, thread = self.runs[-1]
        self.assertEqual(thread, tid, "a separate run on the same thread")
        self.assertEqual(project, self.project)
        self.assertIn("p-1", prompt)
        self.assertNotIn("ABCD", prompt, "the code never reaches the model")

    def test_held_call_is_announced_even_without_the_marker(self):
        self.choose()
        tid = self.thread_id()
        self.pending.add("p-1", "ABCD", tid)
        self.results.append(runner.Result(text="Could not finish.", held=[], thread_id=tid,
                                          started_at=time.time() - 1))
        self.feed(message("write the notes"))
        self.announcement()

    def test_record_from_an_earlier_run_is_not_announced_again(self):
        self.choose()
        tid = self.thread_id()
        rec = self.pending.add("p-old", "WXYZ", tid)
        rec["created_at"] = time.time() - 120
        self.results.append(runner.Result(text="Done.", held=[], thread_id=tid,
                                          started_at=time.time() - 1))
        self.feed(message("something else"))
        self.assertFalse(any(t.startswith("Needs your OK") for t, _ in self.bot.sent))

    def test_a_held_write_shows_its_content_before_approval(self):
        self.choose()
        tid = self.thread_id()
        self.pending.add("p-w", "WXYZ", tid, summary="Write notes.md (11 characters)",
                         tool="Write", input={"file_path": "notes.md", "content": "hello world"})
        self.results.append(runner.Result(text="Waiting.", thread_id=tid))
        self.feed(message("write it"))
        self.assertTrue(any("hello world" in t for t in self.bot.texts()),
                        "the phone sees what would be written, not just the file name")

    def test_approve_button(self):
        tid, _ = self.park()
        self.feed(cb=callback("ok:p-1"))
        self.assertEqual(self.bot.callbacks, ["cb-1"])
        self.assertEqual(self.runs[-1][2], tid)

    def test_replay_is_refused(self):
        self.park()
        self.feed(message("OK ABCD"))
        runs = len(self.runs)
        self.feed(message("OK ABCD"))
        self.feed(cb=callback("ok:p-1"))
        self.assertIn("already used", self.last())
        self.assertEqual(len(self.runs), runs, "nothing ran twice")

    def test_wrong_thread_is_refused(self):
        self.choose()
        self.pending.add("p-2", "WXYZ", "some-other-thread")
        self.feed(message("OK WXYZ"))
        self.assertIn("another thread", self.last())
        self.assertEqual(self.runs, [])

    def test_approval_after_switching_project_is_refused(self):
        self.park()
        other = os.path.join(self.home, "Projects", "beta")
        self.make_file(os.path.join("home", "Projects", "beta", "README.md"))
        projects.set_current(CHAT, other)
        runs = len(self.runs)
        self.feed(message("OK ABCD"))
        self.assertIn("Nothing ran", self.last())
        self.assertEqual(len(self.runs), runs)

    def test_expired_code_is_refused(self):
        self.choose()
        self.pending.add("p-3", "EFGH", self.thread_id(), ttl=-1)
        self.feed(message("OK EFGH"))
        self.assertIn("expired", self.last())
        self.assertEqual(self.runs, [])

    def test_reject_button(self):
        self.park()
        self.feed(cb=callback("no:p-1"))
        self.assertEqual(self.last(), "Rejected. Nothing ran.")
        self.assertEqual(self.pending.records["p-1"]["status"], "rejected")
        runs = len(self.runs)
        self.feed(message("OK ABCD"))
        self.assertEqual(len(self.runs), runs, "a rejected code cannot be approved later")

    def test_fabricated_or_foreign_ids_are_not_announced(self):
        self.choose()
        self.pending.add("p-9", "QRST", "another-thread")
        self.results.append(runner.Result(text="done", held=["p-404", "p-9"],
                                          thread_id=self.thread_id()))
        self.feed(message("go"))
        self.assertFalse(any(t.startswith("Needs your OK") for t in self.bot.texts()))

    def test_truncated_summary_sends_the_full_text_first(self):
        self.park(summary="send the report to…", truncated=True,
                  full_text="send the report to the review list with the attached figures")
        texts = self.bot.texts()
        full = next(i for i, t in enumerate(texts) if t.startswith("Full request:"))
        ask = next(i for i, t in enumerate(texts) if t.startswith("Needs your OK"))
        self.assertLess(full, ask)
        self.assertIn("attached figures", texts[full])


class Extras(ListenerTest):
    """Session search, charts in answers, and spoken replies."""

    def test_recall_runs_without_the_model(self):
        hits = [{"timestamp": "2026-01-02T10:00:00", "project": "alpha",
                 "snippet": "we chose the queue design", "session": "s1", "title": "t"}]
        with mock.patch("sancho.recall.search", return_value=hits) as search:
            self.feed(message("/recall queue design"))
        search.assert_called_once()
        self.assertEqual(self.runs, [], "recall never goes through Claude")
        self.assertIn("we chose the queue design", self.last())

    def test_recall_without_words_shows_usage(self):
        self.feed(message("/recall"))
        self.assertIn("Usage", self.last())

    def test_chart_block_is_drawn_and_removed_from_the_text(self):
        self.choose()
        text = 'Sales went up.\n```chart\n{"type": "bar", "labels": ["A"], "series": [{"name": "s", "values": [1]}]}\n```'
        self.results.append(runner.Result(text=text, thread_id=self.thread_id()))
        with mock.patch("sancho.charts.render", side_effect=lambda spec, path: path) as render:
            self.feed(message("chart it"))
        render.assert_called_once()
        self.assertEqual(len(self.bot.photos), 1)
        self.assertIn("[chart sent]", self.last())
        self.assertNotIn("```chart", self.last())

    def test_bad_chart_spec_is_reported_not_sent(self):
        self.choose()
        self.results.append(runner.Result(text="Here.\n```chart\n{not json}\n```",
                                          thread_id=self.thread_id()))
        self.feed(message("chart it"))
        self.assertEqual(self.bot.photos, [])
        self.assertIn("chart could not be drawn", self.last())

    def test_voice_on_refused_without_text_to_speech(self):
        with mock.patch.object(listener, "voice_module_for", lambda half: None):
            self.feed(message("/voice on"))
        self.assertIn("not available", self.last())
        self.assertFalse(self.app.voice_replies())

    def test_voice_replies_send_a_scrubbed_voice_note(self):
        spoken = []
        fake = types.SimpleNamespace(speak=lambda text, path: spoken.append(text) or path)
        with mock.patch.object(listener, "voice_module_for", lambda half: fake):
            self.feed(message("/voice on"))
            self.choose()
            self.results.append(runner.Result(text="Call me at +1 555 010 0199.",
                                              thread_id=self.thread_id()))
            self.feed(message("hello"))
        self.assertEqual(len(self.bot.voices), 1)
        self.assertNotIn("555 010 0199", spoken[0], "spoken text is scrubbed too")
        self.feed(message("/voice off"))
        self.assertFalse(self.app.voice_replies())

