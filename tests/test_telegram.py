"""Bot API client: request shape, chunking, offsets, downloads, token hygiene."""
from __future__ import annotations

import io
import json
import os
import urllib.error
from unittest import mock

from helpers import SanchoTestCase

from sancho import telegram
from sancho.telegram import Bot, TelegramError, keyboard, split_text

TOKEN = "123456:TEST-token-value"


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def ok(result) -> FakeResponse:
    return FakeResponse(json.dumps({"ok": True, "result": result}).encode())


class Recorder:
    """Replaces urlopen: records each request, answers from a list."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, req, timeout=None):
        self.requests.append((req, timeout))
        nxt = self.responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt

    def body(self, i=-1) -> dict:
        return json.loads(self.requests[i][0].data.decode())

    def method(self, i=-1) -> str:
        return self.requests[i][0].full_url.rsplit("/", 1)[1]


class TelegramTest(SanchoTestCase):
    def bot(self, *responses) -> tuple[Bot, Recorder]:
        rec = Recorder(*responses)
        patcher = mock.patch.object(telegram.urllib.request, "urlopen", rec)
        patcher.start()
        self.addCleanup(patcher.stop)
        return Bot(TOKEN), rec

    def test_send_message_posts_json_with_keyboard(self):
        bot, rec = self.bot(ok({"message_id": 1}))
        kb = keyboard([[("Approve", "ok:abc123"), ("Reject", "no:abc123")]])
        bot.send_message(42, "hello", kb)
        self.assertEqual(rec.method(), "sendMessage")
        body = rec.body()
        self.assertEqual(body["chat_id"], 42)
        self.assertEqual(body["text"], "hello")
        self.assertEqual(body["reply_markup"]["inline_keyboard"][0][1],
                         {"text": "Reject", "callback_data": "no:abc123"})
        self.assertEqual(rec.requests[0][0].get_header("Content-type"), "application/json")
        self.assertIsNotNone(rec.requests[0][1], "every request carries a timeout")

    def test_long_text_is_chunked_and_keyboard_rides_on_the_last_piece(self):
        text = "\n".join(f"line {i} " + "x" * 90 for i in range(100))   # ~10k chars
        bot, rec = self.bot(*[ok({}) for _ in range(5)])
        bot.send_message(1, text, keyboard([[("More", "more:1")]]))
        bodies = [rec.body(i) for i in range(len(rec.requests))]
        self.assertGreaterEqual(len(bodies), 3)
        self.assertTrue(all(len(b["text"]) <= 4096 for b in bodies))
        self.assertEqual("\n".join(b["text"] for b in bodies), text)
        self.assertNotIn("reply_markup", bodies[0])
        self.assertIn("reply_markup", bodies[-1])

    def test_split_text_hard_cuts_a_single_huge_line(self):
        pieces = split_text("y" * 9000)
        self.assertEqual([len(p) for p in pieces], [4096, 4096, 808])

    def test_get_updates_persists_offset_before_returning(self):
        bot, rec = self.bot(ok([{"update_id": 7}, {"update_id": 9}]), ok([]))
        self.assertIsNone(bot.offset)
        updates = bot.get_updates(timeout=5)
        self.assertEqual(len(updates), 2)
        self.assertEqual(bot.offset, 10)
        with open(telegram.offset_path()) as f:
            self.assertEqual(f.read(), "10")
        self.assertEqual(rec.body(0)["allowed_updates"], ["message", "callback_query"])
        self.assertNotIn("offset", rec.body(0))
        bot.get_updates(timeout=5)
        self.assertEqual(rec.body(1)["offset"], 10)
        self.assertGreater(rec.requests[1][1], 5, "HTTP timeout exceeds the long-poll timeout")
        self.assertEqual(Bot(TOKEN).offset, 10, "a new process resumes from the file")

    def test_cold_start_skips_the_backlog(self):
        bot, rec = self.bot(ok([{"update_id": 3}, {"update_id": 5}]))
        bot.skip_backlog()
        self.assertEqual(bot.offset, 6)
        self.assertEqual(rec.body(0)["timeout"], 0)

    def test_skip_backlog_is_a_no_op_with_a_stored_offset(self):
        with open(telegram.offset_path(), "w") as f:
            f.write("50")
        bot, rec = self.bot()
        bot.skip_backlog()
        self.assertEqual(rec.requests, [])

    def test_answer_callback(self):
        bot, rec = self.bot(ok(True))
        bot.answer_callback("cb-1")
        self.assertEqual(rec.method(), "answerCallbackQuery")
        self.assertEqual(rec.body(), {"callback_query_id": "cb-1"})

    def test_upload_is_multipart_with_the_file(self):
        path = self.make_file("out/chart.png", "PNGDATA")
        bot, rec = self.bot(ok({}), ok({}), ok({}), ok({}))
        for send, field in ((bot.send_photo, "photo"), (bot.send_document, "document"),
                            (bot.send_voice, "voice"), (bot.send_audio, "audio")):
            send(1, path, caption="cap")
            req = rec.requests[-1][0]
            self.assertTrue(req.get_header("Content-type").startswith("multipart/form-data"))
            self.assertIn(f'name="{field}"; filename="chart.png"'.encode(), req.data)
            self.assertIn(b"PNGDATA", req.data)
            self.assertIn(b"cap", req.data)
        self.assertEqual([rec.method(i) for i in range(4)],
                         ["sendPhoto", "sendDocument", "sendVoice", "sendAudio"])

    def test_download_writes_to_the_callers_path(self):
        bot, rec = self.bot(ok({"file_path": "voice/file_1.oga", "file_size": 5}),
                            FakeResponse(b"audio"))
        dest = os.path.join(self.tmp, "inbox", "v.oga")
        bot.download("FID", dest)
        with open(dest, "rb") as f:
            self.assertEqual(f.read(), b"audio")
        self.assertTrue(rec.requests[1][0].full_url.endswith("/file/bot" + TOKEN + "/voice/file_1.oga"))

    def test_download_refuses_oversized_files(self):
        bot, _ = self.bot(ok({"file_path": "x", "file_size": 10 ** 9}))
        with self.assertRaises(TelegramError):
            bot.download("FID", os.path.join(self.tmp, "big"))

    def test_errors_never_contain_the_token(self):
        url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
        http = urllib.error.HTTPError(url, 401, "Unauthorized", {},
                                      io.BytesIO(f"bad token {TOKEN}".encode()))
        net = urllib.error.URLError(f"failed for {url}")
        api = FakeResponse(json.dumps({"ok": False, "error_code": 400,
                                       "description": f"echo {TOKEN}"}).encode())
        bot, _ = self.bot(http, net, api)
        for _ in range(3):
            with self.assertRaises(TelegramError) as ctx:
                bot.send_message(1, "x")
            self.assertNotIn(TOKEN, str(ctx.exception))
            self.assertNotIn("TEST-token", repr(ctx.exception))

    def test_missing_token_is_an_error(self):
        with self.assertRaises(TelegramError):
            Bot("")

    def test_bot_id_is_the_numeric_prefix(self):
        self.assertEqual(Bot(TOKEN).bot_id, "123456")
