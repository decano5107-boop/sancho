"""
The listener: long-polls Telegram, lets only the owner's own messages through,
runs one query at a time through the runner, and carries approval requests to
the phone.

    python3 -m sancho.listener

Inbound is an allowlist, checked in this order:

  1. The chat id and the sender id must both equal TELEGRAM_CHAT_ID, the
     owner's private chat with the bot (whose id is the owner's user id).
     Anything else is dropped without a reply, so a stranger cannot even learn
     the bot is alive. A group chat id (negative) is refused at startup: in a
     group, every member could talk to the bot and approve its actions.
  2. Someone else's words are refused with a notice, whatever they say:
     forwards (`forward_origin`, `is_automatic_forward`, and the legacy
     `forward_*` fields), messages sent through another bot (`via_bot`),
     replies quoting another chat (`external_reply`), replies to a message
     written by a third party, and quotes of such a message. A forwarded
     "OK 7F3A" is the cheapest attack on an approval flow; it never gets read.
  3. Media is refused with a notice: documents, photos, videos, stickers and
     the like. Voice notes are accepted only when the optional voice module is
     installed; they are transcribed locally and treated as typed text.
  4. Button presses (callback queries) pass the same chat and sender check.

Approvals: when the gate holds a call, it records it on disk with a one-time
code and denies it with "HELD_FOR_APPROVAL <id> — <summary>". The listener
reads that record (never the model's wording of it), shows the user what is
being approved, the code and Approve/Reject buttons. Approving (a button, or
typing `OK <code>`) marks the record approved for that thread and starts a
separate run on the same thread, in which the gate lets that one call through.
The code never reaches the model.
"""
from __future__ import annotations

import fcntl
import importlib
import logging
import math
import os
import queue
import re
import signal
import sys
import threading
import time

from sancho import config, outbound, pending, projects, runner, tiers
from sancho.telegram import Bot, TelegramError, keyboard

log = logging.getLogger("sancho.listener")

HELP = (
    "I run Claude Code on your computer, under a permission gate.\n"
    "/p <name> — pick the project (sticky until you change it)\n"
    "/p <name> <question> — pick it and ask in one go\n"
    "/status — project, thread, what is running\n"
    "/more — the rest of the last long answer\n"
    "/new — start a clean thread in this project\n"
    "/cancel — stop what is running and clear the queue\n"
    "/recall <words> — search your past Claude Code sessions on this computer\n"
    "/voice on|off — also answer with a voice note\n"
    "OK <code> — approve a held action (or use the buttons)\n"
    "/reject <code> — refuse it\n"
    "Reading runs freely. Writing, sending or spending waits for your code. "
    "Deleting, secrets and unknown network destinations are refused even with it."
)

FORWARD_FIELDS = ("forward_origin", "is_automatic_forward", "forward_from",
                  "forward_from_chat", "forward_sender_name", "forward_date")
MEDIA_FIELDS = ("document", "photo", "video", "video_note", "animation", "sticker",
                "audio", "contact", "location", "venue", "poll", "dice", "story")
PENDING_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
CODE = re.compile(r"^[A-Za-z0-9]{3,12}$")
AUTH_NAG_EVERY = 1800           # seconds between "sign-in expired" notices
CHART_BLOCK = re.compile(r"```chart[ \t]*\n(.*?)```", re.S)


def change_preview(tool: str, tool_input: dict) -> str:
    """What a held write or edit would actually put on disk, so an approval is
    never given on a file name alone."""
    if not isinstance(tool_input, dict):
        return ""
    path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
    if tool == "Write":
        return f"Content to write to {path}:\n{tool_input.get('content', '')}"
    if tool == "Edit":
        return (f"Change in {path}:\n--- replace\n{tool_input.get('old_string', '')}\n"
                f"+++ with\n{tool_input.get('new_string', '')}")
    if tool == "MultiEdit":
        parts = [f"Changes in {path}:"]
        for i, e in enumerate(tool_input.get("edits") or [], 1):
            if isinstance(e, dict):
                parts.append(f"--- {i}. replace\n{e.get('old_string', '')}\n"
                             f"+++ with\n{e.get('new_string', '')}")
        return "\n".join(parts)
    if tool == "NotebookEdit":
        return f"Cell source for {path}:\n{tool_input.get('new_source', '')}"
    return ""


def voice_module_for(half: str):
    """The optional voice module when its `half` ("transcribe" or "speak") works
    on this machine, else None."""
    try:
        module = importlib.import_module("sancho.voice")
        return module if module.available().get(half) else None
    except Exception:
        return None


def voice_module():
    """The optional local speech-to-text module, or None when it is missing or
    its engine is not installed on this machine."""
    try:
        module = importlib.import_module("sancho.voice")
    except Exception:
        return None
    if not callable(getattr(module, "transcribe", None)):
        return None
    check = getattr(module, "available", None)
    if callable(check):
        try:
            if not check().get("transcribe"):
                return None
        except Exception:
            return None
    return module


def owner_id(chat_id: str | int) -> str:
    """TELEGRAM_CHAT_ID as the owner's user id. Only a private chat qualifies:
    its id is a positive integer equal to the owner's user id. ValueError
    otherwise (a group or channel id is negative)."""
    text = str(chat_id).strip()
    if not text.isdigit() or int(text) <= 0:
        raise ValueError(f"TELEGRAM_CHAT_ID must be the id of your private chat with the bot "
                         f"(a positive number, your own user id), not {text!r}; group and "
                         f"channel chats are refused because any member could approve actions")
    return str(int(text))


class Listener:
    def __init__(self, bot: Bot, chat_id: str | int) -> None:
        self.bot = bot
        self.chat_id = owner_id(chat_id)
        self.bot_id = str(getattr(bot, "bot_id", "") or "")
        self.jobs: queue.Queue = queue.Queue()
        self.stop = threading.Event()
        self.busy: dict = {"what": None, "since": 0.0}
        self._last_auth_nag = 0.0

    # ── sending ──────────────────────────────────────────────────────────────

    def send(self, text: str, markup: dict | None = None) -> None:
        try:
            self.bot.send_message(self.chat_id, text, markup)
        except TelegramError as e:
            log.warning("send failed: %s", e)

    def reply(self, text: str) -> None:
        """An answer from the model: through the whole outbound contract."""
        prepared = outbound.prepare(text)
        markup = (keyboard([[("More", f"more:{prepared.detail_id}")]])
                  if prepared.detail_id else None)
        chunks = outbound.chunks(prepared.head)
        for i, chunk in enumerate(chunks):
            self.send(chunk, markup if i == len(chunks) - 1 else None)

    # ── inbound gate ─────────────────────────────────────────────────────────

    def _own_author(self, message: dict | None) -> bool:
        author = str(((message or {}).get("from") or {}).get("id", ""))
        return author in {self.chat_id, self.bot_id} - {""}

    def rejection(self, msg: dict) -> str | None:
        """The notice to send when a message from the right chat still carries
        content that is not the owner's own. None when it may pass."""
        if any(msg.get(f) for f in FORWARD_FIELDS):
            return "Forwarded messages are not accepted. If you want me to look at it, type it yourself."
        if msg.get("via_bot"):
            return "Messages sent through another bot are not accepted."
        if msg.get("external_reply"):
            return "Replies that quote a message from another chat are not accepted."
        replied = msg.get("reply_to_message")
        if replied and not self._own_author(replied):
            return "Replies to someone else's message are not accepted."
        if msg.get("quote") and not replied:
            return "Quotes of someone else's message are not accepted."
        for kind in MEDIA_FIELDS:
            if msg.get(kind):
                return "I only take typed text (and voice notes, when enabled)."
        return None

    def handle_update(self, update: dict) -> None:
        if update.get("callback_query"):
            self.handle_callback(update["callback_query"])
        elif update.get("message"):
            self.handle_message(update["message"])

    def _from_owner(self, chat: dict | None, sender: dict | None) -> bool:
        return (str((chat or {}).get("id", "")) == self.chat_id
                and str((sender or {}).get("id", "")) == self.chat_id)

    def handle_message(self, msg: dict) -> None:
        if not self._from_owner(msg.get("chat"), msg.get("from")):
            return                                      # not the owner: silence
        notice = self.rejection(msg)
        if notice:
            self.send(notice)
            return
        if msg.get("voice"):
            if voice_module() is None:
                self.send("Voice notes are not enabled on this computer. Please type it.")
                return
            self.enqueue(("voice", msg["voice"]), "voice note")
            return
        text = (msg.get("text") or "").strip()
        if not text:
            self.send("I only take typed text (and voice notes, when enabled).")
            return
        self.dispatch(text)

    def handle_callback(self, cb: dict) -> None:
        if not self._from_owner((cb.get("message") or {}).get("chat"), cb.get("from")):
            return
        try:
            self.bot.answer_callback(cb.get("id", ""))
        except TelegramError as e:
            log.warning("answerCallbackQuery failed: %s", e)
        action, _, arg = (cb.get("data") or "").partition(":")
        if action == "ok" and PENDING_ID.match(arg):
            self.approve_button(arg)
        elif action == "no" and PENDING_ID.match(arg):
            self.reject_button(arg)
        elif action == "more":
            self.more(arg)

    # ── commands ─────────────────────────────────────────────────────────────

    def dispatch(self, text: str) -> None:
        head, _, rest = text.partition(" ")
        cmd, rest = head.lower().split("@", 1)[0], rest.strip()
        words = text.split()
        if cmd in ("/help", "/start"):
            self.send(HELP)
        elif cmd == "/status":
            self.status()
        elif cmd == "/cancel":
            self.cancel()
        elif cmd == "/more":
            self.more(rest)
        elif cmd == "/new":
            self.new_thread()
        elif cmd == "/p":
            self.choose_project(rest)
        elif cmd == "/recall":
            if rest:
                self.enqueue(("recall", rest), f"recall: {rest}")
            else:
                self.send("Usage: /recall <words>")
        elif cmd == "/voice":
            self.set_voice_replies(rest.lower())
        elif len(words) == 2 and words[0].lower().lstrip("/") in ("ok", "approve"):
            self.approve_code(words[1])
        elif len(words) == 2 and words[0].lower() in ("/reject", "/no", "reject"):
            self.reject_code(words[1])
        elif text.lower().strip("/ .!") in ("ok", "okay", "approve"):
            self.send("An approval needs its code: reply OK <code>, as shown in the request.")
        elif text.startswith("/"):
            self.send("Unknown command. /help lists them.")
        else:
            self.ask(text)

    def choose_project(self, arg: str) -> None:
        current = projects.current(self.chat_id)
        if not arg:
            self.send(f"Current project: {projects.display_name(current)}. "
                      "Change it with /p <name>.")
            return
        path, question, hints = projects.resolve_with_rest(arg)
        if not path:
            where = projects.display_name(current)
            if hints:
                self.send(f"“{arg}” matches more than one project, or none exactly. Which one?\n"
                          + "\n".join(f"· {h}" for h in hints[:8])
                          + f"\nStill in: {where}.")
            else:
                self.send(f"No project matches “{arg}”. Still in: {where}; nothing ran.")
            return
        projects.set_current(self.chat_id, path)
        self.send(f"Project: {projects.display_name(path)}")
        if question:
            self.ask(question)

    def ask(self, text: str) -> None:
        project = projects.current(self.chat_id)
        if not project:
            self.send("Pick a project first: /p <name>")
            return
        self.enqueue(("ask", text, project), text)

    def status(self) -> None:
        project = projects.current(self.chat_id)
        lines = [f"Project: {projects.display_name(project)}"]
        if project:
            thread = runner.thread_for(project, rotate=False)
            if thread:
                age = int((time.time() - float(thread.get("started_at", 0))) / 3600)
                lines.append(f"Thread: {thread.get('turns', 0)} turns, started {age} h ago")
            else:
                lines.append("Thread: none yet (the next question starts one)")
        if self.busy["what"]:
            mins = int((time.time() - self.busy["since"]) / 60)
            lines.append(f"Running: “{self.busy['what']}” for {mins} min · /cancel stops it")
        else:
            lines.append("Nothing running.")
        if self.jobs.qsize():
            lines.append(f"Queued: {self.jobs.qsize()}")
        lines.append(f"Queries today: {runner.today_count()}")
        self.send("\n".join(lines))

    def cancel(self) -> None:
        dropped = 0
        while True:
            try:
                self.jobs.get_nowait()
                self.jobs.task_done()
                dropped += 1
            except queue.Empty:
                break
        killed = runner.cancel()
        if killed or dropped:
            self.send("Stopped." + (f" {dropped} queued message(s) dropped." if dropped else ""))
        else:
            self.send("Nothing was running.")

    def more(self, detail_id: str) -> None:
        detail_id = detail_id or outbound.latest_detail_id() or ""
        rest = outbound.rest_of(detail_id)
        if not rest:
            self.send("Nothing more to show.")
            return
        for chunk in outbound.chunks(rest):
            self.send(chunk)

    def new_thread(self) -> None:
        project = projects.current(self.chat_id)
        if not project:
            self.send("Pick a project first: /p <name>")
            return
        runner.reset_thread(project)
        self.send(f"New thread in {projects.display_name(project)}.")

    # ── approvals ────────────────────────────────────────────────────────────

    def _live_thread(self) -> tuple[str | None, str | None]:
        project = projects.current(self.chat_id)
        if not project:
            return None, None
        thread = runner.thread_for(project, rotate=False)
        return project, (thread or {}).get("thread_id")

    def announce(self, record: dict) -> None:
        """Show the user exactly what the gate recorded, never the model's version.
        The request text is not scrubbed: approving an action whose recipient or
        target is hidden would be approving blind."""
        if record.get("truncated") and record.get("full_text"):
            for chunk in outbound.chunks("Full request:\n" + str(record["full_text"])):
                self.send(chunk)
        content = tiers.reveal_invisible(
            change_preview(record.get("tool", ""), record.get("input") or {}))
        if content:
            for chunk in outbound.chunks(content):
                self.send(chunk)
        minutes = max(1, math.ceil((float(record.get("expires_at", 0)) - time.time()) / 60))
        pid = record["pending_id"]
        self.send(f"Needs your OK · {record.get('summary', '')} · reply OK {record['code']} "
                  f"(expires in {minutes} min)",
                  keyboard([[("Approve", f"ok:{pid}"), ("Reject", f"no:{pid}")]]))

    def approve_code(self, code: str) -> None:
        code = code.strip().upper()
        project, thread_id = self._live_thread()
        record = pending.approve(code, thread_id) if CODE.match(code) and thread_id else None
        if not record:
            self.send(f"Code {code} is unknown, already used, expired, or belongs to "
                      "another thread. Nothing ran.")
            return
        self.send(f"Approved: {record.get('summary', '')}. Running it now.")
        self.enqueue(("approved", record["pending_id"], project, thread_id), "approved action")

    def approve_button(self, pending_id: str) -> None:
        record = pending.get(pending_id)
        if not record or not record.get("code"):
            self.send("That request is no longer open. Nothing ran.")
            return
        self.approve_code(str(record["code"]))

    def reject_code(self, code: str) -> None:
        pending.reject(code.strip().upper())
        self.send("Rejected. Nothing ran.")

    def reject_button(self, pending_id: str) -> None:
        record = pending.get(pending_id)
        if record and record.get("code"):
            pending.reject(str(record["code"]))
        self.send("Rejected. Nothing ran.")

    # ── the worker: one query at a time ──────────────────────────────────────

    def enqueue(self, job: tuple, label: str) -> None:
        if self.busy["what"]:
            mins = int((time.time() - self.busy["since"]) / 60)
            self.send(f"Still working on “{self.busy['what']}” ({mins} min). Yours is queued "
                      f"({self.jobs.qsize() + 1} waiting). /cancel stops it.")
        self.jobs.put((job, label[:60]))

    def drain(self) -> None:
        """Run every queued job in the calling thread (tests, and shutdown)."""
        while True:
            try:
                job, label = self.jobs.get_nowait()
            except queue.Empty:
                return
            self._run_job(job, label)

    def _worker(self) -> None:
        while not self.stop.is_set():
            try:
                job, label = self.jobs.get(timeout=1)
            except queue.Empty:
                continue
            self._run_job(job, label)

    def _run_job(self, job: tuple, label: str) -> None:
        self.busy.update(what=label, since=time.time())
        threading.Thread(target=self._typing, daemon=True).start()
        try:
            kind = job[0]
            if kind == "ask":
                self._ask(job[1], job[2])
            elif kind == "approved":
                _, pending_id, project, thread_id = job
                self._deliver(runner.run(runner.APPROVED_PROMPT.format(pending_id=pending_id),
                                         project, thread_id=thread_id), project)
            elif kind == "voice":
                self._voice(job[1])
            elif kind == "recall":
                self._recall(job[1])
        except Exception as e:                          # the loop must survive
            log.exception("job failed")
            self.send(f"Something failed: {outbound.scrub(repr(e))[:200]}")
        finally:
            self.busy.update(what=None, since=0.0)
            try:
                self.jobs.task_done()
            except ValueError:
                pass

    def _typing(self) -> None:
        while self.busy["what"] and not self.stop.is_set():
            try:
                self.bot.send_chat_action(self.chat_id)
            except Exception:
                return
            self.stop.wait(4)

    def _ask(self, text: str, project: str) -> None:
        self._deliver(runner.run(text, project), project)

    def _voice(self, voice: dict) -> None:
        module = voice_module()
        if module is None:
            self.send("Voice notes are not enabled on this computer. Please type it.")
            return
        path = os.path.join(config.state_dir("inbox"), f"voice-{int(time.time() * 1000)}.oga")
        try:
            self.bot.download(voice.get("file_id", ""), path)
            heard = (module.transcribe(path) or "").strip()
        except Exception as e:
            self.send(f"Could not transcribe the voice note: {outbound.scrub(str(e))[:150]}")
            return
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
        if not heard:
            self.send("I could not make out any words in that note.")
            return
        self.send(f"Heard: “{heard}”")
        project = projects.current(self.chat_id)
        if not project:
            self.send("Pick a project first: /p <name>")
            return
        self._ask(heard, project)

    # ── extras: session search, charts, voice replies ────────────────────────

    def _recall(self, query: str) -> None:
        """Search past sessions directly — no model involved, so nothing here
        can be steered by what the transcripts say."""
        try:
            from sancho import recall
            hits = recall.search(query, limit=5)
        except Exception as e:
            self.send(f"Session search failed: {outbound.scrub(str(e))[:150]}")
            return
        if not hits:
            self.send(f"No past session mentions “{query[:60]}”.")
            return
        lines = [f"{h.get('timestamp', '')[:10]} · {h.get('project', '')}\n{h.get('snippet', '')}"
                 for h in hits]
        self.reply("\n\n".join(lines))

    def _voice_flag(self) -> str:
        return os.path.join(config.state_dir(), "voice_replies")

    def voice_replies(self) -> bool:
        return os.path.exists(self._voice_flag())

    def set_voice_replies(self, arg: str) -> None:
        if arg == "on":
            module = voice_module_for("speak")
            if module is None:
                self.send("Spoken replies are not available on this computer "
                          "(local text-to-speech is not installed).")
                return
            open(self._voice_flag(), "w").close()
            self.send("Voice replies on. /voice off stops them.")
        elif arg == "off":
            try:
                os.remove(self._voice_flag())
            except OSError:
                pass
            self.send("Voice replies off.")
        else:
            self.send(f"Voice replies are {'on' if self.voice_replies() else 'off'}. "
                      "Use /voice on or /voice off.")

    def _send_charts(self, text: str) -> str:
        """Draw every chart block in the answer and send it as a photo; the
        block itself is replaced by a short marker in the text."""
        def draw(match: re.Match) -> str:
            try:
                import json
                from sancho import charts
                spec = json.loads(match.group(1))
                path = os.path.join(config.state_dir("charts"),
                                    f"chart-{int(time.time() * 1000)}.png")
                charts.render(spec, path)
                try:
                    self.bot.send_photo(self.chat_id, path)
                finally:
                    try:
                        os.remove(path)
                    except OSError:
                        pass
                return "[chart sent]"
            except Exception as e:
                return f"[chart could not be drawn: {str(e)[:120]}]"
        return CHART_BLOCK.sub(draw, text)

    def _speak(self, text: str) -> None:
        module = voice_module_for("speak")
        if module is None:
            return
        path = os.path.join(config.state_dir("outbox"), f"reply-{int(time.time() * 1000)}.ogg")
        try:
            module.speak(outbound.scrub(text), path)
            self.bot.send_voice(self.chat_id, path)
        except Exception as e:
            log.warning("voice reply failed: %s", e)
        finally:
            try:
                os.remove(path)
            except OSError:
                pass

    def _deliver(self, result: runner.Result, project: str) -> None:
        if result.alert:
            self.send(f"Heads-up: {result.daily_count} queries today. If that was not you, "
                      "stop the listener on the computer.")
        if result.error == "auth":
            if time.time() - self._last_auth_nag > AUTH_NAG_EVERY:
                self._last_auth_nag = time.time()
                self.send("Claude Code's sign-in has expired, so I cannot answer. On the "
                          "computer, run `claude setup-token` and update the .env file.")
            return
        if result.error == "timeout":
            self.send("That took too long and was stopped. Narrow the question and try again.")
            return
        if result.error == "cancelled":
            return
        if result.error == "thread-moved":
            self.send("That approval belongs to a thread that has ended. Nothing ran.")
            return
        if result.error:
            self.send(f"Could not complete: {outbound.scrub(result.error)[:300]}")
            return
        # Every call the gate held during this run is announced from the store,
        # not from the reply: the model may forget to repeat the marker, and a
        # marker it invents points at nothing. `result.held` only serves to strip
        # the marker lines from the text.
        announced = False
        for record in pending.list_for_thread(result.thread_id, since=result.started_at):
            self.announce(record)
            announced = True
        if result.text:
            text = self._send_charts(result.text)
            self.reply(f"[{projects.display_name(project)}]\n{text}")
            if self.voice_replies():
                self._speak(text)
        elif not announced:
            self.send(f"[{projects.display_name(project)}] Finished without any text.")

    # ── main loop ────────────────────────────────────────────────────────────

    def serve(self) -> None:
        try:
            self.bot.skip_backlog()
        except TelegramError as e:
            log.warning("could not skip the backlog: %s", e)
        worker = threading.Thread(target=self._worker, daemon=True)
        worker.start()
        self.send("Sancho is online. /help for commands.")
        while not self.stop.is_set():
            try:
                updates = self.bot.get_updates(timeout=25)
            except TelegramError as e:
                log.warning("getUpdates failed: %s", e)
                self.stop.wait(5)
                continue
            for update in updates:
                try:
                    self.handle_update(update)
                except Exception:
                    log.exception("update failed")
                    self.send("Something failed while handling that message.")
        runner.cancel()
        worker.join(timeout=10)


# ── process ──────────────────────────────────────────────────────────────────

_lock_handle = None


def single_instance() -> bool:
    """Hold an exclusive lock for the life of the process. Telegram hands each
    update to one poller only, so two listeners would steal each other's
    messages. The kernel releases the lock when the process dies, even on kill -9."""
    global _lock_handle
    handle = open(os.path.join(config.state_dir(), "listener.lock"), "a+")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return False
    handle.seek(0)
    handle.truncate()
    handle.write(str(os.getpid()))
    handle.flush()
    _lock_handle = handle
    return True


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    values = config.secrets()
    token, chat_id = values.get("TELEGRAM_BOT_TOKEN", ""), values.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        print("sancho: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set in .env",
              file=sys.stderr)
        return 2
    try:
        owner_id(chat_id)
    except ValueError as e:
        print(f"sancho: {e}", file=sys.stderr)
        return 2
    if not single_instance():
        print("sancho: another listener is already running", file=sys.stderr)
        return 1
    listener = Listener(Bot(token), chat_id)

    def shutdown(signum, _frame):
        log.info("signal %s: shutting down", signum)
        listener.stop.set()
        runner.cancel()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    listener.serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
