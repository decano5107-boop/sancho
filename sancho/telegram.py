"""
A minimal Telegram Bot API client, standard library only.

Only what the assistant needs: long-polling `getUpdates` (outbound HTTPS only, no
webhook, no open port), text with inline keyboards, a few media uploads, callback
acknowledgements and file downloads.

The bot token is part of every request URL, so it is the one thing this module
must never print. Every error that leaves here passes through `_redact()`.
"""
from __future__ import annotations

import json
import logging
import mimetypes
import os
import secrets as _random
import urllib.error
import urllib.request
from typing import Any, Iterable

from sancho import config

log = logging.getLogger("sancho.telegram")

API_BASE = "https://api.telegram.org"
MAX_MESSAGE = 4096              # Bot API hard limit for one text message
MAX_DOWNLOAD = 20 * 1024 * 1024  # Bot API ceiling for getFile downloads
REQUEST_TIMEOUT = 30            # seconds, for everything except the long poll
UPLOAD_TIMEOUT = 120


class TelegramError(RuntimeError):
    """A Bot API call failed. The message never contains the token."""


def keyboard(rows: Iterable[Iterable[tuple[str, str]]]) -> dict:
    """Inline keyboard from rows of (label, callback_data) pairs."""
    return {"inline_keyboard": [[{"text": label, "callback_data": data}
                                 for label, data in row] for row in rows]}


def split_text(text: str, limit: int = MAX_MESSAGE) -> list[str]:
    """Cut text into pieces of at most `limit` characters, on line breaks when
    possible, hard-cutting only a single line that is longer than the limit."""
    text = text or ""
    if len(text) <= limit:
        return [text]
    pieces: list[str] = []
    current = ""
    for line in text.split("\n"):
        while len(line) > limit:
            if current:
                pieces.append(current)
                current = ""
            pieces.append(line[:limit])
            line = line[limit:]
        candidate = f"{current}\n{line}" if current else line
        if len(candidate) > limit:
            pieces.append(current)
            current = line
        else:
            current = candidate
    if current:
        pieces.append(current)
    return pieces


def offset_path() -> str:
    return os.path.join(config.state_dir(), "telegram_offset")


class Bot:
    def __init__(self, token: str, api_base: str = API_BASE) -> None:
        if not token:
            raise TelegramError("TELEGRAM_BOT_TOKEN is not set")
        self._token = token
        self._api = api_base.rstrip("/")
        # The numeric part before the colon is the bot's own user id (public).
        self.bot_id = token.split(":", 1)[0] if ":" in token else ""
        self.offset: int | None = self._load_offset()

    @classmethod
    def from_secrets(cls) -> "Bot":
        return cls(config.secrets().get("TELEGRAM_BOT_TOKEN", ""))

    # ── transport ────────────────────────────────────────────────────────────

    def _redact(self, text: str) -> str:
        return str(text).replace(self._token, "<token>")

    def _url(self, method: str) -> str:
        return f"{self._api}/bot{self._token}/{method}"

    def _open(self, request: urllib.request.Request, timeout: float) -> bytes:
        try:
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", "replace")[:300]
            except Exception:
                pass
            finally:
                e.close()
            raise TelegramError(self._redact(f"HTTP {e.code} on {request.get_method()}: "
                                             f"{body}")) from None
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise TelegramError(self._redact(f"network error: {e!r}")) from None

    def _decode(self, raw: bytes, method: str) -> Any:
        try:
            data = json.loads(raw.decode("utf-8"))
        except ValueError:
            raise TelegramError(f"{method}: response is not JSON") from None
        if not data.get("ok"):
            raise TelegramError(self._redact(
                f"{method}: {data.get('error_code')} {data.get('description', '')}"))
        return data.get("result")

    def call(self, method: str, params: dict | None = None,
             timeout: float = REQUEST_TIMEOUT) -> Any:
        """POST a JSON body to a Bot API method and return its `result`."""
        body = json.dumps(params or {}).encode("utf-8")
        req = urllib.request.Request(self._url(method), data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        return self._decode(self._open(req, timeout), method)

    def _upload(self, method: str, fields: dict, file_field: str, path: str,
                filename: str | None = None) -> Any:
        boundary = _random.token_hex(16)
        name = filename or os.path.basename(path)
        ctype = mimetypes.guess_type(name)[0] or "application/octet-stream"
        with open(path, "rb") as f:
            blob = f.read()
        parts: list[bytes] = []
        for key, value in fields.items():
            if value is None:
                continue
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"'
                         f"\r\n\r\n{value}\r\n".encode("utf-8"))
        safe_name = name.replace('"', "").replace("\r", "").replace("\n", "")
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; '
                     f'filename="{safe_name}"\r\nContent-Type: {ctype}\r\n\r\n'
                     .encode("utf-8"))
        parts.append(blob)
        parts.append(f"\r\n--{boundary}--\r\n".encode("utf-8"))
        req = urllib.request.Request(
            self._url(method), data=b"".join(parts), method="POST",
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        return self._decode(self._open(req, UPLOAD_TIMEOUT), method)

    # ── polling ──────────────────────────────────────────────────────────────

    @staticmethod
    def _load_offset() -> int | None:
        try:
            with open(offset_path(), encoding="utf-8") as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            return None

    def _save_offset(self, value: int) -> None:
        self.offset = value
        tmp = offset_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(str(value))
        os.replace(tmp, offset_path())

    def skip_backlog(self) -> None:
        """On a cold start (no stored offset), acknowledge whatever piled up while
        the assistant was down. A command sent hours ago is not a command now."""
        if self.offset is not None:
            return
        updates = self.call("getUpdates", {"timeout": 0}) or []
        ids = [u.get("update_id", 0) for u in updates]
        self._save_offset(max(ids) + 1 if ids else 0)

    def get_updates(self, timeout: int = 25) -> list[dict]:
        """Long-poll for new messages and button presses.

        The offset is persisted *before* the updates are handed back, so delivery
        is at-most-once: if the process dies while handling a message, that
        message is dropped rather than replayed on restart."""
        params: dict = {"timeout": timeout,
                        "allowed_updates": ["message", "callback_query"]}
        if self.offset is not None:
            params["offset"] = self.offset
        updates = self.call("getUpdates", params, timeout=timeout + 15) or []
        if updates:
            self._save_offset(max(u.get("update_id", 0) for u in updates) + 1)
        return updates

    # ── sending ──────────────────────────────────────────────────────────────

    def send_message(self, chat_id: str | int, text: str,
                     reply_markup: dict | None = None) -> list[Any]:
        """Plain text, split into 4096-character messages. The keyboard, if any,
        rides on the last piece so it sits under the end of the answer."""
        pieces = split_text(text or "(empty)")
        results = []
        for i, piece in enumerate(pieces):
            params: dict = {"chat_id": chat_id, "text": piece,
                            "link_preview_options": {"is_disabled": True}}
            if reply_markup and i == len(pieces) - 1:
                params["reply_markup"] = reply_markup
            results.append(self.call("sendMessage", params))
        return results

    def send_photo(self, chat_id, path: str, caption: str | None = None) -> Any:
        return self._upload("sendPhoto", {"chat_id": chat_id, "caption": caption},
                            "photo", path)

    def send_document(self, chat_id, path: str, caption: str | None = None) -> Any:
        return self._upload("sendDocument", {"chat_id": chat_id, "caption": caption},
                            "document", path)

    def send_voice(self, chat_id, path: str, caption: str | None = None) -> Any:
        """OGG/Opus voice note."""
        return self._upload("sendVoice", {"chat_id": chat_id, "caption": caption},
                            "voice", path)

    def send_audio(self, chat_id, path: str, caption: str | None = None) -> Any:
        """MP3/M4A audio file."""
        return self._upload("sendAudio", {"chat_id": chat_id, "caption": caption},
                            "audio", path)

    def send_chat_action(self, chat_id, action: str = "typing") -> Any:
        return self.call("sendChatAction", {"chat_id": chat_id, "action": action})

    def answer_callback(self, callback_id: str, text: str | None = None) -> Any:
        params: dict = {"callback_query_id": callback_id}
        if text:
            params["text"] = text[:200]
        return self.call("answerCallbackQuery", params)

    # ── files ────────────────────────────────────────────────────────────────

    def download(self, file_id: str, dest: str, max_bytes: int = MAX_DOWNLOAD) -> str:
        """Fetch a file the user sent into `dest`. The destination is chosen by
        the caller, never by the sender's file name."""
        meta = self.call("getFile", {"file_id": file_id}) or {}
        remote = meta.get("file_path") or ""
        if not remote:
            raise TelegramError("getFile returned no file_path")
        if int(meta.get("file_size") or 0) > max_bytes:
            raise TelegramError("file is larger than the download limit")
        req = urllib.request.Request(f"{self._api}/file/bot{self._token}/{remote}")
        blob = self._open(req, UPLOAD_TIMEOUT)
        if len(blob) > max_bytes:
            raise TelegramError("file is larger than the download limit")
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        with open(dest, "wb") as f:
            f.write(blob)
        return dest
