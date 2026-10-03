"""
Voice notes in and out, processed on this Mac.

  transcribe(path) -> str       speech to text with Whisper, via `mlx-whisper`
                                (Apple-silicon native). Telegram voice notes
                                arrive as OGG/Opus; ffmpeg turns them into
                                16 kHz mono WAV first.
  speak(text, out_path) -> str  text to speech with Kyutai's Pocket TTS, then
                                ffmpeg to OGG/Opus, the format Telegram's
                                sendVoice plays inline as a voice note.
  available() -> dict           which halves work on this machine, and why not.

Both engines are optional dependencies, imported only when first used; without
them the rest of the application runs and these functions raise
`VoiceUnavailable` with an install hint.

What leaves the machine, precisely:

  * On first use each engine downloads its model weights from the Hugging Face
    Hub and caches them (by default under ~/.cache/huggingface).
  * After that, audio and text are processed locally; this module makes no
    network calls and sends no audio or text anywhere. The Hugging Face client
    library may still make a metadata-only request when a model loads, to check
    for a newer revision. Set "voice": {"offline": true} (or HF_HUB_OFFLINE=1 in
    the environment) to forbid even that once the models are cached.

Configuration (`config.json`, section "voice"; every key optional):

  whisper_model     "mlx-community/whisper-large-v3-turbo"
  whisper_language  ""          ISO code such as "en"; empty = auto-detect
  tts_language      "english"   Pocket TTS language
  tts_voice         "alba"      Pocket TTS voice name
  tts_max_chars     1200        longer text is cut (roughly 90 s of speech)
  offline           false       set HF_HUB_OFFLINE=1 before loading models

Install:
  pip install mlx-whisper          # transcription (Apple silicon)
  pip install pocket-tts           # speech
  brew install ffmpeg              # required by both halves
"""
from __future__ import annotations

import array
import importlib
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
import wave

from sancho import config

DEFAULT_WHISPER_MODEL = "mlx-community/whisper-large-v3-turbo"
FFMPEG_TIMEOUT = 120

_tts_cache: dict = {}


class VoiceUnavailable(RuntimeError):
    """A required engine or ffmpeg is not installed."""


# ── availability ─────────────────────────────────────────────────────────────

def _has_module(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _ffmpeg() -> str | None:
    return shutil.which("ffmpeg")


def available() -> dict:
    """{"transcribe": bool, "speak": bool, "ffmpeg": bool, "missing": [hints]}"""
    ffmpeg = _ffmpeg() is not None
    whisper = _has_module("mlx_whisper")
    tts = _has_module("pocket_tts")
    missing = []
    if not ffmpeg:
        missing.append("ffmpeg (brew install ffmpeg)")
    if not whisper:
        missing.append("mlx-whisper (pip install mlx-whisper)")
    if not tts:
        missing.append("pocket-tts (pip install pocket-tts)")
    return {"transcribe": ffmpeg and whisper, "speak": ffmpeg and tts,
            "ffmpeg": ffmpeg, "missing": missing}


def _require(module: str, package: str):
    if config.get("voice", "offline", False):
        os.environ.setdefault("HF_HUB_OFFLINE", "1")
    if not _has_module(module):
        raise VoiceUnavailable(f"{package} is not installed (pip install {package})")
    return importlib.import_module(module)


def _run_ffmpeg(args: list[str]) -> None:
    exe = _ffmpeg()
    if not exe:
        raise VoiceUnavailable("ffmpeg is not installed (brew install ffmpeg)")
    proc = subprocess.run([exe, "-v", "error", "-y", *args],
                          capture_output=True, text=True, timeout=FFMPEG_TIMEOUT)
    if proc.returncode != 0:
        raise RuntimeError(f"ffmpeg failed: {(proc.stderr or '').strip()[-300:]}")


# ── speech to text ───────────────────────────────────────────────────────────

def transcribe(path: str) -> str:
    """Text of an audio file (any format ffmpeg reads, e.g. Telegram OGG/Opus)."""
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    if not _ffmpeg():
        raise VoiceUnavailable("ffmpeg is not installed (brew install ffmpeg)")
    whisper = _require("mlx_whisper", "mlx-whisper")
    model = config.get("voice", "whisper_model", DEFAULT_WHISPER_MODEL) or DEFAULT_WHISPER_MODEL
    language = config.get("voice", "whisper_language", "") or None
    with tempfile.TemporaryDirectory(prefix="sancho-voice-") as tmp:
        wav = os.path.join(tmp, "input.wav")
        _run_ffmpeg(["-i", path, "-ar", "16000", "-ac", "1", wav])
        result = whisper.transcribe(wav, path_or_hf_repo=model, language=language)
    text = result.get("text", "") if isinstance(result, dict) else str(result or "")
    return text.strip()


# ── text to speech ───────────────────────────────────────────────────────────

def speakable(text: str, max_chars: int | None = None) -> str:
    """Text with what cannot be read aloud removed: code, markup, links, paths."""
    max_chars = max_chars or config.get("voice", "tts_max_chars", 1200)
    t = re.sub(r"```.*?```", " ", text or "", flags=re.S)
    t = re.sub(r"<[^>\n]{1,80}>", " ", t)
    t = re.sub(r"\[([^\]\n]+)\]\([^)\s]+\)", r"\1", t)   # [label](url) -> label
    t = re.sub(r"https?://\S+", " a link ", t)
    t = re.sub(r"`([^`\n]+)`", r"\1", t)
    t = re.sub(r"(?<!\w)[~.]?/[\w.\-]+(?:/[\w.\-]+)+", " a file path ", t)
    t = re.sub(r"(\*{1,3}|_{2,3})(?=\S)(.+?)(?<=\S)\1", r"\2", t)   # emphasis
    t = re.sub(r"[*#|>]+", " ", t)
    t = re.sub(r"[ \t]+([.,;:!?])", r"\1", t)
    t = re.sub(r"[\U0001F000-\U0001FAFF\u2600-\u27BF\uFE0F]", " ", t)
    t = re.sub(r"[ \t]{2,}", " ", t)
    t = re.sub(r"\n\s*\n+", "\n", t).strip()
    if len(t) > max_chars:
        cut = t[:max_chars]
        end = max(cut.rfind(". "), cut.rfind("\n"))
        t = cut[:end + 1] if end > max_chars // 2 else cut
    return t.strip()


def _tts_model(language: str):
    """Loaded once per language; loading is the slow part."""
    if language not in _tts_cache:
        pocket_tts = _require("pocket_tts", "pocket-tts")
        try:
            model = pocket_tts.TTSModel.load_model(language=language)
        except TypeError:
            # Releases without multilingual support take no `language` argument.
            if language != "english":
                raise VoiceUnavailable(
                    f"this pocket-tts release does not support language {language!r}")
            model = pocket_tts.TTSModel.load_model()
        _tts_cache[language] = model
    return _tts_cache[language]


def _write_wav(path: str, audio, sample_rate: int) -> None:
    """Float samples in [-1, 1] -> 16-bit mono WAV, using only the stdlib."""
    if hasattr(audio, "detach"):
        audio = audio.detach().cpu()
    if hasattr(audio, "numpy"):
        audio = audio.numpy()
    try:
        import numpy as np  # present whenever pocket-tts is
        frames = (np.clip(np.asarray(audio, dtype="float32").reshape(-1), -1.0, 1.0)
                  * 32767).astype("<i2").tobytes()
    except ImportError:
        pcm = array.array("h", (int(max(-1.0, min(1.0, float(s))) * 32767) for s in audio))
        if sys.byteorder != "little":
            pcm.byteswap()
        frames = pcm.tobytes()
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(int(sample_rate))
        w.writeframes(frames)


def speak(text: str, out_path: str) -> str:
    """Synthesize `text` into an OGG/Opus voice note at `out_path`; returns it."""
    script = speakable(text)
    if not script:
        raise ValueError("nothing left to say after removing unspeakable content")
    if not _ffmpeg():
        raise VoiceUnavailable("ffmpeg is not installed (brew install ffmpeg)")
    language = config.get("voice", "tts_language", "english") or "english"
    voice = config.get("voice", "tts_voice", "alba") or "alba"
    model = _tts_model(language)
    state = model.get_state_for_audio_prompt(voice)
    audio = model.generate_audio(state, script)
    out_dir = os.path.dirname(os.path.abspath(out_path))
    os.makedirs(out_dir, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sancho-voice-") as tmp:
        wav = os.path.join(tmp, "speech.wav")
        _write_wav(wav, audio, model.sample_rate)
        _run_ffmpeg(["-i", wav, "-c:a", "libopus", "-b:a", "32k",
                     "-ar", "48000", "-ac", "1", out_path])
    return out_path


# ── CLI ──────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    usage = ("usage: python3 -m sancho.voice status | transcribe FILE | "
             "speak OUT.ogg TEXT...")
    if not args or args[0] == "status":
        a = available()
        print(f"transcribe: {'yes' if a['transcribe'] else 'no'} · "
              f"speak: {'yes' if a['speak'] else 'no'}")
        for hint in a["missing"]:
            print(f"  missing: {hint}")
        return 0
    try:
        if args[0] == "transcribe" and len(args) == 2:
            print(transcribe(args[1]))
            return 0
        if args[0] == "speak" and len(args) >= 3:
            print(speak(" ".join(args[2:]), args[1]))
            return 0
    except (VoiceUnavailable, RuntimeError, ValueError, FileNotFoundError) as e:
        print(f"voice: {e}", file=sys.stderr)
        return 1
    print(usage, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
