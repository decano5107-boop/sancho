"""Voice: availability reporting and the ffmpeg/engine plumbing, with every
engine and every subprocess mocked. No model is ever loaded here."""
from __future__ import annotations

import os
import subprocess
import sys
import types
import wave
from unittest import mock

from helpers import SanchoTestCase

from sancho import voice


def fake_find_spec(present: set[str]):
    def find_spec(name, *args, **kwargs):
        return object() if name in present else None
    return find_spec


class FakeFfmpeg:
    """Stands in for subprocess.run: records calls and creates the output file."""

    def __init__(self, returncode: int = 0, stderr: str = ""):
        self.calls: list[list[str]] = []
        self.returncode = returncode
        self.stderr = stderr

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        if self.returncode == 0:
            with open(cmd[-1], "wb") as f:
                f.write(b"audio")
        return subprocess.CompletedProcess(cmd, self.returncode, "", self.stderr)


class Available(SanchoTestCase):
    def test_nothing_installed(self):
        with mock.patch("importlib.util.find_spec", fake_find_spec(set())), \
             mock.patch("shutil.which", return_value=None):
            a = voice.available()
        self.assertEqual((a["transcribe"], a["speak"], a["ffmpeg"]), (False, False, False))
        self.assertEqual(len(a["missing"]), 3)

    def test_each_half_needs_its_engine_and_ffmpeg(self):
        with mock.patch("importlib.util.find_spec", fake_find_spec({"mlx_whisper"})), \
             mock.patch("shutil.which", return_value="/usr/bin/ffmpeg"):
            a = voice.available()
        self.assertTrue(a["transcribe"])
        self.assertFalse(a["speak"])
        self.assertEqual(a["missing"], ["pocket-tts (pip install pocket-tts)"])
        with mock.patch("importlib.util.find_spec", fake_find_spec({"mlx_whisper", "pocket_tts"})), \
             mock.patch("shutil.which", return_value=None):
            a = voice.available()
        self.assertEqual((a["transcribe"], a["speak"]), (False, False))

    def test_missing_engine_raises_a_clear_error(self):
        audio = self.make_file("note.ogg", "x")
        with mock.patch("importlib.util.find_spec", fake_find_spec(set())), \
             mock.patch("shutil.which", return_value="/usr/bin/ffmpeg"):
            with self.assertRaisesRegex(voice.VoiceUnavailable, "mlx-whisper"):
                voice.transcribe(audio)
            voice._tts_cache.clear()
            with self.assertRaisesRegex(voice.VoiceUnavailable, "pocket-tts"):
                voice.speak("hello there", os.path.join(self.tmp, "out.ogg"))

    def test_missing_ffmpeg_raises_before_any_model_loads(self):
        audio = self.make_file("note.ogg", "x")
        with mock.patch("shutil.which", return_value=None):
            with self.assertRaisesRegex(voice.VoiceUnavailable, "ffmpeg"):
                voice.transcribe(audio)
            with self.assertRaisesRegex(voice.VoiceUnavailable, "ffmpeg"):
                voice.speak("hello there", os.path.join(self.tmp, "out.ogg"))


class Transcribe(SanchoTestCase):
    config_data = {"voice": {"whisper_model": "example/tiny-model", "whisper_language": "en"}}

    def setUp(self) -> None:
        super().setUp()
        self.whisper = types.ModuleType("mlx_whisper")
        self.whisper.transcribe = mock.Mock(return_value={"text": "  hello from the phone  "})
        self.modules = mock.patch.dict(sys.modules, {"mlx_whisper": self.whisper})
        self.modules.start()
        self.addCleanup(self.modules.stop)

    def test_converts_with_ffmpeg_then_transcribes_with_the_configured_model(self):
        audio = self.make_file("note.ogg", "x")
        ffmpeg = FakeFfmpeg()
        with mock.patch("importlib.util.find_spec", fake_find_spec({"mlx_whisper"})), \
             mock.patch("shutil.which", return_value="/usr/bin/ffmpeg"), \
             mock.patch("subprocess.run", ffmpeg):
            text = voice.transcribe(audio)
        self.assertEqual(text, "hello from the phone")
        cmd = ffmpeg.calls[0]
        self.assertEqual(cmd[0], "/usr/bin/ffmpeg")
        self.assertIn(audio, cmd)
        self.assertEqual(cmd[cmd.index("-ar") + 1], "16000")
        self.assertEqual(cmd[cmd.index("-ac") + 1], "1")
        wav = cmd[-1]
        self.assertTrue(wav.endswith(".wav"))
        self.assertFalse(os.path.exists(wav), "temporary WAV is cleaned up")
        args, kwargs = self.whisper.transcribe.call_args
        self.assertEqual(args[0], wav)
        self.assertEqual(kwargs["path_or_hf_repo"], "example/tiny-model")
        self.assertEqual(kwargs["language"], "en")

    def test_ffmpeg_failure_is_reported(self):
        audio = self.make_file("note.ogg", "x")
        with mock.patch("importlib.util.find_spec", fake_find_spec({"mlx_whisper"})), \
             mock.patch("shutil.which", return_value="/usr/bin/ffmpeg"), \
             mock.patch("subprocess.run", FakeFfmpeg(returncode=1, stderr="Invalid data")):
            with self.assertRaisesRegex(RuntimeError, "Invalid data"):
                voice.transcribe(audio)
        self.whisper.transcribe.assert_not_called()

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            voice.transcribe(os.path.join(self.tmp, "nope.ogg"))


class Speak(SanchoTestCase):
    def setUp(self) -> None:
        super().setUp()
        voice._tts_cache.clear()
        self.addCleanup(voice._tts_cache.clear)
        self.model = mock.Mock()
        self.model.sample_rate = 24000
        self.model.get_state_for_audio_prompt.return_value = "voice-state"
        self.model.generate_audio.return_value = [0.0, 0.5, -0.5, 1.5]
        self.tts = types.ModuleType("pocket_tts")
        self.tts.TTSModel = mock.Mock()
        self.tts.TTSModel.load_model.return_value = self.model
        self.modules = mock.patch.dict(sys.modules, {"pocket_tts": self.tts})
        self.modules.start()
        self.addCleanup(self.modules.stop)
        self.wav_seen: dict = {}

    def ffmpeg(self):
        fake = FakeFfmpeg()
        outer = self

        def run(cmd, **kwargs):
            wav = cmd[cmd.index("-i") + 1]
            with wave.open(wav, "rb") as w:
                outer.wav_seen = {"rate": w.getframerate(), "frames": w.getnframes(),
                                  "channels": w.getnchannels()}
            return fake(cmd, **kwargs)
        run.calls = fake.calls
        return run

    def patches(self, run):
        return (mock.patch("importlib.util.find_spec", fake_find_spec({"pocket_tts"})),
                mock.patch("shutil.which", return_value="/usr/bin/ffmpeg"),
                mock.patch("subprocess.run", run))

    def test_defaults_voice_and_language_and_encodes_opus(self):
        out = os.path.join(self.tmp, "replies", "reply.ogg")
        run = self.ffmpeg()
        p1, p2, p3 = self.patches(run)
        with p1, p2, p3:
            self.assertEqual(voice.speak("The build **passed**. See `make test`.", out), out)
        self.tts.TTSModel.load_model.assert_called_once_with(language="english")
        self.model.get_state_for_audio_prompt.assert_called_once_with("alba")
        spoken = self.model.generate_audio.call_args[0][1]
        self.assertEqual(spoken, "The build passed. See make test.")
        cmd = run.calls[0]
        self.assertEqual(cmd[-1], out)
        self.assertEqual(cmd[cmd.index("-c:a") + 1], "libopus")
        self.assertEqual(self.wav_seen, {"rate": 24000, "frames": 4, "channels": 1})
        self.assertTrue(os.path.exists(out))

    def test_configured_voice_and_language(self):
        self.write_config({"voice": {"tts_voice": "narrator", "tts_language": "french"}})
        p1, p2, p3 = self.patches(self.ffmpeg())
        with p1, p2, p3:
            voice.speak("Bonjour tout le monde", os.path.join(self.tmp, "o.ogg"))
        self.tts.TTSModel.load_model.assert_called_once_with(language="french")
        self.model.get_state_for_audio_prompt.assert_called_once_with("narrator")

    def test_model_is_loaded_once(self):
        p1, p2, p3 = self.patches(self.ffmpeg())
        with p1, p2, p3:
            voice.speak("first message here", os.path.join(self.tmp, "a.ogg"))
            voice.speak("second message here", os.path.join(self.tmp, "b.ogg"))
        self.assertEqual(self.tts.TTSModel.load_model.call_count, 1)

    def test_nothing_speakable_is_an_error(self):
        with mock.patch("shutil.which", return_value="/usr/bin/ffmpeg"):
            with self.assertRaises(ValueError):
                voice.speak("```\nprint('only code')\n```", os.path.join(self.tmp, "o.ogg"))


class Speakable(SanchoTestCase):
    def test_strips_what_cannot_be_read_aloud(self):
        text = ("# Status\nDone, see [the report](https://example.com/r) and "
                "`~/work/project/notes.md`.\n```bash\nls -la\n```\n**Next**: deploy")
        out = voice.speakable(text)
        for gone in ("#", "**", "```", "ls -la", "https://", "notes.md"):
            self.assertNotIn(gone, out)
        self.assertIn("the report", out)
        self.assertIn("a file path", out)
        self.assertIn("Next", out)

    def test_long_text_is_cut_at_a_sentence(self):
        out = voice.speakable("This is a sentence. " * 200, max_chars=100)
        self.assertLessEqual(len(out), 100)
        self.assertTrue(out.endswith("."))


class Offline(SanchoTestCase):
    config_data = {"voice": {"offline": True}}

    def test_offline_flag_sets_hub_offline_before_import(self):
        saved = os.environ.pop("HF_HUB_OFFLINE", None)
        self.addCleanup(lambda: os.environ.__setitem__("HF_HUB_OFFLINE", saved)
                        if saved is not None else os.environ.pop("HF_HUB_OFFLINE", None))
        with mock.patch("importlib.util.find_spec", fake_find_spec(set())):
            with self.assertRaises(voice.VoiceUnavailable):
                voice._require("mlx_whisper", "mlx-whisper")
        self.assertEqual(os.environ.get("HF_HUB_OFFLINE"), "1")


class Cli(SanchoTestCase):
    def test_status_runs_without_any_engine(self):
        with mock.patch("importlib.util.find_spec", fake_find_spec(set())), \
             mock.patch("shutil.which", return_value=None), \
             mock.patch("builtins.print") as printed:
            self.assertEqual(voice.main(["status"]), 0)
        self.assertIn("transcribe: no", printed.call_args_list[0][0][0])


if __name__ == "__main__":
    import unittest
    unittest.main()
