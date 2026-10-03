"""
Test plumbing. Every test gets a private HOME, config file and state directory,
so nothing ever reads or writes the real ~/.sancho, ~/.claude or the repo's .env.

Run the suite from the repository root:  python3 -m unittest discover -s tests
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from sancho import config  # noqa: E402


class SanchoTestCase(unittest.TestCase):
    """Isolated HOME + config + state dir, restored after each test."""

    config_data: dict = {}

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = os.path.realpath(self._tmp.name)
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self._saved_env = {k: os.environ.get(k) for k in
                           ("HOME", "SANCHO_CONFIG", "SANCHO_ENV_FILE")}
        os.environ["HOME"] = self.home
        os.environ["SANCHO_ENV_FILE"] = os.path.join(self.tmp, ".env")
        self.write_config(self.config_data)

    def tearDown(self) -> None:
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        config.reload()
        self._tmp.cleanup()

    def write_config(self, data: dict) -> None:
        data = json.loads(json.dumps(data))
        data.setdefault("sancho", {})["state_dir"] = os.path.join(self.tmp, "state")
        self.config_path = os.path.join(self.tmp, "config.json")
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.environ["SANCHO_CONFIG"] = self.config_path
        config.reload()

    def make_file(self, rel: str, text: str = "") -> str:
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def run_script(self, rel_script: str, stdin: str = "", *args: str,
                   env: dict | None = None) -> subprocess.CompletedProcess:
        """Run a repo script as a subprocess inside the isolated environment."""
        full_env = {**os.environ, **(env or {})}
        return subprocess.run([sys.executable, os.path.join(REPO, rel_script), *args],
                              input=stdin, capture_output=True, text=True,
                              env=full_env, timeout=60)
