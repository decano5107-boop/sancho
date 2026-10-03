"""Recall: what gets indexed, what never does, and what a search returns."""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import time

from helpers import REPO, SanchoTestCase

from sancho import recall


def turn(role: str, content, ts: str = "2025-01-10T09:00:00.000Z",
         cwd: str = "/work/demo", session: str = "s1") -> str:
    return json.dumps({"type": role, "timestamp": ts, "cwd": cwd, "sessionId": session,
                       "message": {"role": role, "content": content}})


class RecallTestCase(SanchoTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.root = os.path.join(self.home, ".claude", "projects")

    def transcript(self, folder: str, name: str, lines: list[str]) -> str:
        path = os.path.join(self.root, folder, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return path

    def rows(self) -> int:
        con = sqlite3.connect(recall.db_path())
        try:
            return con.execute("SELECT count(*) FROM turns").fetchone()[0]
        finally:
            con.close()


class Search(RecallTestCase):
    def test_finds_a_turn_with_session_project_timestamp_and_snippet(self):
        self.transcript("-work-demo", "abc.jsonl", [
            json.dumps({"type": "custom-title", "customTitle": "Router rewrite"}),
            turn("user", "we need to fix the message router before the demo", session="abc"),
        ])
        hits = recall.search("message router")
        self.assertEqual(len(hits), 1)
        h = hits[0]
        self.assertEqual(h["session"], "abc")
        self.assertEqual(h["project"], "demo")
        self.assertEqual(h["timestamp"], "2025-01-10T09:00:00.000Z")
        self.assertEqual(h["title"], "Router rewrite")
        self.assertIn("router", h["snippet"])
        self.assertEqual(set(h), {"session", "project", "timestamp", "title", "snippet"})

    def test_results_never_carry_a_transcript_path(self):
        self.transcript("-work-demo", "s1.jsonl", [turn("user", "talking about the lighthouse")])
        for h in recall.search("lighthouse"):
            self.assertNotIn(".jsonl", json.dumps(h))

    def test_snippet_is_short_even_for_a_huge_turn(self):
        body = "filler " * 3000 + "the keyword is butterfly " + "filler " * 3000
        self.transcript("-work-demo", "s1.jsonl", [turn("assistant", body)])
        h = recall.search("butterfly")[0]
        self.assertLess(len(h["snippet"]), 300)
        self.assertIn("butterfly", h["snippet"])

    def test_all_terms_first_newest_first(self):
        self.transcript("-work-demo", "s1.jsonl", [
            turn("user", "first talk about the database migration", ts="2025-01-01T00:00:00Z"),
            turn("user", "second talk about the database migration", ts="2025-03-01T00:00:00Z"),
            turn("user", "only the database, nothing else here", ts="2025-06-01T00:00:00Z"),
        ])
        hits = recall.search("database migration")
        self.assertEqual([h["timestamp"][:10] for h in hits], ["2025-03-01", "2025-01-01"])

    def test_falls_back_to_any_term(self):
        self.transcript("-work-demo", "s1.jsonl", [turn("user", "notes on the kangaroo exhibit")])
        self.assertEqual(len(recall.search("kangaroo platypus")), 1)

    def test_limit_and_project_filter(self):
        for proj in ("alpha", "beta"):
            self.transcript(f"-work-{proj}", "s.jsonl", [
                turn("user", f"shared topic number {i} about the pipeline", cwd=f"/work/{proj}",
                     ts=f"2025-01-0{i + 1}T00:00:00Z") for i in range(4)])
        self.assertEqual(len(recall.search("pipeline", limit=3)), 3)
        hits = recall.search("pipeline", limit=10, project="Beta")
        self.assertEqual({h["project"] for h in hits}, {"beta"})
        self.assertEqual(len(hits), 4)

    def test_project_roots_give_the_project_not_the_subfolder(self):
        self.write_config({"recall": {"project_roots": ["/work"]}})
        self.transcript("-work-demo-docs", "s.jsonl",
                        [turn("user", "editing the architecture notes", cwd="/work/demo/docs/sub")])
        self.assertEqual(recall.search("architecture")[0]["project"], "demo")

    def test_fts_syntax_in_the_query_does_not_crash(self):
        self.transcript("-work-demo", "s.jsonl", [turn("user", "the quarterly report is ready")])
        for q in ('report"', "report AND", "NOT", "(report", "report*", "' OR 1=1 --"):
            self.assertIsInstance(recall.search(q), list, q)
        self.assertEqual(recall.search(""), [])

    def test_no_hits_is_an_empty_list(self):
        self.transcript("-work-demo", "s.jsonl", [turn("user", "nothing special here today")])
        self.assertEqual(recall.search("supercalifragilistic"), [])

    def test_missing_transcripts_root_is_not_an_error(self):
        self.assertEqual(recall.search("anything"), [])


class WhatGetsIndexed(RecallTestCase):
    def test_only_spoken_text_is_indexed(self):
        self.transcript("-work-demo", "s.jsonl", [
            turn("assistant", [
                {"type": "thinking", "thinking": "private reasoning about zebras"},
                {"type": "text", "text": "the answer mentions giraffes clearly"},
                {"type": "tool_use", "name": "Bash", "input": {"command": "ls zebras"}},
            ]),
            turn("user", [{"type": "tool_result", "content": "zebras.txt output listing"}]),
            turn("user", "<system-reminder> harness notice about pelicans </system-reminder>"),
            turn("user", "ok"),
        ])
        self.assertEqual(len(recall.search("giraffes")), 1)
        self.assertEqual(recall.search("zebras"), [])
        self.assertEqual(recall.search("pelicans"), [])
        self.assertEqual(self.rows(), 1)

    def test_a_corrupt_line_does_not_sink_the_file(self):
        self.transcript("-work-demo", "s.jsonl", [
            "{not json", "[1, 2]", turn("user", "the valid line about orchids survives")])
        self.assertEqual(len(recall.search("orchids")), 1)

    def test_markup_is_stripped_from_snippets(self):
        body = ("word " * 30) + "## Heading with `code` and **bold marker cut " + ("word " * 80)
        self.transcript("-work-demo", "s.jsonl", [turn("user", body + " <thinking> gecko")])
        snippet = recall.search("heading")[0]["snippet"]
        for marker in ("**", "`", "##"):
            self.assertNotIn(marker, snippet)


class Incremental(RecallTestCase):
    def test_unchanged_files_are_not_reread(self):
        self.transcript("-work-demo", "a.jsonl", [turn("user", "alpha file about tulips")])
        self.transcript("-work-demo", "b.jsonl", [turn("user", "beta file about roses")])
        first = recall.index()
        self.assertEqual((first["indexed"], first["unchanged"]), (2, 0))
        second = recall.index()
        self.assertEqual((second["indexed"], second["unchanged"]), (0, 2))
        self.assertEqual(second["turns"], 2)

    def test_a_changed_file_is_reindexed_without_duplicates(self):
        path = self.transcript("-work-demo", "a.jsonl", [turn("user", "first version about tulips")])
        recall.index()
        with open(path, "a", encoding="utf-8") as f:
            f.write(turn("user", "appended later about daffodils") + "\n")
        later = time.time() + 5
        os.utime(path, (later, later))
        stats = recall.index()
        self.assertEqual(stats["indexed"], 1)
        self.assertEqual(self.rows(), 2)
        self.assertEqual(len(recall.search("tulips")), 1)
        self.assertEqual(len(recall.search("daffodils")), 1)

    def test_deleted_files_leave_the_index(self):
        path = self.transcript("-work-demo", "a.jsonl", [turn("user", "ephemeral note on comets")])
        recall.index()
        os.remove(path)
        self.assertEqual(recall.index()["removed"], 1)
        self.assertEqual(recall.search("comets"), [])
        self.assertEqual(self.rows(), 0)

    def test_the_database_lives_in_the_state_dir(self):
        recall.index()
        self.assertTrue(recall.db_path().startswith(os.path.join(self.tmp, "state")))
        self.assertTrue(os.path.exists(recall.db_path()))


class ExcludeGlobs(RecallTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.transcript("-work-project", "s.jsonl",
                        [turn("user", "bug report about the parser", cwd="/work/project")])
        self.transcript("-work-demo", "s.jsonl",
                        [turn("user", "bug report about the parser")])

    def test_default_indexes_everything(self):
        self.assertEqual(len(recall.search("parser report", limit=10)), 2)

    def test_excluded_folders_are_never_indexed(self):
        self.write_config({"recall": {"exclude_globs": ["*work-project*"]}})
        hits = recall.search("parser report", limit=10)
        self.assertEqual([h["project"] for h in hits], ["demo"])
        con = sqlite3.connect(recall.db_path())
        try:
            paths = [p for (p,) in con.execute("SELECT path FROM turns")]
        finally:
            con.close()
        self.assertFalse(any("work-project" in p for p in paths))

    def test_a_glob_added_later_purges_and_hides_at_once(self):
        self.assertEqual(len(recall.search("parser report", limit=10)), 2)
        self.write_config({"recall": {"exclude_globs": ["-work-project/*"]}})
        # Even before a refresh, search filters by the same globs.
        hits = recall.search("parser report", limit=10, refresh=False)
        self.assertEqual([h["project"] for h in hits], ["demo"])
        self.assertEqual(recall.index()["removed"], 1)
        self.assertEqual(self.rows(), 1)

    def test_turns_whose_cwd_is_excluded_are_skipped_anywhere(self):
        self.transcript("-work-general", "s.jsonl", [
            turn("user", "sensitive llama discussion", cwd="/private/vault"),
            turn("user", "harmless llama discussion", cwd="/work/general"),
        ])
        self.write_config({"recall": {"exclude_globs": ["/private/vault*"]}})
        hits = recall.search("llama", limit=10)
        self.assertEqual(len(hits), 1)
        self.assertIn("harmless", hits[0]["snippet"])

    def test_tilde_globs_expand(self):
        self.write_config({"recall": {"exclude_globs": ["~/.claude/projects/-work-demo/*"]}})
        hits = recall.search("parser report", limit=10)
        self.assertEqual([h["project"] for h in hits], ["project"])


class Redaction(RecallTestCase):
    def test_redact_patterns(self):
        cases = [
            ("write to jane.doe@example.com today", "[email]", "jane.doe"),
            ("call +1 555 010 0000 now", "[phone]", "010 0000"),
            ("call (555) 010-0000 now", "[phone]", "010-0000"),
            ("card 4111 1111 1111 1111 on file", "[card]", "1111"),
            ("Acme Bank card ending in 0000", "[card]", "0000"),
            ("masked 411111XXXXXX0000 here", "[card]", "XXXXXX"),
            ("customer id 123456789 opened", "[number]", "123456789"),
            ("key " + "sk-" + "abcdefghijklmnopqrstuvwxyz123456 leaked", "[secret]", "abcdefghij"),
        ]
        for text, marker, leaked in cases:
            out = recall.redact(text)
            self.assertIn(marker, out, text)
            self.assertNotIn(leaked, out, text)

    def test_ordinary_text_is_left_alone(self):
        for text in ("meeting on 2024-01-31 at 10:30", "version 3.11.2 released",
                     "we shipped 42 fixes in 2025", "two dates 2024-01-31 2024-02-01"):
            self.assertEqual(recall.redact(text), text)

    def test_pii_never_reaches_the_index_or_the_snippet(self):
        self.transcript("-work-demo", "s.jsonl", [turn(
            "user", "refund for jane.doe@example.com card 4111 1111 1111 1111 "
                    "phone +1 555 010 0000 account 98765432 at Acme Bank")])
        hits = recall.search("refund")
        snippet = hits[0]["snippet"]
        for leaked in ("jane.doe", "4111", "555 010", "98765432"):
            self.assertNotIn(leaked, snippet)
        self.assertIn("Acme Bank", snippet)
        con = sqlite3.connect(recall.db_path())
        try:
            stored = " ".join(b for (b,) in con.execute("SELECT body FROM turns"))
        finally:
            con.close()
        for leaked in ("jane.doe", "4111", "98765432"):
            self.assertNotIn(leaked, stored)
        self.assertEqual(recall.search("98765432"), [])

    def test_titles_are_redacted_too(self):
        self.transcript("-work-demo", "s.jsonl", [
            json.dumps({"type": "custom-title", "customTitle": "Mail to jane.doe@example.com"}),
            turn("user", "drafting the onboarding letter")])
        self.assertEqual(recall.search("onboarding")[0]["title"], "Mail to [email]")


class Cli(RecallTestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-m", "sancho.recall", *args],
                              cwd=REPO, capture_output=True, text=True, timeout=60,
                              env=dict(os.environ))

    def test_cli_search_and_index(self):
        self.transcript("-work-demo", "s.jsonl", [turn("user", "the observatory telescope plan")])
        p = self.run_cli("telescope")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("demo", p.stdout)
        self.assertIn("telescope", p.stdout)
        p = self.run_cli("--index")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("1 turns indexed", p.stdout)
        p = self.run_cli("nonexistentword")
        self.assertIn("Nothing about", p.stdout)
        self.assertEqual(self.run_cli().returncode, 2)


if __name__ == "__main__":
    import unittest
    unittest.main()
