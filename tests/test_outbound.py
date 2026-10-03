"""Outbound contract: scrub, detable, plain text, the line cut, /more, chunks.
All personal data below is synthetic (reserved example domains, 555 numbers,
published test card numbers)."""
from __future__ import annotations

import os

from helpers import SanchoTestCase

from sancho import outbound


class Scrub(SanchoTestCase):
    def test_emails(self):
        self.assertEqual(outbound.scrub("write to jane.doe+x@example.com today"),
                         "write to [email] today")

    def test_phone_numbers(self):
        for raw in ("+1 415 555 0100", "+44 20 7946 0958", "(415) 555-0100", "415.555.0100"):
            self.assertEqual(outbound.scrub(f"call {raw} now"), "call [phone] now", raw)

    def test_card_numbers_need_a_valid_checksum(self):
        self.assertEqual(outbound.scrub("card 4111 1111 1111 1111 ok"), "card [card] ok")
        self.assertEqual(outbound.scrub("card 5500-0000-0000-0004"), "card [card]")
        # 16 digits failing the Luhn check are still a long id, never left bare
        self.assertEqual(outbound.scrub("ref 1234567812345678"), "ref [id]")

    def test_long_digit_ids(self):
        self.assertEqual(outbound.scrub("account 12345678 and 1234567"),
                         "account [id] and 1234567")

    def test_ordinary_numbers_survive(self):
        text = "On 2026-01-15 at 10:30, 42 files, v2.1.3, 95.5% done, cost $1,250"
        self.assertEqual(outbound.scrub(text), text)

    def test_extra_patterns_from_config(self):
        self.write_config({"outbound": {"scrub_patterns": [r"\bCUST-\d+\b", "([bad"]}})
        self.assertEqual(outbound.scrub("see CUST-991 please"), "see [redacted] please")


class Detable(SanchoTestCase):
    def test_two_columns(self):
        md = "| Name | State |\n|---|---|\n| alpha | done |\n| beta | open |"
        self.assertEqual(outbound.detable(md), "• alpha — done\n• beta — open")

    def test_three_columns_carry_the_header(self):
        md = "| Item | Owner | Due |\n| :-- | :--: | --: |\n| docs | ana | Fri |"
        self.assertEqual(outbound.detable(md), "• docs — Owner: ana · Due: Fri")

    def test_text_around_a_table_is_kept(self):
        md = "Summary first.\n\n| a | b |\n|---|---|\n| 1 | 2 |\n\nAfter."
        self.assertEqual(outbound.detable(md), "Summary first.\n\n• 1 — 2\n\nAfter.")


class Plain(SanchoTestCase):
    def test_markdown_symbols_are_removed(self):
        md = "## Result\n**Done**: three files\n- one\n```\ncode\n```"
        self.assertEqual(outbound.plain(md), "Result\nDone: three files\n• one\ncode")


class LengthContract(SanchoTestCase):
    def test_short_answers_go_out_whole(self):
        reply = outbound.prepare("one\ntwo\nthree")
        self.assertEqual(reply.head, "one\ntwo\nthree")
        self.assertIsNone(reply.detail_id)

    def test_long_answers_are_cut_and_stored(self):
        text = "\n".join(f"line {i}" for i in range(1, 26))
        reply = outbound.prepare(text)
        self.assertEqual(reply.head.split("\n")[:10], [f"line {i}" for i in range(1, 11)])
        self.assertTrue(reply.head.endswith("…"))
        path = os.path.join(outbound.detail_dir(), f"{reply.detail_id}.md")
        with open(path) as f:
            self.assertEqual(f.read(), text)
        self.assertEqual(outbound.rest_of(reply.detail_id),
                         "\n".join(f"line {i}" for i in range(11, 26)))
        self.assertEqual(outbound.latest_detail_id(), reply.detail_id)

    def test_the_stored_detail_is_scrubbed_too(self):
        text = "\n".join(["x"] * 12 + ["mail ops@example.org"])
        reply = outbound.prepare(text)
        self.assertEqual(outbound.rest_of(reply.detail_id), "x\nx\nmail [email]")

    def test_max_lines_is_configurable(self):
        self.write_config({"outbound": {"max_lines": 3}})
        reply = outbound.prepare("a\nb\nc\nd")
        self.assertEqual(reply.head, "a\nb\nc\n…")
        self.assertEqual(outbound.rest_of(reply.detail_id), "d")

    def test_rest_of_rejects_unknown_or_malformed_ids(self):
        self.assertIsNone(outbound.rest_of("../../etc/passwd"))
        self.assertIsNone(outbound.rest_of("abcdefabcdef"))
        self.assertIsNone(outbound.rest_of(""))

    def test_old_details_are_pruned(self):
        for _ in range(outbound.KEEP_DETAILS + 5):
            outbound.store_detail("x")
        files = [f for f in os.listdir(outbound.detail_dir()) if f.endswith(".md")]
        self.assertEqual(len(files), outbound.KEEP_DETAILS)


class Chunks(SanchoTestCase):
    def test_chunks_stay_under_the_limit(self):
        text = "\n".join("z" * 1000 for _ in range(10))
        parts = outbound.chunks(text)
        self.assertTrue(all(len(p) <= 4096 for p in parts))
        self.assertEqual("\n".join(parts), text)
