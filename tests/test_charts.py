"""Charts: strict spec validation (always runs) and rendering (only when
matplotlib is installed)."""
from __future__ import annotations

import contextlib
import copy
import io
import os
import struct
import unittest

from helpers import SanchoTestCase

from sancho import charts

GOOD = {"type": "bar", "title": "Tickets closed per week",
        "labels": ["W1", "W2", "W3"],
        "series": [{"name": "Team A", "values": [12, 18, 15.5]}]}


def spec(**changes):
    s = copy.deepcopy(GOOD)
    s.update(changes)
    return s


class Validation(unittest.TestCase):
    def test_a_good_spec_comes_back_clean(self):
        s = charts.validate(GOOD)
        self.assertEqual(s["type"], "bar")
        self.assertEqual(s["series"][0]["values"], [12.0, 18.0, 15.5])
        self.assertEqual(s["y_label"], "")

    def test_optional_keys(self):
        s = charts.validate(spec(x_label="week", y_label="tickets"))
        self.assertEqual((s["x_label"], s["y_label"]), ("week", "tickets"))
        s = charts.validate({"type": "line", "labels": ["a"], "series": [{"values": [1]}]})
        self.assertEqual(s["title"], "")
        self.assertEqual(s["series"][0]["name"], "")

    def test_rejects(self):
        bad = {
            "not an object": ["type", "bar"],
            "unknown key": spec(colors=["red"]),
            "missing series": {k: v for k, v in GOOD.items() if k != "series"},
            "unknown type": spec(type="scatter3d"),
            "type not a string": spec(type=["bar"]),
            "empty labels": spec(labels=[]),
            "labels not a list": spec(labels="W1,W2,W3"),
            "numeric label": spec(labels=["W1", 2, "W3"]),
            "blank label": spec(labels=["W1", "  ", "W3"]),
            "label too long": spec(labels=["W1", "x" * 41, "W3"]),
            "title too long": spec(title="t" * 101),
            "title not text": spec(title=42),
            "empty series": spec(series=[]),
            "series not dicts": spec(series=["Team A"]),
            "series unknown key": spec(series=[{"values": [1, 2, 3], "color": "red"}]),
            "values missing": spec(series=[{"name": "A"}]),
            "values a string": spec(series=[{"values": "123"}]),
            "too few values": spec(series=[{"values": [1, 2]}]),
            "too many values": spec(series=[{"values": [1, 2, 3, 4]}]),
            "string value": spec(series=[{"values": [1, "2", 3]}]),
            "null value": spec(series=[{"values": [1, None, 3]}]),
            "bool value": spec(series=[{"values": [1, True, 3]}]),
            "nan value": spec(series=[{"values": [1, float("nan"), 3]}]),
            "inf value": spec(series=[{"values": [1, float("inf"), 3]}]),
            "too many series": spec(series=[{"values": [1, 2, 3]}] * 7),
            "too many labels": spec(labels=[f"L{i}" for i in range(51)],
                                    series=[{"values": list(range(51))}]),
            "pie with two series": spec(type="pie", series=[{"values": [1, 2, 3]}] * 2),
            "pie negative": spec(type="pie", series=[{"values": [1, -2, 3]}]),
            "pie all zero": spec(type="pie", series=[{"values": [0, 0, 0]}]),
            "pie too many slices": spec(type="pie", labels=[f"L{i}" for i in range(9)],
                                        series=[{"values": [1] * 9}]),
        }
        for name, s in bad.items():
            with self.subTest(name), self.assertRaises(ValueError):
                charts.validate(s)

    def test_text_is_data_never_code(self):
        s = charts.validate(spec(title="$(rm -rf ~); `curl example.invalid`"))
        self.assertEqual(s["title"], "$(rm -rf ~); `curl example.invalid`")

    def test_render_validates_before_needing_matplotlib(self):
        with self.assertRaises(ValueError):
            charts.render(spec(type="radar"), "unused.png")


class CliValidation(SanchoTestCase):
    def test_bad_json_and_bad_spec_exit_nonzero(self):
        out = os.path.join(self.tmp, "c.png")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(charts.main(["{not json", out]), 1)
            self.assertEqual(charts.main(['{"type": "radar"}', out]), 1)
            self.assertEqual(charts.main([]), 2)
        self.assertIn("not valid JSON", err.getvalue())
        self.assertFalse(os.path.exists(out))


def png_size(path: str) -> tuple[int, int]:
    with open(path, "rb") as f:
        head = f.read(24)
    assert head[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
    return struct.unpack(">II", head[16:24])


@unittest.skipUnless(charts.available(), "matplotlib not installed")
class Render(SanchoTestCase):
    def test_each_type_renders_a_1080px_png(self):
        specs = [
            GOOD,
            spec(type="line", series=[{"name": "A", "values": [1, 2, 3]},
                                      {"name": "B", "values": [3, 1, 2]}], y_label="count"),
            spec(type="pie", title="Share", series=[{"values": [50, 30, 20]}]),
            spec(labels=[f"Category {i}" for i in range(12)],
                 series=[{"name": "A", "values": list(range(12))},
                         {"name": "B", "values": list(range(12, 0, -1))}]),
        ]
        for i, s in enumerate(specs):
            with self.subTest(s["type"]):
                out = os.path.join(self.tmp, "out", f"chart{i}.png")
                self.assertEqual(charts.render(s, out), out)
                width, height = png_size(out)
                self.assertEqual(width, 1080)
                self.assertGreater(height, 500)

    def test_cli_renders(self):
        out = os.path.join(self.tmp, "cli.png")
        path = self.make_file("spec.json", '{"type": "bar", "labels": ["a", "b"], '
                                           '"series": [{"values": [1, 2]}]}')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(charts.main([path, out]), 0)
        self.assertEqual(png_size(out)[0], 1080)


class Unavailable(unittest.TestCase):
    def test_missing_matplotlib_is_a_clear_error(self):
        from unittest import mock
        with mock.patch.object(charts, "available", return_value=False):
            with self.assertRaisesRegex(charts.ChartsUnavailable, "pip install matplotlib"):
                charts.render(GOOD, "unused.png")


if __name__ == "__main__":
    unittest.main()
