"""
Charts from a small JSON spec, sized for reading on a phone.

The model never writes plotting code. It writes DATA — a spec like

    {"type": "bar",
     "title": "Tickets closed per week",
     "labels": ["W1", "W2", "W3"],
     "series": [{"name": "Team A", "values": [12, 18, 15]}],
     "y_label": "tickets"}

and `render(spec, out_path)` turns it into a PNG. The spec is validated
strictly: unknown keys, wrong types, non-finite numbers, mismatched lengths and
oversized inputs raise `ValueError` rather than being silently fixed, because a
chart that quietly shows something other than what was asked for is worse than
no chart. Text in the spec is only ever drawn, never evaluated.

Spec keys:
  type      "bar" | "line" | "pie"                          required
  labels    list of 1-50 strings (category / x-axis labels) required
  series    list of 1-6 {"name": str, "values": [numbers]}  required; each
            "values" has exactly len(labels) numbers. "pie" takes exactly one
            series of non-negative values, at most 8 slices.
  title     string, up to 100 characters                    optional
  x_label   string, up to 60 characters                     optional
  y_label   string, up to 60 characters                     optional

Output: 1080 px wide PNG, large fonts, drawn with the Okabe-Ito palette (a
neutral, colour-blind-safe set of eight colours) on a white background.

matplotlib is an optional dependency (pip install matplotlib), imported only
when a chart is drawn; `validate` works without it.

CLI: python3 -m sancho.charts SPEC.json|'{"type": ...}' OUT.png
"""
from __future__ import annotations

import importlib.util
import json
import math
import os
import sys

TYPES = ("bar", "line", "pie")
REQUIRED_KEYS = {"type", "labels", "series"}
OPTIONAL_KEYS = {"title", "x_label", "y_label"}
SERIES_KEYS = {"name", "values"}
MAX_LABELS = 50
MAX_SERIES = 6
MAX_PIE_SLICES = 8
MAX_TITLE = 100
MAX_AXIS_LABEL = 60
MAX_LABEL = 40
MAX_SERIES_NAME = 40

# Okabe & Ito (2008), ordered so the low-contrast yellow comes late.
PALETTE = ["#0072B2", "#E69F00", "#009E73", "#D55E00",
           "#56B4E9", "#CC79A7", "#F0E442", "#000000"]

WIDTH_PX = 1080
DPI = 100


class ChartsUnavailable(RuntimeError):
    """matplotlib is not installed."""


def available() -> bool:
    try:
        return importlib.util.find_spec("matplotlib") is not None
    except (ImportError, ValueError):
        return False


# ── validation ───────────────────────────────────────────────────────────────

def _text(value, field: str, limit: int, required: bool = False) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    value = " ".join(value.split())
    if required and not value:
        raise ValueError(f"{field} must not be empty")
    if len(value) > limit:
        raise ValueError(f"{field} is longer than {limit} characters")
    return value


def _number(value, field: str) -> float:
    # bool is an int subclass; True is not a data point.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a number")
    value = float(value)
    if not math.isfinite(value):
        raise ValueError(f"{field} must be finite")
    return value


def validate(spec) -> dict:
    """A clean copy of `spec`, or ValueError naming the first problem."""
    if not isinstance(spec, dict):
        raise ValueError("spec must be a JSON object")
    unknown = set(spec) - REQUIRED_KEYS - OPTIONAL_KEYS
    if unknown:
        raise ValueError(f"unknown spec keys: {', '.join(sorted(map(str, unknown)))}")
    missing = REQUIRED_KEYS - set(spec)
    if missing:
        raise ValueError(f"missing spec keys: {', '.join(sorted(missing))}")

    kind = spec["type"]
    if kind not in TYPES:
        raise ValueError(f"type must be one of {', '.join(TYPES)}")

    labels = spec["labels"]
    if not isinstance(labels, list) or not labels:
        raise ValueError("labels must be a non-empty list")
    if len(labels) > MAX_LABELS:
        raise ValueError(f"at most {MAX_LABELS} labels")
    labels = [_text(v, f"labels[{i}]", MAX_LABEL, required=True)
              for i, v in enumerate(labels)]

    series = spec["series"]
    if not isinstance(series, list) or not series:
        raise ValueError("series must be a non-empty list")
    if len(series) > MAX_SERIES:
        raise ValueError(f"at most {MAX_SERIES} series")
    clean_series = []
    for i, s in enumerate(series):
        if not isinstance(s, dict):
            raise ValueError(f"series[{i}] must be an object")
        extra = set(s) - SERIES_KEYS
        if extra:
            raise ValueError(f"series[{i}] has unknown keys: {', '.join(sorted(map(str, extra)))}")
        values = s.get("values")
        if not isinstance(values, list):
            raise ValueError(f"series[{i}].values must be a list of numbers")
        if len(values) != len(labels):
            raise ValueError(f"series[{i}].values has {len(values)} numbers; "
                             f"expected {len(labels)} (one per label)")
        clean_series.append({
            "name": _text(s.get("name"), f"series[{i}].name", MAX_SERIES_NAME),
            "values": [_number(v, f"series[{i}].values[{j}]") for j, v in enumerate(values)],
        })

    if kind == "pie":
        if len(clean_series) != 1:
            raise ValueError("a pie chart takes exactly one series")
        if len(labels) > MAX_PIE_SLICES:
            raise ValueError(f"a pie chart takes at most {MAX_PIE_SLICES} slices")
        values = clean_series[0]["values"]
        if any(v < 0 for v in values):
            raise ValueError("pie values must not be negative")
        if sum(values) <= 0:
            raise ValueError("pie values must add up to more than zero")

    return {
        "type": kind,
        "title": _text(spec.get("title"), "title", MAX_TITLE),
        "x_label": _text(spec.get("x_label"), "x_label", MAX_AXIS_LABEL),
        "y_label": _text(spec.get("y_label"), "y_label", MAX_AXIS_LABEL),
        "labels": labels,
        "series": clean_series,
    }


# ── rendering ────────────────────────────────────────────────────────────────

def _format_value(v: float) -> str:
    if v == int(v) and abs(v) < 1e15:
        return f"{int(v):,}"
    return f"{v:,.2f}".rstrip("0").rstrip(".")


def render(spec: dict, out_path: str) -> str:
    """Validate `spec`, draw it, save a PNG at `out_path`, return the path."""
    s = validate(spec)
    if not available():
        raise ChartsUnavailable("matplotlib is not installed (pip install matplotlib)")
    # The object API with an explicit Agg canvas: no pyplot global state, no GUI
    # backend, safe to call from a long-running process.
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    from matplotlib.figure import Figure

    width_in = WIDTH_PX / DPI
    height_in = width_in if s["type"] == "pie" else width_in * 0.8
    fig = Figure(figsize=(width_in, height_in), dpi=DPI, facecolor="white")
    FigureCanvasAgg(fig)
    ax = fig.add_subplot(1, 1, 1)
    labels, series = s["labels"], s["series"]
    n = len(labels)

    if s["type"] == "pie":
        values = series[0]["values"]
        ax.pie(values, labels=labels, colors=PALETTE[:n], startangle=90,
               counterclock=False, autopct="%1.0f%%", pctdistance=0.72,
               textprops={"fontsize": 22},
               wedgeprops={"edgecolor": "white", "linewidth": 2})
        ax.set_aspect("equal")
    else:
        positions = list(range(n))
        if s["type"] == "line":
            for i, ser in enumerate(series):
                ax.plot(positions, ser["values"], color=PALETTE[i % len(PALETTE)],
                        linewidth=4, marker="o", markersize=9, label=ser["name"] or None)
        else:
            k = len(series)
            width = 0.8 / k
            for i, ser in enumerate(series):
                xs = [p - 0.4 + width * (i + 0.5) for p in positions]
                bars = ax.bar(xs, ser["values"], width=width,
                              color=PALETTE[i % len(PALETTE)], label=ser["name"] or None)
                if k == 1 and n <= 12:
                    ax.bar_label(bars, labels=[_format_value(v) for v in ser["values"]],
                                 fontsize=18, padding=4)
        longest = max(len(label) for label in labels)
        rotate = n > 6 or (n > 3 and longest > 8)
        ax.set_xticks(positions)
        ax.set_xticklabels(labels, fontsize=20, rotation=35 if rotate else 0,
                           ha="right" if rotate else "center")
        ax.tick_params(axis="y", labelsize=20)
        ax.grid(axis="y", color="#DDDDDD", linewidth=1)
        ax.set_axisbelow(True)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)
        if s["x_label"]:
            ax.set_xlabel(s["x_label"], fontsize=22, labelpad=10)
        if s["y_label"]:
            ax.set_ylabel(s["y_label"], fontsize=22, labelpad=10)
        if any(ser["name"] for ser in series):
            ax.legend(fontsize=20, frameon=False)

    if s["title"]:
        ax.set_title(s["title"], fontsize=30, fontweight="bold", loc="left", pad=20,
                     wrap=True)
    fig.tight_layout()
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    fig.savefig(out_path, format="png", dpi=DPI, facecolor="white")
    return out_path


# ── CLI ──────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print("usage: python3 -m sancho.charts SPEC.json|'<json>' OUT.png", file=sys.stderr)
        return 2
    raw, out = args
    try:
        if os.path.isfile(raw):
            with open(raw, encoding="utf-8") as f:
                raw = f.read()
        try:
            spec = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"spec is not valid JSON: {e}") from None
        print(render(spec, out))
    except (ValueError, ChartsUnavailable) as e:
        print(f"charts: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
