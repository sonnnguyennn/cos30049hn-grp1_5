"""Shared helpers for Duy's A2 analysis scripts (CODE 4.1-4.4).

Every script reads saved evidence only. Nothing here fits, tunes or re-evaluates a model,
and nothing opens TEST arrays: TEST numbers are read from saved receipts/manifests.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
ANALYSIS_DIR = SCRIPTS_DIR.parent  # ml/analysis/duy_a2
ML_DIR = ANALYSIS_DIR.parents[1]  # ml/
# DUY_A2_OUTPUT_DIR redirects all outputs (used only for the synthetic self-tests).
OUTPUT_DIR = Path(os.environ.get("DUY_A2_OUTPUT_DIR", ANALYSIS_DIR / "outputs")).resolve()
TABLE_DIR = OUTPUT_DIR / "tables"
FIGURE_DIR = OUTPUT_DIR / "figures"
LOG_DIR = OUTPUT_DIR / "logs"
INDEX_FRAGMENT_DIR = LOG_DIR / "figure_index_fragments"

# Class colours (validated categorical slots 1-2; colour always means the TRUE class).
BENIGN = "#2a78d6"
MALICIOUS = "#eb6834"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"
BLUE_RAMP = [
    "#cde2fb",
    "#b7d3f6",
    "#9ec5f4",
    "#86b6ef",
    "#6da7ec",
    "#5598e7",
    "#3987e5",
    "#2a78d6",
    "#256abf",
    "#1c5cab",
    "#184f95",
    "#104281",
    "#0d366b",
]

FULL_WIDTH_IN = 6.3  # A4 text width (about 16 cm)
HALF_WIDTH_IN = 3.1

# Text sizes in points (figures are drawn at final print size, so these are the printed sizes).
FS_BASE = 7.0
FS_TITLE = 7.5
FS_TICK = 6.5
FS_VALUE = 6.0  # value labels next to marks
FS_CELL_COUNT = 7.0  # confusion-matrix counts
FS_CELL_PCT = 6.0  # confusion-matrix row percentages
DOT_S = 20  # scatter marker area (pt^2) used for labelled dots
LABEL_PAD_PT = 2.5  # clear space between a mark and its value label
# Minimum clear space the layout audit requires (points).
GAP_TEXT_PT = 0.75
GAP_TICK_PT = 2.0
GAP_MARK_PT = 1.0


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def ensure_dirs() -> None:
    for directory in (TABLE_DIR, FIGURE_DIR, LOG_DIR, INDEX_FRAGMENT_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def rel(path: Path) -> str:
    """Path relative to ml/ when possible, for portable provenance records."""
    path = Path(path).resolve()
    try:
        return path.relative_to(ML_DIR).as_posix()
    except ValueError:
        return path.name


def input_record(path: Path, label: str | None = None) -> dict:
    path = Path(path)
    return {
        "label": label or path.name,
        "path": rel(path),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def runtime() -> dict:
    import matplotlib
    import numpy

    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "numpy": numpy.__version__,
        "matplotlib": matplotlib.__version__,
    }


def write_csv(path: Path, rows: list[dict], fieldnames: list[str] | None = None) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = fieldnames or list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: ("N/A" if row.get(k) is None else row.get(k)) for k in fieldnames})
    return path


def _json_default(value):
    if isinstance(value, set | frozenset):
        return sorted(value)
    if hasattr(value, "item"):  # numpy scalar
        return value.item()
    if hasattr(value, "tolist"):  # numpy array
        return value.tolist()
    if isinstance(value, Path):
        return value.as_posix()
    raise TypeError(f"not JSON serialisable: {type(value).__name__}")


def dumps(payload) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False, default=_json_default) + "\n"


def write_log(name: str, payload: dict) -> Path:
    ensure_dirs()
    payload = {
        "script": name,
        "created_utc": datetime.now(UTC).isoformat(),
        "runtime": runtime(),
        **payload,
    }
    path = LOG_DIR / f"{name}.json"
    path.write_text(dumps(payload), encoding="utf-8")
    return path


def register_figure(figure_id: str, **fields) -> None:
    """Write one figure_index row; build_figure_index.py merges the fragments."""
    ensure_dirs()
    required = (
        "files",
        "inputs",
        "dataset",
        "scope",
        "n",
        "weighting",
        "sampling_transform",
        "caption",
        "commentary",
    )
    missing = [k for k in required if k not in fields]
    if missing:
        raise ValueError(f"figure {figure_id} missing {missing}")
    row = {"figure_id": figure_id, "run_id": fields.pop("run_id", "N/A"), **fields}
    (INDEX_FRAGMENT_DIR / f"{figure_id}.json").write_text(dumps(row), encoding="utf-8")


def setup_matplotlib():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": FS_BASE,
            "axes.titlesize": FS_TITLE,
            "axes.titleweight": "bold",
            "axes.titlepad": 4.0,
            "axes.labelsize": FS_BASE,
            "axes.edgecolor": AXIS,
            "axes.labelcolor": INK_2,
            "axes.linewidth": 0.8,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": False,
            "xtick.color": INK_2,
            "ytick.color": INK_2,
            "xtick.labelsize": FS_TICK,
            "ytick.labelsize": FS_TICK,
            "legend.fontsize": FS_TICK,
            "legend.frameon": False,
            "legend.handlelength": 1.6,
            "legend.columnspacing": 1.6,
            "figure.dpi": 100,
            "figure.constrained_layout.h_pad": 0.03,
            "figure.constrained_layout.w_pad": 0.03,
            "savefig.dpi": 300,
            "savefig.bbox": "tight",
            "savefig.pad_inches": 0.03,
            "pdf.fonttype": 42,
            "text.color": INK,
        }
    )
    return plt


def style_grid(ax, axis="x"):
    ax.set_axisbelow(True)
    ax.grid(True, axis=axis, color=GRID, linewidth=0.6, linestyle="-")


def label_point(ax, x, y, text, marker_size=None, side="right", fontsize=None, color=None, **kw):
    """Value label a fixed distance (in points) from a mark, so it never touches it on any scale."""
    offset = (marker_size**0.5 / 2 if marker_size else 0.0) + LABEL_PAD_PT
    return ax.annotate(
        text,
        xy=(x, y),
        xytext=(offset if side == "right" else -offset, 0),
        textcoords="offset points",
        ha="left" if side == "right" else "right",
        va="center",
        fontsize=fontsize or FS_VALUE,
        color=color or INK_2,
        annotation_clip=False,
        **kw,
    )


def draw_confusion(ax, tn, fp, fn, tp, title, ylabels=True):
    """2x2 confusion matrix, order [benign, malicious]; colour and percentages per TRUE class."""
    import numpy as np
    from matplotlib.colors import LinearSegmentedColormap

    cmap = LinearSegmentedColormap.from_list("blue", ["#f1f4f8"] + BLUE_RAMP)
    counts = np.array([[tn, fp], [fn, tp]], dtype=float)
    share = counts / counts.sum(axis=1, keepdims=True)
    ax.imshow(share, cmap=cmap, vmin=0, vmax=1)
    for i in range(2):
        for j in range(2):
            color = "white" if share[i, j] > 0.6 else INK
            ax.text(
                j,
                i - 0.13,
                fmt_int(counts[i, j]),
                ha="center",
                va="center",
                fontsize=FS_CELL_COUNT,
                color=color,
                fontweight="bold",
            )
            ax.text(
                j,
                i + 0.19,
                fmt_pct(100 * share[i, j]),
                ha="center",
                va="center",
                fontsize=FS_CELL_PCT,
                color=color,
            )
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["benign", "malicious"])
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["benign", "malicious"] if ylabels else ["", ""])
    ax.set_xlabel("predicted")
    if ylabels:
        ax.set_ylabel("true class")
    ax.set_title(title, loc="left", fontsize=FS_BASE)
    ax.tick_params(length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.set_xticks(np.arange(-0.5, 2, 1), minor=True)
    ax.set_yticks(np.arange(-0.5, 2, 1), minor=True)
    ax.grid(which="minor", color="white", linewidth=2)
    ax.tick_params(which="minor", length=0)


# --------------------------------------------------------------------------- layout audit
def _bbox_gap(a, b) -> float:
    """Clear distance between two display boxes (negative = overlap depth)."""
    dx = max(b.x0 - a.x1, a.x0 - b.x1)
    dy = max(b.y0 - a.y1, a.y0 - b.y1)
    if dx < 0 and dy < 0:
        return max(dx, dy)
    return max(dx, 0.0) if dy < 0 else (max(dy, 0.0) if dx < 0 else (dx * dx + dy * dy) ** 0.5)


def _point_box_gap(cx, cy, r, box) -> float:
    dx = max(box.x0 - cx, 0.0, cx - box.x1)
    dy = max(box.y0 - cy, 0.0, cy - box.y1)
    return (dx * dx + dy * dy) ** 0.5 - r


def _drawn_texts(fig, renderer):
    """Every text that is drawn, with role, owning axes, display bbox and data anchor."""
    from matplotlib.text import Annotation

    out = []

    def add(t, role, axes_id, **extra):
        if t is None or not t.get_visible() or not t.get_text().strip():
            return
        bb = t.get_window_extent(renderer)
        if bb.width <= 0 or bb.height <= 0:
            return
        out.append({"artist": t, "role": role, "axes": axes_id, "bbox": bb, **extra})

    for k, ax in enumerate(fig.axes):
        if not ax.get_visible():
            continue
        for child in ax.get_children():
            if child in ax.texts:
                anchor = child.xy if isinstance(child, Annotation) else child.get_position()
                add(
                    child,
                    "annotation" if isinstance(child, Annotation) else "text",
                    k,
                    anchor=[float(anchor[0]), float(anchor[1])],
                )
            elif child.__class__.__name__ == "Text":
                add(child, "title", k)
        for name, axis in (("x", ax.xaxis), ("y", ax.yaxis)):
            add(axis.label, f"{name}label", k)
            lo, hi = sorted(axis.get_view_interval())
            span = (hi - lo) or 1.0
            for tick in axis.get_major_ticks() + axis.get_minor_ticks():
                loc = tick.get_loc()
                if loc is None or not (lo - 1e-9 * span <= loc <= hi + 1e-9 * span):
                    continue
                for lab in (tick.label1, tick.label2):
                    add(lab, f"{name}tick", k, tick_loc=float(loc), scale=axis.get_scale())
        legend = ax.get_legend()
        if legend is not None and legend.get_visible():
            out.append(
                {
                    "artist": legend,
                    "role": "legend",
                    "axes": k,
                    "bbox": legend.get_window_extent(renderer),
                    "texts": [t.get_text() for t in legend.get_texts()],
                }
            )
    for legend in fig.legends:
        out.append(
            {
                "artist": legend,
                "role": "legend",
                "axes": None,
                "bbox": legend.get_window_extent(renderer),
                "texts": [t.get_text() for t in legend.get_texts()],
            }
        )
    for t in fig.texts:
        add(t, "figure_text", None)
    return out


def _obstacles(fig, renderer):
    """Marks text must not touch: scatter dots, bars and visible spines."""
    import numpy as np
    from matplotlib.collections import PathCollection
    from matplotlib.patches import Rectangle

    px_per_pt = fig.dpi / 72.0
    dots, boxes = [], []
    for k, ax in enumerate(fig.axes):
        if not ax.get_visible():
            continue
        clip = ax.get_window_extent(renderer)
        for coll in ax.collections:
            if not isinstance(coll, PathCollection) or not coll.get_visible():
                continue
            offsets = np.asarray(coll.get_offsets(), dtype=float)
            if offsets.size == 0:
                continue
            xy = coll.get_offset_transform().transform(offsets)
            sizes = np.broadcast_to(np.asarray(coll.get_sizes(), dtype=float), (len(xy),))
            widths = np.broadcast_to(np.asarray(coll.get_linewidths(), dtype=float), (len(xy),))
            for (cx, cy), s, lw in zip(xy, sizes, widths):
                if clip.x0 - 1 <= cx <= clip.x1 + 1 and clip.y0 - 1 <= cy <= clip.y1 + 1:
                    dots.append((k, cx, cy, (s**0.5 / 2 + lw / 2) * px_per_pt))
        for patch in ax.patches:
            if isinstance(patch, Rectangle) and patch.get_visible():
                if patch.get_width() != 0 and patch.get_height() != 0:
                    boxes.append((k, "bar", patch.get_window_extent(renderer)))
        for name, spine in ax.spines.items():
            if spine.get_visible():
                boxes.append((k, f"spine-{name}", spine.get_window_extent(renderer)))
    return dots, boxes


def audit_layout(fig, stem: str) -> dict:
    """Find every text that overlaps or touches another text, a dot, a bar or a spine.

    Writes logs/figure_text/<stem>.json with every drawn text (role, string, size, position,
    data anchor) so the numbers shown in a figure can be checked against the sources.
    """
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    pt = fig.dpi / 72.0  # display pixels per point
    texts = _drawn_texts(fig, renderer)
    dots, boxes = _obstacles(fig, renderer)
    problems = []

    def name(rec):
        if rec["role"] == "legend":
            return f"legend {rec['texts']}"
        return f"{rec['role']} {rec['artist'].get_text()!r}"

    for i, a in enumerate(texts):
        for b in texts[i + 1 :]:
            same_axis_ticks = a["role"] == b["role"] and a["role"].endswith("tick")
            same_axis_ticks = same_axis_ticks and a["axes"] == b["axes"]
            need = (GAP_TICK_PT if same_axis_ticks else GAP_TEXT_PT) * pt
            gap = _bbox_gap(a["bbox"], b["bbox"])
            if gap < need:
                problems.append(
                    {"kind": "text-text", "a": name(a), "b": name(b), "gap_pt": round(gap / pt, 2)}
                )
        for k, cx, cy, r in dots:
            gap = _point_box_gap(cx, cy, r, a["bbox"])
            if gap < GAP_MARK_PT * pt:
                problems.append(
                    {"kind": "text-dot", "a": name(a), "axes": k, "gap_pt": round(gap / pt, 2)}
                )
        for k, kind, box in boxes:
            own_decoration = a["axes"] == k and a["role"] in ("xtick", "ytick", "xlabel", "ylabel")
            if kind.startswith("spine") and own_decoration:
                continue
            gap = _bbox_gap(a["bbox"], box)
            if gap < 0.25 * pt:
                problems.append(
                    {"kind": f"text-{kind}", "a": name(a), "axes": k, "gap_pt": round(gap / pt, 2)}
                )
    tight = fig.get_tightbbox(renderer)
    width, height = fig.get_size_inches()
    for size, limit, axis in ((tight.width, width, "width"), (tight.height, height, "height")):
        if size > limit + 0.02:  # something sticks out of the canvas; the saved file would grow
            problems.append(
                {"kind": f"figure-{axis}", "a": f"saved {size:.3f} in > figure {limit:.3f} in"}
            )
    for p in problems:
        if "gap_pt" in p:
            p["gap_pt"] = float(p["gap_pt"])
    record = {
        "figure": stem,
        "figure_size_in": [round(v, 3) for v in fig.get_size_inches()],
        "saved_size_in": [round(tight.width, 3), round(tight.height, 3)],
        "min_fontsize_pt": min(
            (r["artist"].get_fontsize() for r in texts if r["role"] != "legend"), default=None
        ),
        "problems": problems,
        "texts": [
            {
                "role": r["role"],
                "axes": r["axes"],
                "axes_title": (
                    " | ".join(
                        t
                        for t in (
                            fig.axes[r["axes"]].get_title(loc=loc) for loc in ("left", "center")
                        )
                        if t
                    )
                    if r["axes"] is not None
                    else None
                ),
                "text": r["texts"] if r["role"] == "legend" else r["artist"].get_text(),
                "fontsize_pt": None if r["role"] == "legend" else r["artist"].get_fontsize(),
                "bbox_pt": [
                    round(v / pt, 2)
                    for v in (r["bbox"].x0, r["bbox"].y0, r["bbox"].x1, r["bbox"].y1)
                ],
                **{k: r[k] for k in ("anchor", "tick_loc", "scale") if k in r},
            }
            for r in texts
        ],
    }
    out_dir = LOG_DIR / "figure_text"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{stem}.json").write_text(dumps(record), encoding="utf-8")
    if problems:
        print(f"WARNING {stem}: {len(problems)} text layout problem(s):")
        for p in problems:
            print("   ", p)
    return record


def save_figure(fig, stem: str) -> list[str]:
    ensure_dirs()
    audit_layout(fig, stem)
    files = []
    for ext in ("png", "pdf"):
        path = FIGURE_DIR / f"{stem}.{ext}"
        # no creation date in the PDF, so re-running gives byte-identical files
        meta = (
            {"Creator": "duy_a2 analysis scripts"}
            if ext == "png"
            else {"Creator": "duy_a2", "CreationDate": None}
        )
        fig.savefig(path, metadata=meta)
        files.append(rel(path))
    return files


def fmt_int(value) -> str:
    return f"{int(round(value)):,}"


def fmt_pct(value) -> str:
    """Percent label that never rounds a minority share to 0% or a majority to 100%."""
    value = float(value)
    if value == 0 or value == 100:
        return f"{value:.0f}%"
    if value >= 99.9:
        digits = 3
        while round(value, digits) >= 100 and digits < 9:
            digits += 1
        return f"{value:.{digits}f}%"
    if value >= 1:
        return f"{value:.2f}%"
    return f"{value:.3g}%"


def assert_equal(label: str, actual, expected, checks: list) -> None:
    ok = actual == expected
    checks.append(
        {"check": label, "actual": actual, "expected": expected, "status": "PASS" if ok else "FAIL"}
    )
    if not ok:
        raise AssertionError(f"{label}: {actual!r} != {expected!r}")


def assert_close(label: str, actual, expected, checks: list, tol=1e-9) -> None:
    ok = abs(float(actual) - float(expected)) <= tol
    checks.append(
        {
            "check": label,
            "actual": actual,
            "expected": expected,
            "tolerance": tol,
            "status": "PASS" if ok else "FAIL",
        }
    )
    if not ok:
        raise AssertionError(f"{label}: {actual!r} vs {expected!r} (tol {tol})")
