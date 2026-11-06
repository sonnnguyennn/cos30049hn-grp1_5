"""Histogram and summary helpers shared by the N-BaIoT and Bot-IoT feature plots (CODE 4.1.2).

Both classes always use the SAME bin edges, and each class is normalised by its own size
(share of that class per bin), because the classes differ in size by orders of magnitude.
The transform is log1p for non-negative features (signed log1p if a feature has negatives);
every figure and table names the transform explicitly.
"""

from __future__ import annotations

import _common as C
import numpy as np

N_BINS = 40
QUANTILES = (0.01, 0.25, 0.5, 0.75, 0.99)


def slog1p(values):
    values = np.asarray(values, dtype=np.float64)
    return np.sign(values) * np.log1p(np.abs(values))


def transform_name(values) -> str:
    return "log1p" if np.nanmin(values) >= 0 else "signed log1p"


def histogram_rows(dataset, partition, feature, values, y, n_bins=N_BINS):
    """Shared-edge histogram per class on the transformed scale."""
    t = slog1p(values)
    lo, hi = float(t.min()), float(t.max())
    if hi == lo:
        hi = lo + 1.0
    edges = np.linspace(lo, hi, n_bins + 1)
    rows = []
    for cls, name in ((0, "benign"), (1, "malicious")):
        sel = t[y == cls]
        counts, _ = np.histogram(sel, bins=edges)
        if counts.sum() != len(sel):
            raise AssertionError(f"{feature}/{name}: histogram lost records")
        for i, count in enumerate(counts):
            rows.append(
                {
                    "dataset": dataset,
                    "partition": partition,
                    "feature": feature,
                    "transform": transform_name(values),
                    "bin_index": i,
                    "bin_left": edges[i],
                    "bin_right": edges[i + 1],
                    "class": name,
                    "count": int(count),
                    "class_total": int(len(sel)),
                    "fraction_of_class": float(count) / len(sel),
                }
            )
    return rows


def summary_rows(dataset, partition, feature, values, y, quantile_method="exact (numpy.quantile)"):
    rows = []
    for cls, name in ((0, "benign"), (1, "malicious")):
        sel = np.asarray(values[y == cls], dtype=np.float64)
        q = np.quantile(sel, QUANTILES)
        rows.append(
            {
                "dataset": dataset,
                "partition": partition,
                "feature": feature,
                "class": name,
                "n": int(len(sel)),
                "share_zero": float(np.mean(sel == 0)),
                "min": float(sel.min()),
                "p01": q[0],
                "p25": q[1],
                "median": q[2],
                "p75": q[3],
                "p99": q[4],
                "max": float(sel.max()),
                "mean": float(sel.mean()),
                "quantile_method": quantile_method,
            }
        )
    return rows


def _compact(v: float) -> str:
    for size, suffix in ((1e9, "G"), (1e6, "M"), (1e3, "k")):
        if v >= size:
            return f"{v / size:g}{suffix}"
    return f"{v:g}"


def raw_ticks(lo, hi, min_gap_share=0.12):
    """Ticks on the log1p axis at raw 0, 1, 10, 100, ... spaced so labels never collide."""
    candidates = [0.0] + [10.0**k for k in range(0, 13)]
    gap = min_gap_share * (hi - lo)
    kept = []
    for v in candidates:
        t = float(slog1p(v))
        if lo - 1e-9 <= t <= hi + 1e-9 and (not kept or t - kept[-1][0] >= gap):
            kept.append((t, v))
    if len(kept) > 5:  # narrow panels: label every other decade
        kept = kept[::2]
    return [t for t, _ in kept], [_compact(v) for _, v in kept]


def plot_panels(rows_by_feature, specs, title_prefix=""):
    """rows_by_feature: {feature: histogram rows}; specs: list of (feature, display, unit)."""
    plt = C.setup_matplotlib()
    fig, axes = plt.subplots(
        1, len(specs), figsize=(C.FULL_WIDTH_IN, 2.1), sharey=False, layout="constrained"
    )
    axes = np.atleast_1d(axes)
    transforms = set()
    for ax, (feature, display, unit) in zip(axes, specs):
        rows = rows_by_feature[feature]
        for name, color in (("benign", C.BENIGN), ("malicious", C.MALICIOUS)):
            sel = sorted((r for r in rows if r["class"] == name), key=lambda r: r["bin_index"])
            edges = [sel[0]["bin_left"]] + [r["bin_right"] for r in sel]
            frac = [r["fraction_of_class"] for r in sel]
            n = sel[0]["class_total"]
            ax.stairs(frac, edges, color=color, linewidth=1.2, label=f"{name} (n={C.fmt_int(n)})")
            ax.stairs(frac, edges, color=color, alpha=0.10, fill=True)
        lo, hi = rows[0]["bin_left"], max(r["bin_right"] for r in rows)
        ticks, labels = raw_ticks(lo, hi)
        ax.set_xticks(ticks)
        ax.set_xticklabels(labels)
        ax.set_xlim(lo, hi)
        ax.set_ylim(0, None)
        transforms.add(rows[0]["transform"])
        ax.set_xlabel(f"{display}{f' ({unit})' if unit else ''}")
        ax.set_title(f"{title_prefix}{feature}", loc="left")
        C.style_grid(ax, "y")
    axes[0].set_ylabel("share of class records per bin")
    # Class sizes are identical in every panel (same records), so one figure legend suffices.
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="outside upper center", ncol=2)
    fig.supxlabel(
        f"x axes: {' / '.join(sorted(transforms))} scale, tick labels in raw units; "
        f"the same {len(rows_by_feature[specs[0][0]]) // 2} bins for both classes",
        fontsize=C.FS_TICK,
        color=C.INK_2,
    )
    fig.get_layout_engine().set(wspace=0.06)
    return fig
