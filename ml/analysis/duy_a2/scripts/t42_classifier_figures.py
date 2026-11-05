"""CODE 4.2.1-4.2.4 - classifier tables, comparison figures and confusion matrices.

Inputs are the accepted records only (no model is loaded or re-run):
  * artifacts/manifests/primary_classifier_comparison_20261105.csv  (official comparison)
  * artifacts/manifests/primary_classifier_selection_20261105.json  (winner, ranking, CSV hash)
  * artifacts/manifests/primary_final_test_receipt_20261105.json    (single final TEST run)
The main table keeps only train_population_kind == "full" with an empty excluded_reason
(must be 9 runs); subset runs go to a separate diagnostic table. Every metric is recomputed
from the confusion counts and must match the CSV. VALIDATION and TEST are kept separate;
TEST exists only for the selected XGBoost.

Usage (from ml/):  python analysis/duy_a2/scripts/t42_classifier_figures.py
"""

from __future__ import annotations

import csv

import _common as C
import numpy as np

MANIFESTS = C.ML_DIR / "artifacts" / "manifests"
COMPARISON = MANIFESTS / "primary_classifier_comparison_20261105.csv"
SELECTION = MANIFESTS / "primary_classifier_selection_20261105.json"
TEST_RECEIPT = MANIFESTS / "primary_final_test_receipt_20261105.json"
EXPECTED_TEST = {"TN": 83_531, "FP": 1, "FN": 11, "TP": 977_723}
VALIDATION_ROWS, VAL_BENIGN, VAL_MALICIOUS = 1_056_372, 83_435, 972_937

CONFIG = {  # from each run's result.json (resolved_configuration.parameters)
    "xgb_frac1_seed42_lr01": ("XGB", "300 rounds, learning_rate 0.1, max_depth 6"),
    "xgb_frac1_seed42_d4": ("XGB", "100 rounds, learning_rate 0.3, max_depth 4"),
    "xgb_frac1_seed42": ("XGB", "baseline: 100 rounds, learning_rate 0.3, max_depth 6"),
    "rf_frac1_seed42": ("RF", "baseline: 100 trees, max_features sqrt, min_samples_leaf 1"),
    "xgb_frac1_seed42_d8": ("XGB", "100 rounds, learning_rate 0.3, max_depth 8"),
    "rf_frac1_seed42_leaf5": ("RF", "100 trees, min_samples_leaf 5"),
    "rf_frac1_seed42_mf03": ("RF", "100 trees, max_features 0.3"),
    "lr_full_20261102T011513018213Z": ("LR", "lbfgs, C 1.0, TRAIN-only standard scaling"),
    "dummy_full_20261102T011513018213Z": ("Dummy", "most_frequent (always malicious)"),
}


def short_label(run_id: str, winner: str) -> str:
    if run_id.startswith("lr_full_"):
        return "LR (lr_full_...018213Z)"
    if run_id.startswith("dummy_full_"):
        return "Dummy (dummy_full_...018213Z)"
    extra = {"xgb_frac1_seed42": " (XGB baseline)", "rf_frac1_seed42": " (RF baseline)"}.get(
        run_id, ""
    )
    return run_id + extra + ("  [selected]" if run_id == winner else "")


def metrics_from_counts(tn, fp, fn, tp):
    def div(a, b):
        return None if b == 0 else a / b

    def f1(tp_, fp_, fn_):
        return div(2 * tp_, 2 * tp_ + fp_ + fn_)

    out = {
        "accuracy": div(tn + tp, tn + fp + fn + tp),
        "benign_precision": div(tn, tn + fn),
        "benign_recall": div(tn, tn + fp),
        "benign_f1": f1(tn, fn, fp),
        "benign_support": tn + fp,
        "malicious_precision": div(tp, tp + fp),
        "malicious_recall": div(tp, tp + fn),
        "malicious_f1": f1(tp, fp, fn),
        "malicious_support": fn + tp,
        "fpr": div(fp, fp + tn),
    }
    out["macro_f1"] = (
        None
        if None in (out["benign_f1"], out["malicious_f1"])
        else (out["benign_f1"] + out["malicious_f1"]) / 2
    )
    return out


def num(value):
    return None if value in ("", None) else float(value)


def load(checks):
    C.assert_equal(
        "comparison CSV hash == selection record",
        C.sha256_file(COMPARISON),
        C.read_json(SELECTION)["comparison"]["sha256"],
        checks,
    )
    with COMPARISON.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    full = [r for r in rows if r["train_population_kind"] == "full" and r["excluded_reason"] == ""]
    subset = [r for r in rows if r not in full]
    C.assert_equal("number of Full runs in the main table", len(full), 9, checks)
    C.assert_equal(
        "subset runs all carry an exclusion reason",
        all(r["excluded_reason"] for r in subset),
        True,
        checks,
    )
    selection = C.read_json(SELECTION)
    C.assert_equal(
        "Full-run order == selection ranking",
        [r["run_id"] for r in sorted(full, key=lambda r: int(r["rank"]))],
        selection["ranking"],
        checks,
    )
    test = C.read_json(TEST_RECEIPT)
    C.assert_equal(
        "TEST receipt model == selection winner",
        test["selected_run_id"],
        selection["winner"],
        checks,
    )
    for r in full + subset:
        tn, fp, fn, tp = (int(r[k]) for k in ("TN", "FP", "FN", "TP"))
        C.assert_equal(
            f"{r['run_id']} counts sum to VALIDATION rows",
            tn + fp + fn + tp,
            VALIDATION_ROWS,
            checks,
        )
        C.assert_equal(f"{r['run_id']} benign support", tn + fp, VAL_BENIGN, checks)
        recomputed = metrics_from_counts(tn, fp, fn, tp)
        for key, value in recomputed.items():
            stored = num(r[key]) if key in r else None
            if key.endswith("support"):
                C.assert_equal(f"{r['run_id']} {key}", value, int(r[key]), checks)
            elif value is None or stored is None:
                C.assert_equal(
                    f"{r['run_id']} {key} undefined in both", (value, stored), (None, None), checks
                )
            else:
                C.assert_close(f"{r['run_id']} {key} recomputed", value, stored, checks, tol=1e-12)
    return sorted(full, key=lambda r: int(r["rank"])), subset, selection, test


def tables(full, subset, winner, test, checks):
    overview, per_class, subset_rows = [], [], []
    for r in full:
        rid = r["run_id"]
        algo, cfg = CONFIG[rid]
        overview.append(
            {
                "rank": int(r["rank"]),
                "run_id": rid,
                "algorithm": algo,
                "configuration": cfg,
                "input_view": r["input_view"],
                "selected": rid == winner,
                "accuracy": num(r["accuracy"]),
                "macro_f1": num(r["macro_f1"]),
                "fpr": num(r["fpr"]),
                "TN": int(r["TN"]),
                "FP": int(r["FP"]),
                "FN": int(r["FN"]),
                "TP": int(r["TP"]),
                "partition": "VALIDATION",
                "validation_rows": int(r["validation_rows"]),
                "train_rows": int(r["actual_train_rows"]),
            }
        )
        for cls in ("benign", "malicious"):
            per_class.append(
                {
                    "rank": int(r["rank"]),
                    "run_id": rid,
                    "class": cls,
                    "precision": num(r[f"{cls}_precision"]),
                    "recall": num(r[f"{cls}_recall"]),
                    "f1": num(r[f"{cls}_f1"]),
                    "support": int(r[f"{cls}_support"]),
                    "partition": "VALIDATION",
                }
            )
    for r in subset:
        subset_rows.append(
            {
                "run_id": r["run_id"],
                "algorithm": r["algorithm"],
                "train_population_kind": r["train_population_kind"],
                "actual_train_rows": int(r["actual_train_rows"]),
                "excluded_reason": r["excluded_reason"],
                "macro_f1": num(r["macro_f1"]),
                "fpr": num(r["fpr"]),
                "FP": int(r["FP"]),
                "FN": int(r["FN"]),
                "partition": "VALIDATION",
                "use": "diagnostic only; not in the comparison",
            }
        )
    m = test["metrics"]
    counts = {k: m[k] for k in ("TN", "FP", "FN", "TP")}
    C.assert_equal("TEST confusion counts == expected (brief 2.4)", counts, EXPECTED_TEST, checks)
    C.assert_equal(
        "TEST counts sum to TEST rows", sum(counts.values()), test["inference"]["rows"], checks
    )
    recomputed = metrics_from_counts(*(counts[k] for k in ("TN", "FP", "FN", "TP")))
    stored = {
        "accuracy": m["accuracy"],
        "macro_f1": m["macro_f1"],
        "fpr": m["fpr"],
        **{
            f"{c}_{k}": m["per_class"][c][k]
            for c in ("benign", "malicious")
            for k in ("precision", "recall", "f1", "support")
        },
    }
    for key, value in stored.items():
        if key.endswith("support"):
            C.assert_equal(f"TEST {key}", recomputed[key], value, checks)
        else:
            C.assert_close(f"TEST {key} recomputed", recomputed[key], value, checks, tol=1e-12)
    test_rows = [
        {
            "run_id": test["selected_run_id"],
            "partition": "TEST",
            "metric": k,
            "value": stored[k] if k in stored else counts[k],
        }
        for k in (
            "TN",
            "FP",
            "FN",
            "TP",
            "accuracy",
            "macro_f1",
            "fpr",
            "benign_precision",
            "benign_recall",
            "benign_f1",
            "benign_support",
            "malicious_precision",
            "malicious_recall",
            "malicious_f1",
            "malicious_support",
        )
    ]
    return overview, per_class, subset_rows, test_rows


def markdown(overview, per_class, test_rows):
    def f(v, d=6):
        return "N/A" if v is None else f"{v:.{d}f}"

    lines = [
        "# Classifier tables (VALIDATION unless stated)",
        "",
        "## Table A - Full runs, VALIDATION (n = 1,056,372; benign 83,435; malicious 972,937)",
        "",
        "| Rank | Run ID | Algorithm | Accuracy | Macro-F1 | FPR | TN | FP | FN | TP |",
        "|---:|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in overview:
        sel = " (selected)" if r["selected"] else ""
        lines.append(
            f"| {r['rank']} | `{r['run_id']}`{sel} | {r['algorithm']} | {f(r['accuracy'])} | "
            f"{f(r['macro_f1'])} | {f(r['fpr'], 7)} | {r['TN']:,} | {r['FP']:,} | "
            f"{r['FN']:,} | {r['TP']:,} |"
        )
    lines += [
        "",
        "## Table B - per-class results, VALIDATION",
        "",
        "| Run ID | Class | Precision | Recall | F1 | Support |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for r in per_class:
        lines.append(
            f"| `{r['run_id']}` | {r['class']} | {f(r['precision'])} | {f(r['recall'])} | "
            f"{f(r['f1'])} | {r['support']:,} |"
        )
    lines += [
        "",
        "N/A = undefined (no record predicted benign, so benign precision is 0/0).",
        "",
        "## Table C - selected XGBoost, final TEST (single run, n = 1,061,266)",
        "",
        "| Metric | Value |",
        "|---|---:|",
    ]
    for r in test_rows:
        v = r["value"]
        lines.append(
            f"| {r['metric']} | {v:,} |" if isinstance(v, int) else f"| {r['metric']} | {v:.9f} |"
        )
    return "\n".join(lines) + "\n"


def value_text(v):
    """Exact 0/1 shown as 0/1; values >= 0.99 with 6 decimals so close runs stay distinct."""
    if v is None:
        return "N/A"
    if v in (0, 1):
        return f"{v:.0f}"
    return f"{v:.6f}" if v >= 0.99 else f"{v:.4f}"


def bar_panel(ax, labels, series, title, xlabel, xlim=(0, 1.0)):
    """series: list of (name, values, color); horizontal grouped bars on a 0-1 scale."""
    n = len(series)
    height = 0.84 / n
    y = np.arange(len(labels))[::-1]
    for k, (name, values, color) in enumerate(series):
        offs = y + (n - 1 - 2 * k) * height / 2
        vals = [0 if v is None else v for v in values]
        ax.barh(offs, vals, height=height * 0.86, color=color, label=name, zorder=2)
        for yo, v in zip(offs, values):
            C.label_point(ax, 0 if v is None else v, yo, value_text(v))
    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.set_xlim(*xlim)
    ax.set_ylim(-0.6, len(labels) - 0.4)
    ax.set_title(title, loc="left")
    ax.set_xlabel(xlabel)
    ax.tick_params(axis="y", length=0)
    C.style_grid(ax, "x")


def dot_panel_symlog(ax, labels, series, title, xlabel, linthresh, fmt, xmax, tick_fmt=None):
    tick_fmt = tick_fmt or (lambda t: f"{t:g}")
    y = np.arange(len(labels))[::-1]
    n = len(series)
    for k, (name, values, color) in enumerate(series):
        offs = y + (n - 1 - 2 * k) * 0.2
        ax.scatter(
            values,
            offs,
            s=C.DOT_S,
            color=color,
            edgecolor="white",
            linewidth=0.8,
            zorder=3,
            label=name,
            clip_on=False,
        )
        for yo, v in zip(offs, values):
            C.label_point(ax, v, yo, fmt(v), C.DOT_S)
    ax.set_xscale("symlog", linthresh=linthresh, linscale=0.6)
    ax.set_xlim(0, xmax)
    ticks = [0.0] + [t for t in (linthresh * 10**k for k in range(0, 12)) if t <= xmax / 2]
    ax.set_xticks(ticks)
    ax.set_xticklabels([tick_fmt(t) for t in ticks])
    ax.minorticks_off()
    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.set_ylim(-0.6, len(labels) - 0.4)
    ax.set_title(title, loc="left")
    ax.set_xlabel(xlabel)
    ax.tick_params(axis="y", length=0, pad=5)
    C.style_grid(ax, "x")


def figures(overview, per_class, test, winner):
    plt = C.setup_matplotlib()
    labels = [short_label(r["run_id"], winner) for r in overview]
    pc = {(r["run_id"], r["class"]): r for r in per_class}

    # 4.2a - macro-F1 and per-class recall on the full 0-1 scale
    fig, axes = plt.subplots(
        1, 2, figsize=(C.FULL_WIDTH_IN, 3.1), sharey=True, layout="constrained"
    )
    bar_panel(
        axes[0],
        labels,
        [("macro-F1", [r["macro_f1"] for r in overview], C.MUTED)],
        "(a) Macro-F1",
        "macro-F1 (0-1 scale)",
        xlim=(0, 1.3),
    )
    bar_panel(
        axes[1],
        labels,
        [
            ("benign recall", [pc[(r["run_id"], "benign")]["recall"] for r in overview], C.BENIGN),
            (
                "malicious recall",
                [pc[(r["run_id"], "malicious")]["recall"] for r in overview],
                C.MALICIOUS,
            ),
        ],
        "(b) Recall by true class",
        "recall (0-1 scale)",
        xlim=(0, 1.3),
    )
    handles, names = axes[1].get_legend_handles_labels()
    fig.legend(handles, names, loc="outside upper right", ncol=2)
    for ax in axes:
        ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
    fig.get_layout_engine().set(wspace=0.04)
    files_a = C.save_figure(fig, "fig42a_validation_f1_recall")
    plt.close(fig)

    # 4.2b - error counts and FPR (symmetric log scale so 0 can be shown; exact values labelled)
    fig, axes = plt.subplots(
        1, 2, figsize=(C.FULL_WIDTH_IN, 3.1), sharey=True, layout="constrained"
    )
    dot_panel_symlog(
        axes[0],
        labels,
        [
            ("FP: benign flagged malicious", [r["FP"] for r in overview], C.BENIGN),
            ("FN: malicious missed", [r["FN"] for r in overview], C.MALICIOUS),
        ],
        "(a) Errors on VALIDATION",
        "records (symmetric log scale)",
        1,
        lambda v: f"{v:,}",
        2e6,
        tick_fmt=lambda t: {
            0: "0",
            1: "1",
            10: "10",
            100: "100",
            1e3: "1k",
            1e4: "10k",
            1e5: "100k",
            1e6: "1M",
        }.get(t, f"{t:g}"),
    )
    dot_panel_symlog(
        axes[1],
        labels,
        [("FPR", [100 * r["fpr"] for r in overview], C.BENIGN)],
        "(b) FPR = FP / 83,435 benign",
        "FPR, % (symmetric log scale)",
        1e-3,
        lambda v: "0%" if v == 0 else C.fmt_pct(v),
        400,
        tick_fmt=lambda t: f"{t:g}",
    )
    handles, names = axes[0].get_legend_handles_labels()
    fig.legend(handles, names, loc="outside upper center", ncol=2)
    fig.get_layout_engine().set(wspace=0.04)
    files_b = C.save_figure(fig, "fig42b_validation_errors_fpr")
    plt.close(fig)

    # 4.2c - confusion matrices, VALIDATION (rows = true class, columns = prediction)
    chosen = [
        ("lr_full_20261102T011513018213Z", "LR"),
        ("rf_frac1_seed42", "RF baseline"),
        (winner, "XGB selected"),
    ]
    by_id = {r["run_id"]: r for r in overview}
    fig, axes = plt.subplots(1, 3, figsize=(C.FULL_WIDTH_IN, 2.15), layout="constrained")
    for k, (ax, (rid, name)) in enumerate(zip(axes, chosen)):
        r = by_id[rid]
        shown = "lr_full_...018213Z" if rid.startswith("lr_full_") else rid
        C.draw_confusion(
            ax, r["TN"], r["FP"], r["FN"], r["TP"], f"{name}\n{shown}", ylabels=(k == 0)
        )
    files_c = C.save_figure(fig, "fig42c_validation_confusion")
    plt.close(fig)

    # 4.2d - selected model, final TEST only
    m = test["metrics"]
    fig, ax = plt.subplots(figsize=(C.HALF_WIDTH_IN, 2.25), layout="constrained")
    C.draw_confusion(
        ax, m["TN"], m["FP"], m["FN"], m["TP"], f"XGB selected, TEST\n{test['selected_run_id']}"
    )
    files_d = C.save_figure(fig, "fig42d_test_confusion_selected")
    plt.close(fig)
    return files_a, files_b, files_c, files_d, chosen


def main():
    C.ensure_dirs()
    checks = []
    full, subset, selection, test = load(checks)
    winner = selection["winner"]
    overview, per_class, subset_rows, test_rows = tables(full, subset, winner, test, checks)
    outs = [
        C.write_csv(C.TABLE_DIR / "t42_validation_full_runs_overview.csv", overview),
        C.write_csv(C.TABLE_DIR / "t42_validation_full_runs_per_class.csv", per_class),
        C.write_csv(C.TABLE_DIR / "t42_validation_subset_runs_diagnostic.csv", subset_rows),
        C.write_csv(C.TABLE_DIR / "t42_test_selected_xgb.csv", test_rows),
    ]
    md = C.TABLE_DIR / "t42_tables.md"
    md.write_text(markdown(overview, per_class, test_rows), encoding="utf-8")
    files_a, files_b, files_c, files_d, chosen = figures(overview, per_class, test, winner)
    inputs = [C.input_record(COMPARISON), C.input_record(SELECTION)]
    val_scope = "VALIDATION (1,056,372 records: 83,435 benign, 972,937 malicious)"
    o = {r["run_id"]: r for r in overview}
    trees = [r for r in overview if r["algorithm"] in ("RF", "XGB")]
    C.assert_equal("tree-model Full runs", len(trees), 7, checks)
    f1_spread = max(r["macro_f1"] for r in trees) - min(r["macro_f1"] for r in trees)
    errors = [r["FP"] + r["FN"] for r in trees]
    dummy = o["dummy_full_20261102T011513018213Z"]
    lr = o["lr_full_20261102T011513018213Z"]
    C.register_figure(
        "fig42a_validation_f1_recall",
        files=files_a,
        inputs=inputs,
        dataset="N-BaIoT",
        scope=val_scope,
        run_id="; ".join(r["run_id"] for r in overview),
        n="9 Full runs; supports benign 83,435 / malicious 972,937",
        weighting="1 per record",
        sampling_transform="none; 0-1 scale, no axis truncation",
        caption="VALIDATION macro-F1 and per-class recall for the nine Full runs, ranked by the "
        "selection rule (0-1 scale; exact values labelled).",
        commentary=(
            "On the full 0-1 scale every run except the Dummy is indistinguishable from 1 "
            f"(even LR reaches macro-F1 {lr['macro_f1']:.4f}). The Dummy classifier, which "
            "predicts malicious for every record, keeps malicious recall 1 but benign recall 0 "
            f"(macro-F1 {dummy['macro_f1']:.4f}) despite {C.fmt_pct(100 * dummy['accuracy'])} "
            f"accuracy. The seven tree models differ by at most {f1_spread:.5f} in macro-F1, "
            "so Figure fig42b compares their error counts instead."
        ),
    )
    error_analysis = C.ML_DIR / "experiments" / winner / "error_analysis.json"
    ea = C.read_json(error_analysis)
    C.assert_equal(
        "winner error analysis: FN count", ea["false_negatives"], o[winner]["FN"], checks
    )
    C.assert_equal(
        "winner error analysis: FP count", ea["false_positives"], o[winner]["FP"], checks
    )
    C.assert_equal(
        "winner error analysis: distinct wrong vectors", ea["distinct_wrong_vectors"], 2, checks
    )
    C.assert_equal(
        "winner error analysis: repeats of the wrong vectors add up to the errors",
        sum(ea["most_repeated_wrong_vector_counts"]),
        o[winner]["FP"] + o[winner]["FN"],
        checks,
    )
    wrong_types = sorted(k for k, v in ea["by_traffic_type"].items() if v["errors"] > 0)
    C.assert_equal(
        "winner error analysis: errors per traffic type add up",
        sum(ea["by_traffic_type"][k]["errors"] for k in wrong_types),
        o[winner]["FP"] + o[winner]["FN"],
        checks,
    )
    repeats = ea["most_repeated_wrong_vector_counts"]
    repeat_txt = (
        f"repeated {repeats[0]} times each"
        if len(set(repeats)) == 1
        else "repeated " + " and ".join(map(str, repeats)) + " times"
    )
    C.register_figure(
        "fig42b_validation_errors_fpr",
        files=files_b,
        inputs=inputs + [C.input_record(error_analysis, f"{winner} error_analysis.json")],
        dataset="N-BaIoT",
        scope=val_scope,
        run_id="; ".join(r["run_id"] for r in overview),
        n="9 Full runs; FPR denominator 83,435 benign records",
        weighting="1 per record",
        sampling_transform=(
            "none; symmetric log axes (linear below 1 record / 0.001%) so zero is shown"
        ),
        caption="VALIDATION false positives (benign flagged malicious) and false negatives "
        "(malicious missed) per Full run, and the false-positive rate FP/(FP+TN); "
        "symmetric log axes, exact values labelled.",
        commentary=(
            f"The selected run {winner} makes {o[winner]['FP']} false positives and "
            f"{o[winner]['FN']} false negatives, against {o['rf_frac1_seed42']['FP']} and "
            f"{o['rf_frac1_seed42']['FN']} for the RF baseline and {lr['FP']} and {lr['FN']} "
            f"for LR. The seven tree models make between {min(errors)} and {max(errors)} "
            f"errors on {VALIDATION_ROWS:,} records, from a single seed, and the winner's "
            f"{o[winner]['FP'] + o[winner]['FN']} errors are only "
            f"{ea['distinct_wrong_vectors']} distinct feature vectors {repeat_txt} ("
            + " and ".join(t.replace("_", " ") for t in wrong_types)
            + ", per its error_analysis.json), so this ranking is not evidence of a stable "
            "advantage."
        ),
    )
    C.register_figure(
        "fig42c_validation_confusion",
        files=files_c,
        inputs=inputs,
        dataset="N-BaIoT",
        scope=val_scope,
        run_id="; ".join(rid for rid, _ in chosen),
        n="1,056,372 VALIDATION records per matrix",
        weighting="1 per record",
        sampling_transform=(
            "none; colour and percentages are row-normalised (share of each true class)"
        ),
        caption="VALIDATION confusion matrices for LR, the RF baseline and the selected XGBoost "
        "(rows = true class, columns = prediction; counts with row percentages).",
        commentary=(
            "Row normalisation keeps the 83,435 benign records visible next to 972,937 "
            "malicious ones: the benign-row error share is the FPR ("
            f"{C.fmt_pct(100 * lr['fpr'])} for LR, "
            f"{C.fmt_pct(100 * o['rf_frac1_seed42']['fpr'])} for RF, "
            f"{C.fmt_pct(100 * o[winner]['fpr'])} for the selected XGBoost). LR's errors are "
            "spread across both rows, whereas the tree models' few errors are almost all "
            "missed malicious records."
        ),
    )
    C.register_figure(
        "fig42d_test_confusion_selected",
        files=files_d,
        inputs=[C.input_record(TEST_RECEIPT)],
        dataset="N-BaIoT",
        scope="final TEST, single evaluation of the frozen model (1,061,266 records: 83,532 "
        "benign, 977,734 malicious)",
        run_id=test["selected_run_id"],
        n="1,061,266 TEST records",
        weighting="1 per record",
        sampling_transform="none; row-normalised colour and percentages",
        caption="Final TEST confusion matrix of the frozen XGBoost (xgb_frac1_seed42_lr01), "
        "read from the saved TEST receipt; no other model was evaluated on TEST.",
        commentary=(
            "On TEST the frozen model misclassifies 1 of 83,532 benign records "
            "(FPR 0.0012%) and 11 of 977,734 malicious records (macro-F1 0.99996), in line "
            "with its VALIDATION result. This is a single within-corpus run: all nine "
            "devices appear in every partition, so it does not show performance on unseen "
            "devices or future traffic. LR and RF have no TEST result in this evaluation."
        ),
    )
    C.write_log(
        "t42_classifier_figures",
        {
            "inputs": inputs + [C.input_record(TEST_RECEIPT)],
            "outputs": [C.rel(p) for p in outs]
            + [C.rel(md), *files_a, *files_b, *files_c, *files_d],
            "checks": checks,
        },
    )
    print(f"{len(checks)} checks PASS")


if __name__ == "__main__":
    main()
