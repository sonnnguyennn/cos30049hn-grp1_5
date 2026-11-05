"""CODE 4.3 - Bot-IoT Full Dummy/LR results: row-weighted vs group-weighted VALIDATION metrics.

Inputs: the Full run outputs (Bot_IoT_Full_experiment_outputs, run
bot_iot_secondary_full_20261102T062917639798Z) and the Bot-IoT v2 package manifest.
Nothing is re-fitted. Saved predictions, labels and metadata are hashed against the run's own
output_checksums.json, then:
  * row_primary metrics (weight 1 per record) are recomputed from predictions + labels;
  * group_sensitivity metrics use weight 1/n_g, where n_g is the ORIGINAL exact-X group size
    stored in VALIDATION_metadata.npy (13 raw predictors, never the 36 encoded columns, never
    split by label). Weighted confusion values stay weighted masses.
Both must match the saved JSON. Metrics the JSON does not store (benign precision/F1,
malicious F1) are computed from the stored confusion values and flagged as such.

Usage (from ml/):
  python analysis/duy_a2/scripts/t43_botiot_analysis.py --full-outputs <dir> --botiot-package <dir>
"""

from __future__ import annotations

import argparse
from pathlib import Path

import _common as C
import numpy as np

BRIEF = {  # check values given in the task brief (section 3.2 / 3.3)
    "row TN/FP/FN/TP": (7, 89, 3, 733_605),
    "row accuracy": 0.999875,
    "row benign recall": 7 / 96,
    "row FPR": 89 / 96,
    "row macro-F1": 0.566006,
    "group macro-F1": 0.580328,
    "group benign recall": 0.0909,
    "VALIDATION benign rows": 96,
    "VALIDATION benign groups": 77,
}
STORED_KEYS = (
    "FPR",
    "accuracy_supplementary",
    "benign_recall",
    "macro_f1",
    "malicious_precision",
    "malicious_recall",
)


def derived(tn, fp, fn, tp):
    def div(a, b):
        return None if b == 0 else a / b

    bp, br = div(tn, tn + fn), div(tn, tn + fp)
    mp, mr = div(tp, tp + fp), div(tp, tp + fn)
    bf = div(2 * tn, 2 * tn + fn + fp)
    mf = div(2 * tp, 2 * tp + fp + fn)
    return {
        "accuracy": div(tn + tp, tn + fp + fn + tp),
        "benign_precision": bp,
        "benign_recall": br,
        "benign_f1": bf,
        "malicious_precision": mp,
        "malicious_recall": mr,
        "malicious_f1": mf,
        "macro_f1": None if None in (bf, mf) else (bf + mf) / 2,
        "fpr": div(fp, fp + tn),
        "benign_support": tn + fp,
        "malicious_support": fn + tp,
    }


def confusion(y, pred, w=None):
    w = np.ones(len(y)) if w is None else w
    return {
        "TN": float(w[(y == 0) & (pred == 0)].sum()),
        "FP": float(w[(y == 0) & (pred == 1)].sum()),
        "FN": float(w[(y == 1) & (pred == 0)].sum()),
        "TP": float(w[(y == 1) & (pred == 1)].sum()),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--full-outputs", required=True, type=Path)
    parser.add_argument("--botiot-package", required=True, type=Path)
    args = parser.parse_args()
    C.ensure_dirs()
    checks = []
    out_dir, pkg = args.full_outputs.resolve(), args.botiot_package.resolve()
    sums = C.read_json(out_dir / "output_checksums.json")
    used = [
        "lr_result.json",
        "dummy_result.json",
        "VALIDATION_y.npy",
        "VALIDATION_metadata.npy",
        "lr_VALIDATION_predictions.npy",
        "dummy_VALIDATION_predictions.npy",
    ]
    for name in used:
        C.assert_equal(
            f"Full output {name} hash == run checksum list",
            C.sha256_file(out_dir / name),
            sums[name],
            checks,
        )
    manifest = C.read_json(pkg / "manifest.json")
    C.assert_equal(
        "VALIDATION_y.npy is the package payload",
        sums["VALIDATION_y.npy"],
        manifest["files"]["VALIDATION_y.npy"]["sha256"],
        checks,
    )
    C.assert_equal(
        "VALIDATION_metadata.npy is the package payload",
        sums["VALIDATION_metadata.npy"],
        manifest["files"]["VALIDATION_metadata.npy"]["sha256"],
        checks,
    )

    y = np.load(out_dir / "VALIDATION_y.npy", allow_pickle=False).astype(np.int64)
    meta = np.load(out_dir / "VALIDATION_metadata.npy", allow_pickle=False)
    groups, sizes = np.asarray(meta["group"]), np.asarray(meta["group_size"]).astype(np.float64)
    uniq, inverse, counts = np.unique(groups, return_inverse=True, return_counts=True)
    C.assert_equal(
        "stored group_size == size of that group in VALIDATION",
        bool(np.array_equal(counts[inverse], sizes.astype(np.int64))),
        True,
        checks,
    )
    C.assert_equal(
        "VALIDATION distinct exact-X groups == manifest",
        int(len(uniq)),
        manifest["expected_partitions"]["VALIDATION"]["distinct_X_groups"],
        checks,
    )
    weights = 1.0 / sizes

    results, rows, group_detail = {}, [], []
    for model in ("dummy", "lr"):
        res = C.read_json(out_dir / f"{model}_result.json")
        C.assert_equal(f"{model}: mode is Full", res["mode"], "full", checks)
        C.assert_equal(f"{model}: not diagnostic-only", res["diagnostic_only"], False, checks)
        C.assert_equal(
            f"{model}: TRAIN population == package TRAIN membership",
            res["train_population_sha256"],
            manifest["expected_partitions"]["TRAIN"]["membership_sha256"],
            checks,
        )
        C.assert_equal(
            f"{model}: VALIDATION population == package VALIDATION membership",
            res["validation_population_sha256"],
            manifest["expected_partitions"]["VALIDATION"]["membership_sha256"],
            checks,
        )
        pred = np.load(out_dir / f"{model}_VALIDATION_predictions.npy", allow_pickle=False).astype(
            np.int64
        )
        C.assert_equal(
            f"{model}: one prediction per VALIDATION record", int(len(pred)), int(len(y)), checks
        )
        # identical feature vectors must receive identical predictions
        per_group_max = np.zeros(len(uniq))
        per_group_min = np.ones(len(uniq))
        np.maximum.at(per_group_max, inverse, pred)
        np.minimum.at(per_group_min, inverse, pred)
        C.assert_equal(
            f"{model}: every exact-X group received one prediction",
            bool(np.array_equal(per_group_max, per_group_min)),
            True,
            checks,
        )
        for weighting, key, w in (
            ("row (1 per record)", "row_primary", None),
            ("group (1/n_g per original exact-X group)", "group_sensitivity", weights),
        ):
            stored = res["metrics"][key]
            cm = confusion(y, pred, w)
            for cell in ("TN", "FP", "FN", "TP"):
                C.assert_close(
                    f"{model} {key} {cell} recomputed",
                    cm[cell],
                    stored["confusion"][cell],
                    checks,
                    tol=1e-6,
                )
            d = derived(*(cm[c] for c in ("TN", "FP", "FN", "TP")))
            mapping = {
                "FPR": "fpr",
                "accuracy_supplementary": "accuracy",
                "benign_recall": "benign_recall",
                "macro_f1": "macro_f1",
                "malicious_precision": "malicious_precision",
                "malicious_recall": "malicious_recall",
            }
            for skey in STORED_KEYS:
                C.assert_close(
                    f"{model} {key} {skey} recomputed",
                    d[mapping[skey]],
                    stored[skey],
                    checks,
                    tol=1e-9,
                )
            row = {
                "model": {"dummy": "Dummy (most_frequent)", "lr": "LR (lbfgs, C 1.0)"}[model],
                "run_id": res["run_id"],
                "partition": "VALIDATION",
                "weighting": weighting,
                "confusion_kind": stored["confusion_kind"],
                **cm,
                **d,
                "computed_not_stored": (
                    "benign_precision, benign_f1, malicious_f1 (from stored confusion)"
                ),
            }
            rows.append(row)
            results[(model, key)] = row
        if model == "lr":
            benign_groups = np.unique(inverse[y == 0])
            for g in benign_groups:
                members = inverse == g
                group_detail.append(
                    {
                        "group_sha256_prefix": uniq[g][:12].decode(),
                        "rows": int(members.sum()),
                        "lr_prediction": "malicious (FP)"
                        if pred[members][0] == 1
                        else "benign (TN)",
                    }
                )
    group_detail.sort(key=lambda r: (-r["rows"], r["lr_prediction"], r["group_sha256_prefix"]))

    lr_row, lr_grp = results[("lr", "row_primary")], results[("lr", "group_sensitivity")]
    brief_checks = [
        (
            "row TN/FP/FN/TP",
            BRIEF["row TN/FP/FN/TP"],
            tuple(int(lr_row[c]) for c in ("TN", "FP", "FN", "TP")),
            0,
        ),
        ("row accuracy (about 99.9875%)", BRIEF["row accuracy"], lr_row["accuracy"], 5e-7),
        ("row benign recall 7/96", BRIEF["row benign recall"], lr_row["benign_recall"], 1e-12),
        ("row FPR 89/96", BRIEF["row FPR"], lr_row["fpr"], 1e-12),
        ("row macro-F1 (about 0.566006)", BRIEF["row macro-F1"], lr_row["macro_f1"], 5e-7),
        ("group macro-F1 (about 0.580328)", BRIEF["group macro-F1"], lr_grp["macro_f1"], 5e-7),
        (
            "group benign recall (about 9.09%)",
            BRIEF["group benign recall"],
            lr_grp["benign_recall"],
            5e-5,
        ),
        ("VALIDATION benign rows", BRIEF["VALIDATION benign rows"], int((y == 0).sum()), 0),
        ("VALIDATION benign groups", BRIEF["VALIDATION benign groups"], len(group_detail), 0),
    ]
    brief_rows = []
    for name, expected, actual, tol in brief_checks:
        if tol == 0:
            C.assert_equal(f"brief: {name}", actual, expected, checks)
        else:
            C.assert_close(f"brief: {name}", actual, expected, checks, tol=tol)
        brief_rows.append(
            {"check": name, "expected_from_brief": expected, "actual": actual, "status": "PASS"}
        )

    comparison = [
        {
            "aspect": "predictors",
            "N-BaIoT": "115 numeric (float64)",
            "Bot-IoT": "13 raw: 10 numeric + 3 categorical (flgs, proto, state)",
        },
        {
            "aspect": "model input columns",
            "N-BaIoT": "115 (raw for trees; TRAIN-scaled for LR)",
            "Bot-IoT": "36 encoded (10 TRAIN-scaled numeric + 26 one-hot incl. 3 UNKNOWN slots)",
        },
        {"aspect": "records in corpus", "N-BaIoT": "7,062,606", "Bot-IoT": "3,668,522 (5% subset)"},
        {
            "aspect": "TRAIN / VALIDATION / TEST",
            "N-BaIoT": "4,944,968 / 1,056,372 / 1,061,266",
            "Bot-IoT": "2,201,114 / 733,704 / 733,704",
        },
        {
            "aspect": "benign share of corpus",
            "N-BaIoT": "7.87% (555,932)",
            "Bot-IoT": "0.013% (477)",
        },
        {
            "aspect": "benign records in VALIDATION",
            "N-BaIoT": "83,435",
            "Bot-IoT": "96 (77 exact-X groups)",
        },
        {
            "aspect": "duplicate excess on model predictors",
            "N-BaIoT": "64.85% of rows (115 features)",
            "Bot-IoT": "81.67% of rows (13 predictors); 0% on all 43 source fields",
        },
        {
            "aspect": "models evaluated",
            "N-BaIoT": "7 RF/XGB Full runs + LR + Dummy; final TEST for selected XGB only",
            "Bot-IoT": "Dummy + LR Full baseline; VALIDATION only, TEST not evaluated",
        },
        {
            "aspect": "best VALIDATION macro-F1",
            "N-BaIoT": "0.999941 (xgb_frac1_seed42_lr01)",
            "Bot-IoT": f"{lr_row['macro_f1']:.6f} row / {lr_grp['macro_f1']:.6f} group (LR)",
        },
        {
            "aspect": "benign recall of that model",
            "N-BaIoT": "1.0 (0 of 83,435 benign flagged)",
            "Bot-IoT": (
                f"{lr_row['benign_recall']:.4f} row (7/96) / "
                f"{lr_grp['benign_recall']:.4f} group (7/77)"
            ),
        },
        {
            "aspect": "design history",
            "N-BaIoT": "split and policy fixed before any model was fitted",
            "Bot-IoT": "v2 preprocessing revised after structural TEST diagnostics "
            "(before any model fit); "
            "TEST is not design-blind",
        },
        {
            "aspect": "relationship",
            "N-BaIoT": "separate experiment",
            "Bot-IoT": "separate experiment; no model is transferred between datasets",
        },
    ]

    t1 = C.write_csv(C.TABLE_DIR / "t43_botiot_validation_row_vs_group.csv", rows)
    t2 = C.write_csv(C.TABLE_DIR / "t43_botiot_brief_checks.csv", brief_rows)
    t3 = C.write_csv(C.TABLE_DIR / "t43_dataset_comparison.csv", comparison)
    t4 = C.write_csv(C.TABLE_DIR / "t43_botiot_validation_benign_groups_lr.csv", group_detail)

    files_a, files_b, files_c = figures(results, group_detail)
    inputs = [
        {
            "label": f"Full output {n}",
            "path": n,
            "bytes": (out_dir / n).stat().st_size,
            "sha256": sums[n],
        }
        for n in used
    ] + [C.input_record(pkg / "manifest.json", "Bot-IoT package manifest")]
    run_id = lr_row["run_id"]
    big = group_detail[0]
    C.register_figure(
        "fig43a_botiot_confusion_row",
        files=files_a,
        inputs=inputs,
        dataset="Bot-IoT",
        run_id=run_id,
        scope="VALIDATION (733,704 records: 96 benign, 733,608 malicious)",
        n="733,704 per matrix",
        weighting="1 per record (row_primary)",
        sampling_transform="none; row-normalised colour and percentages",
        caption="Bot-IoT VALIDATION confusion matrices for the Full Dummy and LR baselines "
        "(integer "
        "record counts, rows = true class, percentages of each true class).",
        commentary=(
            "LR reaches 99.987% accuracy while flagging 89 of the 96 benign records as "
            "malicious (FPR 92.7%, benign recall 7.3%); the Dummy model scores 99.987% too by "
            "never predicting benign. Because 99.987% of VALIDATION records are malicious, "
            "accuracy is dominated by the malicious row and hides that benign traffic is "
            "almost never recognised."
        ),
    )
    C.register_figure(
        "fig43b_botiot_row_vs_group",
        files=files_b,
        inputs=inputs,
        dataset="Bot-IoT",
        run_id=run_id,
        scope="VALIDATION",
        n="733,704 records; 138,060 exact-X groups (77 benign)",
        weighting="row: 1 per record; group: 1/n_g per original exact-X group (13 raw predictors)",
        sampling_transform="none; 0-1 scale",
        caption="Row-weighted versus group-weighted VALIDATION metrics for Dummy and LR. Group "
        "weighting gives every original exact-X group a total weight of 1; it is not label "
        "balancing.",
        commentary=(
            f"Down-weighting repeated rows raises LR macro-F1 from {lr_row['macro_f1']:.4f} to "
            f"{lr_grp['macro_f1']:.4f} and benign recall from {lr_row['benign_recall']:.1%} to "
            f"{lr_grp['benign_recall']:.1%}, but FPR stays above 90% either way, so the weak "
            "benign detection is not an artefact of duplicates. The 77 benign groups are not "
            "77 guaranteed-independent observations (they can share capture context), and "
            "group weighting does not balance the two classes."
        ),
    )
    C.register_figure(
        "fig43c_botiot_benign_groups_lr",
        files=files_c,
        inputs=inputs,
        dataset="Bot-IoT",
        run_id=run_id,
        scope="VALIDATION benign records only (96 records, 77 exact-X groups)",
        n="96 records / 77 groups",
        weighting="sizes are record counts per group",
        sampling_transform="none",
        caption="Sizes of the 77 benign exact-X groups in Bot-IoT VALIDATION and the LR "
        "prediction each group received (identical vectors always receive the same "
        "prediction). Groups are ranked by size; groups of equal size are listed TN first, "
        "then by group hash.",
        commentary=(
            f"The largest benign group alone holds {big['rows']} of the 96 benign records "
            f"({big['rows'] / 96:.1%}) and LR predicts it {big['lr_prediction'].split()[0]}, "
            "which is why "
            "row-weighted and group-weighted benign recall differ. All 7 correctly "
            "recognised benign records are single-record groups. With only 77 groups, one "
            "group more or less changes benign recall by 1.3 percentage points."
        ),
    )
    C.write_log(
        "t43_botiot_analysis",
        {
            "inputs": inputs,
            "outputs": [C.rel(t) for t in (t1, t2, t3, t4)] + files_a + files_b + files_c,
            "checks": checks,
        },
    )
    print(f"{len(checks)} checks PASS")
    for r in rows:
        print(
            {
                k: (round(r[k], 6) if isinstance(r[k], float) else r[k])
                for k in (
                    "model",
                    "weighting",
                    "TN",
                    "FP",
                    "FN",
                    "TP",
                    "accuracy",
                    "benign_precision",
                    "benign_recall",
                    "benign_f1",
                    "malicious_f1",
                    "macro_f1",
                    "fpr",
                )
            }
        )


def figures(results, group_detail):
    plt = C.setup_matplotlib()
    fig, axes = plt.subplots(1, 2, figsize=(C.FULL_WIDTH_IN * 0.72, 2.15), layout="constrained")
    for k, (ax, model, name) in enumerate(zip(axes, ("dummy", "lr"), ("Dummy", "LR"))):
        r = results[(model, "row_primary")]
        C.draw_confusion(
            ax,
            r["TN"],
            r["FP"],
            r["FN"],
            r["TP"],
            f"{name}\nVALIDATION, row-weighted",
            ylabels=(k == 0),
        )
    files_a = C.save_figure(fig, "fig43a_botiot_confusion_row")
    plt.close(fig)

    metrics = [
        ("accuracy", "accuracy"),
        ("macro_f1", "macro-F1"),
        ("benign_recall", "benign recall"),
        ("fpr", "FPR"),
    ]
    fig, axes = plt.subplots(
        1, 2, figsize=(C.FULL_WIDTH_IN, 2.1), sharey=True, layout="constrained"
    )
    for ax, model, name in zip(axes, ("dummy", "lr"), ("(a) Dummy", "(b) LR")):
        y = np.arange(len(metrics))[::-1]
        for k, (key, wname, color) in enumerate(
            (
                ("row_primary", "row-weighted", C.INK_2),
                ("group_sensitivity", "group-weighted", C.MUTED),
            )
        ):
            vals = [results[(model, key)][m] for m, _ in metrics]
            off = y + (0.2 if k == 0 else -0.2)
            ax.barh(off, vals, height=0.36, color=color, label=wname, zorder=2)
            for yo, v in zip(off, vals):
                C.label_point(ax, v, yo, "0" if v == 0 else ("1" if v == 1 else f"{v:.5f}"))
        ax.set_yticks(y)
        ax.set_yticklabels([m for _, m in metrics])
        ax.set_xlim(0, 1.25)
        ax.set_ylim(-0.6, len(metrics) - 0.4)
        ax.set_xticks([0, 0.25, 0.5, 0.75, 1.0])
        ax.set_title(name, loc="left")
        ax.set_xlabel("value (0-1 scale)")
        ax.tick_params(axis="y", length=0)
        C.style_grid(ax, "x")
    handles, names = axes[1].get_legend_handles_labels()
    fig.legend(handles, names, loc="outside upper right", ncol=2)
    fig.get_layout_engine().set(wspace=0.04)
    files_b = C.save_figure(fig, "fig43b_botiot_row_vs_group")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(C.FULL_WIDTH_IN, 1.6), layout="constrained")
    x = np.arange(len(group_detail))
    colors = [
        C.BENIGN if g["lr_prediction"].startswith("benign") else C.MALICIOUS for g in group_detail
    ]
    ax.bar(x, [g["rows"] for g in group_detail], color=colors, width=0.75, zorder=2)
    ax.set_xlim(-1, len(group_detail))
    last = len(group_detail)
    ticks = [1] + list(range(10, last - 4, 10)) + [last]  # 1-based group ranks
    ax.set_xticks([t - 1 for t in ticks])
    ax.set_xticklabels([str(t) for t in ticks])
    ax.set_xlabel(f"benign exact-X groups ranked by size, 1 = largest ({last} groups)")
    ax.set_ylabel("records in group")
    C.style_grid(ax, "y")
    from matplotlib.patches import Patch

    fig.legend(
        handles=[
            Patch(color=C.BENIGN, label="LR predicts benign (TN)"),
            Patch(color=C.MALICIOUS, label="LR predicts malicious (FP)"),
        ],
        loc="outside upper right",
        ncol=2,
    )
    files_c = C.save_figure(fig, "fig43c_botiot_benign_groups_lr")
    plt.close(fig)
    return files_a, files_b, files_c


if __name__ == "__main__":
    main()
