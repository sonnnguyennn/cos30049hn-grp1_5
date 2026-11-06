"""CODE 4.2.5 - clustering figures from the saved K-Means outputs (no refit, no TEST).

Defaults to ml/notebooks/Clustering/results/full/ (selected run g3b_standard_k8_seed42 plus the
raw_k4_seed42 sensitivity run). Checks before plotting:
  * the outputs name the same G3B package and TRAIN/VALIDATION populations as the
    classifier comparison (metadata SHA-256 fingerprints);
  * each assignment file has one cluster per partition record and matches its saved hash;
  * cluster sizes and the saved VALIDATION composition agree with the assignment files;
  * optionally (--validation-labels), the composition is recomputed from the package's
    VALIDATION_y.npy, record by record.
Labels only DESCRIBE clusters after fitting; no cluster is called "benign" or "malicious".

Usage (from ml/):
  python analysis/duy_a2/scripts/t42_clustering_figures.py [--validation-labels <VALIDATION_y.npy>]
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import _common as C
import numpy as np

DEFAULT_RESULTS = C.ML_DIR / "notebooks" / "Clustering" / "results" / "full"
COMPARISON = C.ML_DIR / "artifacts" / "manifests" / "primary_classifier_comparison_20261105.csv"
PUBLISHED_MANIFEST = "6ab99e86397242e219bfa1f8490d8e03b169ec87a092af80cb3e7aef1e61147b"
ROWS = {"TRAIN": 4_944_968, "VALIDATION": 1_056_372}
VALIDATION_Y_SHA256 = "4b0dafa2e0caef115c1474e4caa2c6982f93c743805285c9de703b0823b70d71"


def read_csv(path):
    with Path(path).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def check_run(results_dir, run_id, checks, y_val=None):
    run = results_dir / run_id
    coverage = C.read_json(run / "prediction_coverage.json")
    assignments = {}
    for partition, rows in ROWS.items():
        path = run / f"{partition}_clusters.npy"
        C.assert_equal(
            f"{run_id} {partition} assignment file hash == saved",
            C.sha256_file(path),
            coverage[partition]["labels_sha256"],
            checks,
        )
        labels = np.load(path, allow_pickle=False)
        C.assert_equal(
            f"{run_id} {partition} one cluster per record", int(len(labels)), rows, checks
        )
        k = len(coverage[partition]["cluster_counts"])
        counts = np.bincount(labels.astype(np.int64), minlength=k).tolist()
        C.assert_equal(
            f"{run_id} {partition} cluster sizes == saved coverage",
            counts,
            coverage[partition]["cluster_counts"],
            checks,
        )
        assignments[partition] = labels
    comp = read_csv(run / "cluster_composition_validation.csv")
    C.assert_equal(
        f"{run_id} composition totals == VALIDATION sizes",
        [int(r["total"]) for r in comp],
        coverage["VALIDATION"]["cluster_counts"],
        checks,
    )
    C.assert_equal(
        f"{run_id} composition benign total",
        sum(int(r["benign_count"]) for r in comp),
        83_435,
        checks,
    )
    C.assert_equal(
        f"{run_id} composition malicious total",
        sum(int(r["malicious_count"]) for r in comp),
        972_937,
        checks,
    )
    if y_val is not None:
        k = len(comp)
        lab = assignments["VALIDATION"].astype(np.int64)
        recomputed = [
            [int(((lab == c) & (y_val == 0)).sum()), int(((lab == c) & (y_val == 1)).sum())]
            for c in range(k)
        ]
        C.assert_equal(
            f"{run_id} composition recomputed from package VALIDATION_y.npy",
            recomputed,
            [[int(r["benign_count"]), int(r["malicious_count"])] for r in comp],
            checks,
        )
    return coverage, comp


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=DEFAULT_RESULTS,
        help="Full clustering results directory in the checkout or a verified restore",
    )
    parser.add_argument(
        "--validation-labels",
        type=Path,
        help="package VALIDATION_y.npy (e.g. copy written by t41_nbaiot_extract_local.py)",
    )
    args = parser.parse_args()
    C.ensure_dirs()
    checks = []
    results_dir = args.results_dir.resolve()
    selection = C.read_json(results_dir / "selection.json")
    selected = selection["selected_run_id"]
    if selected != "g3b_standard_k8_seed42":
        raise ValueError("Unexpected selected run for the A2 clustering figures")
    identity = selection["identity"]
    C.assert_equal(
        "clustering package manifest == published G3B manifest",
        identity["manifest_sha256"],
        PUBLISHED_MANIFEST,
        checks,
    )
    cmp_rows = read_csv(COMPARISON)
    C.assert_equal(
        "clustering TRAIN population == classifier TRAIN population",
        identity["partitions"]["TRAIN"]["metadata_sha256"],
        {
            r["train_population_sha256"] for r in cmp_rows if r["train_population_kind"] == "full"
        }.pop(),
        checks,
    )
    C.assert_equal(
        "clustering VALIDATION population == classifier VALIDATION population",
        identity["partitions"]["VALIDATION"]["metadata_sha256"],
        {r["validation_population_sha256"] for r in cmp_rows}.pop(),
        checks,
    )
    C.assert_equal(
        "ground truth not used for fitting/selection", selection["ground_truth_used"], False, checks
    )
    y_val = None
    inputs = [C.input_record(results_dir / "selection.json")]
    if args.validation_labels:
        C.assert_equal(
            "VALIDATION_y.npy == package payload hash",
            C.sha256_file(args.validation_labels),
            VALIDATION_Y_SHA256,
            checks,
        )
        y_val = np.load(args.validation_labels, allow_pickle=False).astype(np.int64)
        inputs.append(
            {
                "label": "package VALIDATION_y.npy",
                "path": "VALIDATION_y.npy",
                "bytes": args.validation_labels.stat().st_size,
                "sha256": VALIDATION_Y_SHA256,
            }
        )

    runs = {}
    for run_id in (selected, "raw_k4_seed42"):
        runs[run_id] = check_run(results_dir, run_id, checks, y_val)
        inputs += [
            C.input_record(results_dir / run_id / f)
            for f in ("prediction_coverage.json", "cluster_composition_validation.csv")
        ]

    cluster_rows = []
    for run_id, (coverage, comp) in runs.items():
        tr, va = coverage["TRAIN"]["cluster_counts"], coverage["VALIDATION"]["cluster_counts"]
        for c, r in enumerate(comp):
            cluster_rows.append(
                {
                    "run_id": run_id,
                    "role": "selected (primary)" if run_id == selected else "sensitivity",
                    "cluster_id": c,
                    "train_rows": tr[c],
                    "train_share_percent": 100 * tr[c] / ROWS["TRAIN"],
                    "validation_rows": va[c],
                    "validation_share_percent": 100 * va[c] / ROWS["VALIDATION"],
                    "validation_benign": int(r["benign_count"]),
                    "validation_malicious": int(r["malicious_count"]),
                    "validation_malicious_fraction": float(r["malicious_fraction"]),
                    "malicious_lift_vs_validation": float(r["malicious_lift_vs_validation"]),
                    "label_scope": "entire VALIDATION, post-selection description",
                    "composition_check": "recomputed from VALIDATION_y.npy"
                    if y_val is not None
                    else "saved composition; totals checked",
                }
            )
    internal = {r["run_id"]: r for r in C.read_json(results_dir / "internal_metrics.json")}
    external = {r["run_id"]: r for r in C.read_json(results_dir / "external_metrics.json")}
    inputs += [
        C.input_record(results_dir / "internal_metrics.json"),
        C.input_record(results_dir / "external_metrics.json"),
    ]
    metric_rows = []
    for run_id in runs:
        i, e = internal[run_id], external[run_id]
        metric_rows += [
            {
                "run_id": run_id,
                "metric": "silhouette (mean of 3 repeats)",
                "value": i["silhouette_mean"],
                "spread": f"sample sd {i['silhouette_sample_std']:.6f}",
                "computed_on": "SAMPLE",
                "rows": f"3 x {i['silhouette_rows_per_repeat']:,} VALIDATION records",
            },
            {
                "run_id": run_id,
                "metric": "Davies-Bouldin index",
                "value": i["davies_bouldin"],
                "spread": "",
                "computed_on": "SAMPLE",
                "rows": f"{i['geometry_eval_rows']:,} VALIDATION records",
            },
            {
                "run_id": run_id,
                "metric": "Calinski-Harabasz index",
                "value": i["calinski_harabasz"],
                "spread": "",
                "computed_on": "SAMPLE",
                "rows": f"{i['geometry_eval_rows']:,} VALIDATION records",
            },
            {
                "run_id": run_id,
                "metric": "mean squared distance to centre",
                "value": i["full_validation_mean_squared_distance"],
                "spread": "",
                "computed_on": "FULL PARTITION",
                "rows": "1,056,372 VALIDATION records",
            },
            {
                "run_id": run_id,
                "metric": "ARI vs binary label",
                "value": e["ari"],
                "spread": "",
                "computed_on": "FULL PARTITION",
                "rows": f"{e['external_eval_rows']:,} VALIDATION records",
            },
            {
                "run_id": run_id,
                "metric": "NMI vs binary label",
                "value": e["nmi"],
                "spread": "",
                "computed_on": "FULL PARTITION",
                "rows": f"{e['external_eval_rows']:,} VALIDATION records",
            },
        ]
    t1 = C.write_csv(C.TABLE_DIR / "t42_clustering_clusters.csv", cluster_rows)
    t2 = C.write_csv(C.TABLE_DIR / "t42_clustering_metrics.csv", metric_rows)

    # Figure: sizes (TRAIN, VALIDATION) and VALIDATION composition, selected run
    plt = C.setup_matplotlib()
    sel = [r for r in cluster_rows if r["run_id"] == selected]
    fig, axes = plt.subplots(
        1,
        2,
        figsize=(C.FULL_WIDTH_IN, 3.0),
        sharey=True,
        gridspec_kw={"width_ratios": [1, 1.1]},
        layout="constrained",
    )
    y = np.arange(len(sel))[::-1]
    ax = axes[0]
    ring_s = C.DOT_S + 4
    ax.scatter(
        [r["train_rows"] for r in sel],
        y + 0.24,
        s=C.DOT_S,
        color=C.INK_2,
        edgecolor="white",
        linewidth=0.8,
        label="TRAIN",
        zorder=3,
    )
    ax.scatter(
        [r["validation_rows"] for r in sel],
        y - 0.24,
        s=ring_s,
        facecolor="white",
        edgecolor=C.INK_2,
        linewidth=1.1,
        label="VALIDATION",
        zorder=3,
    )
    for yi, r in zip(y, sel):
        C.label_point(ax, r["train_rows"], yi + 0.24, f"{r['train_rows']:,}", C.DOT_S)
        C.label_point(ax, r["validation_rows"], yi - 0.24, f"{r['validation_rows']:,}", ring_s)
    ax.set_xscale("log")
    ax.set_xlim(1e2, 1e7)
    ax.set_ylim(-0.6, len(sel) - 0.4)
    ax.set_yticks(y)
    ax.set_yticklabels([f"cluster {r['cluster_id']}" for r in sel])
    ax.tick_params(axis="y", length=0)
    ax.set_xlabel("records per cluster (log scale)")
    ax.set_title("(a) Cluster sizes", loc="left")
    C.style_grid(ax, "x")
    handles_a, names_a = ax.get_legend_handles_labels()
    ax = axes[1]
    ben = [r["validation_benign"] / r["validation_rows"] for r in sel]
    mal = [r["validation_malicious"] / r["validation_rows"] for r in sel]
    ax.barh(y, ben, color=C.BENIGN, height=0.62, label="benign", zorder=2)
    ax.barh(
        y,
        mal,
        left=ben,
        color=C.MALICIOUS,
        height=0.62,
        label="malicious",
        zorder=2,
        edgecolor="white",
        linewidth=1.0,
    )
    for yi, r in zip(y, sel):
        share = r["validation_malicious"] / r["validation_rows"]
        C.assert_close(
            f"cluster {r['cluster_id']} malicious share == saved fraction",
            share,
            r["validation_malicious_fraction"],
            checks,
            tol=1e-12,
        )
        C.label_point(
            ax, 1.0, yi, f"{C.fmt_pct(100 * share)} malicious (n={r['validation_rows']:,})"
        )
    overall_benign = 83_435 / ROWS["VALIDATION"]
    ax.axvline(
        overall_benign,
        color=C.INK_2,
        linewidth=0.8,
        zorder=3,
        label=f"benign share of all VALIDATION ({C.fmt_pct(100 * overall_benign)})",
    )
    ax.set_xlim(0, 1)
    ax.tick_params(axis="y", length=0)
    ax.set_xlabel("share of the cluster's VALIDATION records")
    ax.set_title("(b) Label composition, all VALIDATION", loc="left")
    handles_b, names_b = ax.get_legend_handles_labels()
    fig.legend(handles_a, names_a, loc="outside upper left", ncol=2)
    fig.legend(handles_b, names_b, loc="outside upper right", ncol=3)
    fig.get_layout_engine().set(wspace=0.04)
    files = C.save_figure(fig, "fig42e_clustering_sizes_composition")
    plt.close(fig)

    i, e = internal[selected], external[selected]
    largest_two = sorted((r["validation_rows"] for r in sel), reverse=True)[:2]
    two_largest_share = 100 * sum(largest_two) / ROWS["VALIDATION"]
    small = sum(1 for r in sel if r["validation_share_percent"] < 1)
    pure = [r["cluster_id"] for r in sel if r["validation_malicious"] == 0]
    near_pure = [
        r
        for r in sel
        if 0 < r["validation_malicious"] and r["validation_malicious_fraction"] < 0.05
    ]
    C.register_figure(
        "fig42e_clustering_sizes_composition",
        files=files,
        inputs=inputs,
        dataset="N-BaIoT",
        scope="TRAIN and VALIDATION assignments of the selected K-Means run (TEST not opened)",
        run_id=selected,
        n="TRAIN 4,944,968; VALIDATION 1,056,372 (every record assigned)",
        weighting="1 per record",
        sampling_transform="sizes and composition use full partitions; silhouette/DBI/CH in the "
        "metrics table use VALIDATION samples",
        caption=f"K-Means run {selected} (K=8, TRAIN-only standardisation): cluster sizes on "
        "TRAIN and VALIDATION, and the true-label composition of each cluster on the "
        "entire VALIDATION partition. Labels were used only after fitting and selection.",
        commentary=(
            f"Two clusters hold {two_largest_share:.1f}% "
            f"of VALIDATION records, and {small} of the 8 clusters each hold under 1%. "
            f"Clusters {' and '.join(map(str, pure))} contain no malicious VALIDATION records "
            "and "
            + "; ".join(
                f"cluster {r['cluster_id']} is "
                f"{C.fmt_pct(100 * r['validation_benign'] / r['validation_rows'])} benign"
                for r in near_pure
            )
            + ", but the two large clusters are mixed and "
            "mostly malicious, so the partition aligns only weakly with the binary label "
            f"(ARI {e['ari']:.4f}, NMI {e['nmi']:.4f} on all of VALIDATION). Silhouette "
            f"{i['silhouette_mean']:.3f} is a sample estimate (3 x 1,500 records) and K=8 "
            "used one seed, so no stability claim is made."
        ),
    )
    C.write_log(
        "t42_clustering_figures",
        {"inputs": inputs, "outputs": [C.rel(t1), C.rel(t2), *files], "checks": checks},
    )
    print(f"{len(checks)} checks PASS")


if __name__ == "__main__":
    main()
