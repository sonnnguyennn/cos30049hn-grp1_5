"""CODE 4.1.3 - duplicate (identical feature vector) summary for both datasets.

Terminology used in every table and caption:
  * rows in repeated groups - every row whose feature vector occurs 2+ times;
  * excess (redundant) rows - rows left over if each distinct vector were kept once
    (= rows - distinct vectors = rows in repeated groups - repeated groups).
Bot-IoT is reported for BOTH definitions: all 43 observed non-label source fields (no
duplicates) and the 13 model predictors (many duplicates). Nothing is deduplicated here.

Usage (from ml/):
  python analysis/duy_a2/scripts/t41_duplicates.py --botiot-package <dir>
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import _common as C
import numpy as np

AUDIT = C.ML_DIR / "artifacts" / "audit"
MANIFESTS = C.ML_DIR / "artifacts" / "manifests"
NB_DUP = AUDIT / "n_baiot_duplicate_summary.json"
NB_NUMERIC = AUDIT / "g3a_numeric_equivalence_summary.json"
NB_EFFECTIVE = AUDIT / "n_baiot_effective_imbalance.csv"
BI_DUP_SOURCE = AUDIT / "bot_iot_duplicate_summary.json"
BI_SPLIT = MANIFESTS / "bot_iot_candidate_proposed_split_summary.json"


def group_stats(groups: np.ndarray, sizes: np.ndarray | None = None):
    uniq, inverse, counts = np.unique(groups, return_inverse=True, return_counts=True)
    if sizes is not None and not np.array_equal(counts[inverse], sizes):
        raise AssertionError("stored group_size disagrees with counted group size")
    repeated = counts >= 2
    return {
        "rows": int(len(groups)),
        "distinct_vectors": int(len(uniq)),
        "repeated_groups": int(repeated.sum()),
        "rows_in_repeated_groups": int(counts[repeated].sum()),
        "excess_rows": int(len(groups) - len(uniq)),
        "largest_group_rows": int(counts.max()),
    }


def overall_rows(checks, botiot_package: Path):
    rows = []
    nb = C.read_json(NB_DUP)
    num = C.read_json(NB_NUMERIC)
    nb_row = {
        "dataset": "N-BaIoT",
        "scope": "full corpus (historical audit)",
        "feature_view": "all 115 predictors (exact values)",
        "rows": nb["total_rows"],
        "distinct_vectors": nb["unique_records"],
        "repeated_groups": nb["duplicate_group_count"],
        "rows_in_repeated_groups": nb["duplicate_row_occurrences"],
        "excess_rows": nb["duplicate_excess_rows"],
        "cross_label_groups": nb["same_feature_benign_malicious_conflict"]["group_count"],
        "cross_partition_group_overlap": num["evaluation_group_cross_partition_overlap_count"],
        "source": f"{C.rel(NB_DUP)}; {C.rel(NB_NUMERIC)}",
    }
    C.assert_equal(
        "N-BaIoT numeric groups == lexical groups",
        num["unique_evaluation_group_count"],
        nb["unique_records"],
        checks,
    )
    rows.append(nb_row)

    src = C.read_json(BI_DUP_SOURCE)["all_features_5pct_shards"]["all_43_observed_non_label_fields"]
    rows.append(
        {
            "dataset": "Bot-IoT",
            "scope": "full 5% corpus (historical audit)",
            "feature_view": "all 43 observed non-label source fields",
            "rows": src["total_rows"],
            "distinct_vectors": src["unique_records"],
            "repeated_groups": src["duplicate_group_count"],
            "rows_in_repeated_groups": src["duplicate_row_occurrences"],
            "excess_rows": src["duplicate_excess_rows"],
            "cross_label_groups": 0,
            "cross_partition_group_overlap": None,
            "source": C.rel(BI_DUP_SOURCE),
        }
    )

    split = C.read_json(BI_SPLIT)
    st = split["statistics"]
    rows.append(
        {
            "dataset": "Bot-IoT",
            "scope": "full 5% corpus (candidate scan)",
            "feature_view": "13 model predictors (exact-X groups)",
            "rows": st["total_observations"],
            "distinct_vectors": st["unique_X_groups"],
            "repeated_groups": st["repeated_groups"],
            "rows_in_repeated_groups": st["rows_involved_in_duplicates"],
            "excess_rows": st["duplicate_excess_rows"],
            "cross_label_groups": split["binary_label_conflicts"]["groups"],
            "cross_partition_group_overlap": split["exact_tuple_partition_overlap_count"],
            "source": C.rel(BI_SPLIT),
        }
    )

    manifest = C.read_json(botiot_package / "manifest.json")
    per_partition_class = []
    for partition in ("TRAIN", "VALIDATION"):
        meta = np.load(
            botiot_package / f"{partition}_metadata.npy", mmap_mode="r", allow_pickle=False
        )
        y = np.load(botiot_package / f"{partition}_y.npy", mmap_mode="r", allow_pickle=False)
        groups = np.asarray(meta["group"])
        stats = group_stats(groups, np.asarray(meta["group_size"]))
        exp = manifest["expected_partitions"][partition]
        C.assert_equal(
            f"Bot-IoT {partition} distinct groups == manifest",
            stats["distinct_vectors"],
            exp["distinct_X_groups"],
            checks,
        )
        y = np.asarray(y)
        mixed = 0
        for cls, name in ((0, "benign"), (1, "malicious")):
            cstats = group_stats(groups[y == cls])
            C.assert_equal(
                f"Bot-IoT {partition} {name} distinct groups == manifest",
                cstats["distinct_vectors"],
                exp["distinct_groups_per_class"][name],
                checks,
            )
            per_partition_class.append(
                {"dataset": "Bot-IoT", "partition": partition, "class": name, **cstats}
            )
        both = len(np.intersect1d(groups[y == 0], groups[y == 1]))
        mixed = int(both)
        rows.append(
            {
                "dataset": "Bot-IoT",
                "scope": f"{partition} partition (package metadata)",
                "feature_view": "13 model predictors (exact-X groups)",
                **{
                    k: stats[k]
                    for k in (
                        "rows",
                        "distinct_vectors",
                        "repeated_groups",
                        "rows_in_repeated_groups",
                        "excess_rows",
                    )
                },
                "cross_label_groups": mixed,
                "cross_partition_group_overlap": 0,
                "source": f"package {partition}_metadata.npy (group, group_size)",
            }
        )
    for r in rows:
        C.assert_equal(
            f"{r['dataset']} {r['scope']} {r['feature_view']}: rows - distinct == excess",
            r["rows"] - r["distinct_vectors"],
            r["excess_rows"],
            checks,
        )
        C.assert_equal(
            f"{r['dataset']} {r['scope']} {r['feature_view']}: in-repeated - groups == excess",
            r["rows_in_repeated_groups"] - r["repeated_groups"],
            r["excess_rows"],
            checks,
        )
        r["excess_percent_of_rows"] = round(100 * r["excess_rows"] / r["rows"], 4)
        r["rows_in_repeated_percent"] = round(100 * r["rows_in_repeated_groups"] / r["rows"], 4)
    return rows, per_partition_class


def by_class_rows(checks):
    out = []
    with NB_EFFECTIVE.open(newline="", encoding="utf-8") as handle:
        eff = [r for r in csv.DictReader(handle) if r["label_level"] == "binary"]
    for r in eff:
        out.append(
            {
                "dataset": "N-BaIoT",
                "feature_view": "115 predictors",
                "class": r["label"],
                "rows": int(r["raw_row_count"]),
                "distinct_vectors": int(r["unique_vector_count"]),
                "excess_rows": int(r["duplicate_excess"]),
                "share_of_rows_percent": float(r["raw_percentage"]),
                "share_of_distinct_percent": float(r["unique_vector_percentage"]),
                "note": "",
                "source": C.rel(NB_EFFECTIVE),
            }
        )
    split = C.read_json(BI_SPLIT)
    cc = split["class_counts"]
    group_sum = cc["0"]["groups"] + cc["1"]["groups"]
    conflicts = split["binary_label_conflicts"]
    C.assert_equal(
        "Bot-IoT per-class groups double count exactly the mixed group",
        group_sum - split["statistics"]["unique_X_groups"],
        conflicts["groups"],
        checks,
    )
    C.assert_equal(
        "Bot-IoT mixed group rows == benign + malicious rows",
        conflicts["benign_rows"] + conflicts["malicious_rows"],
        conflicts["rows"],
        checks,
    )
    mixed_note = (
        f"{conflicts['groups']} mixed group ({conflicts['benign_rows']:,} benign + "
        f"{conflicts['malicious_rows']:,} malicious rows) counted in both classes"
    )
    for key, name in (("0", "benign"), ("1", "malicious")):
        out.append(
            {
                "dataset": "Bot-IoT",
                "feature_view": "13 predictors",
                "class": name,
                "rows": cc[key]["rows"],
                "distinct_vectors": cc[key]["groups"],
                "excess_rows": cc[key]["rows"] - cc[key]["groups"],
                "share_of_rows_percent": 100
                * cc[key]["rows"]
                / split["statistics"]["total_observations"],
                "share_of_distinct_percent": 100 * cc[key]["groups"] / group_sum,
                "note": mixed_note,
                "source": C.rel(BI_SPLIT),
            }
        )
    for r in out:
        r["duplication_factor"] = round(r["rows"] / r["distinct_vectors"], 4)
    return out, conflicts


def figure(by_class):
    plt = C.setup_matplotlib()
    from matplotlib.lines import Line2D

    fig, ax = plt.subplots(figsize=(C.FULL_WIDTH_IN, 2.0), layout="constrained")
    order = [
        ("N-BaIoT", "benign"),
        ("N-BaIoT", "malicious"),
        ("Bot-IoT", "benign"),
        ("Bot-IoT", "malicious"),
    ]
    ys = [3.7, 2.7, 1.2, 0.2]
    ring_s = 26
    for (dataset, cls), yv in zip(order, ys):
        r = next(x for x in by_class if x["dataset"] == dataset and x["class"] == cls)
        color = C.BENIGN if cls == "benign" else C.MALICIOUS
        # all rows (filled) above, distinct vectors (open) below: never drawn on top of each other
        ax.plot([1e2, r["rows"]], [yv + 0.17] * 2, color=C.GRID, linewidth=0.8, zorder=1)
        ax.plot(
            [1e2, r["distinct_vectors"]], [yv - 0.17] * 2, color=C.GRID, linewidth=0.8, zorder=1
        )
        ax.scatter(
            [r["rows"]],
            [yv + 0.17],
            s=C.DOT_S,
            color=color,
            edgecolor="white",
            linewidth=0.8,
            zorder=3,
        )
        ax.scatter(
            [r["distinct_vectors"]],
            [yv - 0.17],
            s=ring_s,
            facecolor="white",
            edgecolor=color,
            linewidth=1.2,
            zorder=3,
        )
        C.label_point(ax, r["rows"], yv + 0.17, f"{C.fmt_int(r['rows'])} rows", C.DOT_S)
        C.label_point(
            ax,
            r["distinct_vectors"],
            yv - 0.17,
            f"{C.fmt_int(r['distinct_vectors'])} distinct (×{r['duplication_factor']:.2f})",
            ring_s,
        )
    ax.set_yticks(ys)
    view = {"N-BaIoT": "115 features", "Bot-IoT": "13 predictors"}
    ax.set_yticklabels([f"{d} {c}\n({view[d]})" for d, c in order])
    ax.set_xscale("log")
    ax.set_xlim(1e2, 1e8)
    ax.set_ylim(-0.35, 4.25)
    ax.tick_params(axis="y", length=0)
    ax.spines["left"].set_visible(False)
    C.style_grid(ax, "x")
    ax.set_xlabel("records (log scale); ×N = average rows per distinct vector")
    handles = [
        Line2D(
            [0],
            [0],
            marker="o",
            linestyle="",
            markersize=4.5,
            markerfacecolor=C.MUTED,
            markeredgecolor="white",
            label="all rows",
        ),
        Line2D(
            [0],
            [0],
            marker="o",
            linestyle="",
            markersize=4.5,
            markerfacecolor="white",
            markeredgecolor=C.MUTED,
            label="distinct feature vectors",
        ),
    ]
    fig.legend(handles=handles, loc="outside upper center", ncol=2)
    files = C.save_figure(fig, "fig41e_duplicates_by_class")
    plt.close(fig)
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--botiot-package", required=True, type=Path)
    args = parser.parse_args()
    C.ensure_dirs()
    checks = []
    package = args.botiot_package.resolve()
    overall, per_partition_class = overall_rows(checks, package)
    by_class, conflicts = by_class_rows(checks)
    t1 = C.write_csv(C.TABLE_DIR / "t41_duplicates_summary.csv", overall)
    t2 = C.write_csv(C.TABLE_DIR / "t41_duplicates_by_class.csv", by_class)
    t3 = C.write_csv(
        C.TABLE_DIR / "t41_botiot_duplicates_by_partition_class.csv", per_partition_class
    )
    files = figure(by_class)
    inputs = [
        C.input_record(p) for p in (NB_DUP, NB_NUMERIC, NB_EFFECTIVE, BI_DUP_SOURCE, BI_SPLIT)
    ]

    def pick(dataset, cls):
        return next(r for r in by_class if r["dataset"] == dataset and r["class"] == cls)

    nb, nbm = pick("N-BaIoT", "benign"), pick("N-BaIoT", "malicious")
    bi = pick("Bot-IoT", "benign")
    C.register_figure(
        "fig41e_duplicates_by_class",
        files=files,
        inputs=inputs,
        dataset="N-BaIoT; Bot-IoT",
        scope="full corpora (historical audit / candidate scan)",
        n="N-BaIoT 7,062,606 rows; Bot-IoT 3,668,522 rows",
        weighting="1 per record (rows) vs 1 per distinct vector",
        sampling_transform="none; log-scale x axis",
        caption="Rows versus distinct feature vectors per class (N-BaIoT: all 115 features; "
        "Bot-IoT: the 13 model predictors). Filled dot = all rows, open dot = distinct "
        "vectors; ×N = average rows per distinct vector. Bot-IoT has "
        f"{conflicts['groups']} vector that occurs with both labels ("
        f"{conflicts['benign_rows']:,} benign + {conflicts['malicious_rows']:,} malicious rows); "
        "it is counted once in each class.",
        commentary=(
            "Duplication is concentrated in the malicious class: N-BaIoT malicious rows repeat "
            f"on average {nbm['duplication_factor']:.2f} times per distinct vector versus "
            f"{nb['duplication_factor']:.2f} for benign, so benign is "
            f"{nb['share_of_rows_percent']:.2f}% of rows but "
            f"{nb['share_of_distinct_percent']:.2f}% "
            "of distinct vectors. On the 13 Bot-IoT predictors benign is "
            f"{bi['share_of_rows_percent']:.3f}% of rows and "
            f"{bi['share_of_distinct_percent']:.3f}% "
            "of distinct vectors; on all 43 source fields Bot-IoT has no duplicates at all. "
            "Because identical vectors are kept inside one partition, repeated rows inflate "
            "support counts but cannot leak across TRAIN/VALIDATION/TEST."
        ),
    )
    C.write_log(
        "t41_duplicates",
        {"inputs": inputs, "outputs": [C.rel(t1), C.rel(t2), C.rel(t3), *files], "checks": checks},
    )
    print(f"{len(checks)} checks PASS")
    for r in overall:
        print(
            {
                k: r[k]
                for k in (
                    "dataset",
                    "scope",
                    "feature_view",
                    "rows",
                    "distinct_vectors",
                    "repeated_groups",
                    "rows_in_repeated_groups",
                    "excess_rows",
                    "excess_percent_of_rows",
                    "cross_label_groups",
                )
            }
        )


if __name__ == "__main__":
    main()
