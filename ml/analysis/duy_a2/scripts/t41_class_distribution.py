"""CODE 4.1.1 - class counts and percentages for N-BaIoT and Bot-IoT.

Two scopes are kept apart on purpose:
  * full corpus  - read from the audit CSVs in ml/artifacts/audit/ (historical audit);
  * partitions   - TRAIN/VALIDATION/TEST counts from the fixed split.
Levels are never added together: N-BaIoT uses binary, family or fine_class on its own;
Bot-IoT is filtered to representation=all_features_5pct_shards and uses attack, category
or subcategory on its own (one record appears once in EVERY level).

Bot-IoT TRAIN/VALIDATION counts are recomputed from the package label arrays; TEST counts
come from the package manifest only (TEST arrays are not opened). N-BaIoT partition counts
come from the G3A split audit; if the local package check receipt is supplied
(t41_nbaiot_extract_local.py), TRAIN/VALIDATION are also cross-checked against the
package label arrays.

Usage (from ml/):
  python analysis/duy_a2/scripts/t41_class_distribution.py --botiot-package <dir>
         [--nbaiot-local-receipt <nbaiot_local_receipt.json>]
"""

from __future__ import annotations

import argparse
import csv
from decimal import Decimal
from pathlib import Path

import _common as C
import numpy as np

AUDIT = C.ML_DIR / "artifacts" / "audit"
NB_LABELS = AUDIT / "n_baiot_label_distribution.csv"
BI_LABELS = AUDIT / "bot_iot_label_distribution.csv"
G3A_CLASSES = AUDIT / "g3a_class_distribution.csv"
BI_REPRESENTATION = "all_features_5pct_shards"
NB_TOTAL = 7_062_606
BI_TOTAL = 3_668_522
NB_PARTITIONS = {"TRAIN": 4_944_968, "VALIDATION": 1_056_372, "TEST": 1_061_266}
FINE_ORDER = [
    "benign",
    "gafgyt_combo",
    "gafgyt_junk",
    "gafgyt_scan",
    "gafgyt_tcp",
    "gafgyt_udp",
    "mirai_ack",
    "mirai_scan",
    "mirai_syn",
    "mirai_udp",
    "mirai_udpplain",
]
BI_CATEGORY_ORDER = ["Normal", "DDoS", "DoS", "Reconnaissance", "Theft"]
BI_SUB_ORDER = [
    "Normal",
    "UDP",
    "TCP",
    "HTTP",
    "Service_Scan",
    "OS_Fingerprint",
    "Keylogging",
    "Data_Exfiltration",
]


def read_rows(path):
    with Path(path).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def corpus_tables(checks):
    rows = []
    # N-BaIoT
    nb = read_rows(NB_LABELS)
    for level in ("binary", "family", "fine_class"):
        sel = [r for r in nb if r["distribution_level"] == level]
        total = sum(int(r["count"]) for r in sel)
        C.assert_equal(
            f"N-BaIoT corpus {level} level sums to corpus total", total, NB_TOTAL, checks
        )
        for r in sel:
            count = int(r["count"])
            pct = 100 * count / total
            C.assert_close(
                f"N-BaIoT {level}/{r['label']} percent matches audit",
                pct,
                float(Decimal(r["percentage_of_total"])),
                checks,
                tol=1e-9,
            )
            binary = "benign" if r["label"] == "benign" else "malicious"
            rows.append(
                {
                    "dataset": "N-BaIoT",
                    "scope": "full corpus (historical audit)",
                    "source_file": C.rel(NB_LABELS),
                    "representation": "115 numeric features",
                    "level": level,
                    "class": r["label"],
                    "binary_class": binary,
                    "rows": count,
                    "level_total": total,
                    "percent": round(pct, 6),
                }
            )
    fam = {
        r["class"]: r["rows"] for r in rows if r["dataset"] == "N-BaIoT" and r["level"] == "family"
    }
    fine = {
        r["class"]: r["rows"]
        for r in rows
        if r["dataset"] == "N-BaIoT" and r["level"] == "fine_class"
    }
    binary = {
        r["class"]: r["rows"] for r in rows if r["dataset"] == "N-BaIoT" and r["level"] == "binary"
    }
    C.assert_equal(
        "N-BaIoT benign identical across levels",
        {fam["benign"], fine["benign"]},
        {binary["benign"]},
        checks,
    )
    for family in ("gafgyt", "mirai"):
        C.assert_equal(
            f"N-BaIoT family {family} = sum of its fine classes",
            fam[family],
            sum(v for k, v in fine.items() if k.startswith(family + "_")),
            checks,
        )

    # Bot-IoT, one representation, three single levels
    bi = [r for r in read_rows(BI_LABELS) if r["representation"] == BI_REPRESENTATION]
    level_key = {
        "attack": "raw_attack",
        "category": "raw_category",
        "subcategory": "raw_subcategory",
    }
    for level, key in level_key.items():
        sel = [r for r in bi if r["distribution_level"] == level]
        total = sum(int(r["count"]) for r in sel)
        C.assert_equal(
            f"Bot-IoT corpus {level} level sums to corpus total", total, BI_TOTAL, checks
        )
        for r in sel:
            count = int(r["count"])
            pct = 100 * count / total
            C.assert_close(
                f"Bot-IoT {level}/{r[key]} percent matches audit",
                pct,
                float(Decimal(r["percentage_of_representation"])),
                checks,
                tol=1e-9,
            )
            label = {"0": "benign (attack=0)", "1": "malicious (attack=1)"}.get(r[key], r[key])
            is_benign = r[key] in ("0", "Normal")
            rows.append(
                {
                    "dataset": "Bot-IoT",
                    "scope": "full 5% corpus (historical audit)",
                    "source_file": C.rel(BI_LABELS),
                    "representation": BI_REPRESENTATION,
                    "level": level,
                    "class": label,
                    "binary_class": "benign" if is_benign else "malicious",
                    "rows": count,
                    "level_total": total,
                    "percent": round(pct, 6),
                }
            )

    def by(lvl):
        return {
            r["class"]: r["rows"] for r in rows if r["dataset"] == "Bot-IoT" and r["level"] == lvl
        }

    C.assert_equal(
        "Bot-IoT benign identical across levels",
        {by("category")["Normal"], by("subcategory")["Normal"]},
        {by("attack")["benign (attack=0)"]},
        checks,
    )
    return rows


def partition_tables(botiot_package: Path, nbaiot_receipt: Path | None, checks):
    rows, inputs = [], [C.input_record(G3A_CLASSES)]
    g3a = [r for r in read_rows(G3A_CLASSES) if r["level"] == "binary"]
    nb_local = C.read_json(nbaiot_receipt)["label_counts"] if nbaiot_receipt else {}
    if nbaiot_receipt:
        inputs.append(C.input_record(nbaiot_receipt, "N-BaIoT local package receipt"))
    for partition, expected_total in NB_PARTITIONS.items():
        sel = {r["class"]: int(r["row_count"]) for r in g3a if r["split"] == partition}
        total = sum(sel.values())
        C.assert_equal(f"N-BaIoT {partition} total matches Table 1", total, expected_total, checks)
        local = nb_local.get(partition)
        if local is not None:
            C.assert_equal(
                f"N-BaIoT {partition} counts: package y.npy == G3A audit",
                {"benign": local["benign"], "malicious": local["malicious"]},
                sel,
                checks,
            )
        for cls in ("benign", "malicious"):
            source = C.rel(G3A_CLASSES)
            if local is not None:
                source += " + package y.npy (local check)"
            elif partition == "TEST":
                source += " (TEST arrays not opened)"
            rows.append(
                {
                    "dataset": "N-BaIoT",
                    "partition": partition,
                    "source": source,
                    "class": cls,
                    "rows": sel[cls],
                    "partition_total": total,
                    "percent_within_partition": round(100 * sel[cls] / total, 6),
                }
            )
    for cls in ("benign", "malicious"):
        C.assert_equal(
            f"N-BaIoT {cls}: TRAIN+VALIDATION+TEST = corpus",
            sum(r["rows"] for r in rows if r["dataset"] == "N-BaIoT" and r["class"] == cls),
            {"benign": 555_932, "malicious": 6_506_674}[cls],
            checks,
        )

    manifest_path = botiot_package / "manifest.json"
    manifest = C.read_json(manifest_path)
    inputs.append(C.input_record(manifest_path, "Bot-IoT package manifest"))
    expected = manifest["expected_partitions"]
    for partition in ("TRAIN", "VALIDATION", "TEST"):
        info = expected[partition]["binary_rows"]
        if partition == "TEST":
            counts = {"benign": info["benign"], "malicious": info["malicious"]}
            source = "package manifest.json (TEST arrays not opened)"
        else:
            y_path = botiot_package / f"{partition}_y.npy"
            C.assert_equal(
                f"Bot-IoT {partition}_y.npy hash matches manifest",
                C.sha256_file(y_path),
                manifest["files"][y_path.name]["sha256"],
                checks,
            )
            y = np.load(y_path, mmap_mode="r", allow_pickle=False)
            bc = np.bincount(np.asarray(y, dtype=np.int64), minlength=2)
            counts = {"benign": int(bc[0]), "malicious": int(bc[1])}
            C.assert_equal(
                f"Bot-IoT {partition} y.npy counts == manifest",
                counts,
                {"benign": info["benign"], "malicious": info["malicious"]},
                checks,
            )
            source = f"package {partition}_y.npy"
            inputs.append(
                {
                    "label": f"Bot-IoT {partition}_y.npy",
                    "path": y_path.name,
                    "bytes": y_path.stat().st_size,
                    "sha256": manifest["files"][y_path.name]["sha256"],
                }
            )
        total = counts["benign"] + counts["malicious"]
        C.assert_equal(
            f"Bot-IoT {partition} total == manifest rows",
            total,
            expected[partition]["rows"],
            checks,
        )
        for cls in ("benign", "malicious"):
            rows.append(
                {
                    "dataset": "Bot-IoT",
                    "partition": partition,
                    "source": source,
                    "class": cls,
                    "rows": counts[cls],
                    "partition_total": total,
                    "percent_within_partition": round(100 * counts[cls] / total, 6),
                }
            )
    C.assert_equal(
        "Bot-IoT partitions sum to the 5% corpus",
        sum(r["rows"] for r in rows if r["dataset"] == "Bot-IoT"),
        BI_TOTAL,
        checks,
    )
    C.assert_equal(
        "Bot-IoT benign partitions sum to corpus Normal",
        sum(r["rows"] for r in rows if r["dataset"] == "Bot-IoT" and r["class"] == "benign"),
        477,
        checks,
    )
    return rows, inputs


def dot_panel(ax, labels, counts, colors, title, totals, xlim):
    """Dots on a log axis (no bars: a bar's length from an arbitrary log origin misleads)."""
    y = np.arange(len(labels))[::-1]
    totals = totals if isinstance(totals, list | tuple) else [totals] * len(labels)
    for yi, count, color, total in zip(y, counts, colors, totals):
        ax.plot([xlim[0], count], [yi, yi], color=C.GRID, linewidth=0.8, zorder=1)
        ax.scatter(
            [count], [yi], s=C.DOT_S, color=color, edgecolor="white", linewidth=0.8, zorder=3
        )
        C.label_point(
            ax,
            count,
            yi,
            f"{C.fmt_int(count)} ({C.fmt_pct(100 * count / total)})",
            marker_size=C.DOT_S,
        )
    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.set_xscale("log")
    ax.set_xlim(*xlim)
    ax.set_ylim(-0.7, len(labels) - 0.3)
    if title:
        ax.set_title(title, loc="left")
    ax.tick_params(axis="y", length=0)
    C.style_grid(ax, "x")
    ax.spines["left"].set_visible(False)


def class_legend_handles():
    from matplotlib.lines import Line2D

    return [
        Line2D(
            [0],
            [0],
            marker="o",
            linestyle="",
            markersize=4.5,
            markerfacecolor=color,
            markeredgecolor="white",
            label=name,
        )
        for name, color in (("benign", C.BENIGN), ("malicious", C.MALICIOUS))
    ]


def figures(corpus_rows):
    plt = C.setup_matplotlib()

    def pick(dataset, level, order=None):
        sel = [r for r in corpus_rows if r["dataset"] == dataset and r["level"] == level]
        if order:
            sel.sort(key=lambda r: order.index(r["class"]))
        return sel

    def colour(r):
        return C.BENIGN if r["binary_class"] == "benign" else C.MALICIOUS

    # Figure 4.1a - binary balance: one titled panel per corpus, same log axis
    fig, axes = plt.subplots(
        2, 1, figsize=(C.FULL_WIDTH_IN, 1.9), sharex=True, layout="constrained"
    )
    panels = [
        ("N-BaIoT", "binary", NB_TOTAL, f"N-BaIoT, full corpus: {NB_TOTAL:,} records"),
        (
            "Bot-IoT",
            "attack",
            BI_TOTAL,
            f"Bot-IoT, 5% subset ({BI_REPRESENTATION}): {BI_TOTAL:,} records",
        ),
    ]
    for ax, (dataset, level, total, title) in zip(axes, panels):
        sel = sorted(pick(dataset, level), key=lambda r: r["binary_class"] != "benign")
        dot_panel(
            ax,
            [r["binary_class"] for r in sel],
            [r["rows"] for r in sel],
            [colour(r) for r in sel],
            title,
            total,
            (1e2, 1e8),
        )
    axes[-1].set_xlabel("records (log scale); labels: exact count (share of that corpus)")
    files_a = C.save_figure(fig, "fig41a_binary_class_balance")
    plt.close(fig)

    # Figure 4.1b - attack groups (each panel is ONE level, never summed across levels)
    fig = plt.figure(figsize=(C.FULL_WIDTH_IN, 3.2), layout="constrained")
    gs = fig.add_gridspec(2, 2, height_ratios=[5, 8], width_ratios=[1, 1.08])
    ax_nb = fig.add_subplot(gs[:, 0])
    ax_cat = fig.add_subplot(gs[0, 1])
    ax_sub = fig.add_subplot(gs[1, 1])
    fine = pick("N-BaIoT", "fine_class", FINE_ORDER)
    dot_panel(
        ax_nb,
        [r["class"].replace("_", " / ", 1) if r["class"] != "benign" else "benign" for r in fine],
        [r["rows"] for r in fine],
        [colour(r) for r in fine],
        "N-BaIoT fine class (family / attack)",
        NB_TOTAL,
        (1e4, 1e7),
    )
    cat = pick("Bot-IoT", "category", BI_CATEGORY_ORDER)
    dot_panel(
        ax_cat,
        [r["class"] for r in cat],
        [r["rows"] for r in cat],
        [colour(r) for r in cat],
        "Bot-IoT category",
        BI_TOTAL,
        (1, 1e7),
    )
    sub = pick("Bot-IoT", "subcategory", BI_SUB_ORDER)
    dot_panel(
        ax_sub,
        [r["class"].replace("_", " ") for r in sub],
        [r["rows"] for r in sub],
        [colour(r) for r in sub],
        "Bot-IoT subcategory",
        BI_TOTAL,
        (1, 1e7),
    )
    ax_nb.set_xlabel("records (log scale)")
    ax_sub.set_xlabel("records (log scale)")
    fig.legend(handles=class_legend_handles(), loc="outside upper center", ncol=2)
    files_b = C.save_figure(fig, "fig41b_attack_groups")
    plt.close(fig)
    return files_a, files_b


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--botiot-package",
        required=True,
        type=Path,
        help="extracted Bot_IoT_processed_package_v2 directory",
    )
    parser.add_argument(
        "--nbaiot-local-receipt",
        type=Path,
        help="nbaiot_local_receipt.json from t41_nbaiot_extract_local.py",
    )
    args = parser.parse_args()
    C.ensure_dirs()
    checks = []
    corpus = corpus_tables(checks)
    partitions, part_inputs = partition_tables(
        args.botiot_package.resolve(), args.nbaiot_local_receipt, checks
    )
    t1 = C.write_csv(C.TABLE_DIR / "t41_class_counts_corpus.csv", corpus)
    t2 = C.write_csv(C.TABLE_DIR / "t41_class_counts_partitions.csv", partitions)
    files_a, files_b = figures(corpus)
    corpus_inputs = [C.input_record(NB_LABELS), C.input_record(BI_LABELS)]

    def binary(dataset, cls):
        level = "binary" if dataset == "N-BaIoT" else "attack"
        return next(
            r
            for r in corpus
            if r["dataset"] == dataset and r["level"] == level and r["binary_class"] == cls
        )

    nb_benign_pct = C.fmt_pct(100 * binary("N-BaIoT", "benign")["rows"] / NB_TOTAL)
    nb_malicious_pct = C.fmt_pct(100 * binary("N-BaIoT", "malicious")["rows"] / NB_TOTAL)
    bi_benign = binary("Bot-IoT", "benign")["rows"]
    bi_benign_pct = C.fmt_pct(100 * bi_benign / BI_TOTAL)
    bi_malicious_pct = C.fmt_pct(100 * binary("Bot-IoT", "malicious")["rows"] / BI_TOTAL)
    C.register_figure(
        "fig41a_binary_class_balance",
        files=files_a,
        inputs=corpus_inputs,
        dataset="N-BaIoT; Bot-IoT",
        scope="full corpus (historical audit), not a partition",
        n="N-BaIoT 7,062,606; Bot-IoT 3,668,522 (all_features_5pct_shards)",
        weighting="1 per record",
        sampling_transform="none; log-scale x axis",
        caption="Benign and malicious record counts in each full corpus: N-BaIoT, and the "
        f"Bot-IoT 5% subset ({BI_REPRESENTATION}). Audit counts on a log-scale axis; labels "
        "give the exact count and its share of that corpus.",
        commentary="Both corpora are dominated by malicious traffic, but at very different "
        f"levels: benign records are {nb_benign_pct} of N-BaIoT and only {bi_benign_pct} "
        f"({bi_benign:,} records) of the Bot-IoT 5% subset. A classifier that labels "
        f"everything malicious would therefore reach {nb_malicious_pct} and "
        f"{bi_malicious_pct} accuracy respectively, so accuracy alone cannot show whether "
        "benign traffic is recognised. These are corpus totals from the audit; partition "
        "counts are in Table t41_class_counts_partitions.",
    )
    C.register_figure(
        "fig41b_attack_groups",
        files=files_b,
        inputs=corpus_inputs,
        dataset="N-BaIoT; Bot-IoT",
        scope="full corpus (historical audit)",
        n="N-BaIoT 7,062,606; Bot-IoT 3,668,522",
        weighting="1 per record",
        sampling_transform="none; one label level per panel; log-scale x axis",
        caption="Record counts by attack group: N-BaIoT fine classes (family / attack) and "
        "Bot-IoT category and subcategory (each panel is a single label level; levels "
        "are not added together).",
        commentary="N-BaIoT malicious traffic is spread over ten Gafgyt and Mirai attack "
        "classes, each between 3.6% and 17.4% of the corpus, with benign at 7.9%. "
        "Bot-IoT is concentrated in DDoS and DoS (97.5% of records), while Theft "
        "has only 79 records and Data_Exfiltration only 6. The binary task merges "
        "all attack groups, so these imbalances within the malicious class are "
        "not visible in binary metrics.",
    )
    C.write_log(
        "t41_class_distribution",
        {
            "inputs": corpus_inputs + part_inputs,
            "outputs": [C.rel(t1), C.rel(t2), *files_a, *files_b],
            "checks": checks,
            "notes": [
                "Bot-IoT TEST counts from package manifest; TEST arrays not opened.",
                "N-BaIoT TEST counts from the G3A split audit only.",
            ],
        },
    )
    print(f"{len(checks)} checks PASS; wrote {C.rel(t1)}, {C.rel(t2)} and 2 figures")


if __name__ == "__main__":
    main()
