"""CODE 4.1.2 (N-BaIoT, plotting step) - TRAIN feature distributions by class.

Input is the folder written by t41_nbaiot_extract_local.py on the machine holding the
package (3 TRAIN columns + TRAIN labels, all 4,944,968 rows, hashes in its receipt).
Feature names and positions come from the package's own feature contract.

Usage (from ml/):
  python analysis/duy_a2/scripts/t41_nbaiot_train_features.py --extract-dir <nbaiot_extract_01>
"""

from __future__ import annotations

import argparse
from pathlib import Path

import _common as C
import _features as F
import numpy as np

DISPLAY = {
    "MI_dir_L0.1_weight": ("MI_dir_L0.1_weight", "decayed packet count"),
    "H_L0.1_mean": ("H_L0.1_mean", "mean packet size"),
    "HH_jit_L0.1_mean": ("HH_jit_L0.1_mean", "mean inter-packet interval"),
}
PUBLISHED_MANIFEST = "6ab99e86397242e219bfa1f8490d8e03b169ec87a092af80cb3e7aef1e61147b"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--extract-dir", required=True, type=Path)
    parser.add_argument(
        "--expected-manifest-sha256",
        default=PUBLISHED_MANIFEST,
        help="only change for the synthetic self-test",
    )
    args = parser.parse_args()
    C.ensure_dirs()
    checks = []
    root = args.extract_dir.resolve()
    receipt_path = root / "nbaiot_local_receipt.json"
    receipt = C.read_json(receipt_path)
    npz_path = root / "nbaiot_train_selected_features.npz"
    C.assert_equal("local extract status", receipt["status"], "PASS", checks)
    C.assert_equal(
        "package manifest SHA-256",
        receipt["manifest_sha256"],
        args.expected_manifest_sha256,
        checks,
    )
    C.assert_equal("no TEST member opened", receipt["test_members_opened"], [], checks)
    C.assert_equal(
        "extract hash matches receipt",
        C.sha256_file(npz_path),
        receipt["outputs"][npz_path.name]["sha256"],
        checks,
    )
    data = np.load(npz_path, allow_pickle=False)
    X, y = data["X"], data["y"]
    names = [str(n) for n in data["feature_names"]]
    C.assert_equal(
        "rows == TRAIN label count", int(len(y)), receipt["label_counts"]["TRAIN"]["rows"], checks
    )
    C.assert_equal(
        "class counts == receipt",
        [int(v) for v in np.bincount(y, minlength=2)],
        [receipt["label_counts"]["TRAIN"]["benign"], receipt["label_counts"]["TRAIN"]["malicious"]],
        checks,
    )

    hist_rows, summary, by_feature, specs = [], [], {}, []
    for j, name in enumerate(names):
        values = X[:, j]
        rows = F.histogram_rows("N-BaIoT", "TRAIN", name, values, y)
        by_feature[name] = rows
        hist_rows += rows
        summary += F.summary_rows("N-BaIoT", "TRAIN", name, values, y)
        specs.append((name, DISPLAY.get(name, (name, ""))[1], ""))
    t_hist = C.write_csv(C.TABLE_DIR / "t41_nbaiot_train_feature_histograms.csv", hist_rows)
    t_sum = C.write_csv(C.TABLE_DIR / "t41_nbaiot_train_feature_summary.csv", summary)
    fig = F.plot_panels(by_feature, specs)
    files = C.save_figure(fig, "fig41d_nbaiot_train_features")

    s = {(r["feature"], r["class"]): r for r in summary}
    n_b, n_m = (
        receipt["label_counts"]["TRAIN"]["benign"],
        receipt["label_counts"]["TRAIN"]["malicious"],
    )

    def med(feature, cls):
        return s[(feature, cls)]["median"]

    def overlap(feature):
        """Histogram overlap: sum over the shared bins of the smaller class share (1 = same)."""
        share = {(r["class"], r["bin_index"]): r["fraction_of_class"] for r in by_feature[feature]}
        return sum(min(share[("benign", i)], share[("malicious", i)]) for i in range(F.N_BINS))

    ov = {f: overlap(f) for f in names}
    if max(ov.values()) - min(ov.values()) < 0.01:
        ranking = "so none of the three separates the classes clearly better than the others"
    else:
        ranking = (
            f"so {min(ov, key=ov.get)} separates the classes most and {max(ov, key=ov.get)} least"
        )
    commentary = (
        "Medians (benign vs malicious): "
        + "; ".join(f"{f} {med(f, 'benign'):,.3g} vs {med(f, 'malicious'):,.3g}" for f in names)
        + ". The two class histograms overlap by "
        + ", ".join(f"{100 * ov[f]:.0f}%" for f in names)
        + " respectively (sum over the shared bins of the smaller class share; 100% = same "
        f"shape), {ranking}. All {n_b + n_m:,} TRAIN records are used (no sampling; "
        f"benign {n_b:,}), and the figure describes TRAIN only, not unseen devices."
    )
    C.register_figure(
        "fig41d_nbaiot_train_features",
        files=files,
        inputs=[
            C.input_record(receipt_path, "N-BaIoT local extract receipt"),
            C.input_record(npz_path, "N-BaIoT TRAIN 3-column extract"),
        ],
        dataset="N-BaIoT",
        scope="TRAIN partition (G3B package, raw float64 values)",
        n=f"all TRAIN records: benign {n_b:,}, malicious {n_m:,}",
        weighting="1 per record; each class normalised by its own size",
        sampling_transform="no sampling; log1p transform; 40 shared bins per feature",
        caption="N-BaIoT TRAIN distributions by class of three of the 115 features, chosen as one "
        "each for volume, packet size and timing at the same decay window (L0.1); names and "
        "positions from the package's feature contract. Raw values on a log1p scale, the same "
        f"{F.N_BINS} bins for both classes, each curve sums to 1 within its class; benign "
        f"n={n_b:,}, malicious n={n_m:,} (all TRAIN records).",
        commentary=commentary,
    )
    C.write_log(
        "t41_nbaiot_train_features",
        {
            "inputs": [C.input_record(receipt_path), C.input_record(npz_path)],
            "outputs": [C.rel(t_hist), C.rel(t_sum), *files],
            "checks": checks,
            "features": receipt["features"],
            "histogram_overlap": ov,
            "local_environment": receipt["environment"],
        },
    )
    print(f"{len(checks)} checks PASS; wrote {files[0]}")
    for r in summary:
        print(
            {
                k: r[k]
                for k in ("feature", "class", "n", "share_zero", "p25", "median", "p75", "max")
            }
        )


if __name__ == "__main__":
    main()
