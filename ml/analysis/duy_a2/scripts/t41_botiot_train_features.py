"""CODE 4.1.2 (Bot-IoT) - TRAIN distributions of pkts, bytes and dur by class.

Uses the package's own loader exactly as documented: package.load("TRAIN") returns the raw
numeric values, categorical codes, labels and metadata. The plot uses the RAW numeric values,
never the 36 encoded/scaled model columns. All 2,201,114 TRAIN records are used (no sampling).

Usage (from ml/):
  python analysis/duy_a2/scripts/t41_botiot_train_features.py --botiot-package <dir>
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

import _common as C
import _features as F
import numpy as np

FEATURES = [("pkts", "pkts", "packets"), ("bytes", "bytes", ""), ("dur", "dur", "seconds")]
REASON = {
    "pkts": "packet count of the flow record (traffic volume)",
    "bytes": "total bytes of the flow record (data volume)",
    "dur": "flow duration in seconds (timing)",
}


def load_package(root: Path, checks):
    loader_path = root / "bot_iot_package_v2.py"
    manifest = C.read_json(root / "manifest.json")
    C.assert_equal(
        "Bot-IoT loader hash matches package manifest",
        C.sha256_file(loader_path),
        manifest["files"]["bot_iot_package_v2.py"]["sha256"],
        checks,
    )
    # Import the package's loader from its exact file without putting the data folder on sys.path,
    # and without writing a __pycache__ folder into the data package.
    before = sorted(p.name for p in root.iterdir())
    spec = importlib.util.spec_from_file_location("bot_iot_package_v2", loader_path)
    module = importlib.util.module_from_spec(spec)
    previous, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    C.assert_equal(
        "nothing written into the package folder by the import",
        sorted(p.name for p in root.iterdir()),
        before,
        checks,
    )
    package = module.SecondaryPackage(root, verify=True)  # verifies every payload checksum
    return module, package, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--botiot-package", required=True, type=Path)
    args = parser.parse_args()
    C.ensure_dirs()
    checks = []
    root = args.botiot_package.resolve()
    listing = sorted(p.name for p in root.iterdir())
    module, package, manifest = load_package(root, checks)
    numeric, _categorical, y, _metadata = package.load("TRAIN")
    C.assert_equal(
        "package folder unchanged after loading TRAIN",
        sorted(p.name for p in root.iterdir()),
        listing,
        checks,
    )
    C.assert_equal(
        "loader numeric column order", list(module.NUMERIC)[:3], ["pkts", "bytes", "dur"], checks
    )
    y = np.asarray(y)
    C.assert_equal(
        "TRAIN rows", int(len(y)), manifest["expected_partitions"]["TRAIN"]["rows"], checks
    )
    C.assert_equal(
        "TRAIN class counts",
        [int(v) for v in np.bincount(y, minlength=2)],
        [
            manifest["expected_partitions"]["TRAIN"]["binary_rows"]["benign"],
            manifest["expected_partitions"]["TRAIN"]["binary_rows"]["malicious"],
        ],
        checks,
    )

    hist_rows, summary, by_feature = [], [], {}
    for j, (feature, _display, _unit) in enumerate(FEATURES):
        values = np.asarray(numeric[:, j], dtype=np.float64)
        if not np.isfinite(values).all() or (values < 0).any():
            raise AssertionError(f"{feature}: expected finite non-negative raw values")
        rows = F.histogram_rows("Bot-IoT", "TRAIN", feature, values, y)
        by_feature[feature] = rows
        hist_rows += rows
        summary += F.summary_rows("Bot-IoT", "TRAIN", feature, values, y)
    t_hist = C.write_csv(C.TABLE_DIR / "t41_botiot_train_feature_histograms.csv", hist_rows)
    t_sum = C.write_csv(C.TABLE_DIR / "t41_botiot_train_feature_summary.csv", summary)

    fig = F.plot_panels(by_feature, FEATURES)
    files = C.save_figure(fig, "fig41c_botiot_train_features")
    inputs = [
        C.input_record(root / "manifest.json", "Bot-IoT package manifest"),
        {
            "label": "Bot-IoT TRAIN_numeric.npy",
            "path": "TRAIN_numeric.npy",
            "bytes": manifest["files"]["TRAIN_numeric.npy"]["bytes"],
            "sha256": manifest["files"]["TRAIN_numeric.npy"]["sha256"],
        },
        {
            "label": "Bot-IoT TRAIN_y.npy",
            "path": "TRAIN_y.npy",
            "bytes": manifest["files"]["TRAIN_y.npy"]["bytes"],
            "sha256": manifest["files"]["TRAIN_y.npy"]["sha256"],
        },
    ]
    s = {(r["feature"], r["class"]): r for r in summary}
    C.register_figure(
        "fig41c_botiot_train_features",
        files=files,
        inputs=inputs,
        dataset="Bot-IoT",
        scope="TRAIN partition (package v2), raw numeric values via package.load('TRAIN')",
        n="all TRAIN records: benign 286, malicious 2,200,828",
        weighting="1 per record; each class normalised by its own size",
        sampling_transform="no sampling; log1p transform; 40 shared bins per feature",
        caption="Bot-IoT TRAIN distributions of pkts, bytes and dur by class (raw values, "
        "log1p scale, same 40 bins for both classes; each curve sums to 1 within its "
        "class). Benign n=286, malicious n=2,200,828.",
        commentary=(
            "Benign TRAIN records are mostly short flows (median "
            f"{s[('pkts', 'benign')]['median']:g} packets, "
            f"{s[('bytes', 'benign')]['median']:,.0f} bytes, "
            f"{s[('dur', 'benign')]['median']:.2f} s), while malicious records centre on "
            f"{s[('pkts', 'malicious')]['median']:g} packets, "
            f"{s[('bytes', 'malicious')]['median']:,.0f} bytes and "
            f"{s[('dur', 'malicious')]['median']:.1f} s, so all three features shift between "
            "the classes. The ranges still overlap, and a small benign tail of very long flows "
            f"(99th percentile about {s[('pkts', 'benign')]['p99']:,.0f} packets) lies beyond "
            f"the malicious maximum of {s[('pkts', 'malicious')]['max']:,.0f}. The benign "
            "curves rest on only 286 records and are coarse; these are 3 of the 13 predictors "
            "(10 numeric plus flgs/proto/state)."
        ),
        run_id="N/A (data description)",
    )
    C.write_log(
        "t41_botiot_train_features",
        {
            "inputs": inputs,
            "outputs": [C.rel(t_hist), C.rel(t_sum), *files],
            "checks": checks,
            "feature_reasons": REASON,
            "notes": [
                "package.load('TRAIN') raw numeric values; encoded 36-column view not used",
                "TEST not loaded (loader verify=True hashes payloads only)",
            ],
        },
    )
    print(f"{len(checks)} checks PASS; wrote {C.rel(t_hist)}, {C.rel(t_sum)}, {files[0]}")
    for r in summary:
        print(
            {
                k: r[k]
                for k in ("feature", "class", "n", "share_zero", "p25", "median", "p75", "max")
            }
        )


if __name__ == "__main__":
    main()
