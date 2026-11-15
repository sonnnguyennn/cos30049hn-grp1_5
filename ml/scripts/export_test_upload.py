"""Export real N-BaIoT TEST rows as matching web-upload CSV and JSON files."""

import argparse
import csv
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from iotguard.evaluation.primary_runtime import read_json, verified_package, write_json

ML_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PACKAGE = ML_ROOT.parent.parent / "g3b_primary_v1"
DEFAULT_OUT = ML_ROOT / "data/samples/test-upload"
FREEZE_PATH = ML_ROOT / "artifacts/manifests/primary_model_freeze_20261105.json"


def export_test_upload(package_root, output, *, rows=1000, seed=42, chunk_size=10000):
    """Sample without replacement, or export all rows when rows is None; no inference."""
    if rows is not None and (type(rows) is not int or rows < 1):
        raise ValueError("rows must be a positive integer, or None for the full TEST split")
    if type(seed) is not int or seed < 0:
        raise ValueError("seed must be a nonnegative integer")
    if type(chunk_size) is not int or not 1 <= chunk_size <= 10000:
        raise ValueError("chunk_size must be between 1 and 10000")
    output = Path(output)
    if output.exists():
        raise FileExistsError(f"Choose a new output directory: {output}")

    package, verification = verified_package(package_root, partitions=("TEST",))
    names = package.manifest["feature_order"]
    if names != read_json(FREEZE_PATH)["input_contract"]["feature_order"]:
        raise ValueError("Package feature order differs from the web classifier")
    # The user's explicit TEST export request authorizes read-only TEST access.
    x, y, metadata = package.load("TEST", allow_test=True)
    count = len(y) if rows is None else rows
    if not 1 <= count <= len(y):
        raise ValueError(f"Choose between 1 and {len(y)} TEST rows")
    indices = (
        np.arange(len(y)) if count == len(y)
        else np.sort(np.random.default_rng(seed).choice(len(y), count, replace=False))
    )

    output.mkdir(parents=True, exist_ok=False)
    uploads = []
    class_counts = {"benign": 0, "malicious": 0}
    with (output / "expected_labels.csv").open("x", newline="", encoding="utf-8") as stream:
        labels = csv.writer(stream)
        labels.writerow(["upload_stem", "row", "test_index", "actual_label",
                         "target_binary_numeric", "source", "source_row"])
        for part, start in enumerate(range(0, count, chunk_size), start=1):
            chosen = indices[start:start + chunk_size]
            block = np.asarray(x[chosen], dtype=np.float64)
            with np.errstate(over="ignore"):
                valid = np.isfinite(block).all() and np.isfinite(block.astype(np.float32)).all()
            if not valid:
                raise ValueError("TEST features contain nonfinite values or overflow float32")
            if not np.isin(y[chosen], [0, 1]).all():
                raise ValueError("TEST labels must be 0 (benign) or 1 (malicious)")
            stem = "test_input" if count <= chunk_size else f"test_input_{part:03d}"
            json_path = output / f"{stem}.json"
            with json_path.open("x", encoding="utf-8") as json_stream:
                json.dump({"feature_order": names, "rows": block.tolist()}, json_stream,
                          allow_nan=False, separators=(",", ":"))
                json_stream.write("\n")
            csv_path = output / f"{stem}.csv"
            with csv_path.open("x", newline="", encoding="utf-8") as csv_stream:
                writer = csv.writer(csv_stream)
                writer.writerow(names)
                for row in block:
                    writer.writerow([format(float(value), ".17g") for value in row])
            for row_number, index in enumerate(chosen, start=1):
                target = int(y[index])
                label = "malicious" if target else "benign"
                class_counts[label] += 1
                labels.writerow([stem, row_number, int(index), label, target,
                                 int(metadata[index]["source"]), int(metadata[index]["row"])])
            uploads.append({"csv": csv_path.name, "json": json_path.name, "rows": len(chosen),
                            "csv_bytes": csv_path.stat().st_size,
                            "json_bytes": json_path.stat().st_size})

    report = {
        "partition": "TEST",
        "available_rows": len(y),
        "exported_rows": count,
        "features": len(names),
        "selection": "all rows" if count == len(y) else "random sample without replacement",
        "seed": seed,
        "order": "original TEST index ascending",
        "input_view": "raw",
        "class_counts": class_counts,
        "uploads": uploads,
        "expected_labels": "expected_labels.csv",
        "label_row_numbering": "1-based data row within each upload; test_index is 0-based",
        "package_verification": verification,
        "note": "Upload either CSV or JSON from each pair; they contain identical rows. "
                "Labels are separate. No training, scaling or model inference was performed.",
    }
    write_json(output / "export_manifest.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, default=DEFAULT_PACKAGE,
                        help="G3B package directory (default: ../g3b_primary_v1 from repo)")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--rows", type=int, default=1000,
                           help="Number of randomly sampled TEST rows (default: 1000)")
    selection.add_argument("--all", action="store_true", help="Export the entire TEST split")
    parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")
    parser.add_argument("--chunk-size", type=int, default=10000,
                        help="Maximum rows per upload pair, 1..10000 (default: 10000)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                        help="New output directory (default: ml/data/samples/test-upload)")
    args = parser.parse_args()
    try:
        report = export_test_upload(args.package, args.out,
                                    rows=None if args.all else args.rows,
                                    seed=args.seed, chunk_size=args.chunk_size)
    except (OSError, ValueError, KeyError) as error:
        print(f"TEST export failed: {error}", file=sys.stderr)
        return 1
    print(f"Exported {report['exported_rows']} TEST rows: "
          f"{report['class_counts']['benign']} benign, "
          f"{report['class_counts']['malicious']} malicious.")
    print(f"Saved {len(report['uploads'])} CSV/JSON upload pair(s) to {args.out.resolve()}")
    print("Upload either format. Use expected_labels.csv to check predictions by row.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
