"""Run a small, reproducible prediction demo on real VALIDATION rows; no fitting."""

import argparse
import csv
import importlib.metadata
import sys
from pathlib import Path

import numpy as np

from iotguard.evaluation.primary_runtime import (
    environment,
    file_identity,
    load_predictor,
    read_json,
    verified_package,
    write_json,
)

ML_ROOT = Path(__file__).resolve().parents[3]
FREEZE_PATH = ML_ROOT / "artifacts/manifests/primary_model_freeze_20261105.json"
DEFAULT_MODEL = ML_ROOT / "experiments/xgb_frac1_seed42_lr01/model.json"
DEFAULT_PACKAGE = ML_ROOT.parent.parent / "g3b_primary_v1"


def sample_predictions(package_root, model_path, *, per_class=3):
    """Select the first rows of each class without using predictions to choose them."""
    if isinstance(per_class, bool) or not isinstance(per_class, int) or not 1 <= per_class <= 100:
        raise ValueError("Choose between 1 and 100 samples per class")
    freeze = read_json(FREEZE_PATH)
    model_identity = file_identity(model_path)
    if any(model_identity[key] != freeze["model"][key] for key in ("sha256", "bytes")):
        raise ValueError("Model differs from the team's frozen classifier")

    # Hash only VALIDATION and the shared package files; never open TRAIN/TEST arrays.
    package, verification = verified_package(package_root, partitions=("VALIDATION",))
    contract = freeze["input_contract"]
    if package.manifest["feature_order"] != contract["feature_order"]:
        raise ValueError("Package feature order differs from the frozen classifier")
    x, y, metadata = package.load("VALIDATION")
    chosen = []
    for label in (0, 1):
        indices = np.flatnonzero(y == label)[:per_class]
        if len(indices) != per_class:
            raise ValueError(f"Not enough VALIDATION rows for class {label}")
        chosen.extend(indices.tolist())
    rows = np.asarray(x[chosen], dtype=np.float64)
    if not np.isfinite(rows).all():
        raise ValueError("Sample features contain NaN or infinity")
    with np.errstate(over="ignore"):
        encoded = rows.astype(np.float32)
    if not np.isfinite(encoded).all():
        raise ValueError("Sample features overflow float32")

    predict, model_summary = load_predictor(model_path, contract)
    probabilities = np.asarray(predict(encoded))
    if (probabilities.shape != (len(chosen),) or not np.isfinite(probabilities).all()
            or np.any((probabilities < 0) | (probabilities > 1))):
        raise ValueError("Model returned invalid probabilities")
    predictions = (probabilities >= 0.5).astype(np.uint8)
    actual = y[chosen]
    labels = ["benign", "malicious"]
    records = [
        {
            "sample": i + 1,
            "validation_index": index,
            "source": int(metadata[index]["source"]),
            "source_row": int(metadata[index]["row"]),
            "actual_label": labels[int(actual[i])],
            "predicted_label": labels[int(predictions[i])],
            "probability_malicious": float(probabilities[i]),
            "correct": bool(predictions[i] == actual[i]),
        }
        for i, index in enumerate(chosen)
    ]
    inputs = {"feature_order": contract["feature_order"], "rows": rows.tolist()}
    runtime = environment()
    try:
        runtime["packages"]["xgboost-cpu"] = importlib.metadata.version("xgboost-cpu")
    except importlib.metadata.PackageNotFoundError:
        pass
    report = {
        "schema_version": "primary_sample_prediction_v1",
        "selected_run_id": freeze["selected_run_id"],
        "partition": "VALIDATION",
        "selection_rule": f"first {per_class} rows of each class, benign then malicious",
        "threshold": 0.5,
        "input_view": "raw",
        "model_dtype": "float32",
        "apply_scaler": False,
        "model": model_identity,
        "model_load": model_summary,
        "package_verification": verification,
        "environment": runtime,
        "classifiers_fitted": False,
        "TEST_opened": False,
        "note": "Small demonstration sample; correctness here is not a performance estimate.",
        "correct_samples": int(np.sum(predictions == actual)),
        "total_samples": len(chosen),
        "probabilities": probabilities.astype(float).tolist(),
        "predictions": predictions.tolist(),
        "labels": [labels[int(p)] for p in predictions],
        "samples": records,
    }
    return inputs, report


def export_samples(directory, inputs, report):
    """Keep labels/lineage separate from the 115 predictor columns."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    write_json(directory / "sample_input.json", inputs)
    write_json(directory / "predictions.json", report)
    with (directory / "sample_input.csv").open("x", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(inputs["feature_order"])
        for row in inputs["rows"]:
            writer.writerow([format(value, ".17g") for value in row])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, default=DEFAULT_PACKAGE,
                        help="Original G3B directory (default: ../g3b_primary_v1 from repo)")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL,
                        help="Frozen XGBoost model.json; checksum must match")
    parser.add_argument("--per-class", type=int, default=3, choices=range(1, 101),
                        metavar="1..100")
    parser.add_argument("--out", type=Path, help="New directory for JSON/CSV inputs and results")
    args = parser.parse_args()
    if args.out is not None and args.out.exists():
        parser.error("--out must be a new directory; existing results are preserved")
    try:
        inputs, report = sample_predictions(args.package, args.model, per_class=args.per_class)
        if args.out is not None:
            export_samples(args.out, inputs, report)
    except (OSError, ValueError, KeyError, ImportError) as error:
        print(f"Sample prediction failed: {error}", file=sys.stderr)
        return 1

    print(f"Model: {report['selected_run_id']} | VALIDATION | threshold = 0.5")
    print("Sample  Actual      Predicted   P(malicious)  Result")
    for row in report["samples"]:
        print(f"{row['sample']:>6}  {row['actual_label']:<10}  {row['predicted_label']:<10}  "
              f"{row['probability_malicious']:>12.8f}  "
              f"{'correct' if row['correct'] else 'MISCLASSIFIED'}")
    print(f"{report['correct_samples']}/{report['total_samples']} sample predictions correct.")
    print(report["note"])
    if args.out is not None:
        print(f"Saved sample_input.json, sample_input.csv and predictions.json to {args.out}")
    return 0
