"""Analyze CSV or JSON features with the team's saved model; importable by FastAPI."""

import argparse
import csv
import hashlib
import io
import json
import sys
from functools import lru_cache
from pathlib import Path

import numpy as np
import xgboost as xgb

if __package__:
    from .upload_limits import MAX_ROWS, MAX_UPLOAD_BYTES, UPLOAD_LIMIT_MESSAGE
else:
    from upload_limits import MAX_ROWS, MAX_UPLOAD_BYTES, UPLOAD_LIMIT_MESSAGE

REPO_ROOT = Path(__file__).resolve().parents[2]
FREEZE = REPO_ROOT / "ml/artifacts/manifests/primary_model_freeze_20261105.json"
MODEL = REPO_ROOT / "ml/experiments/xgb_frac1_seed42_lr01/model.json"


def feature_names():
    """The names and order expected in the CSV header."""
    return json.loads(FREEZE.read_text(encoding="utf-8"))["input_contract"]["feature_order"]


@lru_cache(maxsize=1)
def load_model():
    """Check the saved model once, then reuse it across uploads."""
    freeze = json.loads(FREEZE.read_text(encoding="utf-8"))
    if hashlib.sha256(MODEL.read_bytes()).hexdigest() != freeze["model"]["sha256"]:
        raise RuntimeError("Saved model does not match the team's frozen model")
    model = xgb.Booster()
    model.load_model(MODEL)
    model.set_param({"nthread": 2})
    return model


def analyze_csv(csv_text):
    """CSV text in -> JSON-compatible dictionary out. Does not train or save uploads."""
    check_text_size(csv_text)
    names = feature_names()
    reader = csv.reader(io.StringIO(csv_text.removeprefix("\ufeff")), strict=True)
    rows = []
    try:
        if next(reader, None) != names:
            raise ValueError("CSV header must contain exactly the 115 model features in order")
        for row_number, row in enumerate(reader, start=1):
            if row_number > MAX_ROWS:
                raise ValueError(f"CSV must contain at most {MAX_ROWS} data rows")
            if len(row) != len(names):
                raise ValueError(f"Data row {row_number}: expected 115 values")
            try:
                rows.append([float(value) for value in row])
            except ValueError as error:
                raise ValueError(f"Data row {row_number}: all values must be numeric") from error
    except csv.Error as error:
        raise ValueError(f"Invalid CSV: {error}") from error
    if not rows:
        raise ValueError("CSV has no data rows")
    return analyze_rows(rows, names)


def check_text_size(text):
    if len(text.encode("utf-8")) > MAX_UPLOAD_BYTES:
        raise ValueError(UPLOAD_LIMIT_MESSAGE)


def analyze_json(json_text):
    """Accept {\"feature_order\": [115 names], \"rows\": [[115 numbers], ...]}."""
    check_text_size(json_text)
    try:
        data = json.loads(json_text.removeprefix("\ufeff"))
    except (ValueError, RecursionError) as error:
        raise ValueError("Invalid JSON file") from error
    names = feature_names()
    if not isinstance(data, dict) or data.get("feature_order") != names:
        raise ValueError("JSON feature_order must contain exactly the 115 model features in order")
    rows = data.get("rows")
    if not isinstance(rows, list) or not rows:
        raise ValueError("JSON rows must be a nonempty array of numeric rows")
    if len(rows) > MAX_ROWS:
        raise ValueError(f"JSON must contain at most {MAX_ROWS} data rows")
    for number, row in enumerate(rows, start=1):
        if not isinstance(row, list) or len(row) != len(names):
            raise ValueError(f"Data row {number}: expected an array of 115 values")
        if any(type(value) not in (int, float) for value in row):
            raise ValueError(f"Data row {number}: use JSON numbers, not strings, booleans or null")
    return analyze_rows(rows, names)


def analyze_file(content, filename):
    """Uploaded bytes and filename in -> analysis dictionary out."""
    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError(UPLOAD_LIMIT_MESSAGE)
    extension = Path(filename).suffix.lower()
    if extension not in {".csv", ".json"}:
        raise ValueError("Choose a .csv or .json file")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError("Save the CSV or JSON file using UTF-8 encoding") from error
    return analyze_json(text) if extension == ".json" else analyze_csv(text)


def analyze_rows(rows, names):
    """Shared numeric validation, inference and statistics for both formats."""
    try:
        values = np.asarray(rows, dtype=np.float64)
    except (ValueError, OverflowError) as error:
        raise ValueError("File contains values too large for numeric analysis") from error
    if not np.isfinite(values).all():
        raise ValueError("File cannot contain NaN or infinity")
    with np.errstate(over="ignore"):
        model_values = values.astype(np.float32)
    if not np.isfinite(model_values).all():
        raise ValueError("File contains values too large for the model's float32 input")

    # This tree model uses raw values: do not apply a scaler.
    probabilities = load_model().predict(xgb.DMatrix(model_values, nthread=2))
    if (probabilities.shape != (len(rows),) or not np.isfinite(probabilities).all()
            or np.any((probabilities < 0) | (probabilities > 1))):
        raise RuntimeError("Model returned invalid probabilities")
    malicious = probabilities >= 0.5
    return {
        "model": "xgb_frac1_seed42_lr01",
        "threshold": 0.5,
        "runtime": {"numpy": np.__version__, "xgboost": xgb.__version__},
        "summary": {
            "rows": len(rows),
            "features": len(names),
            "benign": int((~malicious).sum()),
            "malicious": int(malicious.sum()),
        },
        "results": [
            {"row": i + 1, "label": "malicious" if malicious[i] else "benign",
             "probability_malicious": float(probability)}
            for i, probability in enumerate(probabilities)
        ],
        "feature_stats": [
            {"feature": name, "min": float(values[:, i].min()),
             "max": float(values[:, i].max()), "mean": float(values[:, i].mean())}
            for i, name in enumerate(names)
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_file", type=Path, help="UTF-8 .csv or .json file")
    parser.add_argument("--output", type=Path, help="New JSON file; otherwise print JSON")
    args = parser.parse_args()
    try:
        with args.input_file.open("rb") as stream:
            content = stream.read(MAX_UPLOAD_BYTES + 1)
        result = analyze_file(content, args.input_file.name)
        output = json.dumps(result, indent=2, allow_nan=False) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(output)
            print(f"Saved results to {args.output}")
        else:
            print(output, end="")
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Analysis failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
