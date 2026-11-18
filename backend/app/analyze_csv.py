"""Analyze CSV or JSON features with the team's saved model; importable by FastAPI."""

import argparse
import csv
import hashlib
import io
import json
import sys
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from time import perf_counter

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
    try:
        return json.loads(FREEZE.read_text(encoding="utf-8"))["input_contract"]["feature_order"]
    except (OSError, ValueError, KeyError) as error:
        raise RuntimeError("Frozen input contract unavailable") from error


@lru_cache(maxsize=1)
def load_model():
    """Check the saved model once, then reuse it across uploads."""
    freeze = json.loads(FREEZE.read_text(encoding="utf-8"))
    if hashlib.sha256(MODEL.read_bytes()).hexdigest() != freeze["model"]["sha256"]:
        raise RuntimeError("Saved model does not match the team's frozen model")
    try:
        model = xgb.Booster()
        model.load_model(MODEL)
    except xgb.core.XGBoostError as error:
        raise RuntimeError("Frozen model could not be loaded") from error
    model.set_param({"nthread": 2})
    return model


def analyze_csv(csv_text, *, filename=None):
    """CSV text in -> JSON-compatible dictionary out. Does not train or save uploads."""
    check_text_size(csv_text)
    names = feature_names()
    reader = csv.reader(io.StringIO(csv_text.removeprefix("\ufeff")), strict=True)
    rows = []
    metadata = []
    try:
        header = next(reader, None)
        if (header is None or header[:len(names)] != names
                or len(set(header)) != len(header)
                or not set(header[len(names):]).issubset({"sample_name", "ground_truth"})):
            raise ValueError("CSV header must contain exactly the 115 model features in order; "
                             "optional sample_name and ground_truth columns may follow")
        extra_names = header[len(names):]
        for row_number, row in enumerate(reader, start=1):
            if row_number > MAX_ROWS:
                raise ValueError(f"CSV must contain at most {MAX_ROWS} data rows")
            if len(row) != len(header):
                raise ValueError(f"Data row {row_number}: expected {len(header)} values")
            try:
                rows.append([float(value) for value in row[:len(names)]])
            except ValueError as error:
                raise ValueError(f"Data row {row_number}: all values must be numeric") from error
            item = dict(zip(extra_names, row[len(names):], strict=True))
            if "ground_truth" in item:
                label = item["ground_truth"].strip().lower()
                item["ground_truth"] = {"0": "benign", "1": "malicious", "": None}.get(
                    label, label)
            if item.get("sample_name") == "":
                item["sample_name"] = None
            metadata.append(item)
    except csv.Error as error:
        raise ValueError(f"Invalid CSV: {error}") from error
    if not rows:
        raise ValueError("CSV has no data rows")
    return analyze_rows(rows, names, metadata=metadata, filename=filename, input_format="csv")


def check_text_size(text):
    if len(text.encode("utf-8")) > MAX_UPLOAD_BYTES:
        raise ValueError(UPLOAD_LIMIT_MESSAGE)


def analyze_json(json_text, *, filename=None):
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
    return analyze_rows(rows, names, metadata=data.get("sample_metadata"),
                        filename=filename, input_format="json")


def analyze_file(content, filename):
    """Uploaded bytes and filename in -> analysis dictionary out."""
    started = perf_counter()
    started_at = datetime.now(UTC).isoformat()
    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError(UPLOAD_LIMIT_MESSAGE)
    extension = Path(filename).suffix.lower()
    if extension not in {".csv", ".json"}:
        raise ValueError("Choose a .csv or .json file")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError("Save the CSV or JSON file using UTF-8 encoding") from error
    # Treat the supplied name as a display name, never as a server filesystem path.
    filename = filename.replace("\\", "/").rsplit("/", 1)[-1]
    result = (analyze_json(text, filename=filename) if extension == ".json"
              else analyze_csv(text, filename=filename))
    result["summary"].update({
        "file_size_bytes": len(content),
        "started_at": started_at,
        "completed_at": datetime.now(UTC).isoformat(),
        "processing_ms": round((perf_counter() - started) * 1000, 3),
    })
    return result


def sample_metadata(metadata, count, filename):
    """Ground truth is supplied by the caller; it is never inferred from predictions."""
    if metadata is None:
        metadata = [{} for _ in range(count)]
    if not isinstance(metadata, list) or len(metadata) != count:
        raise ValueError("sample_metadata must contain one object per data row")
    normalized = []
    for number, item in enumerate(metadata, start=1):
        if not isinstance(item, dict) or not set(item).issubset({"sample_name", "ground_truth"}):
            raise ValueError(f"Sample {number}: use only sample_name and ground_truth metadata")
        name = item.get("sample_name")
        if name is not None and (not isinstance(name, str) or not name.strip() or len(name) > 200):
            raise ValueError(f"Sample {number}: sample_name must be 1..200 characters")
        truth = item.get("ground_truth")
        if type(truth) is int and truth in (0, 1):
            truth = "malicious" if truth else "benign"
        if truth is not None and (not isinstance(truth, str)
                                  or truth not in {"benign", "malicious"}):
            raise ValueError(f"Sample {number}: ground_truth must be benign, malicious, 0, 1 or null")
        normalized.append({
            "sample_name": name.strip() if name is not None else f"{filename or 'Sample'} · {number}",
            "ground_truth": truth,
        })
    return normalized


def analyze_rows(rows, names, *, metadata=None, filename=None, input_format=None):
    """Shared numeric validation, inference and statistics for both formats."""
    started = perf_counter()
    started_at = datetime.now(UTC).isoformat()
    metadata = sample_metadata(metadata, len(rows), filename)
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
    model = load_model()
    inference_started = perf_counter()
    try:
        probabilities = model.predict(xgb.DMatrix(model_values, nthread=2))
    except xgb.core.XGBoostError as error:
        raise RuntimeError("Frozen model prediction failed") from error
    inference_ms = round((perf_counter() - inference_started) * 1000, 3)
    if (probabilities.shape != (len(rows),) or not np.isfinite(probabilities).all()
            or np.any((probabilities < 0) | (probabilities > 1))):
        raise RuntimeError("Model returned invalid probabilities")
    malicious = probabilities >= 0.5
    freeze = json.loads(FREEZE.read_text(encoding="utf-8"))
    results = []
    for i, probability in enumerate(probabilities):
        score = float(probability)
        label = "malicious" if malicious[i] else "benign"
        truth = metadata[i]["ground_truth"]
        results.append({
            "row": i + 1,
            "sample_name": metadata[i]["sample_name"],
            "label": label,
            "score": score,
            "probability_malicious": score,
            "probability_benign": 1 - score,
            "confidence": score if malicious[i] else 1 - score,
            "ground_truth": truth,
            "correct": label == truth if truth is not None else None,
        })
    labeled = [row for row in results if row["ground_truth"] is not None]
    correct = sum(row["correct"] for row in labeled)
    response = {
        "schema_version": "traffic_analysis_v2",
        "model": "xgb_frac1_seed42_lr01",
        "threshold": 0.5,
        "runtime": {"numpy": np.__version__, "xgboost": xgb.__version__},
        "summary": {
            "rows": len(rows),
            "features": len(names),
            "benign": int((~malicious).sum()),
            "malicious": int(malicious.sum()),
            "file_name": filename,
            "input_format": input_format,
            "file_size_bytes": None,
            "mode": "manual_analysis",
            "started_at": started_at,
            "inference_ms": inference_ms,
            "malicious_rate": float(malicious.mean()),
            "mean_score": float(np.mean(probabilities, dtype=np.float64)),
            "mean_confidence": float(np.mean([row["confidence"] for row in results])),
            "score_type": "probability_malicious",
            "threshold": 0.5,
            "model": {
                "id": freeze["selected_run_id"],
                "name": "XGBoost binary traffic classifier",
                "algorithm": "XGBoost",
                "objective": "binary:logistic",
                "sha256": freeze["model"]["sha256"],
            },
            "preprocessor": {
                "name": "Raw N-BaIoT features → float32",
                "feature_count": len(names),
                "input_dtype": "float64",
                "model_dtype": "float32",
                "scaling_applied": False,
                "steps": ["Validate feature order", "Validate finite numeric values",
                          "Cast to float32"],
            },
            "ground_truth": {
                "source": "upload_metadata" if labeled else None,
                "provided_rows": len(labeled),
                "missing_rows": len(rows) - len(labeled),
                "correct": correct,
                "incorrect": len(labeled) - correct,
                "accuracy": correct / len(labeled) if labeled else None,
            },
        },
        "results": results,
        "feature_stats": [
            {"feature": name, "min": float(values[:, i].min()),
             "max": float(values[:, i].max()), "mean": float(values[:, i].mean())}
            for i, name in enumerate(names)
        ],
    }
    response["summary"].update({
        "completed_at": datetime.now(UTC).isoformat(),
        "processing_ms": round((perf_counter() - started) * 1000, 3),
    })
    return response


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
