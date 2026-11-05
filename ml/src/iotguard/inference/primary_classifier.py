"""Standalone frozen primary XGBoost inference; NumPy/XGBoost only, no fitting."""

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


class FrozenPrimaryPredictor:
    """Require the externally published manifest identity and exact feature order."""

    def __init__(self, directory, *, expected_manifest_sha256):
        import xgboost as xgb

        self.root = Path(directory).resolve()
        if sha256(self.root / "manifest.json") != expected_manifest_sha256:
            raise ValueError("Unexpected inference bundle manifest")
        manifest = read_json(self.root / "manifest.json")
        if manifest["schema_version"] != "primary_inference_handoff_v1":
            raise ValueError("Unsupported inference bundle schema")
        for name, identity in manifest["files"].items():
            path = (self.root / name).resolve()
            if (
                path.parent != self.root
                or path.stat().st_size != identity["bytes"]
                or sha256(path) != identity["sha256"]
            ):
                raise ValueError(f"Bundle payload checksum mismatch: {name}")
        self.contract = read_json(self.root / "input_contract.json")
        contract = self.contract
        if (
            contract["schema_version"] != "primary_classifier_input_v1"
            or len(contract["feature_order"]) != 115
            or len(set(contract["feature_order"])) != 115
            or contract["threshold"] != 0.5
            or contract["input_view"] != "raw"
            or contract["model_dtype"] != "float32"
            or contract["apply_scaler"] is not False
            or contract["label_mapping"] != {"benign": 0, "malicious": 1}
            or contract["model_sha256"] != manifest["files"]["model.json"]["sha256"]
        ):
            raise ValueError("Incompatible frozen input contract")
        self.model = xgb.Booster()
        self.model.load_model(self.root / "model.json")
        self.model.set_param({"nthread": 2})
        config = json.loads(self.model.save_config())
        if (
            self.model.num_features() != 115
            or config["learner"]["objective"]["name"] != "binary:logistic"
        ):
            raise ValueError("Incompatible frozen model")
        self.manifest_sha256 = expected_manifest_sha256

    def validate_inputs(self, values, *, feature_order):
        if list(feature_order) != self.contract["feature_order"]:
            raise ValueError("Require exact ordered primary feature names")
        raw = np.asarray(values)
        if (
            raw.ndim != 2
            or raw.shape[1] != 115
            or raw.shape[0] == 0
            or raw.dtype.kind not in "iuf"
            or not np.isfinite(raw).all()
        ):
            raise ValueError("Require nonempty finite numeric rows with 115 columns")
        with np.errstate(over="ignore"):
            encoded = np.asarray(raw, dtype=np.float32)
        if not np.isfinite(encoded).all():
            raise ValueError("Input overflows the frozen float32 model view")
        return encoded

    def predict(self, values, *, feature_order):
        import xgboost as xgb

        inputs = self.validate_inputs(values, feature_order=feature_order)
        probability = self.model.predict(xgb.DMatrix(inputs, nthread=2))
        if (
            probability.shape != (len(inputs),)
            or not np.isfinite(probability).all()
            or np.any((probability < 0) | (probability > 1))
        ):
            raise ValueError("Invalid model probabilities")
        predictions = (probability >= 0.5).astype("uint8")
        return {
            "probabilities": probability.astype(float).tolist(),
            "predictions": predictions.tolist(),
            "labels": ["malicious" if p else "benign" for p in predictions],
        }


def verify(directory, expected_manifest):
    predictor = FrozenPrimaryPredictor(directory, expected_manifest_sha256=expected_manifest)
    example = read_json(Path(directory) / "example_input.json")
    expected = read_json(Path(directory) / "example_expected.json")
    actual = predictor.predict(example["rows"], feature_order=example["feature_order"])
    if (
        not np.allclose(actual["probabilities"], expected["probabilities"], rtol=1e-12, atol=1e-12)
        or actual["predictions"] != expected["predictions"]
        or actual["labels"] != expected["labels"]
    ):
        raise ValueError("Standalone inference example parity failed")
    import xgboost

    return {
        "status": "PASS",
        "manifest_sha256": expected_manifest,
        "model_sha256": predictor.contract["model_sha256"],
        "example_rows": len(example["rows"]),
        "actual_output": actual,
        "numpy": np.__version__,
        "xgboost": xgboost.__version__,
        "raw_dataset_required": False,
        "git_checkout_required": False,
        "classifiers_fitted": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--expected-manifest", required=True)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="New output JSON path")
    args = parser.parse_args()
    if args.verify:
        result = verify(args.bundle, args.expected_manifest)
    else:
        if args.input is None:
            parser.error("--input is required for inference")
        inputs = read_json(args.input)
        predictor = FrozenPrimaryPredictor(
            args.bundle, expected_manifest_sha256=args.expected_manifest
        )
        result = predictor.predict(inputs["rows"], feature_order=inputs["feature_order"])
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(result)


if __name__ == "__main__":
    main()
