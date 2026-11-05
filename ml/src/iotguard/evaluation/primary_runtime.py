"""Inference-only runtime shared by primary validation replay and final evaluation."""

import hashlib
import importlib.metadata
import json
import platform
import subprocess
import warnings
from pathlib import Path

import numpy as np

from iotguard.data.primary_package import PrimaryPackage, sha256_file

EXPECTED_MANIFEST = "6ab99e86397242e219bfa1f8490d8e03b169ec87a092af80cb3e7aef1e61147b"


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, data):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, allow_nan=False)
        stream.write("\n")


def file_identity(path):
    path = Path(path).resolve()
    return {"path": str(path), "sha256": sha256_file(path), "bytes": path.stat().st_size}


def check_file(identity):
    path = Path(identity["path"])
    if path.stat().st_size != identity["bytes"] or sha256_file(path) != identity["sha256"]:
        raise ValueError(f"Bound file changed: {path}")
    return path


def environment():
    versions = {}
    for name in ("numpy", "scikit-learn", "xgboost", "joblib", "scipy", "threadpoolctl"):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            pass
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "packages": versions,
    }


def evaluation_identity():
    repo = Path(__file__).resolve().parents[4]
    paths = [
        Path(__file__),
        Path(__file__).with_name("primary.py"),
        Path(__file__).with_name("population.py"),
    ]
    paths += sorted(Path(__file__).parent.glob("primary_*evaluation.py"))
    paths += [
        Path(__file__).with_name("comparison.py"),
        Path(__file__).with_name("primary_acceptance.py"),
        repo / "ml/scripts/final_primary_evaluation.py",
        repo / "ml/docs/protocols/primary_final_evaluation_v1.md",
    ]
    return {
        "revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True
        ).strip(),
        "dirty_worktree": bool(
            subprocess.check_output(["git", "status", "--porcelain"], cwd=repo, text=True)
        ),
        "implementation": {p.name: file_identity(p) for p in paths},
    }


def verified_package(
    root, *, expected_manifest=EXPECTED_MANIFEST, partitions=("TRAIN", "VALIDATION")
):
    root = Path(root)
    if sha256_file(root / "manifest.json") != expected_manifest:
        raise ValueError("Unexpected package manifest SHA-256")
    package = PrimaryPackage(root, verify=False)
    m = package.manifest
    checked = {}
    for name, identity in m["files"].items():
        if name.startswith("TEST_") and "TEST" not in partitions:
            continue
        if name.startswith(("TRAIN_", "VALIDATION_", "TEST_")) and not any(
            name.startswith(p + "_") for p in partitions
        ):
            continue
        if sha256_file(root / name) != identity["sha256"]:
            raise ValueError(f"Package checksum mismatch: {name}")
        checked[name] = identity
    for partition in partitions:
        package.load(partition, allow_test=partition == "TEST")
    return package, {
        "status": "PASS",
        "manifest": file_identity(root / "manifest.json"),
        "checked_payloads": checked,
        "partitions": list(partitions),
        "TEST_opened": "TEST" in partitions,
    }


def input_contract(package, result):
    config = result["resolved_configuration"]
    if config["threshold"] != 0.5 or config["input_view"] not in {"raw", "scaled"}:
        raise ValueError("Invalid input view or threshold")
    parameters = config["parameters"]
    if config["input_view"] == "scaled":
        family, dtype = "LR", "float64"
    elif parameters.get("strategy") == "most_frequent":
        family, dtype = "Dummy", "uint8 constant single-column input"
    elif parameters.get("algorithm") == "RandomForestClassifier":
        family, dtype = "RF", "float32"
    elif parameters.get("algorithm") == "XGBoost":
        family, dtype = "XGB", "float32"
    else:
        raise ValueError("Unsupported classifier workflow")
    return {
        "family": family,
        "input_view": config["input_view"],
        "fit_dtype": dtype,
        "feature_order": package.manifest["feature_order"],
        "feature_contract": file_identity(package.root / "n_baiot_feature_contract_v1.json"),
        "scaler": file_identity(package.root / "scaler.json"),
        "label_mapping": {"benign": 0, "malicious": 1},
        "threshold": 0.5,
    }


def load_predictor(model_path, contract, *, parameters=None):
    """Deserialize only trusted inventoried models. This module contains no fitting."""
    model_path = Path(model_path)
    family = contract["family"]
    captured = []
    if family == "XGB":
        import xgboost as xgb

        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            model = xgb.Booster()
            model.load_model(model_path)
        model.set_param({"nthread": 2})
        if model.num_features() != 115:
            raise ValueError("Model feature count differs")
        if parameters and model.num_boosted_rounds() != parameters["num_boost_round"]:
            raise ValueError("Persisted boosting rounds differ")

        def predict(block):
            return model.predict(xgb.DMatrix(np.asarray(block, dtype=np.float32), nthread=2))

        summary = {
            "features": model.num_features(),
            "rounds": model.num_boosted_rounds(),
            "persisted_config": json.loads(model.save_config()),
            "limitation": "Model JSON does not retain every historical training parameter; "
            "original result plus exact Git implementation supplies those parameters.",
        }
    else:
        import joblib
        import sklearn
        from sklearn.exceptions import InconsistentVersionWarning

        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            model = joblib.load(model_path)
        if any(issubclass(w.category, InconsistentVersionWarning) for w in captured):
            raise ValueError("Use the original scikit-learn version to load this model")
        if list(model.classes_) != [0, 1]:
            raise ValueError("Model class order differs")
        expected_class = {
            "RF": "RandomForestClassifier",
            "LR": "LogisticRegression",
            "Dummy": "DummyClassifier",
        }[family]
        if type(model).__name__ != expected_class:
            raise ValueError("Model family differs from result")
        if family != "Dummy" and model.n_features_in_ != 115:
            raise ValueError("Model feature count differs")
        actual = model.get_params()
        for key, value in (parameters or {}).items():
            if key in actual and actual[key] != value:
                raise ValueError(f"Persisted model configuration differs: {key}")
        if family == "RF":
            model.set_params(n_jobs=2)  # inference resource limit; no model fitting

        def predict(block):
            if family == "Dummy":
                block = np.zeros((len(block), 1), dtype=np.uint8)
            elif family == "RF":
                block = np.asarray(block, dtype=np.float32)
            return model.predict_proba(block)[:, 1]

        summary = {
            "class": expected_class,
            "parameters": actual,
            "scikit_learn": sklearn.__version__,
        }
    summary["load_warnings"] = [
        {"category": w.category.__name__, "message": str(w.message)} for w in captured
    ]
    return predict, summary


def predict_partition(
    package, result, model_path, partition, output, *, allow_test=False, chunk_size=16_384
):
    if partition == "TEST" and not allow_test:
        raise PermissionError("Final freeze gate required before TEST inference")
    if chunk_size < 1:
        raise ValueError("chunk_size must be positive")
    contract = input_contract(package, result)
    predict, summary = load_predictor(
        model_path, contract, parameters=result["resolved_configuration"]["parameters"]
    )
    reloaded, _ = load_predictor(
        model_path, contract, parameters=result["resolved_configuration"]["parameters"]
    )
    x, y, metadata = package.load(partition, allow_test=allow_test)
    probability_path = Path(output) / "probabilities.npy"
    probabilities = np.lib.format.open_memmap(
        probability_path, mode="w+", dtype="<f8", shape=(len(y),)
    )
    max_delta = 0.0
    for start in range(0, len(y), chunk_size):
        stop = min(start + chunk_size, len(y))
        block = x[start:stop]
        if contract["input_view"] == "scaled":
            block = (block - package.mean) / package.scale
        if not np.isfinite(block).all():
            raise ValueError("Nonfinite inference features")
        p, q = np.asarray(predict(block)), np.asarray(reloaded(block))
        if p.shape != (stop - start,) or not np.isfinite(p).all() or np.any((p < 0) | (p > 1)):
            raise ValueError("Invalid model probabilities")
        if not np.allclose(p, q, rtol=1e-12, atol=1e-12) or np.any((p >= 0.5) != (q >= 0.5)):
            raise ValueError("Reload prediction parity failed")
        max_delta = max(max_delta, float(np.max(np.abs(p - q))))
        probabilities[start:stop] = p
    probabilities.flush()
    del probabilities
    probabilities = np.load(probability_path, mmap_mode="r", allow_pickle=False)
    np.save(Path(output) / "predictions.npy", (probabilities >= 0.5).astype("uint8"))
    np.save(Path(output) / "labels.npy", y)
    np.save(Path(output) / "metadata.npy", metadata)
    if (
        sha256_file(Path(output) / "metadata.npy")
        != package.manifest["files"][f"{partition}_metadata.npy"]["sha256"]
    ):
        raise ValueError("Output row identity differs from package")
    return (
        y,
        probabilities,
        {
            "reload_parity": "PASS",
            "max_probability_delta": max_delta,
            "rows": len(y),
            "model_state": summary,
            "input_contract": contract,
        },
    )


def payload_identities(directory):
    return {p.name: file_identity(p) for p in sorted(Path(directory).iterdir()) if p.is_file()}


def json_digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
