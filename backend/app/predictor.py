"""Single prediction entry point for the server and the Raspberry Pi.

Only NumPy and XGBoost are required, so this file can be copied to the Pi
together with ``model.json`` and ``input_contract.json`` (or the freeze manifest).
It never trains, scales or modifies the model: raw values are cast to float32,
and a malicious probability >= THRESHOLD means "malicious".

Typical use::

    predictor = get_predictor()                  # verifies the model SHA-256 once
    out = predictor.predict(rows)                # rows: n x 115 numbers
    out["labels"], out["probabilities"]
"""

from __future__ import annotations

import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path

import numpy as np

THRESHOLD = 0.5
N_FEATURES = 115
LABELS = ("benign", "malicious")

REPO_ROOT = Path(__file__).resolve().parents[2]
# Paths can be overridden so a packaged app does not depend on the author's layout.
FREEZE_PATH = Path(os.environ.get(
    "IOTGUARD_FREEZE_PATH",
    REPO_ROOT / "ml/artifacts/manifests/primary_model_freeze_20261105.json"))
MODEL_PATH = Path(os.environ.get(
    "IOTGUARD_MODEL_PATH",
    REPO_ROOT / "ml/experiments/xgb_frac1_seed42_lr01/model.json"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class FrozenPredictor:
    """Loads the frozen XGBoost model once and predicts n x 115 raw feature rows."""

    def __init__(self, model_path: Path = MODEL_PATH, freeze_path: Path = FREEZE_PATH):
        import xgboost as xgb

        freeze = json.loads(Path(freeze_path).read_text(encoding="utf-8"))
        contract = freeze["input_contract"]
        if (contract["threshold"] != THRESHOLD or contract["input_view"] != "raw"
                or contract["label_mapping"] != {"benign": 0, "malicious": 1}
                or len(contract["feature_order"]) != N_FEATURES):
            raise RuntimeError("Unsupported frozen input contract")
        if _sha256(Path(model_path)) != freeze["model"]["sha256"]:
            raise RuntimeError("Saved model does not match the team's frozen model")

        self._xgb = xgb
        self.feature_order: list[str] = list(contract["feature_order"])
        self.model_id: str = freeze["selected_run_id"]
        self.model_sha256: str = freeze["model"]["sha256"]
        self.booster = xgb.Booster()
        self.booster.load_model(model_path)
        self.booster.set_param({"nthread": 2})
        if self.booster.num_features() != N_FEATURES:
            raise RuntimeError("Model does not expect 115 features")

    def validate(self, rows) -> np.ndarray:
        """Return a float32 (n, 115) matrix, or raise ValueError with a clear reason."""
        nonnumeric_scalars = (bool, np.bool_, str, bytes)
        try:
            # Object dtype preserves scalar types in mixed Python rows.
            raw = rows if isinstance(rows, np.ndarray) else np.asarray(rows, dtype=object)
            if raw.dtype.kind in "bSUT" or (
                raw.dtype.kind == "O"
                and any(isinstance(value, nonnumeric_scalars) for value in raw.flat)
            ):
                raise TypeError("Boolean and string features are not supported")
            values = np.asarray(raw, dtype=np.float64)
        except (TypeError, ValueError, OverflowError) as error:
            raise ValueError("Rows must contain only numbers") from error
        if values.ndim != 2 or values.shape[0] == 0:
            raise ValueError("Rows must be a nonempty list of rows")
        if values.shape[1] != N_FEATURES:
            raise ValueError(f"Each row needs exactly {N_FEATURES} values, got {values.shape[1]}")
        if not np.isfinite(values).all():
            raise ValueError("Rows cannot contain NaN or infinity")
        with np.errstate(over="ignore"):
            encoded = values.astype(np.float32)
        if not np.isfinite(encoded).all():
            raise ValueError("Rows contain values too large for the model's float32 input")
        return encoded

    def predict(self, rows) -> dict:
        """Predict raw rows. Returns aligned probabilities, predictions and labels."""
        encoded = self.validate(rows)
        probabilities = self.booster.predict(self._xgb.DMatrix(encoded, nthread=2))
        if (probabilities.shape != (len(encoded),) or not np.isfinite(probabilities).all()
                or np.any((probabilities < 0) | (probabilities > 1))):
            raise RuntimeError("Model returned invalid probabilities")
        malicious = probabilities >= THRESHOLD
        return {
            "model_id": self.model_id,
            "model_sha256": self.model_sha256,
            "threshold": THRESHOLD,
            "probabilities": probabilities.astype(float).tolist(),
            "predictions": malicious.astype(int).tolist(),
            "labels": [LABELS[int(flag)] for flag in malicious],
        }


@lru_cache(maxsize=1)
def get_predictor() -> FrozenPredictor:
    """Shared instance; the SHA-256 check runs only on first use."""
    return FrozenPredictor()


def predict(rows) -> dict:
    """Convenience wrapper around the shared predictor."""
    return get_predictor().predict(rows)
