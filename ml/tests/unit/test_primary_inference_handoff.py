"""Portable input validation uses fixed values; no model fitting."""

import json

import numpy as np
import pytest

from iotguard.inference.primary_classifier import FrozenPrimaryPredictor, sha256


@pytest.fixture
def predictor():
    instance = object.__new__(FrozenPrimaryPredictor)
    instance.contract = {"feature_order": [f"feature_{i}" for i in range(115)]}
    return instance


def test_raw_view_uses_float32_without_scaling(predictor):
    rows = np.full((2, 115), 100.25, dtype=np.float64)
    actual = predictor.validate_inputs(rows, feature_order=predictor.contract["feature_order"])
    assert actual.dtype == np.float32 and np.all(actual == 100.25)


@pytest.mark.parametrize(
    "kind", ["order", "shape", "empty", "nan", "infinity", "overflow", "text", "boolean"]
)
def test_invalid_inputs_rejected(predictor, kind):
    rows = np.zeros((2, 115))
    names = list(predictor.contract["feature_order"])
    if kind == "order":
        names.reverse()
    elif kind == "shape":
        rows = rows[:, :-1]
    elif kind == "empty":
        rows = rows[:0]
    elif kind in {"nan", "infinity", "overflow"}:
        rows[0, 0] = {"nan": np.nan, "infinity": np.inf, "overflow": 1e100}[kind]
    elif kind == "text":
        rows = rows.astype(str)
    else:
        rows = rows.astype(bool)
    with pytest.raises(ValueError):
        predictor.validate_inputs(rows, feature_order=names)


def test_manifest_pin_rejects_substituted_bundle(tmp_path):
    (tmp_path / "manifest.json").write_text("{}")
    with pytest.raises(ValueError, match="manifest"):
        FrozenPrimaryPredictor(tmp_path, expected_manifest_sha256="a" * 64)


def test_payload_tamper_rejected_before_model_loading(tmp_path):
    p = tmp_path / "model.json"
    p.write_text("fixed bytes")
    manifest = {
        "schema_version": "primary_inference_handoff_v1",
        "files": {"model.json": {"bytes": p.stat().st_size, "sha256": sha256(p)}},
    }
    m = tmp_path / "manifest.json"
    m.write_text(json.dumps(manifest))
    p.write_text("tampered")
    with pytest.raises(ValueError, match="checksum"):
        FrozenPrimaryPredictor(tmp_path, expected_manifest_sha256=sha256(m))
