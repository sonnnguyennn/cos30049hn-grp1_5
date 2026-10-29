from __future__ import annotations

from pathlib import Path

from iotguard.data.transforms import TrainFittedTransform

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_learned_transform_is_interface_only() -> None:
    assert getattr(TrainFittedTransform, "fit")
    assert getattr(TrainFittedTransform, "transform")


def test_no_fitted_or_split_outputs_exist() -> None:
    prohibited_suffixes = {".joblib", ".pkl", ".pickle", ".onnx", ".tflite", ".pt", ".pth"}
    artifact_files = [path for path in (PROJECT_ROOT / "artifacts").rglob("*") if path.is_file()]
    assert not [path for path in artifact_files if path.suffix.lower() in prohibited_suffixes]
    assert not [
        path
        for path in artifact_files
        if any(
            token in path.name.lower()
            for token in ("train_split", "validation_split", "test_split")
        )
    ]
