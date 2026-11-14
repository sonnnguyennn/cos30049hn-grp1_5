"""Sample export contract and integrity guards; no training or dataset access."""

import csv
import json

import pytest

from iotguard.inference.sample_prediction import (
    FREEZE_PATH,
    export_samples,
    sample_predictions,
)


@pytest.mark.parametrize("count", [0, 101, -1, True, 1.5])
def test_invalid_sample_count_rejected_without_reading_data(tmp_path, count):
    with pytest.raises(ValueError, match="samples per class"):
        sample_predictions(tmp_path / "missing-package", tmp_path / "missing-model",
                           per_class=count)


def test_substituted_model_rejected_before_dataset_access(tmp_path):
    model = tmp_path / "model.json"
    model.write_text("{}")
    with pytest.raises(ValueError, match="frozen classifier"):
        sample_predictions(tmp_path / "missing-package", model)


def test_export_preserves_raw_precision_and_separates_ground_truth(tmp_path):
    features = json.loads(FREEZE_PATH.read_text())["input_contract"]["feature_order"]
    row = [0.0] * 115
    row[0], row[35] = 1.2345678901234567, -0.12345678901234567
    inputs = {"feature_order": features, "rows": [row]}
    report = {"samples": [{"actual_label": "malicious", "predicted_label": "benign"}]}
    destination = tmp_path / "export"
    export_samples(destination, inputs, report)

    assert json.loads((destination / "sample_input.json").read_text()) == inputs
    assert json.loads((destination / "predictions.json").read_text()) == report
    with (destination / "sample_input.csv").open(newline="") as stream:
        header, values = list(csv.reader(stream))
    assert header == features
    assert [float(value) for value in values] == row


def test_existing_results_are_preserved(tmp_path):
    destination = tmp_path / "previous-run"
    destination.mkdir()
    previous = destination / "predictions.json"
    previous.write_text("original results")
    with pytest.raises(FileExistsError):
        export_samples(destination, {}, {})
    assert previous.read_text() == "original results"
    assert list(destination.iterdir()) == [previous]
