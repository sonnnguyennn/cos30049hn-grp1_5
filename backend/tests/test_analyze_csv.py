"""CSV contract and prediction response tests; no model training."""

import csv
import io
import json
import os
import subprocess
import sys
from datetime import datetime
from types import SimpleNamespace

import numpy as np
import pytest

from backend.app import analyze_csv as analyzer


def use_model_stub(monkeypatch, booster):
    freeze = json.loads(analyzer.FREEZE.read_text(encoding="utf-8"))
    shared = SimpleNamespace(
        booster=booster,
        feature_order=freeze["input_contract"]["feature_order"],
        model_id=freeze["selected_run_id"],
        model_sha256=freeze["model"]["sha256"],
    )
    monkeypatch.setattr(analyzer, "load_model", lambda: shared)


def make_csv(rows, header=None):
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(analyzer.feature_names() if header is None else header)
    writer.writerows(rows)
    return stream.getvalue()


@pytest.mark.parametrize("bad_value", ["", "hello", "True", "nan", "inf", "-inf", "1e100"])
def test_invalid_cells_rejected_before_model_load(monkeypatch, bad_value):
    def unexpected_load():
        pytest.fail("Invalid input reached the model")

    monkeypatch.setattr(analyzer, "load_model", unexpected_load)
    with pytest.raises(ValueError):
        analyzer.analyze_csv(make_csv([[bad_value] + [0] * 114]))


@pytest.mark.parametrize("kind", ["missing", "extra", "reordered", "duplicate"])
def test_feature_header_must_match_exactly(kind):
    names = analyzer.feature_names()
    if kind == "missing":
        names.pop()
    elif kind == "extra":
        names.append("label")
    elif kind == "reordered":
        names.reverse()
    else:
        names[1] = names[0]
    with pytest.raises(ValueError, match="header"):
        analyzer.analyze_csv(make_csv([[0] * len(names)], header=names))


@pytest.mark.parametrize("rows", [[], [[]], [[0] * 114], [[0] * 116]])
def test_empty_or_malformed_rows_rejected(rows):
    with pytest.raises(ValueError):
        analyzer.analyze_csv(make_csv(rows))


def test_upload_and_row_limits(monkeypatch):
    monkeypatch.setattr(analyzer, "MAX_UPLOAD_BYTES", 5)
    with pytest.raises(ValueError, match="no larger"):
        analyzer.analyze_csv("123456")
    monkeypatch.setattr(analyzer, "MAX_UPLOAD_BYTES", 100 * 1024 * 1024)
    monkeypatch.setattr(analyzer, "MAX_ROWS", 1)
    with pytest.raises(ValueError, match="at most 1"):
        analyzer.analyze_csv(make_csv([[0] * 115, [1] * 115]))


def test_threshold_raw_values_and_statistics(monkeypatch):
    class Model:
        def predict(self, matrix):
            assert matrix.num_row() == 2 and matrix.num_col() == 115
            # Ensure covariance values remain negative and no scaler is applied.
            np.testing.assert_array_equal(matrix.get_data().toarray(), [[-2] * 115, [4] * 115])
            return np.asarray([0.49, 0.5])

    use_model_stub(monkeypatch, Model())
    result = analyzer.analyze_csv("\ufeff" + make_csv([[-2] * 115, [4] * 115]))
    assert {key: result["summary"][key] for key in ("rows", "features", "benign", "malicious")} == {
        "rows": 2, "features": 115, "benign": 1, "malicious": 1,
    }
    assert result["results"] == [
        {"row": 1, "sample_name": "Sample · 1", "label": "benign", "score": 0.49,
         "probability_malicious": 0.49, "probability_benign": 0.51, "confidence": 0.51,
         "ground_truth": None, "correct": None},
        {"row": 2, "sample_name": "Sample · 2", "label": "malicious", "score": 0.5,
         "probability_malicious": 0.5, "probability_benign": 0.5, "confidence": 0.5,
         "ground_truth": None, "correct": None},
    ]
    assert result["summary"]["ground_truth"]["accuracy"] is None
    assert result["feature_stats"][0] == {
        "feature": analyzer.feature_names()[0], "min": -2, "max": 4, "mean": 1,
    }


@pytest.mark.parametrize("cell", [None, True, False, "2", {}, [], float("nan"),
                                  float("inf"), 1e100, 10 ** 400])
def test_invalid_json_numbers_rejected(cell):
    content = json.dumps({"feature_order": analyzer.feature_names(),
                          "rows": [[cell] + [0] * 114]})
    with pytest.raises(ValueError):
        analyzer.analyze_json(content)


@pytest.mark.parametrize("data", [[], {}, {"rows": []}, {"rows": [[0] * 115]}])
def test_invalid_json_structure_rejected(data):
    with pytest.raises(ValueError):
        analyzer.analyze_json(json.dumps(data))


@pytest.mark.parametrize("rows", [[], None, [None], [[0] * 114], [[0] * 116]])
def test_json_rows_shape_rejected(rows):
    with pytest.raises(ValueError):
        analyzer.analyze_json(json.dumps({"feature_order": analyzer.feature_names(), "rows": rows}))


def test_csv_json_predictions_match_with_real_model():
    rows = [[-2] * 115, [4] * 115]
    csv_result = analyzer.analyze_file(make_csv(rows).encode(), "traffic.CSV")
    json_result = analyzer.analyze_file(json.dumps({
        "feature_order": analyzer.feature_names(), "rows": rows,
    }).encode(), "traffic.JSON")
    assert csv_result["feature_stats"] == json_result["feature_stats"]
    assert [row["probability_malicious"] for row in csv_result["results"]] == [
        row["probability_malicious"] for row in json_result["results"]
    ]
    assert csv_result["summary"]["input_format"] == "csv"
    assert json_result["summary"]["input_format"] == "json"


def test_json_larger_than_old_10_mib_limit_is_accepted():
    content = json.dumps({"feature_order": analyzer.feature_names(), "rows": [[0] * 115]})
    content += " " * (10 * 1024 * 1024)
    result = analyzer.analyze_file(content.encode(), "large.json")
    assert result["summary"]["rows"] == 1


@pytest.mark.parametrize("content, name", [(b"\xff", "file.json"), (b"{}", "file.txt"),
                                           (b"{broken", "file.json")])
def test_invalid_uploads_rejected(content, name):
    with pytest.raises(ValueError):
        analyzer.analyze_file(content, name)


def test_json_row_and_file_limits(monkeypatch):
    content = json.dumps({"feature_order": analyzer.feature_names(), "rows": [[0] * 115] * 2})
    monkeypatch.setattr(analyzer, "MAX_ROWS", 1)
    with pytest.raises(ValueError, match="at most 1"):
        analyzer.analyze_json(content)
    monkeypatch.setattr(analyzer, "MAX_UPLOAD_BYTES", 5)
    with pytest.raises(ValueError, match="no larger"):
        analyzer.analyze_file(content.encode(), "file.json")
    with pytest.raises(ValueError, match="no larger"):
        analyzer.analyze_json(content)


def test_limits_can_be_configured_at_startup():
    command = [sys.executable, "-c", (
        "from backend.app.upload_limits import MAX_UPLOAD_BYTES, MAX_ROWS; "
        "assert MAX_UPLOAD_BYTES == 250 * 1024 * 1024; assert MAX_ROWS == 250000"
    )]
    subprocess.run(command, check=True, env={**os.environ, "IOTGUARD_MAX_UPLOAD_MB": "250",
                                            "IOTGUARD_MAX_ANALYSIS_ROWS": "250000"})


def test_metadata_stays_out_of_model_and_partial_ground_truth_metrics(monkeypatch):
    class Model:
        def predict(self, matrix):
            # Metadata must never become model features.
            assert matrix.num_col() == 115
            np.testing.assert_array_equal(matrix.get_data().toarray(), [[2] * 115] * 3)
            return np.asarray([0.1, 0.9, 0.8])

    use_model_stub(monkeypatch, Model())
    payload = {
        "feature_order": analyzer.feature_names(), "rows": [[2] * 115] * 3,
        "sample_metadata": [
            {"sample_name": "Camera 01", "ground_truth": 0},
            {"sample_name": "Camera 02", "ground_truth": "benign"},
            {},
        ],
    }
    content = json.dumps(payload).encode()
    report = analyzer.analyze_file(content, "C:\\uploads\\camera.json")
    summary = report["summary"]
    assert summary["file_name"] == "camera.json"
    assert summary["file_size_bytes"] == len(content)
    assert summary["mode"] == "manual_analysis"
    assert summary["processing_ms"] >= summary["inference_ms"] >= 0
    assert datetime.fromisoformat(summary["completed_at"]) >= datetime.fromisoformat(
        summary["started_at"])
    assert summary["model"]["id"] == report["model"]
    assert summary["model"]["sha256"] == json.loads(
        analyzer.FREEZE.read_text())["model"]["sha256"]
    assert summary["preprocessor"]["scaling_applied"] is False
    assert summary["preprocessor"]["model_dtype"] == "float32"
    assert summary["ground_truth"] == {
        "source": "upload_metadata", "provided_rows": 2, "missing_rows": 1,
        "correct": 1, "incorrect": 1, "accuracy": 0.5,
    }
    assert [row["correct"] for row in report["results"]] == [True, False, None]
    assert [row["sample_name"] for row in report["results"]] == [
        "Camera 01", "Camera 02", "camera.json · 3",
    ]
    assert summary["mean_score"] == pytest.approx(0.6)
    assert summary["malicious_rate"] == pytest.approx(2 / 3)
    assert summary["mean_confidence"] == pytest.approx((0.9 + 0.9 + 0.8) / 3)
    json.dumps(report, allow_nan=False)


def test_csv_json_metadata_parity_and_prediction_independence():
    rows = [[-2] * 115, [4] * 115]
    metadata = [
        {"sample_name": "benign sample", "ground_truth": "benign"},
        {"sample_name": "attack sample", "ground_truth": "malicious"},
    ]
    csv_content = make_csv([row + [item["sample_name"], item["ground_truth"]]
                            for row, item in zip(rows, metadata, strict=True)],
                           analyzer.feature_names() + ["sample_name", "ground_truth"])
    csv_report = analyzer.analyze_file(csv_content.encode(), "samples.csv")
    json_report = analyzer.analyze_file(json.dumps({
        "feature_order": analyzer.feature_names(), "rows": rows, "sample_metadata": metadata,
    }).encode(), "samples.json")
    assert csv_report["results"] == json_report["results"]
    plain = analyzer.analyze_csv(make_csv(rows))
    assert [row["score"] for row in plain["results"]] == [
        row["score"] for row in csv_report["results"]
    ]
    assert all(row["ground_truth"] is None and row["correct"] is None for row in plain["results"])


@pytest.mark.parametrize("metadata", [
    [], {}, [None], [{"sample_name": ""}], [{"sample_name": 1}],
    [{"sample_name": "x" * 201}], [{"ground_truth": True}], [{"ground_truth": 0.0}],
    [{"ground_truth": "attack"}], [{"ground_truth": []}], [{"label": "benign"}],
])
def test_invalid_metadata_rejected_before_inference(monkeypatch, metadata):
    def unexpected_load():
        pytest.fail("Invalid metadata reached the model")

    monkeypatch.setattr(analyzer, "load_model", unexpected_load)
    with pytest.raises(ValueError):
        analyzer.analyze_json(json.dumps({
            "feature_order": analyzer.feature_names(), "rows": [[0] * 115],
            "sample_metadata": metadata,
        }))


@pytest.mark.parametrize("label, expected", [("0", "benign"), ("1", "malicious"),
                                            (" BENIGN ", "benign"), ("", None)])
def test_optional_csv_ground_truth_without_sample_name(label, expected):
    content = make_csv([[0] * 115 + [label]], analyzer.feature_names() + ["ground_truth"])
    result = analyzer.analyze_csv(content)
    assert result["results"][0]["ground_truth"] == expected
