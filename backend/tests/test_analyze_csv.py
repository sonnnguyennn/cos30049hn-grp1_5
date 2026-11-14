"""CSV contract and prediction response tests; no model training."""

import csv
import io
import json
import os
import subprocess
import sys

import numpy as np
import pytest

from backend.app import analyze_csv as analyzer


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

    monkeypatch.setattr(analyzer, "load_model", lambda: Model())
    result = analyzer.analyze_csv("\ufeff" + make_csv([[-2] * 115, [4] * 115]))
    assert result["summary"] == {"rows": 2, "features": 115, "benign": 1, "malicious": 1}
    assert result["results"] == [
        {"row": 1, "label": "benign", "probability_malicious": 0.49},
        {"row": 2, "label": "malicious", "probability_malicious": 0.5},
    ]
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
    assert csv_result == json_result


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
