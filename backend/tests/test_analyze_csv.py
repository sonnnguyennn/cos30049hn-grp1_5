"""CSV contract and prediction response tests; no model training."""

import csv
import io

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
    monkeypatch.setattr(analyzer, "MAX_CSV_BYTES", 5)
    with pytest.raises(ValueError, match="10 MiB"):
        analyzer.analyze_csv("123456")
    monkeypatch.setattr(analyzer, "MAX_CSV_BYTES", 10 * 1024 * 1024)
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
