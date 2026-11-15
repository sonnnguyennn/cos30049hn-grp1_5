"""TEST upload exports preserve features, row identity and separate ground truth."""

import csv
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

SPEC = importlib.util.spec_from_file_location(
    "export_test_upload", Path(__file__).resolve().parents[2] / "scripts/export_test_upload.py"
)
exporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exporter)


@pytest.fixture
def package(monkeypatch):
    features = json.loads(exporter.FREEZE_PATH.read_text())["input_contract"]["feature_order"]
    x = np.arange(12 * 115, dtype=np.float64).reshape(12, 115) / 7
    x[:, 35] *= -1
    y = np.asarray([0, 1] * 6, dtype=np.uint8)
    metadata = np.array([(i, i + 100) for i in range(12)],
                        dtype=[("source", "<u2"), ("row", "<u8")])

    def load(partition, *, allow_test=False):
        assert partition == "TEST" and allow_test is True
        return x, y, metadata

    def verified(root, *, partitions):
        assert partitions == ("TEST",)
        return SimpleNamespace(manifest={"feature_order": features}, load=load), {"status": "PASS"}

    monkeypatch.setattr(exporter, "verified_package", verified)
    return x, y, features


@pytest.mark.parametrize("rows", [7, None])
def test_chunked_formats_and_labels_round_trip(tmp_path, package, rows):
    x, y, features = package
    destination = tmp_path / "export"
    report = exporter.export_test_upload("unused", destination, rows=rows, chunk_size=4)
    with (destination / "expected_labels.csv").open(newline="") as stream:
        labels = list(csv.DictReader(stream))
    assert len(labels) == report["exported_rows"] == (rows or len(y))
    assert len({row["test_index"] for row in labels}) == len(labels)
    for upload in report["uploads"]:
        data = json.loads((destination / upload["json"]).read_text())
        with (destination / upload["csv"]).open(newline="") as stream:
            header, *values = list(csv.reader(stream))
        assert header == data["feature_order"] == features
        assert len(values) == upload["rows"] <= 4
        np.testing.assert_array_equal(np.asarray(values, dtype=float), data["rows"])
        selected = [row for row in labels if row["upload_stem"] == Path(upload["csv"]).stem]
        indices = [int(row["test_index"]) for row in selected]
        np.testing.assert_array_equal(data["rows"], x[indices])
        assert [int(row["row"]) for row in selected] == list(range(1, len(selected) + 1))
        assert [int(row["target_binary_numeric"]) for row in selected] == y[indices].tolist()
    repeat = tmp_path / "repeat"
    exporter.export_test_upload("unused", repeat, rows=rows, chunk_size=4)
    assert (repeat / "expected_labels.csv").read_bytes() == (
        destination / "expected_labels.csv"
    ).read_bytes()


def test_existing_output_preserved_and_invalid_count_writes_nothing(tmp_path, package):
    with pytest.raises(FileExistsError):
        exporter.export_test_upload("unused", tmp_path)
    destination = tmp_path / "export"
    with pytest.raises(ValueError, match="TEST rows"):
        exporter.export_test_upload("unused", destination, rows=13)
    assert not destination.exists()


def test_metadata_export_matches_separate_ground_truth(tmp_path, package):
    destination = tmp_path / "export"
    report = exporter.export_test_upload("unused", destination, rows=7, chunk_size=4,
                                         include_metadata=True)
    assert report["includes_sample_metadata"] is True
    with (destination / "expected_labels.csv").open(newline="") as stream:
        labels = list(csv.DictReader(stream))
    for upload in report["uploads"]:
        data = json.loads((destination / upload["json"]).read_text())
        with (destination / upload["csv"]).open(newline="") as stream:
            header, *values = list(csv.reader(stream))
        assert header == data["feature_order"] + ["sample_name", "ground_truth"]
        selected = [row for row in labels if row["upload_stem"] == Path(upload["csv"]).stem]
        for actual, metadata, expected in zip(
            values, data["sample_metadata"], selected, strict=True
        ):
            assert metadata == {"sample_name": f"N-BaIoT TEST {expected['test_index']}",
                                "ground_truth": expected["actual_label"]}
            assert actual[-2:] == [metadata["sample_name"], metadata["ground_truth"]]


@pytest.mark.parametrize("traffic_class, target", [("benign", 0), ("malicious", 1)])
@pytest.mark.parametrize("rows", [3, None])
def test_class_filter_uses_original_labels_and_indices(
    tmp_path, package, traffic_class, target, rows
):
    x, y, _ = package
    destination = tmp_path / "filtered"
    report = exporter.export_test_upload("unused", destination, rows=rows,
                                         traffic_class=traffic_class, include_metadata=True)
    with (destination / "expected_labels.csv").open(newline="") as stream:
        labels = list(csv.DictReader(stream))
    indices = [int(row["test_index"]) for row in labels]
    assert len(indices) == (rows or 6)
    assert all(y[index] == target for index in indices)
    assert report["class_counts"][traffic_class] == len(indices)
    assert sum(report["class_counts"].values()) == len(indices)
    assert report["eligible_rows"] == 6
    payload = json.loads((destination / "test_input.json").read_text())
    np.testing.assert_array_equal(payload["rows"], x[indices])
    assert all(item["ground_truth"] == traffic_class for item in payload["sample_metadata"])


def test_insufficient_rows_of_requested_class_writes_nothing(tmp_path, package):
    destination = tmp_path / "filtered"
    with pytest.raises(ValueError, match="6 TEST rows"):
        exporter.export_test_upload("unused", destination, rows=7, traffic_class="benign")
    assert not destination.exists()


@pytest.mark.parametrize("kwargs", [{"rows": 0}, {"rows": True}, {"seed": -1},
                                   {"chunk_size": 0}, {"chunk_size": 10001},
                                   {"traffic_class": "unknown"}])
def test_invalid_options_rejected_before_package_access(tmp_path, kwargs):
    with pytest.raises(ValueError):
        exporter.export_test_upload(tmp_path / "missing", tmp_path / "out", **kwargs)
