import json

import numpy as np
import pytest
from sklearn.preprocessing import StandardScaler

from iotguard.data.primary_package import PrimaryPackage
from iotguard.evaluation.primary import (
    binary_metrics,
    experiment_result,
    resolve_configuration,
    select_validation,
)


def test_known_confusion():
    m = binary_metrics([0, 0, 0, 1, 1], [0, 0.7, 0, 0.8, 0.1])
    assert [m[k] for k in ("TN", "FP", "FN", "TP")] == [2, 1, 1, 1]
    assert m["fpr"] == pytest.approx(1 / 3)
    assert m["macro_f1"] == pytest.approx((2 / 3 + 0.5) / 2)
    assert m["accuracy"] == 0.6


def test_missing_negative_is_undefined():
    m = binary_metrics([1, 1], [0.8, 0.7])
    assert m["fpr"] is None
    assert m["per_class"]["benign"]["recall"] is None
    assert m["macro_f1"] is None
    json.dumps(m, allow_nan=False)


@pytest.mark.parametrize("y,p", [([], []), ([2], [0.5]), ([0], [np.nan]),
                                  ([0], [-0.1]), ([0], [1.1]), ([0, 1], [0.2]),
                                  ([[0]], [[0.1]])])
def test_invalid_metrics(y, p):
    with pytest.raises(ValueError):
        binary_metrics(y, p)


def test_no_test_evaluation_or_threshold_tuning():
    with pytest.raises(ValueError):
        binary_metrics([0, 1], [0.1, 0.8], partition="TEST")
    with pytest.raises(ValueError):
        binary_metrics([0, 1], [0.1, 0.8], threshold=0.4)


def test_selection_tolerance_and_population():
    def candidate(score, fpr, recall):
        m = binary_metrics([0, 1], [0.1, 0.8])
        m["macro_f1"] = score
        m["fpr"] = fpr
        m["per_class"]["malicious"]["recall"] = recall
        return experiment_result("candidate", m, configuration=resolve_configuration(
            input_view="raw", parameters={}), code_revision="unit-test",
            package_version="primary_package_v1", package_manifest_sha256="c" * 64,
            dirty_worktree=False, train_population_sha256="a" * 64,
            validation_population_sha256="b" * 64)
    a, b = candidate(0.8, 0.2, 0.8), candidate(0.7999995, 0.1, 0.7)
    assert select_validation([a, b]) is b
    c = candidate(0.8, 0.1, 0.9)
    assert select_validation([a, b, c]) is c
    c["train_population_sha256"] = "different"
    with pytest.raises(ValueError):
        select_validation([a, c])


@pytest.fixture
def package(tmp_path):
    x = np.arange(345, dtype=np.float64).reshape(3, 115)
    scaler = StandardScaler().partial_fit(x[:2])
    state = {"fit_partition": "TRAIN", "n_samples_seen": 2, "mean": scaler.mean_.tolist(),
             "scale": scaler.scale_.tolist()}
    (tmp_path / "scaler.json").write_text(json.dumps(state))
    manifest = {"package_version": "primary_package_v1", "dtype": "float64",
                "feature_order": [f"f{i}" for i in range(115)], "status": "FULL",
                "split_version": "primary_split_v1", "fit_partition": "TRAIN",
                "label_mapping": {"benign": 0, "malicious": 1}, "counts": {}, "files": {}}
    for p, values in (("TRAIN", x[:2]), ("VALIDATION", x[2:]), ("TEST", x[2:])):
        manifest["counts"][p] = len(values)
        for name, array in (("X", values), ("y", np.zeros(len(values), dtype=np.uint8)),
                            ("metadata", np.zeros(len(values), dtype=[("source", "<u2"),
                                                                      ("row", "<u8")]))):
            path = tmp_path / f"{p}_{name}.npy"
            np.save(path, array)
            from iotguard.data.primary_package import sha256_file
            manifest["files"][path.name] = {"bytes": path.stat().st_size,
                                           "sha256": sha256_file(path)}
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    (tmp_path / "n_baiot_feature_contract_v1.json").write_text(json.dumps(
        {"contract_version": "1.0.0", "ordered_feature_names": manifest["feature_order"]}))
    for name in ("scaler.json", "n_baiot_feature_contract_v1.json"):
        path = tmp_path / name
        manifest["files"][name] = {"bytes": path.stat().st_size, "sha256": sha256_file(path)}
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    return tmp_path, x, scaler


def test_loader_train_only_scaler_and_csv_roundtrip(package):
    root, x, scaler = package
    loader = PrimaryPackage(root, verify=True)
    np.testing.assert_array_equal(loader.load("TRAIN")[0], x[:2])
    np.testing.assert_allclose(next(loader.chunks("VALIDATION", scaled=True))[0],
                               scaler.transform(x[2:]), atol=1e-12, rtol=1e-12)
    with pytest.raises(PermissionError):
        loader.load("TEST")
    with pytest.raises(PermissionError):
        next(loader.chunks("TEST", scaled=True))
    np.testing.assert_allclose(
        next(loader.chunks("TEST", scaled=True, allow_test=True))[0],
        scaler.transform(x[2:]), atol=1e-12, rtol=1e-12)
    loader.export_csv("TRAIN", root / "submission.csv")
    np.testing.assert_array_equal(np.loadtxt(root / "submission.csv", delimiter=",",
                                            skiprows=1)[:, :115], x[:2])


def test_loader_bad_version_and_corruption(package):
    root, _, _ = package
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["package_version"] = "unsupported"
    (root / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        PrimaryPackage(root)


def test_loader_rejects_reordered_features_and_corruption(package):
    root, _, _ = package
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["feature_order"].reverse()
    (root / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        PrimaryPackage(root)
    manifest["feature_order"].reverse()
    (root / "manifest.json").write_text(json.dumps(manifest))
    with (root / "TRAIN_X.npy").open("r+b") as f:
        f.seek(-1, 2)
        f.write(b"\xff")
    with pytest.raises(ValueError):
        PrimaryPackage(root, verify=True)


def test_result_envelope_resolves_seeds_and_requires_identity():
    from iotguard.evaluation.primary import experiment_result, resolve_configuration
    config = resolve_configuration(input_view="raw", parameters={})
    assert config["seeds"] == {"python": 42, "numpy": 42, "scikit_learn": 42}
    result = experiment_result("synthetic", binary_metrics([0, 1], [0.1, 0.8]),
                               configuration=config, code_revision="unit-test",
                               package_version="primary_package_v1",
                               package_manifest_sha256="c" * 64, dirty_worktree=False,
                               train_population_sha256="a" * 64,
                               validation_population_sha256="b" * 64)
    assert result["schema_version"] == "primary_result_v1"
    json.dumps(result, allow_nan=False)
    with pytest.raises(ValueError):
        experiment_result("x", result["metrics"], configuration={}, code_revision="x",
                          package_version="primary_package_v1",
                          package_manifest_sha256="c" * 64, dirty_worktree=False,
                          train_population_sha256="a" * 64,
                          validation_population_sha256="b" * 64)


def test_loader_refuses_scaler_fit_outside_train(package):
    from iotguard.data.primary_package import sha256_file
    root, _, _ = package
    state = json.loads((root / "scaler.json").read_text())
    state["fit_partition"] = "VALIDATION"
    (root / "scaler.json").write_text(json.dumps(state))
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["files"]["scaler.json"] = {
        "bytes": (root / "scaler.json").stat().st_size,
        "sha256": sha256_file(root / "scaler.json")}
    (root / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="Scaler must fit TRAIN"):
        PrimaryPackage(root, verify=True)
