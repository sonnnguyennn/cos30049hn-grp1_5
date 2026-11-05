"""Final-evaluation failure and ordering tests with fixed predictions, never fitting."""

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

from iotguard.evaluation import primary_final_evaluation as final
from iotguard.evaluation.primary import binary_metrics
from iotguard.evaluation.primary_runtime import file_identity, read_json, write_json


@pytest.fixture
def frozen(tmp_path, monkeypatch):
    monkeypatch.setattr(final, "check_result_package", lambda result, package: None)
    package_root = tmp_path / "package"
    package_root.mkdir()
    manifest = {
        "package_version": "primary_package_v1",
        "counts": {p: 4 for p in ("TRAIN", "VALIDATION", "TEST")},
        "files": {},
    }
    for partition in ("TRAIN", "VALIDATION", "TEST"):
        for name in ("X", "y", "metadata"):
            p = package_root / f"{partition}_{name}.npy"
            np.save(p, np.array([0, 0, 1, 1]))
            manifest["files"][p.name] = {k: v for k, v in file_identity(p).items() if k != "path"}
    write_json(package_root / "manifest.json", manifest)
    package = SimpleNamespace(root=package_root, manifest=manifest)
    model = tmp_path / "model.json"
    model.write_text("trusted fixed prediction fixture")
    selection_path = tmp_path / "selection.json"
    comparison_path = tmp_path / "comparison.csv"
    comparison_path.write_text("verified validation comparison")
    result = {"run_id": "selected", "code_revision": "a" * 40, "dirty_worktree": False}
    acceptance_path = tmp_path / "acceptance.json"
    probability_path = tmp_path / "accepted_probabilities.npy"
    np.save(probability_path, [0.1, 0.2, 0.8, 0.9])
    acceptance = {
        "model": file_identity(model),
        "payloads": {"probabilities.npy": file_identity(probability_path)},
        "reported_training_environment": {},
        "evaluation_environment": {},
        "original_experiment_owner": "Le Minh Hieu",
    }
    write_json(acceptance_path, acceptance)
    selection = {
        "winner": "selected",
        "comparison": file_identity(comparison_path),
        "accepted_candidates": {"selected": {"acceptance": file_identity(acceptance_path)}},
    }
    write_json(selection_path, selection)
    monkeypatch.setattr(final, "checked_selection", lambda p: (selection, result, acceptance))
    monkeypatch.setattr(final, "verified_package", lambda p: (package, {"TEST_opened": False}))
    monkeypatch.setattr(
        final,
        "evaluation_identity",
        lambda: {"revision": "a" * 40, "dirty_worktree": False, "implementation": {}},
    )
    monkeypatch.setattr(final, "input_contract", lambda p, r: {"threshold": 0.5})
    monkeypatch.setattr(final, "environment", lambda: {"fixture_runtime": 1})
    monkeypatch.setattr(
        final, "EXPECTED_MANIFEST", file_identity(package_root / "manifest.json")["sha256"]
    )
    path = tmp_path / "freeze.json"
    final.freeze_model(selection_path, package_root, path)
    return path, package, model


def test_freeze_contains_test_identity_without_opening_test(frozen):
    path, _, _ = frozen
    record = read_json(path)
    assert record["TEST_opened"] is False and record["TEST_metrics_seen"] is False
    assert record["package"]["partition_payloads"]["TEST"]["metadata"]["sha256"]


@pytest.mark.parametrize("field", ["status", "threshold_locked", "TEST_opened", "no_refit"])
def test_bad_freeze_fails_before_package_access(frozen, monkeypatch, field):
    path, package, _ = frozen
    data = read_json(path)
    data[field] = "invalid"
    path.write_text(__import__("json").dumps(data))
    monkeypatch.setattr(final, "verified_package", lambda p: pytest.fail("package accessed"))
    with pytest.raises(ValueError, match="gate"):
        final.validate_freeze(path, package.root)


@pytest.mark.parametrize("target", ["model", "selection", "comparison", "selected_acceptance"])
def test_bound_file_mutation_stops_before_test(frozen, target):
    path, package, _ = frozen
    record = read_json(path)
    Path(record[target]["path"]).write_bytes(b"changed")
    with pytest.raises(ValueError, match="changed"):
        final.validate_freeze(path, package.root)


def test_runtime_change_blocks_final(frozen, monkeypatch):
    path, package, _ = frozen
    monkeypatch.setattr(final, "environment", lambda: {"fixture_runtime": 2})
    with pytest.raises(ValueError, match="runtime"):
        final.validate_freeze(path, package.root)


def fixture_predictor(monkeypatch, *, validation_mismatch=False):
    calls = []

    def predict(package, result, model, partition, output, **kwargs):
        calls.append(partition)
        if partition == "TEST":
            assert kwargs["allow_test"] is True
            assert read_json(output / "pretest_gate.json")["status"] == "PASS"
        y = np.array([0, 0, 1, 1], dtype="uint8")
        p = np.array([0.1, 0.2, 0.8, 0.9])
        if validation_mismatch and partition == "VALIDATION":
            p[0] = 0.6
        for name, array in {
            "probabilities": p,
            "labels": y,
            "predictions": (p >= 0.5).astype("uint8"),
            "metadata": np.arange(4),
        }.items():
            np.save(output / f"{name}.npy", array)
        return y, p, {"reload_parity": "PASS"}

    monkeypatch.setattr(final, "predict_partition", predict)
    return calls


def test_failed_validation_parity_never_opens_test_and_retains_failure(
    frozen, monkeypatch, tmp_path
):
    path, package, _ = frozen
    calls = fixture_predictor(monkeypatch, validation_mismatch=True)
    output = tmp_path / "failed_attempt"
    with pytest.raises(ValueError, match="parity"):
        final.final_evaluate(path, package.root, output)
    assert calls == ["VALIDATION"]
    failure = read_json(output / "failure.json")
    assert failure["TEST_access_started"] is False
    assert not (output / "receipt.json").exists()
    with pytest.raises(FileExistsError):
        final.final_evaluate(path, package.root, output)


def test_successful_final_order_receipt_and_shared_metrics(frozen, monkeypatch, tmp_path):
    path, package, _ = frozen
    calls = fixture_predictor(monkeypatch)
    receipt = final.final_evaluate(path, package.root, tmp_path / "success")
    assert calls == ["VALIDATION", "TEST"]
    assert receipt["status"] == "FINAL_TEST_COMPLETE" and receipt["classifiers_fitted"] is False
    expected = binary_metrics([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9])
    expected.update(partition="TEST", schema_version="primary_final_metrics_v1")
    assert receipt["metrics"] == expected
    with pytest.raises(ValueError, match="sealed"):
        binary_metrics([0, 1], [0.1, 0.9], partition="TEST")


def test_final_metrics_reject_missing_freeze():
    with pytest.raises(PermissionError):
        final.final_metrics([0, 1], [0.1, 0.9], validated_freeze={})


def test_changed_test_payload_fails_after_gate_without_inference(frozen, monkeypatch, tmp_path):
    path, package, _ = frozen
    calls = fixture_predictor(monkeypatch)
    (package.root / "TEST_y.npy").write_bytes(b"corrupted")
    out = tmp_path / "failed_checksum"
    with pytest.raises(ValueError, match="checksum"):
        final.final_evaluate(path, package.root, out)
    assert calls == ["VALIDATION"]
    assert read_json(out / "failure.json")["TEST_access_started"] is True


def test_frozen_decision_cannot_be_replaced(frozen, monkeypatch):
    path, package, _ = frozen
    checked = final.checked_selection

    def different(p):
        selection, result, acceptance = checked(p)
        result = deepcopy(result)
        result["run_id"] = "other"
        return selection, result, acceptance

    monkeypatch.setattr(final, "checked_selection", different)
    with pytest.raises(ValueError, match="selection decision"):
        final.validate_freeze(path, package.root)
