from pathlib import Path

import numpy as np
import pytest

from iotguard.experiments import kaggle_lr


def test_diagnostic_indices_are_stratified_deterministic_not_a_new_split():
    labels = np.array([0] * 20 + [1] * 80, dtype=np.uint8)
    first = kaggle_lr.diagnostic_indices(labels, 20, 42)
    np.testing.assert_array_equal(first, kaggle_lr.diagnostic_indices(labels, 20, 42))
    assert len(first) == len(np.unique(first)) == 20
    assert np.all(np.diff(first) > 0)
    assert np.bincount(labels[first], minlength=2).tolist() == [4, 16]


@pytest.mark.parametrize("size", [0, 1, 100, 101, 2.5])
def test_diagnostic_indices_refuse_invalid_sizes(size):
    with pytest.raises(ValueError):
        kaggle_lr.diagnostic_indices(np.array([0] * 20 + [1] * 80), size, 42)


@pytest.mark.parametrize(
    "change",
    [
        {"max_iter": 2000},
        {"smoke_train": 1000},
        {"smoke_validation": 1000},
        {"threads": 0},
        {"threads": 1.5},
        {"chunk_size": -1},
    ],
)
def test_baseline_does_not_silently_change_policy(change):
    with pytest.raises(ValueError):
        kaggle_lr.baseline_configuration(**change)


def test_baseline_resource_options_and_defaults():
    configuration = kaggle_lr.baseline_configuration(threads=2, chunk_size=4096)
    assert configuration == {
        "max_iter": 1000,
        "threads": 2,
        "chunk_size": 4096,
        "smoke_train": 50000,
        "smoke_validation": 10000,
    }


def test_local_execution_stops_before_any_fitting():
    if Path("/kaggle/input").is_dir() and Path("/kaggle/working").is_dir():
        pytest.skip("Local-only guard test is not applicable inside Kaggle")
    with pytest.raises(RuntimeError, match="Training is restricted to Kaggle"):
        kaggle_lr.run(mode="smoke")


@pytest.mark.parametrize(
    "change",
    [
        None,
        {"status": "FAILED"},
        {"mode": "full"},
        {"package_manifest_sha256": "0" * 64},
        {"bundle_manifest_sha256": "1" * 64},
        {"run_configuration": None},
        {"run_configuration": {"threads": 8}},
    ],
)
def test_smoke_gate_binds_configuration_and_both_identities(change):
    config = kaggle_lr.baseline_configuration()
    receipt = {
        "status": "SMOKE_PASS",
        "mode": "smoke",
        "package_manifest_sha256": kaggle_lr.EXPECTED_MANIFEST,
        "bundle_manifest_sha256": "a" * 64,
        "run_configuration": config,
    }
    if change is not None:
        receipt.update(change)
    assert kaggle_lr.smoke_receipt_matches(receipt, "a" * 64, config) is (change is None)
