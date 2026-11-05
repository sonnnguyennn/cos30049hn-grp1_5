"""Acceptance regressions use fixed arrays and stubs; no classifier fitting."""

import hashlib
import io
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import numpy as np
import pytest

from iotguard.evaluation import comparison
from iotguard.evaluation.population import selected_population
from iotguard.evaluation.primary import binary_metrics, experiment_result, resolve_configuration
from iotguard.evaluation.primary_runtime import file_identity, write_json


@pytest.mark.parametrize("indices", [np.arange(5), np.array([0, 2, 4]), np.array([3])])
def test_population_matches_exact_numpy_serialization(indices):
    metadata = np.array([(0, i) for i in range(5)], dtype=[("source", "<u2"), ("row", "<u8")])
    stream = io.BytesIO()
    np.save(stream, metadata[indices])
    population = selected_population(metadata, indices, chunk_size=2)
    assert population["train_population_sha256"] == hashlib.sha256(stream.getvalue()).hexdigest()
    assert population["kind"] == ("full" if len(indices) == 5 else "subset")


@pytest.mark.parametrize("indices", [[], [0, 0], [2, 1], [-1, 2], [0, 5], [0.0, 1.0]])
def test_bad_membership_rejected(indices):
    with pytest.raises(ValueError, match="indices"):
        selected_population(np.arange(5), np.asarray(indices))


def accepted_fixture(tmp_path, run_id="lr_full", *, subset=False):
    root = tmp_path / run_id
    root.mkdir()
    result = experiment_result(
        run_id,
        binary_metrics([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9]),
        configuration=resolve_configuration(input_view="scaled", parameters={"C": 1}),
        code_revision="a" * 40,
        package_version="primary_package_v1",
        package_manifest_sha256="b" * 64,
        dirty_worktree=False,
        train_population_sha256="c" * 64,
        validation_population_sha256="d" * 64,
    )
    result.update(
        {
            "run_mode": "full",
            "diagnostic_only": False,
            "eligible_for_official_comparison": True,
            "runtime": {"converged": True},
        }
    )
    path = root / "result.json"
    write_json(path, result)
    for name in ("probabilities", "predictions", "labels", "metadata"):
        np.save(root / f"{name}.npy", np.arange(4))
    model = root / "model.txt"
    model.write_text("fixed inference stub; no fit")
    receipt = {
        "schema_version": "primary_acceptance_v1",
        "status": "PASS",
        "run_id": run_id,
        "result_sha256": file_identity(path)["sha256"],
        "metrics": result["metrics"],
        "TEST_opened": False,
        "classifiers_fitted": False,
        **{
            k: result[k]
            for k in (
                "package_manifest_sha256",
                "protocol_revision",
                "validation_population_sha256",
            )
        },
        "model": file_identity(model),
        "validation_rows": 4,
        "eligible_for_full_comparison": not subset,
        "population": {
            "kind": "subset" if subset else "full",
            "rows": 2 if subset else 4,
            "rows_in_train": 4,
            "train_population_sha256": "c" * 64,
            "parent_train_population_sha256": "c" * 64,
        },
        "payloads": {p.name: file_identity(p) for p in root.iterdir() if p != model},
        "replay": {"reload_parity": "PASS", "input_contract": {"family": "LR"}},
    }
    write_json(root / "acceptance.json", receipt)
    return comparison.load_runs([tmp_path])[-1]


def test_original_lr_without_sampling_is_readable_and_accepted(tmp_path):
    run = accepted_fixture(tmp_path)
    assert "train_sampling" not in run["result"]["resolved_configuration"]["parameters"]
    assert comparison.accepted_result(run)["run_id"] == "lr_full"
    selection = comparison.compare([run], tmp_path / "comparison")
    assert selection["winner"] == "lr_full" and selection["TEST_used"] is False


def test_missing_sampling_is_never_assumed_full(tmp_path):
    run = accepted_fixture(tmp_path)
    run["receipt"] = None
    with pytest.raises(ValueError, match="unproven"):
        comparison.accepted_result(run)


def test_subset_excluded_from_full(tmp_path):
    run = accepted_fixture(tmp_path, subset=True)
    with pytest.raises(ValueError, match="Subset"):
        comparison.accepted_result(run)


@pytest.mark.parametrize("field", ["package_manifest_sha256", "validation_population_sha256"])
def test_identity_conflict_never_uses_majority(tmp_path, monkeypatch, field):
    run = accepted_fixture(tmp_path)
    runs = [deepcopy(run) for _ in range(3)]
    for index, item in enumerate(runs):
        item["result"]["run_id"] = str(index)
    runs[-1]["result"][field] = "e" * 64
    monkeypatch.setattr(comparison, "accepted_result", lambda r: r["result"])
    with pytest.raises(ValueError, match="identical"):
        comparison.choose_pool(runs)


@pytest.mark.parametrize(
    "mutation", ["threshold", "convergence", "eligibility", "payload", "model"]
)
def test_acceptance_gates(tmp_path, mutation):
    run = accepted_fixture(tmp_path)
    if mutation == "threshold":
        run["result"]["resolved_configuration"]["threshold"] = 0.4
    elif mutation == "convergence":
        run["result"]["runtime"]["converged"] = False
    elif mutation == "eligibility":
        run["result"]["eligible_for_official_comparison"] = False
    elif mutation == "payload":
        Path(run["receipt"]["payloads"]["probabilities.npy"]["path"]).write_bytes(b"bad")
    else:
        Path(run["receipt"]["model"]["path"]).write_text("changed")
    with pytest.raises(ValueError):
        comparison.accepted_result(run)


def test_no_overwrite_and_complete_class_metrics(tmp_path):
    run = accepted_fixture(tmp_path)
    output = tmp_path / "comparison"
    comparison.compare([run], output)
    with pytest.raises(FileExistsError):
        comparison.compare([run], output)
    header = (output / "comparison.csv").read_text().splitlines()[0]
    for label in ("benign", "malicious"):
        for metric in ("precision", "recall", "f1", "support"):
            assert f"{label}_{metric}" in header


def test_training_metrics_remain_test_sealed():
    with pytest.raises(ValueError, match="sealed"):
        binary_metrics([0, 1], [0.1, 0.9], partition="TEST")


@pytest.mark.parametrize("script", ["train_rf_baseline.py", "train_xgb_baseline.py"])
def test_new_training_entrypoints_refuse_local_execution(script):
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, str(root / "scripts" / script), "--help"], capture_output=True, text=True
    )
    assert result.returncode != 0
    assert "Training is restricted to Kaggle" in result.stderr
