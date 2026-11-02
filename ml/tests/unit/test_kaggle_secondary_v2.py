from __future__ import annotations

import ast
import copy
import hashlib
import json
import sqlite3
import zipfile
from pathlib import Path

import numpy as np
import pytest

from iotguard.experiments import kaggle_secondary_v2 as runner


def test_local_guard_precedes_any_training_or_io():
    with pytest.raises(RuntimeError, match="Kaggle"):
        runner.run("smoke")
    with pytest.raises(RuntimeError, match="Kaggle"):
        runner.fit_and_evaluate(None, None, None, None)


def test_fixed_configuration():
    config = runner.configuration()
    assert config["threshold"] == 0.5
    assert config["lr"]["class_weight"] is None
    assert config["lr"]["max_iter"] == 1000
    assert config["dummy"]["strategy"] == "most_frequent"
    assert config["smoke"]["seed"] == 1729


def test_whole_group_selection_deterministic_with_fixed_mixed_anchor():
    records = [(f"{i:064x}", 0, i + 1) for i in range(20)] + [(runner.ANCHOR, 11, 3733)]
    selected = runner.selected_groups(records, limit=3)
    assert selected == runner.selected_groups(list(reversed(records)), limit=3)
    assert (runner.ANCHOR, 11, 3733) in selected
    assert len(selected) <= 4
    with pytest.raises(ValueError, match="anchor"):
        runner.selected_groups(records[:-1], limit=3)


def test_smoke_plan_exact_membership_and_excludes_non_train_groups(tmp_path):
    db = sqlite3.connect(tmp_path / "groups.sqlite")
    db.execute("CREATE TABLE groups(sha TEXT,n0 INTEGER,n1 INTEGER,partition INTEGER)")
    other = "b" * 64
    db.executemany("INSERT INTO groups VALUES(?,?,?,?)", [
        (runner.ANCHOR, 1, 1, 0), (other, 0, 1, 0), ("c" * 64, 1, 9, 2)])
    db.commit()
    db.close()
    records = [["source", 1, "1", "0", runner.ANCHOR],
               ["source", 2, "2", "1", runner.ANCHOR], ["source", 3, "3", "1", other]]
    raw = b"".join(json.dumps(r, separators=(",", ":")).encode() + b"\n" for r in records)
    (tmp_path / "TRAIN_membership.jsonl").write_bytes(raw)
    output = tmp_path / "output"
    output.mkdir()

    class Package:
        root = tmp_path
    plan, keys = runner.smoke_plan(Package(), output)
    assert plan["rows"] == 3 and plan["binary_rows"] == [1, 2] and plan["groups"] == 2
    assert keys == {runner.ANCHOR, other}
    assert (output / "smoke_TRAIN_membership.jsonl").read_bytes() == raw


def test_train_cache_whole_group_rows_and_indices_without_classifier_fit(tmp_path):
    numeric = np.arange(4 * 36, dtype=np.float64).reshape(4, 36)
    labels = np.array([0, 1, 1, 1], dtype=np.uint8)
    metadata = np.zeros(4, dtype=[("group", "S64")])
    metadata["group"] = [runner.ANCHOR.encode()] * 2 + [b"b" * 64] * 2

    class Package:
        manifest = {"expected_partitions": {"TRAIN": {"rows": 4}}}

        def chunks(self, partition, chunk_size):
            assert partition == "TRAIN"
            yield numeric[:1], labels[:1], metadata[:1]
            yield numeric[1:], labels[1:], metadata[1:]
    cache, output = tmp_path / "cache", tmp_path / "output"
    cache.mkdir()
    output.mkdir()
    x, y = runner.create_train_cache(Package(), "smoke", {runner.ANCHOR},
                                     {"rows": 2, "binary_rows": [1, 1]}, cache, output)
    np.testing.assert_array_equal(x, numeric[:2])
    np.testing.assert_array_equal(y, labels[:2])
    np.testing.assert_array_equal(np.load(output / "TRAIN_selected_indices.npy"), [0, 1])
    x._mmap.close()
    y._mmap.close()


def receipt_fixture():
    identity = {"configuration": runner.configuration(), "package": runner.PACKAGE_SHA}
    plan = {"membership_sha256": "a" * 64, "rows": 100, "groups": 8, "binary_rows": [11, 89]}
    receipt = {
        "status": "SMOKE_PASS",
        "mode": "smoke",
        "identity": identity,
        "smoke_plan": plan,
        "train_population_sha256": plan["membership_sha256"],
        "training_rows": 100,
        "validation_rows": 733704,
        "validation_population_sha256": (
            "161376d656b8fe967f6a12549e92f4642c302f9cae46d07980910d16cd6aca1f"
        ),
        "eligible_for_full_population_comparison": False,
        "resource_preflight": {"status": "PASS"},
        "package_verification": {"result": "PASS_STANDALONE_FULL_VERIFICATION"},
        "training_runner_TEST_opened": False,
        "TEST_performance_evaluated": False,
        "models": {n: {"converged": True, "reload_parity": "PASS"} for n in ("dummy", "lr")},
    }
    return receipt, identity, plan


@pytest.mark.parametrize(
    "key,value",
    [
        ("status", "NONCONVERGED_DIAGNOSTIC"),
        ("mode", "full"),
        ("identity", {}),
        ("smoke_plan", {}),
        ("training_rows", 99),
        ("train_population_sha256", "b" * 64),
        ("validation_population_sha256", "b" * 64),
        ("resource_preflight", {"status": "BLOCKED"}),
        ("training_runner_TEST_opened", True),
        ("TEST_performance_evaluated", True),
        ("eligible_for_full_population_comparison", True),
        ("models", {}),
    ],
)
def test_full_gate_rejects_changed_receipt(key, value):
    receipt, identity, plan = receipt_fixture()
    runner.accept_smoke(receipt, identity, plan)
    broken = copy.deepcopy(receipt)
    broken[key] = value
    with pytest.raises(ValueError, match="matching"):
        runner.accept_smoke(broken, identity, plan)


def test_failed_parity_or_convergence_blocks_full():
    for field, value in (("converged", False), ("reload_parity", "FAIL")):
        receipt, identity, plan = receipt_fixture()
        receipt["models"]["lr"][field] = value
        with pytest.raises(ValueError):
            runner.accept_smoke(receipt, identity, plan)


def test_failed_standalone_receipt_blocks_full():
    receipt, identity, plan = receipt_fixture()
    receipt["package_verification"] = {}
    with pytest.raises(ValueError):
        runner.accept_smoke(receipt, identity, plan)


def test_output_checksums_cover_archive_and_refuse_overwrite(tmp_path):
    directory = tmp_path / "run"
    directory.mkdir()
    runner.write_json(directory / "status.json", {"status": "CODE_TEST_NO_FIT"})
    (directory / "payload.bin").write_bytes(b"test-output")
    archive_path = runner.checksums_and_archive(directory)
    previous = archive_path.read_bytes()
    with zipfile.ZipFile(archive_path) as archive:
        checksums = json.loads(archive.read("output_checksums.json"))
        assert set(checksums) == set(archive.namelist()) - {"output_checksums.json"}
        for name, sha in checksums.items():
            assert hashlib.sha256(archive.read(name)).hexdigest() == sha
    with pytest.raises(FileExistsError):
        runner.checksums_and_archive(directory)
    assert archive_path.read_bytes() == previous


def test_group_metrics_preserve_mixed_group_mass_not_class_balancing():
    result = runner.metric_tables(
        np.array([0, 1, 0, 1]), np.array([0.2, 0.8, 0.9, 0.1]), np.array([2, 2, 1, 1])
    )
    assert result["row_primary"]["confusion"] == {"TN": 1, "FP": 1, "FN": 1, "TP": 1}
    assert result["row_primary"]["macro_f1"] == 0.5
    weighted = result["group_sensitivity"]
    assert weighted["confusion"] == {"TN": 0.5, "FP": 1.0, "FN": 1.0, "TP": 0.5}
    assert weighted["class_supports"] == {"benign": 1.5, "malicious": 1.5}
    assert weighted["macro_f1"] == pytest.approx(1 / 3)
    assert weighted["FPR"] == pytest.approx(2 / 3)


@pytest.mark.parametrize(
    "scores,sizes",
    [([np.nan, 0.5], [1, 1]), ([1.1, 0.5], [1, 1]), ([0.5, 0.5], [0, 1]), ([0.5, 0.5], [1.5, 1])],
)
def test_invalid_metrics_inputs(scores, sizes):
    with pytest.raises(ValueError):
        runner.metric_tables([0, 1], scores, sizes)


def test_resources_block_without_fallback_and_encoded_contract():
    assert runner.resources(2201114, 0, 10**12)["status"] == "BLOCKED"
    assert runner.resources(2201114, 10**12, 0)["status"] == "BLOCKED"
    result = runner.resources(2201114, 10**12, 10**12)
    assert result["status"] == "PASS"
    assert result["float64_encoded_cache_bytes"] == 2201114 * 36 * 8
    runner.validate_encoded(np.ones((3, 36), dtype=np.float64))
    for bad in (np.ones((3, 35)), np.ones((3, 36), dtype=np.float32), np.full((3, 36), np.inf)):
        with pytest.raises(ValueError):
            runner.validate_encoded(bad)


def test_classifier_fit_guard_and_no_TEST_load_or_preprocessing_fit_in_runner_source():
    tree = ast.parse(Path(runner.__file__).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in {"load", "chunks"} and node.args:
                assert not (isinstance(node.args[0], ast.Constant) and node.args[0].value == "TEST")
    fits = []
    for function in tree.body:
        if isinstance(function, ast.FunctionDef):
            if any(
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and n.func.attr == "fit"
                for n in ast.walk(function)
            ):
                fits.append(function.name)
                assert isinstance(function.body[0].value, ast.Call)
                assert function.body[0].value.func.id == "assert_kaggle"
    assert fits == ["fit_and_evaluate"]
    assert not any(
        isinstance(n, ast.Name) and n.id in {"StandardScaler", "OneHotEncoder"}
        for n in ast.walk(tree)
    )
