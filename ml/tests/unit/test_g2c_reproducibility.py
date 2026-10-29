from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from iotguard.data.n_baiot import duplicate_group_id, parse_n_baiot_record
from iotguard.data.reproducibility import (
    G2_CLOSURE_CHECKS,
    canonical_record_digest,
    deterministic_traversal_rows,
    g2_closure_status,
    source_observation_identity,
    traversal_expected_row_count,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DRIVER_PATH = PROJECT_ROOT / "scripts" / "run_g2c_validation.py"
SPEC = importlib.util.spec_from_file_location("run_g2c_validation", DRIVER_PATH)
assert SPEC is not None and SPEC.loader is not None
driver = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = driver
SPEC.loader.exec_module(driver)

BENIGN_ID = "n_baiot:source:Danmini_Doorbell/benign_traffic.csv"


def record_at(row_index: int = 1):
    return parse_n_baiot_record(["1"] * 115, BENIGN_ID, data_row_index=row_index)


def test_source_row_identity_is_stable_and_one_based() -> None:
    first = record_at(1)
    second = record_at(1)
    assert source_observation_identity(first) == source_observation_identity(second) == (
        BENIGN_ID,
        1,
    )
    with pytest.raises(ValueError, match="1-based"):
        source_observation_identity(replace(first, data_row_index=0))


def test_traversal_order_does_not_depend_on_input_order() -> None:
    forward = [
        {"logical_id": "source:b", "expected_row_count": 2},
        {"logical_id": "source:a", "expected_row_count": 1},
    ]
    reverse = list(reversed(forward))
    expected = [
        {"traversal_ordinal": 1, "logical_id": "source:a", "expected_row_count": 1},
        {"traversal_ordinal": 2, "logical_id": "source:b", "expected_row_count": 2},
    ]
    assert deterministic_traversal_rows(forward) == expected
    assert deterministic_traversal_rows(reverse) == expected


def test_verified_traversal_reconciles_all_primary_rows() -> None:
    rows = driver.build_traversal_rows()
    assert len(rows) == 89
    assert traversal_expected_row_count(rows) == 7_062_606
    assert [row["traversal_ordinal"] for row in rows] == list(range(1, 90))


def test_equal_exact_tuples_receive_equal_group_ids() -> None:
    first = ["1", "1.0", "1e0"] + ["0"] * 112
    second = list(first)
    assert duplicate_group_id(first) == duplicate_group_id(second)


def test_canonical_record_digest_is_deterministic_and_identity_sensitive() -> None:
    first = record_at(1)
    repeated = record_at(1)
    next_row = record_at(2)
    assert canonical_record_digest(first) == canonical_record_digest(repeated)
    assert canonical_record_digest(first) != canonical_record_digest(next_row)


def test_bounded_materialization_rerun_is_deterministic() -> None:
    path = PROJECT_ROOT / "artifacts" / "audit" / "g2c_bounded_materialization_smoke.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    materialization = payload["bounded_materialization"]
    assert payload["overall_status"] == "PASS"
    assert materialization["rerun_identical"] is True
    assert materialization["first_run_sha256"] == materialization["second_run_sha256"]


def test_g2_closure_refuses_incomplete_and_accepts_complete_checks() -> None:
    complete = dict.fromkeys(G2_CLOSURE_CHECKS, True)
    incomplete = dict(complete)
    incomplete["primary_full_dry_validation_passed"] = False
    missing = dict(complete)
    missing.pop("source_data_immutable")

    assert g2_closure_status(incomplete) == "OPEN"
    assert g2_closure_status(missing) == "OPEN"
    assert g2_closure_status(complete) == "COMPLETE"


def test_no_downstream_learned_state_or_split_artifact() -> None:
    prohibited_suffixes = {".joblib", ".pkl", ".pickle", ".onnx", ".npy", ".npz"}
    roots = [PROJECT_ROOT / "artifacts", PROJECT_ROOT / "data" / "processed"]
    files = [path for root in roots if root.exists() for path in root.rglob("*") if path.is_file()]
    assert not [path for path in files if path.suffix.lower() in prohibited_suffixes]
    assert not [
        path
        for path in files
        if path.name.lower() in {"train.csv", "validation.csv", "test.csv"}
    ]
