import ast
import importlib.util
import sqlite3
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "verify_a5_evidence.py"
SPEC = importlib.util.spec_from_file_location("verify_a5_evidence", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)


def test_verifier_does_not_import_primary_a5() -> None:
    tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert "dataset_leakage_audit" not in imported
    assert "scripts.dataset_leakage_audit" not in imported


def test_independent_port_classification() -> None:
    assert verify.classify_port("443") == "decimal_integer"
    assert verify.classify_port("0x0303") == "hexadecimal_style"
    assert verify.classify_port("-1") == "negative_decimal"
    assert verify.classify_port("?") == "other"
    mask = verify.decimal_failure_mask(pd.Series(["80", "0x0303", "-1", "80"]))
    assert mask.tolist() == [False, True, False, False]


def test_independent_label_counting() -> None:
    frame = pd.DataFrame(
        {
            "attack": ["0", "1", "1"],
            "category": ["Normal", "DoS", "DoS"],
            "subcategory": ["Normal", "TCP", "UDP"],
        }
    )
    levels = verify.new_levels()
    verify.update_levels(levels, frame)
    assert levels["binary"] == {"benign": 1, "malicious": 2}
    assert levels["category"] == {"normal": 1, "dos": 2}


def test_identity_database_is_grouped_independently(tmp_path: Path) -> None:
    database = tmp_path / "identity.sqlite"
    connection = sqlite3.connect(database)
    connection.execute(
        """
        CREATE TABLE bot_exact_rows (
            scope TEXT, exact_hash BLOB, exact_blob BLOB,
            pkseqid INTEGER,
            attack TEXT, category TEXT, subcategory TEXT
        )
        """
    )
    connection.executemany(
        "INSERT INTO bot_exact_rows VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            ("scope", b"h", b"x", 1, "0", "Normal", "Normal"),
            ("scope", b"h", b"x", 2, "1", "DoS", "TCP"),
            ("scope", b"h", b"y", 3, "1", "DoS", "UDP"),
        ],
    )
    connection.commit()
    connection.close()
    result = verify.aggregate_identity_database(database)["scope"]
    assert result["duplicate_groups"] == 1
    assert result["duplicate_excess"] == 1
    assert result["conflicting_attack_groups"] == 1


def test_stratified_masks_are_deterministic_and_exact_size() -> None:
    first = verify.stratified_masks({"a": 10, "b": 5}, 1729)
    second = verify.stratified_masks({"a": 10, "b": 5}, 1729)
    assert (first["a"] == second["a"]).all()
    assert first["a"].sum() == 2
    assert first["b"].sum() == 1


def test_independent_candidate_store_counts_repeated_groups(tmp_path: Path) -> None:
    store = verify.IndependentCandidateHashStore(tmp_path, {"scope": 7})
    store.append("scope", np.array([9, 1, 9, 2, 2, 2, 3], dtype=np.int64))
    assert store.repeated_group_counts() == {"scope": 2}


def test_selected_value_collection_avoids_full_row_iteration() -> None:
    frame = pd.DataFrame(
        {
            "pkSeqID": ["1", "2", "3"],
            "stddev": ["0.1", "0.2", "0.3"],
            "min": ["1", "2", "3"],
        }
    )
    result = verify.collect_selected_values(frame, {2}, ("stddev", "min"))
    assert result == {2: {"stddev": "0.2", "min": "2"}}
