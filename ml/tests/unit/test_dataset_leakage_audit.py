import importlib.util
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "dataset_leakage_audit.py"
SPEC = importlib.util.spec_from_file_location("dataset_leakage_audit", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
a5 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = a5
SPEC.loader.exec_module(a5)


def test_raw_vs_unique_vector_class_distribution() -> None:
    raw, unique = a5.raw_and_unique_label_counts(
        [("attack", 3), ("benign", 2)], Counter({"attack": 1})
    )
    assert raw == {"attack": 4, "benign": 2}
    assert unique == {"attack": 2, "benign": 1}


def test_duplicate_group_spans_random_split() -> None:
    result = a5.exact_group_boundary_metrics([[False, True, False], [True, True]])
    assert result == {"spanning_groups": 1, "test_rows_with_train_vector": 1}


def test_group_aware_assignment_has_zero_overlap() -> None:
    result = a5.exact_group_boundary_metrics([[False, False], [True, True, True]])
    assert result["spanning_groups"] == 0
    assert result["test_rows_with_train_vector"] == 0


def test_device_holdout_cross_device_duplicate_and_unseen_rate() -> None:
    result = a5.device_holdout_overlap_metrics(
        [["held", "train"], ["held", "held"], ["train"]], "held"
    )
    assert result["test_rows"] == 3
    assert result["test_unique_vectors_seen_in_train"] == 1
    assert result["novel_test_vectors"] == 1
    assert result["novel_test_row_percent"] == 100 * 2 / 3
    assert result["isolation_train_rows_affected"] == 1


def test_unique_identifier_range_label_diagnostics() -> None:
    profiles = {
        0: {
            "binary": Counter({"benign": 2}),
            "category": Counter({"normal": 2}),
            "subcategory": Counter({"normal": 2}),
        },
        1: {
            "binary": Counter({"malicious": 2}),
            "category": Counter({"dos": 2}),
            "subcategory": Counter({"tcp": 2}),
        },
    }
    result = a5.range_label_summary(profiles, total=4, bins=2)
    assert (
        result["label_range_concentration"]["binary"]["benign"]["largest_single_bin_fraction"]
        == 1.0
    )


def test_entity_label_purity_and_low_frequency_caveat() -> None:
    accumulator = a5.EntityAccumulator()
    accumulator.observe("one", "benign", "normal", "normal", 2)
    accumulator.observe("two", "malicious", "dos", "tcp", 3)
    accumulator.observe("mixed", "benign", "normal", "normal")
    accumulator.observe("mixed", "malicious", "dos", "tcp")
    result = accumulator.summary()
    assert result["binary_pure_value_count"] == 2
    assert result["weighted_binary_purity"] == 6 / 7
    assert result["interpretation"].startswith("potential context memorization")


def test_entity_train_test_overlap_is_row_weighted() -> None:
    overlap = a5.SplitEntityOverlap()
    overlap.observe("known", False)
    overlap.observe("known", True)
    overlap.observe("known", True)
    overlap.observe("new", True)
    result = overlap.summary()
    assert result["test_rows_with_value_seen_in_train"] == 2
    assert result["test_row_overlap_percent"] == 100 * 2 / 3


def test_identity_free_duplicate_discovery_after_removing_id(tmp_path: Path) -> None:
    frame = pd.DataFrame(
        {
            "pkSeqID": ["1", "2", "3"],
            "feature": ["same", "same", "other"],
            "attack": ["0", "0", "1"],
            "category": ["Normal", "Normal", "DoS"],
            "subcategory": ["Normal", "Normal", "TCP"],
        }
    )
    store = a5.CandidateHashStore(tmp_path, {"scope": 3})
    hashes = a5.candidate_hashes(frame, ["feature"])
    store.append("scope", hashes)
    assert store.finalize() == {"scope": 1}
    database = a5.initialize_a5_database(tmp_path / "exact.sqlite")
    try:
        mask = store.candidate_mask("scope", hashes)
        assert a5.insert_exact_candidates(database, "scope", frame, ["feature"], mask) == 2
        result = a5.summarize_exact_candidates(database, {"scope": 3})["scope"]
        assert result["unique_tuples"] == 2
        assert result["duplicate_excess"] == 1
        assert result["conflicting_attack_groups"] == 0
    finally:
        database.close()


def test_port_lexical_categories_and_negative_semantics() -> None:
    assert a5.classify_port_token("80") == "decimal_integer"
    assert a5.classify_port_token("0x0303") == "hexadecimal_style"
    assert a5.classify_port_token("-1") == "negative_decimal"
    assert a5.classify_port_token("unknown") == "other"
    profile = a5.PortProfile()
    for token in ("80", "0x0303", "-1", "unknown"):
        profile.observe(token)
    summary = profile.as_dict()
    assert summary["hexadecimal_parsed_min"] == 0x0303
    assert summary["unique_negative_tokens"] == {"-1": 1}


def test_numeric_near_equality_rounding_check() -> None:
    first = np.array([1.2344, 2.3454])
    second = np.array([1.234, 2.345])
    assert a5.decimal_rounding_explains(first, second, 3).all()
    assert not a5.decimal_rounding_explains(first, second, 4).any()


def test_three_way_lineage_classification() -> None:
    assert a5.three_way_lineage_classification(1.0, 1.0, 1.0) == "equals_both"
    assert a5.three_way_lineage_classification(1.0, 2.0, 1.0) == "equals_all_features_only"
    assert a5.three_way_lineage_classification(1.0, 2.0, 2.0) == "equals_ten_best_full_only"
    assert a5.three_way_lineage_classification(1.0, 2.0, 3.0) == "equals_neither"


def test_chronological_split_class_coverage() -> None:
    result = a5.chronological_class_counts(
        [1.0, 2.0, 3.0, 4.0], ["normal", "dos", "dos", "theft"], 3.0
    )
    assert result["train"] == {"normal": 1, "dos": 1}
    assert result["test"] == {"dos": 1, "theft": 1}
