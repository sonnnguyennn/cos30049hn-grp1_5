import importlib.util
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "dataset_quality_audit.py"
SPEC = importlib.util.spec_from_file_location("dataset_quality_audit", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
a4 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = a4
SPEC.loader.exec_module(a4)


def profile_numeric(values: list[str]) -> tuple[object, object]:
    frame = pd.DataFrame({"value": values})
    stats = a4.new_column_stats(["value"], {"value"})
    quality = a4.FileQuality()
    a4.update_quality(frame, stats, quality)
    return stats["value"], quality


def lineage_frame(ids: list[int]) -> pd.DataFrame:
    rows = []
    for identifier in ids:
        rows.append(
            {
                "pkSeqID": str(identifier),
                "proto": "tcp",
                "saddr": "10.0.0.1",
                "sport": str(1000 + identifier),
                "daddr": "10.0.0.2",
                "dport": "80",
                "seq": str(identifier),
                "stddev": "1.0",
                "N_IN_Conn_P_SrcIP": "2",
                "min": "0.5",
                "state_number": "1",
                "mean": "1",
                "N_IN_Conn_P_DstIP": "3",
                "drate": "0",
                "srate": "1.5",
                "max": "2",
                "attack": "1",
                "category": "DoS",
                "subcategory": "TCP",
            }
        )
    return pd.DataFrame(rows, columns=a4.LINEAGE_FIELDS)


def exact_row(
    values: list[str], source_id: int, row_number: int, fine_label: str = "same"
) -> tuple[object, ...]:
    exact_hash, exact_blob = a4.encode_exact_row(values)
    return (
        "n_baiot",
        "all_115_features",
        exact_hash,
        exact_blob,
        source_id,
        row_number,
        "",
        "",
        "",
        "malicious",
        "gafgyt",
        fine_label,
    )


def test_quality_empty_field() -> None:
    stats, quality = profile_numeric(["", "1"])
    assert stats.empty_field_count == 1
    assert quality.missing_any_count == 1


def test_semicolon_unnamed_leading_header_is_restored(tmp_path: Path) -> None:
    path = tmp_path / "unnamed.csv"
    path.write_text(";pkSeqID;attack\n0;1;0\n", encoding="utf-8")
    frame = next(iter(a4.read_chunks(path, ";", 10)))
    restored = a4.restore_unnamed_leading_header(frame)
    assert list(restored.columns) == ["", "pkSeqID", "attack"]
    assert restored.iloc[0, 0] == "0"


def test_quality_literal_nan_preserves_token() -> None:
    stats, quality = profile_numeric(["NaN", "nan"])
    assert stats.nan_count == 2
    assert stats.nan_tokens == {"NaN": 1, "nan": 1}
    assert quality.nonfinite_any_count == 2


def test_quality_positive_infinity() -> None:
    stats, quality = profile_numeric(["+inf", "Infinity"])
    assert stats.positive_inf_count == 2
    assert quality.nonfinite_any_count == 2


def test_quality_negative_infinity() -> None:
    stats, quality = profile_numeric(["-inf", "-Infinity"])
    assert stats.negative_inf_count == 2
    assert quality.nonfinite_any_count == 2


def test_quality_nonnumeric_value_in_numeric_candidate() -> None:
    stats, quality = profile_numeric(["abc", "1"])
    assert stats.numeric_parse_failure_count == 1
    assert stats.parse_failure_examples == {"abc": 1}
    assert quality.parse_failure_any_count == 1


def test_negative_finite_value_is_observed_not_invalidated() -> None:
    stats, quality = profile_numeric(["-2.5", "0", "1"])
    assert stats.negative_value_count == 1
    assert stats.finite_count == 3
    assert quality.parse_failure_any_count == 0


def test_no_duplicates(tmp_path: Path) -> None:
    connection = a4.initialize_database(tmp_path / "audit.sqlite")
    try:
        result = a4.duplicate_group_totals(
            connection, "n_baiot", "all_115_features", total_rows=2
        )
        assert result["unique_records"] == 2
        assert result["duplicate_excess_rows"] == 0
    finally:
        connection.close()


def test_within_file_duplicate(tmp_path: Path) -> None:
    connection = a4.initialize_database(tmp_path / "audit.sqlite")
    try:
        a4.insert_exact_rows(
            connection,
            [exact_row(["1", "2"], 0, 1), exact_row(["1", "2"], 0, 2)],
        )
        assert a4.within_source_excess(connection, "n_baiot", "all_115_features") == 1
    finally:
        connection.close()


def test_duplicate_excess_by_source_uses_exact_groups(tmp_path: Path) -> None:
    connection = a4.initialize_database(tmp_path / "audit.sqlite")
    try:
        a4.insert_exact_rows(
            connection,
            [
                exact_row(["x"], 0, 1),
                exact_row(["x"], 0, 2),
                exact_row(["x"], 1, 1),
                exact_row(["y"], 1, 2),
                exact_row(["y"], 1, 3),
                exact_row(["y"], 1, 4),
                exact_row(["unique"], 2, 1),
            ],
        )
        assert a4.duplicate_excess_by_source(
            connection, "n_baiot", "all_115_features"
        ) == {0: 1, 1: 2}
        assert a4.within_source_excess(
            connection, "n_baiot", "all_115_features"
        ) == 3
    finally:
        connection.close()


def test_cross_file_duplicate(tmp_path: Path) -> None:
    connection = a4.initialize_database(tmp_path / "audit.sqlite")
    try:
        a4.insert_exact_rows(
            connection,
            [exact_row(["1", "2"], 0, 1), exact_row(["1", "2"], 1, 1)],
        )
        a4.materialize_exact_group_stats(connection)
        result = a4.grouped_condition_metrics(
            connection, "n_baiot", "all_115_features", "source_count > 1"
        )
        assert result["group_count"] == 1
        assert result["excess_rows"] == 1
    finally:
        connection.close()


def test_same_feature_same_label_duplicate(tmp_path: Path) -> None:
    connection = a4.initialize_database(tmp_path / "audit.sqlite")
    try:
        a4.insert_exact_rows(
            connection,
            [exact_row(["x"], 0, 1, "a"), exact_row(["x"], 1, 1, "a")],
        )
        a4.materialize_exact_group_stats(connection)
        result = a4.grouped_condition_metrics(
            connection, "n_baiot", "all_115_features", "fine_count = 1"
        )
        assert result["group_count"] == 1
    finally:
        connection.close()


def test_same_feature_conflicting_label_duplicate(tmp_path: Path) -> None:
    connection = a4.initialize_database(tmp_path / "audit.sqlite")
    try:
        a4.insert_exact_rows(
            connection,
            [exact_row(["x"], 0, 1, "a"), exact_row(["x"], 1, 1, "b")],
        )
        a4.materialize_exact_group_stats(connection)
        result = a4.grouped_condition_metrics(
            connection, "n_baiot", "all_115_features", "fine_count > 1"
        )
        assert result["group_count"] == 1
    finally:
        connection.close()


def test_candidate_hash_collision_is_split_by_exact_values(tmp_path: Path) -> None:
    connection = a4.initialize_database(tmp_path / "audit.sqlite")
    try:
        a4.insert_exact_rows(
            connection,
            [exact_row(["first"], 0, 1), exact_row(["second"], 1, 1)],
        )
        a4.materialize_exact_group_stats(connection)
        result = a4.duplicate_group_totals(
            connection, "n_baiot", "all_115_features", total_rows=2
        )
        assert result["unique_records"] == 2
        assert result["duplicate_group_count"] == 0
    finally:
        connection.close()


def test_n_duplicate_summary_counts_cross_device_group(tmp_path: Path) -> None:
    connection = a4.initialize_database(tmp_path / "audit.sqlite")
    sources = [
        {"source_id": 0, "device": "one", "logical_id": "one", "expected_rows": 1},
        {"source_id": 1, "device": "two", "logical_id": "two", "expected_rows": 1},
    ]
    try:
        a4.insert_exact_rows(
            connection,
            [exact_row(["x"], 0, 1), exact_row(["x"], 1, 1)],
        )
        a4.create_n_source_metadata_table(connection, sources)
        a4.materialize_exact_group_stats(connection)
        result = a4.n_duplicate_summary(connection, sources)
        assert result["across_devices"]["group_count"] == 1
        assert result["by_logical_csv"]["one"]["within_file_duplicate_excess_rows"] == 0
        assert result["by_logical_csv"]["two"]["within_file_duplicate_excess_rows"] == 0
    finally:
        connection.close()


def test_n_duplicate_summary_distinguishes_file_and_device_overlap(
    tmp_path: Path,
) -> None:
    connection = a4.initialize_database(tmp_path / "audit.sqlite")
    sources = [
        {"source_id": 0, "device": "one", "logical_id": "first", "expected_rows": 1},
        {"source_id": 1, "device": "one", "logical_id": "second", "expected_rows": 1},
    ]
    try:
        a4.insert_exact_rows(
            connection,
            [exact_row(["x"], 0, 1), exact_row(["x"], 1, 1)],
        )
        a4.create_n_source_metadata_table(connection, sources)
        a4.materialize_exact_group_stats(connection)
        result = a4.n_duplicate_summary(connection, sources)
        assert result["across_logical_csvs"]["group_count"] == 1
        assert result["across_devices"]["group_count"] == 0
    finally:
        connection.close()


def test_n_duplicate_summary_scans_exact_rows_once(tmp_path: Path) -> None:
    connection = a4.initialize_database(tmp_path / "audit.sqlite")
    sources = [
        {"source_id": 0, "device": "one", "logical_id": "one", "expected_rows": 2},
        {"source_id": 1, "device": "two", "logical_id": "two", "expected_rows": 1},
    ]
    try:
        a4.insert_exact_rows(
            connection,
            [
                exact_row(["x"], 0, 1),
                exact_row(["x"], 0, 2),
                exact_row(["x"], 1, 1),
            ],
        )
        a4.create_n_source_metadata_table(connection, sources)
        a4.materialize_exact_group_stats(connection)
        statements: list[str] = []
        connection.set_trace_callback(statements.append)
        a4.n_duplicate_summary(connection, sources)
        connection.set_trace_callback(None)
        exact_row_scans = [
            statement
            for statement in statements
            if "FROM exact_rows" in statement and "SELECT" in statement
        ]
        assert len(exact_row_scans) == 1
        assert sum("FROM exact_group_stats" in statement for statement in statements) >= 2
    finally:
        connection.close()


def test_flagged_examples_use_group_stats_before_indexed_member_lookup(
    tmp_path: Path,
) -> None:
    connection = a4.initialize_database(tmp_path / "audit.sqlite")
    sources = [
        {
            "source_id": 0,
            "device": "one",
            "logical_id": "one",
            "expected_rows": 2,
            "root_kind": "raw",
            "relative_path": "one.csv",
        }
    ]
    try:
        a4.insert_exact_rows(
            connection,
            [exact_row(["x"], 0, 1), exact_row(["x"], 0, 2)],
        )
        a4.create_n_source_metadata_table(connection, sources)
        a4.materialize_exact_group_stats(connection)
        statements: list[str] = []
        connection.set_trace_callback(statements.append)
        examples = a4.collect_flagged_examples(connection, sources, [])
        connection.set_trace_callback(None)
        assert len(examples) == 1
        exact_row_queries = [
            statement for statement in statements if "FROM exact_rows" in statement
        ]
        assert len(exact_row_queries) == 1
        assert "exact_hash=" in exact_row_queries[0]
        assert sum("FROM exact_group_stats" in statement for statement in statements) == 8
    finally:
        connection.close()


def test_unique_pkseqid_exact_projection(tmp_path: Path) -> None:
    store = a4.BotLineageStore(tmp_path, 3)
    frame = lineage_frame([1, 2, 3])
    identifiers = a4.add_all_features_lineage(store, frame, 1)
    differences, different_rows = a4.compare_lineage_chunk(store, frame, identifiers)
    assert different_rows == 0
    assert all(count == 0 for count in differences.values())


def test_missing_pkseqid_fails(tmp_path: Path) -> None:
    store = a4.BotLineageStore(tmp_path, 3)
    a4.add_all_features_lineage(store, lineage_frame([1, 2]), 1)
    with pytest.raises(ValueError, match="absent"):
        a4.ensure_ids_present(store, np.array([3], dtype=np.int64))


def test_duplicated_pkseqid_fails(tmp_path: Path) -> None:
    store = a4.BotLineageStore(tmp_path, 3)
    with pytest.raises(ValueError, match="not unique"):
        a4.add_all_features_lineage(store, lineage_frame([1, 1]), 1)


def test_one_field_lineage_mismatch(tmp_path: Path) -> None:
    store = a4.BotLineageStore(tmp_path, 2)
    original = lineage_frame([1, 2])
    identifiers = a4.add_all_features_lineage(store, original, 1)
    changed = original.copy()
    changed.loc[1, "max"] = "3"
    differences, different_rows = a4.compare_lineage_chunk(store, changed, identifiers)
    assert differences["max"] == 1
    assert different_rows == 1


def test_disjoint_exact_train_test_partition() -> None:
    full = np.array([0, 1, 1, 1], dtype=np.uint8)
    train = np.array([0, 1, 1, 0], dtype=np.uint8)
    test = np.array([0, 0, 0, 1], dtype=np.uint8)
    result = a4.partition_set_summary(train, test, full)
    assert result["train_test_are_disjoint"] is True
    assert result["train_test_union_equals_full"] is True


def test_overlapping_train_test_ids() -> None:
    full = np.array([0, 1, 1], dtype=np.uint8)
    train = np.array([0, 1, 1], dtype=np.uint8)
    test = np.array([0, 0, 1], dtype=np.uint8)
    result = a4.partition_set_summary(train, test, full)
    assert result["train_test_are_disjoint"] is False
    assert result["train_test_intersection_count"] == 1


def test_incomplete_train_test_union() -> None:
    full = np.array([0, 1, 1, 1], dtype=np.uint8)
    train = np.array([0, 1, 0, 0], dtype=np.uint8)
    test = np.array([0, 0, 1, 0], dtype=np.uint8)
    result = a4.partition_set_summary(train, test, full)
    assert result["train_test_union_equals_full"] is False


def test_row_order_mismatch_despite_exact_set_identity(tmp_path: Path) -> None:
    store = a4.BotLineageStore(tmp_path, 3)
    a4.add_all_features_lineage(store, lineage_frame([1, 2, 3]), 1)
    assert a4.physical_order_matches(store, np.array([1, 2, 3]), 1) is True
    assert a4.physical_order_matches(store, np.array([2, 1, 3]), 1) is False
