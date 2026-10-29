import importlib.util
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "dataset_structure_audit.py"
SPEC = importlib.util.spec_from_file_location("dataset_structure_audit", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
structure_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(structure_audit)


def metadata(identifier: str) -> dict[str, str]:
    return {"logical_id": identifier, "dataset": "synthetic", "representation": "test"}


def test_ordered_header_signature_is_deterministic_and_order_sensitive() -> None:
    first = structure_audit.ordered_header_digest(["a", "b"])
    assert first == structure_audit.ordered_header_digest(["a", "b"])
    assert first != structure_audit.ordered_header_digest(["b", "a"])


def test_exact_row_count_and_header(tmp_path: Path) -> None:
    path = tmp_path / "sample.csv"
    path.write_text("a,b\n1,2\n3,4\n", encoding="utf-8")

    row = structure_audit.scan_csv(path, metadata("sample"))

    assert row["row_count"] == 2
    assert row["column_count"] == 2
    assert row["parse_status"] == "ok"


def test_empty_csv_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "empty.csv"
    path.write_bytes(b"")

    row = structure_audit.scan_csv(path, metadata("empty"))

    assert row["row_count"] == 0
    assert row["column_count"] == 0
    assert row["parse_status"] == "empty"


def test_header_only_csv_has_zero_data_rows(tmp_path: Path) -> None:
    path = tmp_path / "header.csv"
    path.write_text("a,b\n", encoding="utf-8")

    row = structure_audit.scan_csv(path, metadata("header"))

    assert row["row_count"] == 0
    assert row["column_count"] == 2
    assert row["parse_status"] == "ok"


def test_inconsistent_row_width_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "bad.csv"
    path.write_text("a,b\n1,2\n3\n4,5,6\n", encoding="utf-8")

    row = structure_audit.scan_csv(path, metadata("bad"))

    assert row["row_count"] == 3
    assert row["width_mismatch_count"] == 2
    assert row["parse_status"] == "error"


def test_schema_grouping_identical_and_different_headers(tmp_path: Path) -> None:
    paths = []
    for name, content in (
        ("one.csv", "a,b\n1,2\n"),
        ("two.csv", "a,b\n3,4\n"),
        ("three.csv", "b,a\n5,6\n"),
    ):
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        paths.append(path)
    rows = [
        structure_audit.scan_csv(path, metadata(path.name))
        for path in paths
    ]

    schemas = structure_audit.group_schemas(rows)

    assert len(schemas) == 2
    assert sorted(schema["file_count"] for schema in schemas) == [1, 2]


def test_representation_grouping_logic() -> None:
    assert structure_audit.classify_bot_iot_representation(
        "Dataset/5%/All features/UNSW_2018_IoT_Botnet_Full5pc_1.csv"
    ) == "all_features_5pct_shards"
    assert structure_audit.classify_bot_iot_representation(
        "Dataset/5%/10-best features/UNSW_2018_IoT_Botnet_Final_10_Best.csv"
    ) == "ten_best_full"
    assert structure_audit.classify_bot_iot_representation(
        "Dataset/5%/10-best features/10-best Training-Testing split/"
        "UNSW_2018_IoT_Botnet_Final_10_best_Training.csv"
    ) == "ten_best_predefined_train"


def test_semicolon_csv_preserves_unnamed_leading_header(tmp_path: Path) -> None:
    path = tmp_path / "semicolon.csv"
    path.write_text(";a;b\n0;1;2\n", encoding="utf-8")

    row = structure_audit.scan_csv(path, metadata("semicolon"))

    assert row["delimiter"] == "semicolon"
    assert row["header_columns"] == '["","a","b"]'
    assert row["column_count"] == 3
