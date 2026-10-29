import importlib.util
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "verify_a4_evidence.py"
SPEC = importlib.util.spec_from_file_location("verify_a4_evidence", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
verification = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verification
SPEC.loader.exec_module(verification)


def test_lexical_quality_categories_remain_distinct() -> None:
    counts = verification.new_quality_counts(True)
    for value in ("", "NaN", "+inf", "-inf", "null", "not-a-number", "-2", "0"):
        verification.observe_value(value, counts)
    assert counts["empty_field_count"] == 1
    assert counts["nan_count"] == 1
    assert counts["positive_inf_count"] == 1
    assert counts["negative_inf_count"] == 1
    assert counts["explicit_null_token_count"] == 1
    assert counts["numeric_parse_failure_count"] == 1
    assert counts["negative_value_count"] == 1
    assert counts["zero_value_count"] == 1


def test_profile_selected_columns_preserves_empty_field(tmp_path: Path) -> None:
    path = tmp_path / "quality.csv"
    path.write_text("number,text\n, alpha \n2,beta\n", encoding="utf-8")
    result = verification.profile_selected_columns(
        path, ",", {"number": True, "text": False}
    )
    assert result["row_count"] == 2
    assert result["columns"]["number"]["empty_field_count"] == 1
    assert result["columns"]["text"]["outer_whitespace_count"] == 1


def test_decimal_lineage_comparison_accepts_harmless_numeric_formatting() -> None:
    assert verification.values_equal("mean", "1", "1.0") is True
    assert verification.values_equal("sport", "1", "1.0") is False


def test_binary_data_row_count_handles_final_newline(tmp_path: Path) -> None:
    with_newline = tmp_path / "with.csv"
    without_newline = tmp_path / "without.csv"
    with_newline.write_bytes(b"a,b\n1,2\n3,4\n")
    without_newline.write_bytes(b"a,b\n1,2\n3,4")
    assert verification.binary_data_row_count(with_newline) == 2
    assert verification.binary_data_row_count(without_newline) == 2


def test_duplicate_reconciliation() -> None:
    result = verification.reconcile_duplicate_metrics(
        {
            "total_rows": 10,
            "unique_records": 7,
            "duplicate_excess_rows": 3,
            "duplicate_row_occurrences": 5,
            "duplicate_group_count": 2,
        }
    )
    assert all(result.values())
