import importlib.util
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "verify_a2_evidence.py"
SPEC = importlib.util.spec_from_file_location("verify_a2_evidence", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
verification = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verification)


def test_binary_physical_data_row_count_with_and_without_final_newline(tmp_path: Path) -> None:
    with_newline = tmp_path / "with.csv"
    without_newline = tmp_path / "without.csv"
    with_newline.write_bytes(b"a,b\n1,2\n3,4\n")
    without_newline.write_bytes(b"a,b\n1,2\n3,4")

    assert verification.binary_physical_data_row_count(with_newline) == 2
    assert verification.binary_physical_data_row_count(without_newline) == 2


def test_independent_header_signature_is_order_sensitive(tmp_path: Path) -> None:
    first = tmp_path / "first.csv"
    second = tmp_path / "second.csv"
    first.write_text("a,b\n1,2\n", encoding="utf-8")
    second.write_text("b,a\n2,1\n", encoding="utf-8")

    assert verification.independent_header_signature(
        first, ","
    ) != verification.independent_header_signature(second, ",")
