import importlib.util
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "verify_a3_evidence.py"
SPEC = importlib.util.spec_from_file_location("verify_a3_evidence", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
verify_a3 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_a3)


def test_pandas_label_profile_uses_only_exact_raw_values(tmp_path: Path) -> None:
    path = tmp_path / "labels.csv"
    path.write_text(
        "unused,attack,category,subcategory\n1,0,Normal,Normal\n2,1,DoS,TCP\n",
        encoding="utf-8",
    )
    profile = verify_a3.pandas_label_profile(path, ",", chunk_size=1)
    assert profile["row_count"] == 2
    assert profile["value_counts"]["category"] == {"Normal": 1, "DoS": 1}
    assert profile["joint"][("1", "DoS", "TCP")] == 1
    assert profile["invalid_or_missing_label_rows"] == 0


def test_independent_n_label_qualifies_member_with_family() -> None:
    base = {
        "source_kind": "derived_extracted_attack",
        "source_relative_path": "",
        "parent_archive_relative_path": "device/gafgyt_attacks.rar",
        "archive_family_hint": "gafgyt_attacks",
        "extracted_relative_path": "device/gafgyt_attacks/scan.csv",
        "logical_id": "gafgyt-scan",
    }
    gafgyt = verify_a3.independent_n_label(base)
    base.update(
        {
            "parent_archive_relative_path": "device/mirai_attacks.rar",
            "archive_family_hint": "mirai_attacks",
            "extracted_relative_path": "device/mirai_attacks/scan.csv",
            "logical_id": "mirai-scan",
        }
    )
    mirai = verify_a3.independent_n_label(base)
    assert gafgyt == ("malicious", "gafgyt", "gafgyt_scan")
    assert mirai == ("malicious", "mirai", "mirai_scan")
