import importlib.util
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "dataset_label_audit.py"
SPEC = importlib.util.spec_from_file_location("dataset_label_audit", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
label_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(label_audit)


def n_row(
    *,
    logical_id: str,
    source_kind: str,
    family_hint: str = "",
    source_relative: str = "",
    extracted_relative: str = "",
    parent_archive: str = "",
) -> dict[str, str]:
    return {
        "logical_id": logical_id,
        "device": "device_one",
        "source_kind": source_kind,
        "archive_family_hint": family_hint,
        "source_relative_path": source_relative,
        "extracted_relative_path": extracted_relative,
        "parent_archive_relative_path": parent_archive,
        "row_count": "5",
    }


def attack_row(family: str, member: str) -> dict[str, str]:
    family_hint = f"{family}_attacks"
    return n_row(
        logical_id=f"n_baiot:extracted:device_one/{family_hint}/{member}.csv",
        source_kind="derived_extracted_attack",
        family_hint=family_hint,
        extracted_relative=f"device_one/{family_hint}/{member}.csv",
        parent_archive=f"device_one/{family_hint}.rar",
    )


def profile_from_rows(rows: list[tuple[str, str, str]]) -> dict[str, object]:
    profile = label_audit.new_bot_profile()
    for attack, category, subcategory in rows:
        profile["row_count"] += 1
        profile["value_counts"]["attack"][attack] += 1
        profile["value_counts"]["category"][category] += 1
        profile["value_counts"]["subcategory"][subcategory] += 1
        profile["attack_category"][(attack, category)] += 1
        profile["category_subcategory"][(category, subcategory)] += 1
        profile["joint"][(attack, category, subcategory)] += 1
    return profile


def test_benign_n_baiot_mapping() -> None:
    mapped = label_audit.map_n_baiot_row(
        n_row(
            logical_id="n_baiot:source:device_one/benign_traffic.csv",
            source_kind="immutable_benign_source",
            source_relative="device_one/benign_traffic.csv",
        )
    )
    assert mapped["canonical_binary"] == "benign"
    assert mapped["canonical_family"] == "benign"
    assert mapped["canonical_fine_class"] == "benign"


def test_gafgyt_mapping() -> None:
    mapped = label_audit.map_n_baiot_row(attack_row("gafgyt", "combo"))
    assert mapped["canonical_binary"] == "malicious"
    assert mapped["canonical_family"] == "gafgyt"
    assert mapped["canonical_fine_class"] == "gafgyt_combo"


def test_mirai_mapping() -> None:
    mapped = label_audit.map_n_baiot_row(attack_row("mirai", "ack"))
    assert mapped["canonical_family"] == "mirai"
    assert mapped["canonical_fine_class"] == "mirai_ack"


def test_gafgyt_scan_and_mirai_scan_are_distinct() -> None:
    gafgyt = label_audit.map_n_baiot_row(attack_row("gafgyt", "scan"))
    mirai = label_audit.map_n_baiot_row(attack_row("mirai", "scan"))
    assert gafgyt["canonical_fine_class"] != mirai["canonical_fine_class"]


def test_gafgyt_udp_and_mirai_udp_are_distinct() -> None:
    gafgyt = label_audit.map_n_baiot_row(attack_row("gafgyt", "udp"))
    mirai = label_audit.map_n_baiot_row(attack_row("mirai", "udp"))
    assert gafgyt["canonical_fine_class"] != mirai["canonical_fine_class"]


def test_unmapped_member_fails() -> None:
    with pytest.raises(ValueError, match="Unexpected gafgyt member"):
        label_audit.map_n_baiot_row(attack_row("gafgyt", "unknown"))


def test_incorrect_archive_family_fails() -> None:
    row = attack_row("gafgyt", "combo")
    row["parent_archive_relative_path"] = "device_one/mirai_attacks.rar"
    with pytest.raises(ValueError, match="Parent archive conflicts"):
        label_audit.map_n_baiot_row(row)


def test_bot_iot_label_aggregation(tmp_path: Path) -> None:
    path = tmp_path / "labels.csv"
    path.write_text(
        "feature,attack,category,subcategory\n1,0,Normal,Normal\n2,1,DoS,TCP\n",
        encoding="utf-8",
    )
    profile = label_audit.profile_bot_csv(path, ",")
    assert profile["row_count"] == 2
    assert profile["value_counts"]["attack"] == {"0": 1, "1": 1}
    assert profile["joint"][("1", "DoS", "TCP")] == 1


def test_missing_label_column_fails(tmp_path: Path) -> None:
    path = tmp_path / "missing.csv"
    path.write_text("attack,category\n0,Normal\n", encoding="utf-8")
    with pytest.raises(ValueError, match="subcategory"):
        label_audit.profile_bot_csv(path, ",")


def test_empty_label_is_counted_as_invalid(tmp_path: Path) -> None:
    path = tmp_path / "empty-label.csv"
    path.write_text("attack,category,subcategory\n1,,TCP\n", encoding="utf-8")
    profile = label_audit.profile_bot_csv(path, ",")
    assert profile["invalid_or_missing_label_rows"] == 1
    assert profile["value_counts"]["category"][""] == 1


def test_short_row_is_counted_as_null_and_invalid(tmp_path: Path) -> None:
    path = tmp_path / "short-row.csv"
    path.write_text("attack,category,subcategory\n0,Normal\n", encoding="utf-8")
    profile = label_audit.profile_bot_csv(path, ",")
    assert profile["invalid_or_missing_label_rows"] == 1
    assert profile["value_counts"]["subcategory"][None] == 1


def test_aggregate_distribution_comparison() -> None:
    complete = profile_from_rows([("0", "Normal", "Normal"), ("1", "DoS", "TCP")])
    train = profile_from_rows([("1", "DoS", "TCP")])
    test = profile_from_rows([("0", "Normal", "Normal")])
    profiles = {
        "all_features_5pct_shards": complete,
        "ten_best_full": complete,
        "ten_best_predefined_train": train,
        "ten_best_predefined_test": test,
    }
    rows = label_audit.build_comparison_rows(profiles)
    assert all(row["all_features_matches_ten_best_full"] == "true" for row in rows)
    assert all(row["train_plus_test_matches_ten_best_full"] == "true" for row in rows)


def test_artifact_row_order_is_deterministic() -> None:
    first = profile_from_rows([("1", "DoS", "UDP"), ("0", "Normal", "Normal")])
    second = profile_from_rows([("0", "Normal", "Normal"), ("1", "DoS", "UDP")])
    profiles_a = {"z": first, "a": second}
    profiles_b = {"a": first, "z": second}
    assert label_audit.build_bot_distribution_rows(profiles_a) == (
        label_audit.build_bot_distribution_rows(profiles_b)
    )
