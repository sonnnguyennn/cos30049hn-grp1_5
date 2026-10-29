import importlib.util
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "generate_g2a_contracts.py"
SPEC = importlib.util.spec_from_file_location("generate_g2a_contracts", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
g2a = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = g2a
SPEC.loader.exec_module(g2a)


def test_ordered_115_feature_contract_matches_a2_without_sorting() -> None:
    schema = g2a.load_json(g2a.AUDIT_DIR / "n_baiot_schema.json")
    contract = g2a.build_primary_feature_contract(schema, g2a.source_hashes())
    expected = schema["schemas"][0]["ordered_columns"]
    assert contract["feature_count"] == 115
    assert contract["ordered_feature_names"] == expected
    assert contract["ordered_feature_names"] != sorted(expected)


def test_schema_hash_changes_when_feature_order_changes() -> None:
    original = ["z", "a", "m"]
    changed = ["a", "z", "m"]
    assert g2a.ordered_schema_signature(original) != g2a.ordered_schema_signature(changed)


def test_label_and_provenance_fields_cannot_enter_predictors() -> None:
    g2a.ensure_predictor_boundary(["f1", "f2"], ["target"], ["device"])
    with pytest.raises(ValueError):
        g2a.ensure_predictor_boundary(["f1", "target"], ["target"], ["device"])
    with pytest.raises(ValueError):
        g2a.ensure_predictor_boundary(["f1", "device"], ["target"], ["device"])


def test_exact_vector_group_id_is_deterministic() -> None:
    values = [str(index) for index in range(115)]
    assert g2a.exact_vector_group_id(values) == g2a.exact_vector_group_id(list(values))


def test_exact_vector_group_id_changes_when_one_exact_token_changes() -> None:
    values = [str(index) for index in range(115)]
    changed = list(values)
    changed[42] = "42.0"
    assert g2a.exact_vector_group_id(values) != g2a.exact_vector_group_id(changed)


def test_exact_vector_group_id_requires_original_strings_and_exact_count() -> None:
    with pytest.raises(ValueError):
        g2a.exact_vector_group_id(["1"])
    with pytest.raises(TypeError):
        g2a.exact_vector_group_id([0] * 115)  # type: ignore[list-item]


def test_contract_version_requires_semver() -> None:
    assert g2a.validate_contract_version("1.0.0") == "1.0.0"
    with pytest.raises(ValueError):
        g2a.validate_contract_version("v1")
    with pytest.raises(ValueError):
        g2a.validate_contract_version("1.0")


def test_bot_canonical_representation_has_exactly_four_all_feature_shards() -> None:
    schema = g2a.load_json(g2a.AUDIT_DIR / "bot_iot_schema.json")
    a7 = g2a.load_json(g2a.AUDIT_DIR / "a7_dataset_role_decision.json")
    contract = g2a.build_bot_source_contract(
        schema, g2a.source_hashes(), a7["cross_dataset_policy"]
    )
    assert contract["canonical_representation"] == "all_features_5pct_shards"
    assert len(contract["canonical_source_files"]) == 4
    assert all("Dataset/5%/All features/" in path for path in contract["canonical_source_files"])


def test_bot_targets_and_pkseqid_are_rejected_from_ordinary_predictor_role() -> None:
    schema = g2a.load_json(g2a.AUDIT_DIR / "bot_iot_schema.json")
    a7 = g2a.load_json(g2a.AUDIT_DIR / "a7_dataset_role_decision.json")
    source = g2a.build_bot_source_contract(
        schema, g2a.source_hashes(), a7["cross_dataset_policy"]
    )
    risk = g2a.load_csv(g2a.AUDIT_DIR / "bot_iot_field_risk_profile.csv")
    ports = g2a.load_json(g2a.AUDIT_DIR / "bot_iot_port_encoding_summary.json")
    contract = g2a.build_bot_field_role_contract(source, risk, ports, g2a.source_hashes())
    roles = {item["field_name"]: item for item in contract["field_roles"]}
    for name in ("attack", "category", "subcategory", "pkSeqID"):
        assert roles[name]["ordinary_predictor_eligibility"] == "prohibited"


def test_decimal_and_hexadecimal_port_parse_contract() -> None:
    assert g2a.parse_bot_iot_port_token("80") == {
        "raw": "80",
        "kind": "decimal_integer",
        "value": 80,
    }
    assert g2a.parse_bot_iot_port_token("0x1F90") == {
        "raw": "0x1F90",
        "kind": "hexadecimal_integer",
        "value": 8080,
    }


def test_negative_one_port_remains_unresolved_sentinel() -> None:
    assert g2a.parse_bot_iot_port_token("-1") == {
        "raw": "-1",
        "kind": "unresolved_sentinel",
        "value": None,
    }
    with pytest.raises(ValueError):
        g2a.parse_bot_iot_port_token("-2")


def test_g2a_contract_rejects_downstream_decision_keys() -> None:
    g2a.ensure_g2a_scope({"contract_version": "1.0.0"})
    for key in g2a.FORBIDDEN_CONTRACT_KEYS:
        with pytest.raises(ValueError):
            g2a.ensure_g2a_scope({key: None})
