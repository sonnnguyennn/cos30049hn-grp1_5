import importlib.util
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "dataset_role_decision.py"
SPEC = importlib.util.spec_from_file_location("dataset_role_decision", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
a7 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = a7
SPEC.loader.exec_module(a7)


def sample_context() -> dict:
    return {
        "requirement_statuses": {
            "N-BaIoT": {
                "P1": "SUPPORTED",
                "P2": "SUPPORTED",
                "P3": "SUPPORTED",
                "P4": "SUPPORTED",
            },
            "Bot-IoT": {
                "P1": "PARTIALLY_SUPPORTED",
                "P2": "SUPPORTED",
                "P3": "NOT_SUPPORTED",
                "P4": "PARTIALLY_SUPPORTED",
            },
        },
        "n2": {
            "train_rows": 5_650_017,
            "test_rows": 1_412_589,
            "exact_feature_overlap_rows": 0,
            "test_fine_distribution": {f"class_{index}": 51_596 for index in range(11)},
            "distribution_drift_percentage_points": {"class_0": 0.0888},
        },
        "bot_candidate_benign_counts": {
            "B1": 107,
            "B2": 95,
            "B3": 0,
            "B4-saddr": 107,
            "B4-pair": 56,
        },
        "compatibility": {"exact_named_feature_overlap_count": 0},
        "n_facts": {
            "raw_rows": 7_062_606,
            "benign_rows": 555_932,
            "malicious_rows": 6_506_674,
            "logical_csvs": 89,
            "ordered_numeric_features": 115,
            "fine_classes": 11,
            "unique_exact_vectors": 2_482_676,
            "naive_test_exact_overlap_percent": 84.7,
            "quality_failure_totals": {
                "missing_rows": 0,
                "nan": 0,
                "positive_inf": 0,
                "negative_inf": 0,
                "numeric_parse": 0,
            },
        },
        "bot_facts": {
            "all_features_records": 3_668_522,
            "benign_rows": 477,
            "malicious_rows": 3_668_045,
            "category_count": 5,
            "subcategory_count": 8,
            "rare_label_counts": {
                "Data Exfiltration": 6,
                "Keylogging": 73,
                "Theft": 79,
            },
        },
    }


def test_allowed_role_values_and_primary_differs_from_secondary() -> None:
    a7.validate_roles("N-BaIoT", "Bot-IoT")
    with pytest.raises(ValueError):
        a7.validate_roles("N-BaIoT", "N-BaIoT")
    with pytest.raises(ValueError):
        a7.validate_roles("unknown", "Bot-IoT")


def test_decision_contains_no_numeric_score_or_ranking() -> None:
    decision = a7.build_decision(sample_context())
    assert not a7.contains_forbidden_score(decision)
    assert a7.contains_forbidden_score({"weighted_score": 1})


def test_rejected_alternative_and_cross_dataset_policy_are_explicit() -> None:
    decision = a7.build_decision(sample_context())
    assert decision["rejected_alternative"]["primary_dataset"] == "Bot-IoT"
    assert decision["rejected_alternative"]["secondary_dataset"] == "N-BaIoT"
    assert (
        decision["cross_dataset_policy"]["direct_cross_dataset_model_evaluation"]
        == "NOT_CURRENTLY_DEFENSIBLE"
    )


def test_final_split_predictors_and_implementation_remain_unset() -> None:
    decision = a7.build_decision(sample_context())
    assert decision["adopted_final_split"] is None
    assert decision["adopted_final_predictors"] is None
    assert decision["preprocessing_implemented"] is False
    assert decision["clustering_algorithm_selected"] is False


def test_g2_and_g3_deferrals_and_secondary_ml_requirement_are_present() -> None:
    decision = a7.build_decision(sample_context())
    assert decision["deferred_to_g2"]
    assert decision["deferred_to_g3"]
    assert decision["authorized_secondary_ml_candidates"]
    assert "must select and execute" in decision["secondary_ml_requirement"]


def test_g1_stays_open_when_mandatory_checkpoint_is_missing() -> None:
    statuses = {f"A{index}": True for index in range(7)}
    statuses["A5"] = False
    result = a7.build_closure_checklist(
        statuses,
        roles_assigned=True,
        sources_immutable=True,
        constraints_handed_off=True,
    )
    assert result["closure_status"] == "OPEN"
    assert result["all_mandatory_checks_pass"] is False


def test_g1_closes_when_all_evidence_and_role_decision_exist() -> None:
    statuses = {f"A{index}": True for index in range(7)}
    result = a7.build_closure_checklist(
        statuses,
        roles_assigned=True,
        sources_immutable=True,
        constraints_handed_off=True,
    )
    assert result["closure_status"] == "COMPLETE"
    assert result["all_mandatory_checks_pass"] is True
