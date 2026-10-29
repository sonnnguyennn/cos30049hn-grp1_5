import importlib.util
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "dataset_suitability_audit.py"
SPEC = importlib.util.spec_from_file_location("dataset_suitability_audit", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
a6 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = a6
SPEC.loader.exec_module(a6)


def test_status_framework_validation() -> None:
    assert a6.validate_status("FAVORABLE", a6.SUITABILITY_STATUSES) == "FAVORABLE"
    with pytest.raises(ValueError):
        a6.validate_status("BEST", a6.SUITABILITY_STATUSES)


def test_primary_requirement_allowed_values() -> None:
    for status in a6.REQUIREMENT_STATUSES:
        assert a6.validate_status(status, a6.REQUIREMENT_STATUSES) == status
    with pytest.raises(ValueError):
        a6.validate_status("RANKED_FIRST", a6.REQUIREMENT_STATUSES)


def test_coverage_first_reports_expected_present_missing_before_minimum() -> None:
    result = a6.coverage_first(
        "candidate",
        {"binary": {"benign": 4}, "fine": {"a": 10, "c": 2}},
        {"binary": ("benign", "malicious"), "fine": ("a", "b", "c")},
    )
    assert result["levels"]["binary"]["total_classes_expected"] == 2
    assert result["levels"]["binary"]["classes_present_in_test"] == 1
    assert result["levels"]["binary"]["missing_classes"] == ["malicious"]
    assert result["levels"]["fine"]["minimum_support_among_represented_classes"] == 2
    assert result["levels"]["fine"]["coverage_complete"] is False


def test_baseline_adjusted_purity_does_not_overstate_extreme_binary_purity() -> None:
    result = a6.baseline_adjusted_purity({"benign": 1, "malicious": 999}, 1.0)
    assert result["global_majority_baseline_percent"] == 99.9
    assert result["observed_weighted_purity_percent"] == 100.0
    assert result["increase_over_baseline_percentage_points"] == pytest.approx(0.1)


def test_exact_and_semantic_feature_overlap_are_distinguished() -> None:
    n_schema = {"schemas": [{"ordered_columns": ["window_mean", "window_std"]}]}
    bot_schema = {
        "documentation_cross_check": {"observed_all_features_names": ["mean", "stddev"]}
    }
    result = a6.feature_overlap(n_schema, bot_schema)
    assert result["exact_named_feature_overlap"] == []
    assert result["exact_named_feature_overlap_count"] == 0
    assert result["meaningful_semantic_overlap"]
    assert all(
        "conceptual only" in item["compatibility"]
        for item in result["meaningful_semantic_overlap"]
    )
