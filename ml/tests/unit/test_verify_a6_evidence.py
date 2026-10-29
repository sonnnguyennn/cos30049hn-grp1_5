import importlib.util
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "verify_a6_evidence.py"
SPEC = importlib.util.spec_from_file_location("verify_a6_evidence", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)


def test_missing_class_detection_prevents_complete_claim() -> None:
    result = verify.coverage_record(
        {"binary": {"malicious": 10}}, {"binary": {"benign", "malicious"}}
    )
    assert result["binary"]["missing_classes"] == ["benign"]
    assert result["binary"]["coverage_complete"] is False
    assert result["binary"]["minimum_support_among_represented_classes"] == 10


def test_no_overall_score_or_ranking_guard() -> None:
    assert verify.no_score_or_ranking([{"status": "PASS"}], [[{"dimension": "x"}]])
    assert not verify.no_score_or_ranking([{"overall_score": 10}], [])
    assert not verify.no_score_or_ranking([], [[{"dimension": "x", "rank": "1"}]])


def test_no_primary_secondary_assignment_guard() -> None:
    summary = {
        "method": {
            "primary_dataset_selected": False,
            "secondary_dataset_selected": False,
            "winner_selected": False,
        },
        "role_selection": "not performed",
    }
    compatibility = {"role_selection": "not performed"}
    assert verify.no_role_assignment(summary, compatibility, "A6 assigns no dataset role.")
    assert not verify.no_role_assignment(summary, compatibility, "N-BaIoT is the primary dataset.")
