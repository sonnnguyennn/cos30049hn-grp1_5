import importlib.util
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "verify_a7_evidence.py"
SPEC = importlib.util.spec_from_file_location("verify_a7_evidence", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)


def test_decision_trace_requires_a0_through_a6() -> None:
    rows = [{"checkpoint": f"A{index}", "status": "PASS"} for index in range(7)]
    assert verify.trace_is_complete(rows)
    assert not verify.trace_is_complete(rows[:-1])


def test_requirement_gate_is_recomputed_from_a6_rows() -> None:
    rows = [
        {
            "requirement": "P1",
            "n_baiot_status": "SUPPORTED",
            "bot_iot_status": "PARTIALLY_SUPPORTED",
        },
        {
            "requirement": "P2",
            "n_baiot_status": "SUPPORTED",
            "bot_iot_status": "SUPPORTED",
        },
        {
            "requirement": "P3",
            "n_baiot_status": "SUPPORTED",
            "bot_iot_status": "NOT_SUPPORTED",
        },
    ]
    result = verify.requirement_gate(rows)
    assert result["matches"] is True


def test_numeric_score_and_ranking_are_rejected() -> None:
    assert verify.no_numeric_score_or_ranking(
        {"decision_status": "ACCEPTED"}, "requirements gate without numeric totals"
    )
    assert not verify.no_numeric_score_or_ranking(
        {"overall_score": 10}, "requirements gate"
    )
    assert not verify.no_numeric_score_or_ranking(
        {"decision_status": "ACCEPTED"}, "weighted score: 10"
    )
