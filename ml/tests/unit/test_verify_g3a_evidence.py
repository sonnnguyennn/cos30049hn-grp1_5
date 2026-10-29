from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from iotguard.data.split import assign_evaluation_group, evaluation_group_id

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "verify_g3a_evidence.py"
SPEC = importlib.util.spec_from_file_location("verify_g3a_evidence", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)


def vector(first: float) -> tuple[float, ...]:
    return (first,) + (0.0,) * 114


def test_independent_binary64_group_implementation_matches_contract() -> None:
    for first in (-0.0, 0.0, 1.0, -2.5, 1.0000000000000002):
        assert verify.independent_evaluation_group(vector(first)) == evaluation_group_id(
            vector(first)
        )


def test_independent_split_assignment_matches_contract() -> None:
    for first in (0.0, 1.0, -2.5, 123456.75):
        group_id = verify.independent_evaluation_group(vector(first))
        assert verify.independent_split(group_id) == assign_evaluation_group(group_id)
