from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "verify_g2b_evidence.py"
SPEC = importlib.util.spec_from_file_location("verify_g2b_evidence", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)


def test_independent_group_encoding_is_lexically_sensitive() -> None:
    assert verify.independent_group_id(["1"]) != verify.independent_group_id(["1.0"])


def test_independent_port_parser() -> None:
    assert verify.independent_port_parse("443") == ("decimal", 443)
    assert verify.independent_port_parse("0x0303") == ("hex", 771)
    assert verify.independent_port_parse("-1") == ("unresolved_sentinel", None)
    with pytest.raises(ValueError):
        verify.independent_port_parse("443.0")


def test_full_independent_verification_passes() -> None:
    payload = verify.verify()
    assert payload["overall_status"] == "PASS"
    assert all(payload["checks"].values())
