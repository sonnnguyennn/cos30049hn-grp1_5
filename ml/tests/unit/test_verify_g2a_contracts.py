import importlib.util
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "verify_g2a_contracts.py"
SPEC = importlib.util.spec_from_file_location("verify_g2a_contracts", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)


def test_independent_schema_signature_is_order_sensitive() -> None:
    assert verify.ordered_schema_signature(["a", "b"]) != verify.ordered_schema_signature(
        ["b", "a"]
    )


def test_independent_exact_group_id_is_lexically_sensitive() -> None:
    assert verify.independent_group_id(["1", "2"]) != verify.independent_group_id(
        ["1.0", "2"]
    )


def test_independent_port_examples_and_invalid_token() -> None:
    assert verify.independent_port_parse("443") == ("decimal_integer", 443)
    assert verify.independent_port_parse("0x1bb") == ("hexadecimal_integer", 443)
    assert verify.independent_port_parse("-1") == ("unresolved_sentinel", None)
    with pytest.raises(ValueError):
        verify.independent_port_parse("unknown")
