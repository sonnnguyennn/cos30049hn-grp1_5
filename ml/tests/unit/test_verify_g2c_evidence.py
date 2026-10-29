from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "verify_g2c_evidence.py"
SPEC = importlib.util.spec_from_file_location("verify_g2c_evidence", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)


def test_independent_group_id_is_lexically_sensitive() -> None:
    assert verify.independent_group_id(["1"]) != verify.independent_group_id(["1.0"])


def test_independent_record_digest_matches_implemented_scheme() -> None:
    record = verify.parse_n_baiot_record(
        ["1"] * 115,
        "n_baiot:source:Danmini_Doorbell/benign_traffic.csv",
        data_row_index=1,
    )
    from iotguard.data.reproducibility import canonical_record_digest

    assert verify.independent_record_digest(record) == canonical_record_digest(record)
