from __future__ import annotations

import copy
import json

import numpy as np
import pytest

from iotguard.data.bot_iot_package_v2 import PortablePreprocessor, validate_inputs
from iotguard.data.bot_iot_secondary_v2 import V2Preprocessor


def fixture():
    numeric = np.arange(30, dtype=np.float64).reshape(3, 10)
    categorical = np.array([["e", "tcp", "CON"], ["e *", "udp", "INT"],
                            ["reserved_unknown:flgs", "tcp", "CON"]], dtype=object)
    reference = V2Preprocessor()
    reference.fit_chunk(numeric[:1], categorical[:1], partition="TRAIN")
    reference.fit_chunk(numeric[1:], categorical[1:], partition="TRAIN")
    state = reference.finalize()
    return reference, state, numeric, categorical


def test_train_only_moments_generic_unknown_and_no_vocab_learning():
    reference, state, numeric, cats = fixture()
    np.testing.assert_allclose(state["mean"], numeric.mean(axis=0), rtol=0, atol=0)
    np.testing.assert_allclose(state["var"], numeric.var(axis=0), rtol=1e-14)
    assert state["n_samples_seen"] == 3
    assert state["drop"] is None
    portable = PortablePreprocessor(json.loads(json.dumps(state)))
    novel = np.array([["any_new_flag_827", "arbitrary_protocol_932", "valid_new_state_753"]])
    before = copy.deepcopy(state)
    first = reference.transform(numeric[:1], novel)
    second = portable.transform(numeric[:1], novel)
    np.testing.assert_array_equal(first, second)
    assert first[:, 10:].sum() == 3
    assert state == before
    assert "arbitrary_protocol_932" not in state["vocabulary"]["proto"]
    # A source string resembling a display name remains a distinct known source category.
    known = portable.category_codes(cats)
    assert known[2, 0] != state["unknown"]["flgs"]["index"]
    np.testing.assert_array_equal(reference.transform(numeric, cats),
                                  portable.transform(numeric, cats))


@pytest.mark.parametrize("partition", ["VALIDATION", "TEST", "train"])
def test_heldout_fit_rejected(partition):
    reference = V2Preprocessor()
    with pytest.raises(ValueError, match="TRAIN"):
        reference.fit_chunk(np.ones((1, 10)), [["novel", "novel", "novel"]], partition=partition)
    assert reference.samples == 0
    assert all(not v for v in reference.vocabulary.values())


@pytest.mark.parametrize("bad", ["", " e", "e ", "NaN", "null", "NONE", None,
                                {"kind": "reserved_unknown", "field": "flgs"}])
def test_invalid_category_is_not_unknown(bad):
    _, state, numeric, _ = fixture()
    portable = PortablePreprocessor(state)
    with pytest.raises(ValueError, match="category"):
        portable.transform(numeric[:1], [[bad, "tcp", "CON"]])


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -1.0, 1.5])
def test_invalid_numeric_values(bad):
    numeric = np.ones((1, 10))
    numeric[0, 0] = bad
    with pytest.raises(ValueError):
        validate_inputs(numeric, [["e", "tcp", "CON"]])


def test_integer_precision_and_invalid_code():
    numeric = np.ones((1, 10), dtype=np.int64)
    numeric[0, 0] = 2**53+1
    with pytest.raises(ValueError, match="count"):
        validate_inputs(numeric, [["e", "tcp", "CON"]])
    _, state, nums, cats = fixture()
    portable = PortablePreprocessor(state)
    codes = portable.category_codes(cats)
    codes[0, 1] = 65535
    with pytest.raises(ValueError, match="code"):
        portable.transform_codes(nums, codes)


def test_serialized_state_tampering_and_fit_seal():
    reference, state, numeric, cats = fixture()
    with pytest.raises(ValueError):
        reference.fit_chunk(numeric, cats, partition="TRAIN")
    with pytest.raises(ValueError):
        reference.finalize()
    for key, value in (("encoded_features", ["wrong"]), ("scale", [0.0]*10)):
        broken = copy.deepcopy(state)
        broken[key] = value
        with pytest.raises(ValueError):
            PortablePreprocessor(broken)
    broken = copy.deepcopy(state)
    broken["unknown"]["flgs"] = "reserved_unknown:flgs"
    with pytest.raises(ValueError, match="UNKNOWN"):
        PortablePreprocessor(broken)
