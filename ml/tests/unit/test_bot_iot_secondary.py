from __future__ import annotations

import numpy as np
import pytest

from iotguard.data.bot_iot import BotIoTParseError, parse_bot_iot_record
from iotguard.data.bot_iot_secondary import (
    CATEGORICAL,
    NUMERIC,
    PREDICTORS,
    SecondaryPreprocessor,
    assemble_secondary,
    feature_frame,
)
from iotguard.data.contracts import bot_iot_source_columns, load_contract

SOURCE = "Dataset/5%/All features/UNSW_2018_IoT_Botnet_Full5pc_1.csv"


def row(**updates):
    values = dict.fromkeys(bot_iot_source_columns(), "1")
    values.update(flgs="e *", proto="tcp", state="CON", sport="-1", dport="0x0303",
                  category="DDoS", subcategory="TCP", pkSeqID="42")
    values.update(updates)
    return assemble_secondary(parse_bot_iot_record(
        [values[k] for k in bot_iot_source_columns()], SOURCE, data_row_index=1))


def test_boundaries_ports_order_and_dtype():
    r = row()
    frame = feature_frame([r])
    assert tuple(frame.columns) == PREDICTORS
    assert all(frame[n].dtype == np.float64 for n in NUMERIC)
    assert set(PREDICTORS).isdisjoint({"attack", "category", "subcategory", "pkSeqID",
                                     "sport", "dport", "seq", "stime", "saddr"})
    assert r.metadata["ports"]["sport"]["value"] is None
    assert r.metadata["ports"]["dport"]["value"] == 771
    assert r.target == 1
    assert row(attack="0", category="Normal", subcategory="Normal").target == 0


@pytest.mark.parametrize("name", NUMERIC)
@pytest.mark.parametrize("value", ["", "NaN", "inf", "-1", "broken"])
def test_invalid_numeric_rejected(name, value):
    with pytest.raises(BotIoTParseError):
        row(**{name: value})


@pytest.mark.parametrize("name", CATEGORICAL)
@pytest.mark.parametrize("value", ["", " tcp", "None"])
def test_invalid_category_rejected(name, value):
    with pytest.raises(BotIoTParseError):
        row(**{name: value})


def test_counts_labels_and_ports_fail_closed():
    for changes in ({"pkts": "1.5"}, {"pkts": str(2**53 + 1)},
                    {"pkts": "1.00000000000000001"}, {"attack": "2"},
                    {"sport": "65536"}, {"dport": "-2"}):
        with pytest.raises(BotIoTParseError):
            row(**changes)


def test_equivalence_uses_effective_fields_without_targets_or_context():
    baseline = row(dur="1.0", rate="-0.0")
    equivalent = row(dur="1", rate="0", pkSeqID="999", seq="77", attack="0",
                     category="Normal", saddr="other", sport="0x50", dport="-1")
    assert baseline.equivalence_sha256 == equivalent.equivalence_sha256
    assert baseline.equivalence_sha256 != row(dur="2", rate="0").equivalence_sha256


def test_preprocessing_fit_only_train_transform_without_learning():
    train = feature_frame([row(pkts="1"), row(pkts="3")])
    held = feature_frame([row(pkts="101")])
    p = SecondaryPreprocessor()
    with pytest.raises(ValueError, match="TRAIN"):
        p.fit(held, partition="VALIDATION")
    p.fit(train, partition="TRAIN")
    means = p.transformer.named_transformers_["numeric"].mean_.copy()
    first = p.transform(held)
    second = p.transform(held)
    np.testing.assert_array_equal(first, second)
    np.testing.assert_array_equal(means, p.transformer.named_transformers_["numeric"].mean_)
    assert means[0] == 2
    with pytest.raises(ValueError, match="Fit once"):
        p.fit(held, partition="TRAIN")
    with pytest.raises(ValueError, match="Feature order"):
        p.transform(held[list(reversed(PREDICTORS))])
    with pytest.raises(ValueError, match="unknown categories"):
        p.transform(feature_frame([row(proto="unseen")]))


def test_candidate_contract_matches_implementation_and_covers_every_source_field():
    contract = load_contract("bot_iot_secondary_ml_candidate_v1.json")
    assert contract["status"] == "PROPOSED_FOR_REVIEW"
    assert contract["ready_for_training"] is False
    assert tuple(contract["ordered_predictors"]) == PREDICTORS
    assert tuple(contract["numeric_predictors"]) == NUMERIC
    assert tuple(contract["categorical_predictors"]) == CATEGORICAL
    fields = [name for group in contract["field_decisions"] for name in group["fields"]]
    assert len(fields) == len(set(fields)) == 46
    assert set(fields) == set(bot_iot_source_columns())
