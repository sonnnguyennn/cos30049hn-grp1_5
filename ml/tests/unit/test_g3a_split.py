from __future__ import annotations

import hashlib

import pytest

from iotguard.data.split import (
    TRAIN_BOUNDARY,
    VALIDATION_BOUNDARY,
    acceptance_status,
    assign_evaluation_group,
    class_coverage_passes,
    cross_label_conflicts,
    evaluation_group_bytes,
    evaluation_group_id,
    prevalence_drift_percentage_points,
    split_for_hash_value,
    split_hash_value,
    update_membership_digest,
    validate_test_seal,
)


def vector(first: float = 0.0) -> tuple[float, ...]:
    return (first,) + (0.0,) * 114


def test_binary64_serialization_and_signed_zero_canonicalization() -> None:
    assert len(evaluation_group_bytes(vector(1.0))) == 115 * 8
    assert evaluation_group_bytes(vector(-0.0)) == evaluation_group_bytes(vector(0.0))
    assert evaluation_group_id(vector(-0.0)) == evaluation_group_id(vector(0.0))


def test_numeric_lexical_equivalents_and_feature_change() -> None:
    equivalents = [vector(float(text)) for text in ("1", "1.0", "1e0")]
    assert len({evaluation_group_id(item) for item in equivalents}) == 1
    assert evaluation_group_id(vector(1.0)) != evaluation_group_id(vector(1.0000000000000002))


def test_split_is_deterministic_and_uses_only_group_id() -> None:
    group_id = evaluation_group_id(vector(3.5))
    assert assign_evaluation_group(group_id) == assign_evaluation_group(group_id)
    assert split_hash_value(group_id) == split_hash_value(group_id)
    contexts = (
        {"label": "benign", "device": "a", "source": "x"},
        {"label": "malicious", "device": "b", "source": "y"},
    )
    assert contexts[0] != contexts[1]
    assert len({assign_evaluation_group(group_id) for _ in contexts}) == 1


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (TRAIN_BOUNDARY - 1, "TRAIN"),
        (TRAIN_BOUNDARY, "VALIDATION"),
        (VALIDATION_BOUNDARY - 1, "VALIDATION"),
        (VALIDATION_BOUNDARY, "TEST"),
        ((1 << 64) - 1, "TEST"),
    ],
)
def test_exact_threshold_boundaries(value: int, expected: str) -> None:
    assert split_for_hash_value(value) == expected


def test_cross_label_conflict_detector() -> None:
    conflicts = cross_label_conflicts(
        [
            ("g", "benign", "benign", "benign"),
            ("g", "malicious", "gafgyt", "gafgyt_udp"),
            ("h", "malicious", "mirai", "mirai_ack"),
        ]
    )
    assert set(conflicts) == {"g"}
    assert conflicts["g"]["binary"] == {"benign", "malicious"}


def test_class_coverage_and_drift_checks() -> None:
    required = {"fine": ("benign", "attack")}
    counts = {
        split: {"fine": {"benign": 2, "attack": 1}}
        for split in ("TRAIN", "VALIDATION", "TEST")
    }
    assert class_coverage_passes(counts, required)
    counts["TEST"]["fine"]["attack"] = 0
    assert not class_coverage_passes(counts, required)
    assert prevalence_drift_percentage_points(25, 100, 20, 100) == 5.0


def test_failed_gate_refuses_adoption_and_seal_requires_train_only_fit() -> None:
    assert acceptance_status({"fractions": True, "overlap": False}) == "REJECTED"
    contract = {
        "status": "ADOPTED",
        "test_set_status": "SEALED",
        "learned_transform_fit_partition": "TRAIN",
    }
    assert validate_test_seal(contract)
    assert not validate_test_seal({**contract, "learned_transform_fit_partition": "ALL"})


def test_membership_digest_is_deterministic_and_coordinate_sensitive() -> None:
    def calculate(row_index: int) -> str:
        digest = hashlib.sha256()
        update_membership_digest(
            digest,
            "n_baiot:source:device/benign_traffic.csv",
            row_index,
            evaluation_group_id(vector(2.0)),
            "TRAIN",
        )
        return digest.hexdigest()

    assert calculate(1) == calculate(1)
    assert calculate(1) != calculate(2)
