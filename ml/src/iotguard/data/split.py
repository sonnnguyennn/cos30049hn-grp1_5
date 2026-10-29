"""Deterministic primary evaluation grouping and split-policy primitives for G3A."""

from __future__ import annotations

import hashlib
import math
import struct
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

EVALUATION_GROUP_SCHEME = "evaluation-group-binary64-be-v1"
EVALUATION_GROUP_PREFIX = "sha256:"
SPLIT_VERSION = "primary_split_v1"
SPLIT_NAMESPACE = "iotguard-primary-split-v1"
SPLIT_DELIMITER = b"\x1f"
SPLIT_NAMES = ("TRAIN", "VALIDATION", "TEST")
MEMBERSHIP_DIGEST_SCHEME = "sha256:length-prefixed-utf8-membership-v1"
UINT64_SPACE = 1 << 64
TRAIN_BOUNDARY = (70 * UINT64_SPACE + 99) // 100
VALIDATION_BOUNDARY = (85 * UINT64_SPACE + 99) // 100


def evaluation_group_bytes(features: Sequence[float]) -> bytes:
    """Serialize exactly 115 finite floats as canonical big-endian binary64 values."""

    if len(features) != 115:
        raise ValueError(f"Expected 115 features, found {len(features)}")
    output = bytearray()
    for value in features:
        if not math.isfinite(value):
            raise ValueError("Evaluation-group features must be finite")
        canonical = 0.0 if value == 0.0 else value
        output.extend(struct.pack(">d", canonical))
    return bytes(output)


def evaluation_group_id(features: Sequence[float]) -> str:
    """Return the split-only identity of a parsed model-visible numeric vector."""

    return EVALUATION_GROUP_PREFIX + hashlib.sha256(evaluation_group_bytes(features)).hexdigest()


def split_hash_value(group_id: str) -> int:
    """Map an evaluation-group ID to the first unsigned 64 SHA-256 bits."""

    if not group_id.startswith(EVALUATION_GROUP_PREFIX) or len(group_id) != 71:
        raise ValueError("Evaluation-group ID must be sha256:<64 lowercase hex>")
    suffix = group_id.removeprefix(EVALUATION_GROUP_PREFIX)
    if suffix != suffix.lower() or any(char not in "0123456789abcdef" for char in suffix):
        raise ValueError("Evaluation-group ID must use lowercase hexadecimal")
    payload = SPLIT_NAMESPACE.encode("utf-8") + SPLIT_DELIMITER + group_id.encode("ascii")
    return int.from_bytes(hashlib.sha256(payload).digest()[:8], "big", signed=False)


def split_for_hash_value(value: int) -> str:
    """Apply exact integer boundaries equivalent to u < .70 and u < .85."""

    if not 0 <= value < UINT64_SPACE:
        raise ValueError("Split hash value must be an unsigned 64-bit integer")
    if value < TRAIN_BOUNDARY:
        return "TRAIN"
    if value < VALIDATION_BOUNDARY:
        return "VALIDATION"
    return "TEST"


def assign_evaluation_group(group_id: str) -> str:
    """Assign a group without using labels, device, source, or row identity."""

    return split_for_hash_value(split_hash_value(group_id))


def update_membership_digest(
    digest: Any,
    source_logical_id: str,
    source_data_row_index: int,
    group_id: str,
    split_name: str,
) -> None:
    """Append one unambiguous canonical-traversal membership record."""

    if source_data_row_index < 1:
        raise ValueError("Source data-row index must be positive")
    if split_name not in SPLIT_NAMES:
        raise ValueError("Unknown split name")
    encoded_source = source_logical_id.encode("utf-8")
    digest.update(len(encoded_source).to_bytes(4, "big", signed=False))
    digest.update(encoded_source)
    digest.update(source_data_row_index.to_bytes(8, "big", signed=False))
    for value in (group_id, split_name):
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big", signed=False))
        digest.update(encoded)


def cross_label_conflicts(
    rows: Iterable[tuple[str, str, str, str]],
) -> dict[str, dict[str, set[str]]]:
    """Return evaluation groups associated with more than one label at any level."""

    labels: dict[str, dict[str, set[str]]] = {}
    for group_id, binary, family, fine in rows:
        entry = labels.setdefault(
            group_id, {"binary": set(), "family": set(), "fine": set()}
        )
        entry["binary"].add(binary)
        entry["family"].add(family)
        entry["fine"].add(fine)
    return {
        group_id: levels
        for group_id, levels in labels.items()
        if any(len(values) > 1 for values in levels.values())
    }


def class_coverage_passes(
    counts: Mapping[str, Mapping[str, Mapping[str, int]]],
    required: Mapping[str, Sequence[str]],
) -> bool:
    """Require every declared class to have positive support in every split."""

    return all(
        counts.get(split_name, {}).get(level, {}).get(label, 0) > 0
        for split_name in SPLIT_NAMES
        for level, labels in required.items()
        for label in labels
    )


def prevalence_drift_percentage_points(
    split_class_count: int,
    split_total: int,
    full_class_count: int,
    full_total: int,
) -> float:
    """Return absolute split-vs-corpus prevalence drift in percentage points."""

    if split_total <= 0 or full_total <= 0:
        raise ValueError("Prevalence totals must be positive")
    return abs(100 * split_class_count / split_total - 100 * full_class_count / full_total)


def acceptance_status(checks: Mapping[str, object]) -> str:
    """Refuse ADOPTED unless every supplied mandatory gate is exactly true."""

    if not checks or not all(value is True for value in checks.values()):
        return "REJECTED"
    return "ADOPTED"


def validate_test_seal(contract: Mapping[str, object]) -> bool:
    """Validate the policy boundary needed before an adopted test set is considered sealed."""

    return (
        contract.get("status") == "ADOPTED"
        and contract.get("test_set_status") == "SEALED"
        and contract.get("learned_transform_fit_partition") == "TRAIN"
    )
