"""Stable source identity and canonical-record digest primitives for G2C."""

from __future__ import annotations

import hashlib
import math
import struct
from collections.abc import Iterable, Mapping

from iotguard.data.n_baiot import NBaiotRecord, feature_array

RECORD_DIGEST_SCHEME = "sha256:canonical-record-v1"
ROW_IDENTITY_SCHEME = "source-logical-id-plus-1-based-data-row-v1"
_DIGEST_DOMAIN = b"IOTGUARD\x00CANONICAL_RECORD\x00V1"
G2_CLOSURE_CHECKS = (
    "g1_role_decision_complete",
    "g2a_contracts_committed",
    "g2b_parser_implementation_committed",
    "primary_feature_contract_locked",
    "primary_label_contract_locked",
    "secondary_source_contract_locked",
    "stable_source_row_identity_defined",
    "canonical_traversal_defined",
    "primary_full_dry_validation_passed",
    "primary_row_counts_reconciled",
    "primary_label_counts_reconciled",
    "exact_group_semantics_reconciled_with_a4_a5",
    "secondary_four_shard_headers_validated",
    "secondary_port_parser_real_examples_validated",
    "learned_transform_boundary_documented",
    "no_pre_split_fit",
    "no_full_processed_dataset",
    "no_final_split",
    "no_model_training",
    "reproducibility_manifest_created",
    "source_data_immutable",
)


def source_observation_identity(record: NBaiotRecord) -> tuple[str, int]:
    """Return stable physical-row identity: logical source plus 1-based data row."""

    if not record.source_logical_id:
        raise ValueError("Source logical ID is required")
    if record.data_row_index is None or record.data_row_index < 1:
        raise ValueError("Source data-row index must be 1-based")
    return record.source_logical_id, record.data_row_index


def _update_text(digest: AnyHash, value: str) -> None:
    encoded = value.encode("utf-8")
    digest.update(len(encoded).to_bytes(4, "big", signed=False))
    digest.update(encoded)


class AnyHash:
    """Small structural type used only for hashlib-compatible update calls."""

    def update(self, data: bytes) -> None:  # pragma: no cover - structural declaration
        raise NotImplementedError


def canonical_record_digest(record: NBaiotRecord) -> str:
    """Digest canonical identity, labels, lineage, parsed vector, and exact-group ID."""

    logical_id, data_row_index = source_observation_identity(record)
    features = feature_array(record)
    digest = hashlib.sha256()
    digest.update(_DIGEST_DOMAIN)
    for value in (
        logical_id,
        record.target_binary,
        record.label_family,
        record.label_fine,
        record.device,
        record.archive_or_source_family,
        record.source_member_filename,
    ):
        _update_text(digest, value)
    digest.update(data_row_index.to_bytes(8, "big", signed=False))
    digest.update(len(features).to_bytes(4, "big", signed=False))
    for value in features:
        if not math.isfinite(value):
            raise ValueError("Canonical digest cannot encode a non-finite feature")
        digest.update(struct.pack(">d", value))
    _update_text(digest, record.duplicate_group_id)
    return f"{RECORD_DIGEST_SCHEME}:{digest.hexdigest()}"


def deterministic_traversal_rows(
    rows: Iterable[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Sort verified logical sources by exact logical ID and assign 1-based ordinals."""

    copied = [dict(row) for row in rows]
    copied.sort(key=lambda row: str(row["logical_id"]))
    logical_ids = [str(row["logical_id"]) for row in copied]
    if len(logical_ids) != len(set(logical_ids)):
        raise ValueError("Traversal inputs contain duplicate logical IDs")
    return [
        {"traversal_ordinal": ordinal, **row}
        for ordinal, row in enumerate(copied, start=1)
    ]


def traversal_expected_row_count(rows: Iterable[Mapping[str, object]]) -> int:
    """Sum expected source rows without observing source data."""

    return sum(int(row["expected_row_count"]) for row in rows)


def g2_closure_status(checks: Mapping[str, object]) -> str:
    """Close G2 only when every named mandatory check exists and is exactly true."""

    if set(checks) != set(G2_CLOSURE_CHECKS):
        return "OPEN"
    return "COMPLETE" if all(checks[name] is True for name in G2_CLOSURE_CHECKS) else "OPEN"
