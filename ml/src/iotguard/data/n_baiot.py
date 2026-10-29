"""Strict streaming parser for canonical N-BaIoT logical CSV records."""

from __future__ import annotations

import csv
import hashlib
import math
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from iotguard.data.contracts import PROJECT_ROOT, load_contract, n_baiot_feature_names

DEFAULT_LABEL_MAPPING = PROJECT_ROOT / "artifacts" / "audit" / "n_baiot_label_mapping.csv"


class NBaiotParseError(ValueError):
    """A strict parsing failure with reproducible source location context."""

    def __init__(
        self,
        message: str,
        *,
        source_logical_id: str,
        data_row_index: int | None = None,
        field_name: str | None = None,
    ) -> None:
        details = [f"source={source_logical_id}"]
        if data_row_index is not None:
            details.append(f"data_row={data_row_index}")
        if field_name is not None:
            details.append(f"field={field_name}")
        super().__init__(f"{message} ({', '.join(details)})")
        self.source_logical_id = source_logical_id
        self.data_row_index = data_row_index
        self.field_name = field_name


@dataclass(frozen=True)
class NBaiotProvenance:
    """Verified A3 labels and source lineage for one logical CSV."""

    target_binary: str
    label_family: str
    label_fine: str
    device: str
    source_logical_id: str
    archive_or_source_family: str
    source_member_filename: str


@dataclass(frozen=True)
class NBaiotRecord:
    """Canonical G2A-compatible record; only ``features`` are predictors."""

    features: tuple[float, ...]
    target_binary: str
    label_family: str
    label_fine: str
    device: str
    source_logical_id: str
    archive_or_source_family: str
    source_member_filename: str
    duplicate_group_id: str
    data_row_index: int | None = None


@cache
def _load_label_mapping(mapping_path: Path) -> dict[str, NBaiotProvenance]:
    resolved = mapping_path.resolve()
    try:
        with resolved.open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
    except OSError as error:
        raise ValueError(f"Unable to load verified N-BaIoT label mapping: {resolved}") from error

    label_contract = load_contract("n_baiot_label_contract_v1.json")
    levels = label_contract["levels"]
    mapping: dict[str, NBaiotProvenance] = {}
    for row in rows:
        logical_id = row.get("logical_id", "")
        if not logical_id or logical_id in mapping:
            raise ValueError("Verified N-BaIoT label mapping contains a missing/duplicate ID")
        source_kind = row.get("source_kind", "")
        raw_family = row.get("raw_family_hint", "")
        member = row.get("raw_member_name", "")
        if source_kind == "immutable_benign_source":
            source_family = "benign"
        elif source_kind == "derived_extracted_attack" and raw_family in {
            "gafgyt_attacks",
            "mirai_attacks",
        }:
            source_family = raw_family
        else:
            raise ValueError(f"Invalid verified provenance entry: {logical_id}")
        provenance = NBaiotProvenance(
            target_binary=row.get("canonical_binary", ""),
            label_family=row.get("canonical_family", ""),
            label_fine=row.get("canonical_fine_class", ""),
            device=row.get("device", ""),
            source_logical_id=logical_id,
            archive_or_source_family=source_family,
            source_member_filename=member,
        )
        if (
            provenance.target_binary not in levels["binary"]
            or provenance.label_family not in levels["family"]
            or provenance.label_fine not in levels["fine"]
            or not provenance.device
            or not provenance.source_member_filename
        ):
            raise ValueError(f"Label mapping conflicts with v1 taxonomy: {logical_id}")
        mapping[logical_id] = provenance
    if len(mapping) != 89:
        raise ValueError(f"Expected 89 verified logical sources, found {len(mapping)}")
    return mapping


def map_n_baiot_provenance(
    source_logical_id: str,
    *,
    mapping_path: Path = DEFAULT_LABEL_MAPPING,
) -> NBaiotProvenance:
    """Map only an exact, A3-verified logical source ID; never infer substrings."""

    try:
        return _load_label_mapping(mapping_path)[source_logical_id]
    except KeyError as error:
        raise NBaiotParseError(
            "Unknown or ambiguous N-BaIoT provenance",
            source_logical_id=source_logical_id,
        ) from error


def duplicate_group_id(raw_lexemes: Sequence[str]) -> str:
    """Hash the exact ordered source tokens using the G2A length-prefix encoding."""

    expected_width = len(n_baiot_feature_names())
    if len(raw_lexemes) != expected_width:
        raise ValueError(f"Expected {expected_width} raw lexemes, found {len(raw_lexemes)}")
    digest = hashlib.sha256()
    for lexeme in raw_lexemes:
        if not isinstance(lexeme, str):
            raise TypeError("Exact-vector source lexemes must be strings")
        encoded = lexeme.encode("utf-8")
        if len(encoded) > 0xFFFFFFFF:
            raise ValueError("Source lexeme exceeds unsigned four-byte length encoding")
        digest.update(len(encoded).to_bytes(4, byteorder="big", signed=False))
        digest.update(encoded)
    return f"sha256:{digest.hexdigest()}"


def parse_n_baiot_record(
    raw_lexemes: Sequence[str],
    source_logical_id: str,
    *,
    data_row_index: int | None = None,
) -> NBaiotRecord:
    """Compute exact identity first, then strictly parse one 115-value row."""

    feature_names = n_baiot_feature_names()
    if len(raw_lexemes) != len(feature_names):
        raise NBaiotParseError(
            f"Expected {len(feature_names)} fields, found {len(raw_lexemes)}",
            source_logical_id=source_logical_id,
            data_row_index=data_row_index,
        )
    provenance = map_n_baiot_provenance(source_logical_id)
    group_id = duplicate_group_id(raw_lexemes)
    numeric_values: list[float] = []
    for field_name, lexeme in zip(feature_names, raw_lexemes, strict=True):
        try:
            value = float(lexeme)
        except (TypeError, ValueError) as error:
            raise NBaiotParseError(
                "Numeric parse failed",
                source_logical_id=source_logical_id,
                data_row_index=data_row_index,
                field_name=field_name,
            ) from error
        if not math.isfinite(value):
            raise NBaiotParseError(
                "Non-finite numeric value is prohibited",
                source_logical_id=source_logical_id,
                data_row_index=data_row_index,
                field_name=field_name,
            )
        numeric_values.append(value)
    return NBaiotRecord(
        features=tuple(numeric_values),
        target_binary=provenance.target_binary,
        label_family=provenance.label_family,
        label_fine=provenance.label_fine,
        device=provenance.device,
        source_logical_id=provenance.source_logical_id,
        archive_or_source_family=provenance.archive_or_source_family,
        source_member_filename=provenance.source_member_filename,
        duplicate_group_id=group_id,
        data_row_index=data_row_index,
    )


def iter_n_baiot_records(path: Path, source_logical_id: str) -> Iterator[NBaiotRecord]:
    """Stream a logical CSV and fail immediately on any schema or row violation."""

    expected_header = n_baiot_feature_names()
    map_n_baiot_provenance(source_logical_id)
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        try:
            header = tuple(next(reader))
        except StopIteration as error:
            raise NBaiotParseError(
                "Logical CSV is empty",
                source_logical_id=source_logical_id,
            ) from error
        if header != expected_header:
            raise NBaiotParseError(
                "Header does not exactly match the ordered v1 feature contract",
                source_logical_id=source_logical_id,
            )
        for data_row_index, row in enumerate(reader, start=1):
            yield parse_n_baiot_record(
                row,
                source_logical_id,
                data_row_index=data_row_index,
            )


def feature_array(record: NBaiotRecord) -> tuple[float, ...]:
    """Return the unscaled ordered vector using runtime Python floats.

    Python ``float`` is parsing behavior only, not a final storage/deployment dtype decision.
    """

    expected_width = len(n_baiot_feature_names())
    if len(record.features) != expected_width or not all(
        math.isfinite(value) for value in record.features
    ):
        raise ValueError(f"Canonical feature vector must contain {expected_width} finite values")
    return record.features
