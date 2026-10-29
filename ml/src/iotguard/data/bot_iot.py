"""Deterministic Bot-IoT canonical All-features parsing primitives."""

from __future__ import annotations

import csv
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from iotguard.data.contracts import bot_iot_source_columns, load_contract

_DECIMAL_PORT = re.compile(r"[0-9]+")
_HEX_PORT = re.compile(r"0[xX][0-9a-fA-F]+")


class BotIoTParseError(ValueError):
    """A canonical Bot-IoT parsing failure with source context."""


@dataclass(frozen=True)
class ParsedPort:
    """Lossless lexical port result; unresolved ``-1`` has no numeric value."""

    raw: str
    kind: str
    value: int | None


@dataclass(frozen=True)
class BotIoTRecord:
    """One raw canonical row separated by G2A field roles, without ML encoding."""

    source_logical_id: str
    source_shard: str
    data_row_index: int | None
    target_metadata: Mapping[str, str]
    identifier_metadata: Mapping[str, str]
    fields_by_role: Mapping[str, Mapping[str, str]]
    ports: Mapping[str, ParsedPort]


def parse_bot_iot_port(raw: str) -> ParsedPort:
    """Parse decimal, 0x-prefixed hexadecimal, or the explicit ``-1`` sentinel."""

    if raw == "-1":
        return ParsedPort(raw=raw, kind="unresolved_sentinel", value=None)
    if _DECIMAL_PORT.fullmatch(raw):
        value = int(raw, 10)
        kind = "decimal"
    elif _HEX_PORT.fullmatch(raw):
        value = int(raw, 16)
        kind = "hex"
    else:
        raise BotIoTParseError(f"Invalid Bot-IoT port lexeme: {raw!r}")
    if not 0 <= value <= 65535:
        raise BotIoTParseError(f"Bot-IoT port is outside 0..65535: {raw!r}")
    return ParsedPort(raw=raw, kind=kind, value=value)


def _canonical_source(source_relative_path: str) -> str:
    normalized = source_relative_path.replace("\\", "/")
    contract = load_contract("bot_iot_secondary_source_contract_v1.json")
    canonical_sources = contract["canonical_source_files"]
    if normalized not in canonical_sources:
        raise BotIoTParseError(
            "Bot-IoT input is not one of the four canonical All-features shards: "
            f"{source_relative_path}"
        )
    return normalized


def _field_roles() -> dict[str, str]:
    contract = load_contract("bot_iot_field_role_contract_v1.json")
    roles = {
        entry["field_name"]: entry["contract_role"] for entry in contract["field_roles"]
    }
    if tuple(roles) != bot_iot_source_columns():
        raise BotIoTParseError("Bot-IoT role contract order differs from source contract")
    return roles


def parse_bot_iot_record(
    raw_lexemes: Sequence[str],
    source_relative_path: str,
    *,
    data_row_index: int | None = None,
) -> BotIoTRecord:
    """Separate a canonical raw row into target, identifier, and unresolved role groups."""

    source_shard = _canonical_source(source_relative_path)
    columns = bot_iot_source_columns()
    if len(raw_lexemes) != len(columns):
        raise BotIoTParseError(
            f"Expected {len(columns)} Bot-IoT fields, found {len(raw_lexemes)} "
            f"(source={source_shard}, data_row={data_row_index})"
        )
    raw = dict(zip(columns, raw_lexemes, strict=True))
    ports = {name: parse_bot_iot_port(raw[name]) for name in ("sport", "dport")}
    roles = _field_roles()
    target_metadata = {
        name: raw[name] for name in columns if roles[name] == "target_metadata"
    }
    identifier_metadata = {
        name: raw[name] for name in columns if roles[name] == "identifier_lineage_metadata"
    }
    fields_by_role: dict[str, dict[str, str]] = {}
    for name in columns:
        role = roles[name]
        if role in {"target_metadata", "identifier_lineage_metadata"}:
            continue
        fields_by_role.setdefault(role, {})[name] = raw[name]
    return BotIoTRecord(
        source_logical_id=f"bot_iot:all_features_5pct_shards:{source_shard}",
        source_shard=source_shard,
        data_row_index=data_row_index,
        target_metadata=target_metadata,
        identifier_metadata=identifier_metadata,
        fields_by_role=fields_by_role,
        ports=ports,
    )


def iter_bot_iot_records(
    path: Path,
    source_relative_path: str,
) -> Iterator[BotIoTRecord]:
    """Stream exactly one canonical All-features shard without categorical encoding."""

    source_shard = _canonical_source(source_relative_path)
    expected_header = bot_iot_source_columns()
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        try:
            header = tuple(next(reader))
        except StopIteration as error:
            raise BotIoTParseError(f"Canonical Bot-IoT shard is empty: {source_shard}") from error
        if header != expected_header:
            raise BotIoTParseError(
                "Header does not exactly match the ordered 46-column Bot-IoT contract "
                f"(source={source_shard})"
            )
        for data_row_index, row in enumerate(reader, start=1):
            yield parse_bot_iot_record(
                row,
                source_shard,
                data_row_index=data_row_index,
            )
