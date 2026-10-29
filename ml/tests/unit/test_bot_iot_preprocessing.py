from __future__ import annotations

import csv
from pathlib import Path

import pytest

from iotguard.data.bot_iot import (
    BotIoTParseError,
    iter_bot_iot_records,
    parse_bot_iot_port,
    parse_bot_iot_record,
)
from iotguard.data.contracts import bot_iot_source_columns

CANONICAL_SHARD = "Dataset/5%/All features/UNSW_2018_IoT_Botnet_Full5pc_1.csv"


def bot_row(*, sport: str = "80", dport: str = "0x0303") -> list[str]:
    values = {name: "value" for name in bot_iot_source_columns()}
    values.update(
        {
            "pkSeqID": "42",
            "sport": sport,
            "dport": dport,
            "attack": "1",
            "category": "DoS",
            "subcategory": "HTTP",
        }
    )
    return [values[name] for name in bot_iot_source_columns()]


@pytest.mark.parametrize(
    ("raw", "kind", "value"),
    [
        ("80", "decimal", 80),
        ("0x0303", "hex", 771),
        ("0Xffff", "hex", 65535),
        ("-1", "unresolved_sentinel", None),
    ],
)
def test_port_parser(raw: str, kind: str, value: int | None) -> None:
    assert parse_bot_iot_port(raw) == parse_bot_iot_port(raw)
    parsed = parse_bot_iot_port(raw)
    assert (parsed.raw, parsed.kind, parsed.value) == (raw, kind, value)


@pytest.mark.parametrize("raw", ["", " 80", "+80", "80.0", "0x", "-2", "65536"])
def test_invalid_port_lexeme_fails(raw: str) -> None:
    with pytest.raises(BotIoTParseError):
        parse_bot_iot_port(raw)


def test_canonical_row_separates_target_identifier_and_roles() -> None:
    record = parse_bot_iot_record(bot_row(), CANONICAL_SHARD, data_row_index=3)

    assert record.target_metadata == {
        "attack": "1",
        "category": "DoS",
        "subcategory": "HTTP",
    }
    assert record.identifier_metadata == {"pkSeqID": "42"}
    assert "pkSeqID" not in record.fields_by_role.get("behavioral_statistical_candidate", {})
    assert "attack" not in record.fields_by_role.get("behavioral_statistical_candidate", {})
    assert record.fields_by_role["entity_context_sensitive"]["sport"] == "80"
    assert record.fields_by_role["temporal_order_sensitive"]["stime"] == "value"
    assert record.ports["sport"].kind == "decimal"
    assert record.ports["dport"].value == 771
    assert record.data_row_index == 3


def test_wrong_width_fails() -> None:
    with pytest.raises(BotIoTParseError, match="Expected 46"):
        parse_bot_iot_record(bot_row()[:-1], CANONICAL_SHARD)


def test_streaming_reader_validates_exact_header(tmp_path: Path) -> None:
    path = tmp_path / "shard.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(bot_iot_source_columns())
        writer.writerow(bot_row(sport="-1", dport="443"))

    record = next(iter_bot_iot_records(path, CANONICAL_SHARD))
    assert record.data_row_index == 1
    assert record.ports["sport"].kind == "unresolved_sentinel"


def test_reordered_46_column_header_fails(tmp_path: Path) -> None:
    columns = list(bot_iot_source_columns())
    columns[0], columns[1] = columns[1], columns[0]
    path = tmp_path / "reordered.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(columns)
        writer.writerow(bot_row())

    with pytest.raises(BotIoTParseError, match="Header does not exactly match"):
        next(iter_bot_iot_records(path, CANONICAL_SHARD))


@pytest.mark.parametrize(
    "reference_path",
    [
        "Dataset/5%/10-best features/UNSW_2018_IoT_Botnet_Final_10_Best.csv",
        (
            "Dataset/5%/10-best features/10-best Training-Testing split/"
            "UNSW_2018_IoT_Botnet_Final_10_best_Training.csv"
        ),
        (
            "Dataset/5%/10-best features/10-best Training-Testing split/"
            "UNSW_2018_IoT_Botnet_Final_10_best_Testing.csv"
        ),
    ],
)
def test_reference_or_supplied_split_is_not_canonical(reference_path: str) -> None:
    with pytest.raises(BotIoTParseError, match="not one of the four canonical"):
        parse_bot_iot_record(bot_row(), reference_path)


def test_bot_record_is_deterministic() -> None:
    first = parse_bot_iot_record(bot_row(), CANONICAL_SHARD, data_row_index=1)
    second = parse_bot_iot_record(bot_row(), CANONICAL_SHARD, data_row_index=1)
    assert first == second
