from __future__ import annotations

import csv
from pathlib import Path

import pytest

from iotguard.data.contracts import n_baiot_feature_names
from iotguard.data.n_baiot import (
    NBaiotParseError,
    duplicate_group_id,
    feature_array,
    iter_n_baiot_records,
    map_n_baiot_provenance,
    parse_n_baiot_record,
)

BENIGN_ID = "n_baiot:source:Danmini_Doorbell/benign_traffic.csv"


def raw_row(value: str = "1") -> list[str]:
    return [value] * 115


def write_logical_csv(path: Path, header: tuple[str, ...], row: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(header)
        writer.writerow(row)


def test_valid_strict_row_preserves_order_and_excludes_metadata() -> None:
    lexemes = [str(index) for index in range(115)]
    record = parse_n_baiot_record(lexemes, BENIGN_ID, data_row_index=7)

    assert feature_array(record) == tuple(float(index) for index in range(115))
    assert len(feature_array(record)) == 115
    assert record.target_binary == "benign"
    assert record.label_family == "benign"
    assert record.label_fine == "benign"
    assert record.device == "Danmini_Doorbell"
    assert record.source_logical_id not in record.features
    assert record.data_row_index == 7


@pytest.mark.parametrize("width", [114, 116])
def test_wrong_field_count_fails(width: int) -> None:
    with pytest.raises(NBaiotParseError, match=f"Expected 115 fields, found {width}"):
        parse_n_baiot_record(["1"] * width, BENIGN_ID)


@pytest.mark.parametrize("bad_value", ["", "not-a-number", "NaN", "+Inf", "-Inf"])
def test_invalid_or_nonfinite_values_fail_with_field_context(bad_value: str) -> None:
    lexemes = raw_row()
    lexemes[3] = bad_value
    with pytest.raises(NBaiotParseError, match="MI_dir_L3_weight"):
        parse_n_baiot_record(lexemes, BENIGN_ID, data_row_index=2)


def test_negative_finite_value_is_accepted_without_clipping() -> None:
    lexemes = raw_row()
    lexemes[35] = "-123.5"
    record = parse_n_baiot_record(lexemes, BENIGN_ID)
    assert record.features[35] == -123.5


def test_reordered_header_fails(tmp_path: Path) -> None:
    header = list(n_baiot_feature_names())
    header[0], header[1] = header[1], header[0]
    path = tmp_path / "reordered.csv"
    write_logical_csv(path, tuple(header), raw_row())

    with pytest.raises(NBaiotParseError, match="Header does not exactly match"):
        next(iter_n_baiot_records(path, BENIGN_ID))


def test_streaming_iterator_yields_location_and_exact_width(tmp_path: Path) -> None:
    path = tmp_path / "benign.csv"
    write_logical_csv(path, n_baiot_feature_names(), raw_row("1.0"))

    record = next(iter_n_baiot_records(path, BENIGN_ID))
    assert record.data_row_index == 1
    assert len(record.features) == 115


@pytest.mark.parametrize(
    ("logical_id", "binary", "family", "fine"),
    [
        (BENIGN_ID, "benign", "benign", "benign"),
        *[
            (
                f"n_baiot:extracted:Danmini_Doorbell/gafgyt_attacks/{member}.csv",
                "malicious",
                "gafgyt",
                f"gafgyt_{member}",
            )
            for member in ("combo", "junk", "scan", "tcp", "udp")
        ],
        *[
            (
                f"n_baiot:extracted:Danmini_Doorbell/mirai_attacks/{member}.csv",
                "malicious",
                "mirai",
                f"mirai_{member}",
            )
            for member in ("ack", "scan", "syn", "udp", "udpplain")
        ],
    ],
)
def test_every_verified_fine_mapping(
    logical_id: str,
    binary: str,
    family: str,
    fine: str,
) -> None:
    provenance = map_n_baiot_provenance(logical_id)
    assert (provenance.target_binary, provenance.label_family, provenance.label_fine) == (
        binary,
        family,
        fine,
    )


@pytest.mark.parametrize(
    "logical_id",
    [
        "n_baiot:extracted:Danmini_Doorbell/gafgyt_attacks/ack.csv",
        "n_baiot:extracted:Danmini_Doorbell/mirai_attacks/combo.csv",
        "n_baiot:extracted:Unknown_Device/gafgyt_attacks/combo.csv",
        "n_baiot:source:Danmini_Doorbell/not_benign.csv",
        "gafgyt/combo.csv",
    ],
)
def test_unknown_or_impossible_provenance_fails(logical_id: str) -> None:
    with pytest.raises(NBaiotParseError, match="Unknown or ambiguous"):
        map_n_baiot_provenance(logical_id)


def test_duplicate_group_id_matches_independent_known_vector() -> None:
    assert duplicate_group_id(raw_row("1")) == (
        "sha256:76479386ed7f8818f10e629436b483ec51243e52f8287b0f767295395f718ddd"
    )


def test_lexical_numeric_spelling_changes_group_but_not_numeric_vector() -> None:
    records = [parse_n_baiot_record(raw_row(value), BENIGN_ID) for value in ("1", "1.0", "1e0")]
    assert len({record.duplicate_group_id for record in records}) == 3
    assert records[0].features == records[1].features == records[2].features


def test_processing_is_deterministic() -> None:
    first = parse_n_baiot_record(raw_row("1.25"), BENIGN_ID, data_row_index=1)
    second = parse_n_baiot_record(raw_row("1.25"), BENIGN_ID, data_row_index=1)
    assert first == second
