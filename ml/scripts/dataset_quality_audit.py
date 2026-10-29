"""Run the A4 quality, duplicate, and Bot-IoT lineage audit."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import sqlite3
import sys
import time
import zlib
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, getcontext
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = PROJECT_ROOT / "artifacts" / "audit"
DEFAULT_TEMP_DIR = Path(r"E:\Document\iotguard_dataset_work\a4_fingerprints")
N_TOTAL = 7_062_606
BOT_TOTAL = 3_668_522
LABEL_FIELDS = ("attack", "category", "subcategory")
NULL_TOKEN_CASEFOLDS = {"na", "n/a", "null", "none"}
POSITIVE_INF_CASEFOLDS = {"inf", "+inf", "infinity", "+infinity"}
NEGATIVE_INF_CASEFOLDS = {"-inf", "-infinity"}
LINEAGE_FIELDS = (
    "pkSeqID",
    "proto",
    "saddr",
    "sport",
    "daddr",
    "dport",
    "seq",
    "stddev",
    "N_IN_Conn_P_SrcIP",
    "min",
    "state_number",
    "mean",
    "N_IN_Conn_P_DstIP",
    "drate",
    "srate",
    "max",
    "attack",
    "category",
    "subcategory",
)
LINEAGE_STRING_FIELDS = {
    "proto",
    "saddr",
    "sport",
    "daddr",
    "dport",
    "category",
    "subcategory",
}
LINEAGE_NUMERIC_FIELDS = tuple(
    field_name
    for field_name in LINEAGE_FIELDS
    if field_name != "pkSeqID" and field_name not in LINEAGE_STRING_FIELDS
)
BOT_STRING_COLUMNS = {"flgs", "proto", "saddr", "daddr", "state", "category", "subcategory"}
QUALITY_FIELDS = [
    "record_type",
    "representation",
    "logical_id",
    "column_name",
    "column_display_name",
    "observed_role",
    "total_values",
    "row_count",
    "empty_field_count",
    "explicit_null_token_count",
    "explicit_null_tokens_json",
    "nan_count",
    "nan_tokens_json",
    "positive_inf_count",
    "negative_inf_count",
    "inf_tokens_json",
    "numeric_parse_failure_count",
    "parse_failure_examples_json",
    "finite_count",
    "min_finite",
    "max_finite",
    "negative_value_count",
    "zero_value_count",
    "outer_whitespace_count",
    "missing_any_count",
    "nonfinite_any_count",
    "parse_failure_any_count",
    "read_error_count",
]
EXAMPLE_FIELDS = [
    "dataset",
    "representation",
    "scope",
    "finding_type",
    "exact_group_sha256",
    "first_logical_id",
    "first_source_root_kind",
    "first_source_relative_path",
    "first_data_row",
    "first_binary",
    "first_family",
    "first_fine_label",
    "first_attack",
    "first_category",
    "first_subcategory",
    "second_logical_id",
    "second_source_root_kind",
    "second_source_relative_path",
    "second_data_row",
    "second_binary",
    "second_family",
    "second_fine_label",
    "second_attack",
    "second_category",
    "second_subcategory",
]


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv_atomic(path: Path, fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def percentage(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return ""
    getcontext().prec = 28
    return format(Decimal(numerator) * Decimal(100) / Decimal(denominator), "f")


def compact_counter(counter: Counter[str]) -> str:
    return json.dumps(dict(sorted(counter.items())), ensure_ascii=False, separators=(",", ":"))


@dataclass
class ColumnStats:
    numeric_candidate: bool
    total_values: int = 0
    empty_field_count: int = 0
    explicit_null_token_count: int = 0
    nan_count: int = 0
    positive_inf_count: int = 0
    negative_inf_count: int = 0
    numeric_parse_failure_count: int = 0
    finite_count: int = 0
    min_finite: float | None = None
    max_finite: float | None = None
    negative_value_count: int = 0
    zero_value_count: int = 0
    outer_whitespace_count: int = 0
    explicit_null_tokens: Counter[str] = field(default_factory=Counter)
    nan_tokens: Counter[str] = field(default_factory=Counter)
    inf_tokens: Counter[str] = field(default_factory=Counter)
    parse_failure_examples: Counter[str] = field(default_factory=Counter)

    def merge(self, other: ColumnStats) -> None:
        for attribute in (
            "total_values",
            "empty_field_count",
            "explicit_null_token_count",
            "nan_count",
            "positive_inf_count",
            "negative_inf_count",
            "numeric_parse_failure_count",
            "finite_count",
            "negative_value_count",
            "zero_value_count",
            "outer_whitespace_count",
        ):
            setattr(self, attribute, getattr(self, attribute) + getattr(other, attribute))
        if other.min_finite is not None:
            self.min_finite = (
                other.min_finite
                if self.min_finite is None
                else min(self.min_finite, other.min_finite)
            )
        if other.max_finite is not None:
            self.max_finite = (
                other.max_finite
                if self.max_finite is None
                else max(self.max_finite, other.max_finite)
            )
        self.explicit_null_tokens.update(other.explicit_null_tokens)
        self.nan_tokens.update(other.nan_tokens)
        self.inf_tokens.update(other.inf_tokens)
        for token, count in other.parse_failure_examples.items():
            if token in self.parse_failure_examples or len(self.parse_failure_examples) < 10:
                self.parse_failure_examples[token] += count


@dataclass
class FileQuality:
    row_count: int = 0
    missing_any_count: int = 0
    nonfinite_any_count: int = 0
    parse_failure_any_count: int = 0
    read_error_count: int = 0


def new_column_stats(columns: list[str], numeric_columns: set[str]) -> dict[str, ColumnStats]:
    return {
        column: ColumnStats(numeric_candidate=column in numeric_columns) for column in columns
    }


def update_quality(
    frame: pd.DataFrame,
    stats: dict[str, ColumnStats],
    file_quality: FileQuality,
) -> None:
    row_count = len(frame)
    missing_any = np.zeros(row_count, dtype=bool)
    nonfinite_any = np.zeros(row_count, dtype=bool)
    parse_failure_any = np.zeros(row_count, dtype=bool)
    for column in frame.columns:
        values = frame[column].astype(str)
        folded = values.str.casefold()
        empty = values.eq("").to_numpy()
        null_token = folded.isin(NULL_TOKEN_CASEFOLDS).to_numpy()
        nan_token = folded.eq("nan").to_numpy()
        positive_inf = folded.isin(POSITIVE_INF_CASEFOLDS).to_numpy()
        negative_inf = folded.isin(NEGATIVE_INF_CASEFOLDS).to_numpy()
        outer_whitespace = values.ne(values.str.strip()).to_numpy()
        column_stats = stats[column]
        column_stats.total_values += row_count
        column_stats.empty_field_count += int(empty.sum())
        column_stats.explicit_null_token_count += int(null_token.sum())
        column_stats.nan_count += int(nan_token.sum())
        column_stats.positive_inf_count += int(positive_inf.sum())
        column_stats.negative_inf_count += int(negative_inf.sum())
        column_stats.outer_whitespace_count += int(outer_whitespace.sum())
        for mask, counter in (
            (null_token, column_stats.explicit_null_tokens),
            (nan_token, column_stats.nan_tokens),
            (positive_inf | negative_inf, column_stats.inf_tokens),
        ):
            if mask.any():
                counter.update(
                    {
                        str(value): int(count)
                        for value, count in values[mask].value_counts(sort=False).items()
                    }
                )
        missing = empty | null_token | nan_token
        nonfinite = nan_token | positive_inf | negative_inf
        missing_any |= missing
        nonfinite_any |= nonfinite
        if not column_stats.numeric_candidate:
            continue
        eligible = ~(missing | nonfinite)
        numeric = pd.to_numeric(values.where(eligible), errors="coerce")
        parse_failure = eligible & numeric.isna().to_numpy()
        parse_failure_any |= parse_failure
        column_stats.numeric_parse_failure_count += int(parse_failure.sum())
        if parse_failure.any():
            failed = values[parse_failure]
            for token, count in failed.value_counts(sort=False).items():
                token_text = str(token)
                if (
                    token_text in column_stats.parse_failure_examples
                    or len(column_stats.parse_failure_examples) < 10
                ):
                    column_stats.parse_failure_examples[token_text] += int(count)
        numeric_values = numeric.to_numpy(dtype=np.float64, na_value=np.nan)
        finite = eligible & ~parse_failure & np.isfinite(numeric_values)
        finite_values = numeric_values[finite]
        column_stats.finite_count += int(finite.sum())
        if finite_values.size:
            observed_min = float(finite_values.min())
            observed_max = float(finite_values.max())
            column_stats.min_finite = (
                observed_min
                if column_stats.min_finite is None
                else min(column_stats.min_finite, observed_min)
            )
            column_stats.max_finite = (
                observed_max
                if column_stats.max_finite is None
                else max(column_stats.max_finite, observed_max)
            )
            column_stats.negative_value_count += int((finite_values < 0).sum())
            column_stats.zero_value_count += int((finite_values == 0).sum())
    file_quality.row_count += row_count
    file_quality.missing_any_count += int(missing_any.sum())
    file_quality.nonfinite_any_count += int(nonfinite_any.sum())
    file_quality.parse_failure_any_count += int(parse_failure_any.sum())


def finite_text(value: float | None) -> str:
    if value is None:
        return ""
    return format(value, ".17g")


def quality_column_row(
    *,
    record_type: str,
    representation: str,
    logical_id: str,
    column: str,
    stats: ColumnStats,
) -> dict[str, Any]:
    return {
        "record_type": record_type,
        "representation": representation,
        "logical_id": logical_id,
        "column_name": column,
        "column_display_name": "<UNNAMED_LEADING>" if column == "" else column,
        "observed_role": "numeric_candidate" if stats.numeric_candidate else "string_like",
        "total_values": stats.total_values,
        "row_count": "",
        "empty_field_count": stats.empty_field_count,
        "explicit_null_token_count": stats.explicit_null_token_count,
        "explicit_null_tokens_json": compact_counter(stats.explicit_null_tokens),
        "nan_count": stats.nan_count,
        "nan_tokens_json": compact_counter(stats.nan_tokens),
        "positive_inf_count": stats.positive_inf_count,
        "negative_inf_count": stats.negative_inf_count,
        "inf_tokens_json": compact_counter(stats.inf_tokens),
        "numeric_parse_failure_count": (
            stats.numeric_parse_failure_count if stats.numeric_candidate else ""
        ),
        "parse_failure_examples_json": compact_counter(stats.parse_failure_examples),
        "finite_count": stats.finite_count if stats.numeric_candidate else "",
        "min_finite": finite_text(stats.min_finite),
        "max_finite": finite_text(stats.max_finite),
        "negative_value_count": (
            stats.negative_value_count if stats.numeric_candidate else ""
        ),
        "zero_value_count": stats.zero_value_count if stats.numeric_candidate else "",
        "outer_whitespace_count": stats.outer_whitespace_count,
        "missing_any_count": "",
        "nonfinite_any_count": "",
        "parse_failure_any_count": "",
        "read_error_count": "",
    }


def quality_file_row(
    representation: str, logical_id: str, quality: FileQuality
) -> dict[str, Any]:
    row = {field_name: "" for field_name in QUALITY_FIELDS}
    row.update(
        {
            "record_type": "file",
            "representation": representation,
            "logical_id": logical_id,
            "row_count": quality.row_count,
            "missing_any_count": quality.missing_any_count,
            "nonfinite_any_count": quality.nonfinite_any_count,
            "parse_failure_any_count": quality.parse_failure_any_count,
            "read_error_count": quality.read_error_count,
        }
    )
    return row


def read_chunks(path: Path, delimiter: str, chunk_size: int) -> Iterable[pd.DataFrame]:
    return pd.read_csv(
        path,
        sep=delimiter,
        dtype=str,
        keep_default_na=False,
        na_filter=False,
        encoding="utf-8-sig",
        chunksize=chunk_size,
        engine="c",
    )


def restore_unnamed_leading_header(frame: pd.DataFrame) -> pd.DataFrame:
    if "" not in frame.columns and "Unnamed: 0" in frame.columns:
        return frame.rename(columns={"Unnamed: 0": ""})
    return frame


def candidate_hashes(frame: pd.DataFrame, columns: list[str]) -> np.ndarray:
    hashed = pd.util.hash_pandas_object(
        frame.loc[:, columns], index=False, categorize=False, hash_key="iotguardA4hash16"
    ).to_numpy(dtype=np.uint64)
    return hashed.view(np.int64)


def upsert_hash_counts(
    connection: sqlite3.Connection,
    dataset: str,
    scope: str,
    source_id: int,
    hashes: np.ndarray,
) -> None:
    values, counts = np.unique(hashes, return_counts=True)
    connection.executemany(
        """
        INSERT INTO hash_counts(dataset, scope, h, source_id, count)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(dataset, scope, h, source_id)
        DO UPDATE SET count = count + excluded.count
        """,
        (
            (dataset, scope, int(value), source_id, int(count))
            for value, count in zip(values, counts, strict=True)
        ),
    )


def encode_exact_row(values: Iterable[str]) -> tuple[bytes, bytes]:
    serialized = bytearray()
    for value in values:
        encoded = value.encode("utf-8")
        serialized.extend(len(encoded).to_bytes(4, "big"))
        serialized.extend(encoded)
    raw = bytes(serialized)
    return hashlib.sha256(raw).digest(), zlib.compress(raw, level=1)


def initialize_database(path: Path) -> sqlite3.Connection:
    if path.exists():
        path.unlink()
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=OFF")
    connection.execute("PRAGMA synchronous=OFF")
    connection.execute("PRAGMA temp_store=FILE")
    connection.execute("PRAGMA cache_size=-262144")
    connection.executescript(
        """
        CREATE TABLE hash_counts (
            dataset TEXT NOT NULL,
            scope TEXT NOT NULL,
            h INTEGER NOT NULL,
            source_id INTEGER NOT NULL,
            count INTEGER NOT NULL,
            PRIMARY KEY(dataset, scope, h, source_id)
        ) WITHOUT ROWID;

        CREATE TABLE exact_rows (
            dataset TEXT NOT NULL,
            scope TEXT NOT NULL,
            exact_hash BLOB NOT NULL,
            exact_blob BLOB NOT NULL,
            source_id INTEGER NOT NULL,
            row_number INTEGER NOT NULL,
            attack TEXT NOT NULL,
            category TEXT NOT NULL,
            subcategory TEXT NOT NULL,
            binary_label TEXT NOT NULL,
            family_label TEXT NOT NULL,
            fine_label TEXT NOT NULL
        );

        CREATE TABLE n_source_metadata (
            source_id INTEGER PRIMARY KEY,
            device TEXT NOT NULL
        );

        CREATE TABLE exact_group_stats (
            dataset TEXT NOT NULL,
            scope TEXT NOT NULL,
            exact_hash BLOB NOT NULL,
            exact_blob BLOB NOT NULL,
            occurrence_count INTEGER NOT NULL,
            source_count INTEGER NOT NULL,
            device_count INTEGER NOT NULL,
            binary_count INTEGER NOT NULL,
            family_count INTEGER NOT NULL,
            fine_count INTEGER NOT NULL,
            attack_count INTEGER NOT NULL,
            category_count INTEGER NOT NULL,
            subcategory_count INTEGER NOT NULL,
            label_tuple_count INTEGER NOT NULL,
            PRIMARY KEY(dataset, scope, exact_hash, exact_blob)
        ) WITHOUT ROWID;
        """
    )
    return connection


def phase_started(name: str) -> float:
    print(f"[A4] START {name}", flush=True)
    return time.perf_counter()


def phase_finished(name: str, started_at: float) -> None:
    elapsed = time.perf_counter() - started_at
    print(f"[A4] DONE  {name} ({elapsed:.1f}s)", flush=True)


def get_candidate_set(
    connection: sqlite3.Connection, dataset: str, scope: str
) -> set[int]:
    cursor = connection.execute(
        """
        SELECT h
        FROM hash_counts
        WHERE dataset = ? AND scope = ?
        GROUP BY h
        HAVING SUM(count) > 1
        """,
        (dataset, scope),
    )
    return {int(row[0]) for row in cursor}


class BotLineageStore:
    def __init__(self, temp_dir: Path, capacity: int) -> None:
        self.capacity = capacity
        self.seen = np.memmap(
            temp_dir / "bot_all_seen.bin", dtype=np.uint8, mode="w+", shape=(capacity + 1,)
        )
        self.order = np.memmap(
            temp_dir / "bot_all_order.bin", dtype=np.int32, mode="w+", shape=(capacity + 1,)
        )
        self.numeric = {
            field_name: np.memmap(
                temp_dir / f"bot_all_numeric_{field_name}.bin",
                dtype=np.float64,
                mode="w+",
                shape=(capacity + 1,),
            )
            for field_name in LINEAGE_NUMERIC_FIELDS
        }
        self.string = {
            field_name: np.memmap(
                temp_dir / f"bot_all_string_{field_name}.bin",
                dtype=np.int32,
                mode="w+",
                shape=(capacity + 1,),
            )
            for field_name in LINEAGE_STRING_FIELDS
        }
        self.string_maps: dict[str, dict[str, int]] = {
            field_name: {} for field_name in LINEAGE_STRING_FIELDS
        }
        self.seen[:] = 0
        self.order[:] = 0
        for array in self.string.values():
            array[:] = -1

    def flush(self) -> None:
        self.seen.flush()
        self.order.flush()
        for array in self.numeric.values():
            array.flush()
        for array in self.string.values():
            array.flush()


def parse_pkseqid(values: pd.Series, capacity: int) -> np.ndarray:
    numeric = pd.to_numeric(values, errors="coerce").to_numpy(dtype=np.float64)
    if not np.isfinite(numeric).all() or not np.equal(numeric, np.floor(numeric)).all():
        raise ValueError("pkSeqID contains missing, nonnumeric, nonfinite, or noninteger values")
    identifiers = numeric.astype(np.int64)
    if (identifiers < 1).any() or (identifiers > capacity).any():
        raise ValueError("pkSeqID falls outside the expected 1..row_count range")
    return identifiers


def numeric_values(values: pd.Series, field_name: str) -> np.ndarray:
    parsed = pd.to_numeric(values, errors="coerce").to_numpy(dtype=np.float64)
    if not np.isfinite(parsed).all():
        raise ValueError(f"Lineage field {field_name} is not fully finite numeric")
    return parsed


def add_all_features_lineage(
    store: BotLineageStore, frame: pd.DataFrame, starting_order: int
) -> np.ndarray:
    identifiers = parse_pkseqid(frame["pkSeqID"], store.capacity)
    if len(np.unique(identifiers)) != len(identifiers) or store.seen[identifiers].any():
        raise ValueError("All-features pkSeqID is not unique")
    store.seen[identifiers] = 1
    store.order[identifiers] = np.arange(
        starting_order, starting_order + len(frame), dtype=np.int32
    )
    for field_name in LINEAGE_NUMERIC_FIELDS:
        store.numeric[field_name][identifiers] = numeric_values(frame[field_name], field_name)
    for field_name in LINEAGE_STRING_FIELDS:
        mapping = store.string_maps[field_name]
        for value in frame[field_name].unique():
            value_text = str(value)
            if value_text not in mapping:
                mapping[value_text] = len(mapping)
        store.string[field_name][identifiers] = (
            frame[field_name].map(mapping).to_numpy(dtype=np.int32)
        )
    return identifiers


def compare_lineage_chunk(
    store: BotLineageStore,
    frame: pd.DataFrame,
    identifiers: np.ndarray,
) -> tuple[dict[str, int], int]:
    differences = {field_name: 0 for field_name in LINEAGE_FIELDS}
    any_difference = np.zeros(len(frame), dtype=bool)
    for field_name in LINEAGE_NUMERIC_FIELDS:
        observed = numeric_values(frame[field_name], field_name)
        mismatch = observed != store.numeric[field_name][identifiers]
        differences[field_name] = int(mismatch.sum())
        any_difference |= mismatch
    for field_name in LINEAGE_STRING_FIELDS:
        mapping = store.string_maps[field_name]
        observed = frame[field_name].map(mapping).fillna(-1).to_numpy(dtype=np.int32)
        mismatch = observed != store.string[field_name][identifiers]
        differences[field_name] = int(mismatch.sum())
        any_difference |= mismatch
    return differences, int(any_difference.sum())


def ensure_ids_present(store: BotLineageStore, identifiers: np.ndarray) -> None:
    if (store.seen[identifiers] == 0).any():
        raise ValueError("Lineage representation contains pkSeqID absent from All-features")


def physical_order_matches(
    store: BotLineageStore, identifiers: np.ndarray, starting_order: int
) -> bool:
    expected = np.arange(starting_order, starting_order + len(identifiers), dtype=np.int64)
    return np.array_equal(store.order[identifiers].astype(np.int64), expected)


def partition_set_summary(
    train_seen: np.ndarray, test_seen: np.ndarray, full_seen: np.ndarray
) -> dict[str, Any]:
    overlap = int(np.logical_and(train_seen, test_seen).sum())
    union_mask = np.logical_or(train_seen, test_seen)
    union_count = int(union_mask.sum())
    return {
        "train_test_intersection_count": overlap,
        "train_test_union_count": union_count,
        "train_test_union_equals_full": np.array_equal(union_mask, full_seen.astype(bool)),
        "train_test_are_disjoint": overlap == 0,
    }


def merge_difference_counts(target: dict[str, int], observed: dict[str, int]) -> None:
    for field_name, count in observed.items():
        target[field_name] = target.get(field_name, 0) + count


def build_n_sources(
    n_root: Path, extracted_root: Path
) -> list[dict[str, Any]]:
    structure = {
        row["logical_id"]: row
        for row in load_csv(AUDIT_DIR / "n_baiot_csv_structure.csv")
    }
    mapping = load_csv(AUDIT_DIR / "n_baiot_label_mapping.csv")
    sources: list[dict[str, Any]] = []
    for source_id, mapped in enumerate(sorted(mapping, key=lambda row: row["logical_id"])):
        row = structure[mapped["logical_id"]]
        if row["source_kind"] == "immutable_benign_source":
            root_kind = "n_baiot_raw"
            relative_path = row["source_relative_path"]
            path = n_root / Path(relative_path)
        else:
            root_kind = "n_baiot_extracted"
            relative_path = row["extracted_relative_path"]
            path = extracted_root / Path(relative_path)
        sources.append(
            {
                "source_id": source_id,
                "logical_id": row["logical_id"],
                "representation": row["representation"],
                "path": path,
                "root_kind": root_kind,
                "relative_path": relative_path,
                "expected_rows": int(row["row_count"]),
                "device": mapped["device"],
                "binary": mapped["canonical_binary"],
                "family": mapped["canonical_family"],
                "fine": mapped["canonical_fine_class"],
            }
        )
    return sources


def build_bot_sources(bot_root: Path) -> list[dict[str, Any]]:
    rows = load_csv(AUDIT_DIR / "bot_iot_csv_structure.csv")
    representation_order = {
        "all_features_5pct_shards": 0,
        "ten_best_full": 1,
        "ten_best_predefined_train": 2,
        "ten_best_predefined_test": 3,
    }
    rows.sort(key=lambda row: (representation_order[row["representation"]], row["logical_id"]))
    return [
        {
            "source_id": source_id,
            "logical_id": row["logical_id"],
            "representation": row["representation"],
            "path": bot_root / Path(row["source_relative_path"]),
            "root_kind": "bot_iot_raw",
            "relative_path": row["source_relative_path"],
            "expected_rows": int(row["row_count"]),
            "delimiter": {"comma": ",", "semicolon": ";"}[row["delimiter"]],
            "header": json.loads(row["header_columns"]),
        }
        for source_id, row in enumerate(rows)
    ]


def scan_n_baiot_first_pass(
    sources: list[dict[str, Any]],
    connection: sqlite3.Connection,
    chunk_size: int,
) -> tuple[list[dict[str, Any]], dict[str, ColumnStats], dict[str, Any]]:
    quality_rows: list[dict[str, Any]] = []
    aggregate: dict[str, ColumnStats] | None = None
    total_rows = 0
    total_file_quality = FileQuality()
    for source in sources:
        file_stats: dict[str, ColumnStats] | None = None
        file_quality = FileQuality()
        observed_rows = 0
        for frame in read_chunks(source["path"], ",", chunk_size):
            frame = frame.reset_index(drop=True)
            columns = list(frame.columns)
            if file_stats is None:
                file_stats = new_column_stats(columns, set(columns))
            update_quality(frame, file_stats, file_quality)
            hashes = candidate_hashes(frame, columns)
            upsert_hash_counts(
                connection, "n_baiot", "all_115_features", source["source_id"], hashes
            )
            observed_rows += len(frame)
        if file_stats is None or observed_rows != source["expected_rows"]:
            raise ValueError(f"N-BaIoT scan row mismatch: {source['logical_id']}")
        if aggregate is None:
            aggregate = new_column_stats(list(file_stats), set(file_stats))
        for column, stats in file_stats.items():
            aggregate[column].merge(stats)
            quality_rows.append(
                quality_column_row(
                    record_type="file_column",
                    representation="device_traffic",
                    logical_id=source["logical_id"],
                    column=column,
                    stats=stats,
                )
            )
        quality_rows.append(
            quality_file_row("device_traffic", source["logical_id"], file_quality)
        )
        total_rows += observed_rows
        total_file_quality.row_count += file_quality.row_count
        total_file_quality.missing_any_count += file_quality.missing_any_count
        total_file_quality.nonfinite_any_count += file_quality.nonfinite_any_count
        total_file_quality.parse_failure_any_count += file_quality.parse_failure_any_count
        connection.commit()
    if aggregate is None or total_rows != N_TOTAL:
        raise ValueError(f"N-BaIoT total quality rows do not reconcile: {total_rows}")
    for column, stats in aggregate.items():
        quality_rows.append(
            quality_column_row(
                record_type="column",
                representation="device_traffic",
                logical_id="",
                column=column,
                stats=stats,
            )
        )
    return quality_rows, aggregate, {
        "total_rows": total_rows,
        "logical_file_count": len(sources),
        "missing_any_rows": total_file_quality.missing_any_count,
        "nonfinite_any_rows": total_file_quality.nonfinite_any_count,
        "parse_failure_any_rows": total_file_quality.parse_failure_any_count,
    }


def bot_scopes(representation: str, columns: list[str]) -> dict[str, list[str]]:
    if representation == "all_features_5pct_shards":
        return {
            "full_46_observed_fields": columns,
            "all_43_observed_non_label_fields": [
                column for column in columns if column not in LABEL_FIELDS
            ],
        }
    if representation == "ten_best_full":
        non_label = [column for column in columns if column not in LABEL_FIELDS]
        return {
            "full_20_observed_fields": columns,
            "all_17_observed_non_label_fields_including_unnamed": non_label,
            "named_16_non_label_fields_excluding_unnamed": [
                column for column in non_label if column != ""
            ],
        }
    return {}


def scan_bot_first_pass(
    sources: list[dict[str, Any]],
    connection: sqlite3.Connection,
    temp_dir: Path,
    chunk_size: int,
) -> tuple[
    list[dict[str, Any]],
    dict[str, dict[str, ColumnStats]],
    dict[str, Any],
    BotLineageStore,
]:
    quality_rows: list[dict[str, Any]] = []
    aggregate: dict[str, dict[str, ColumnStats]] = {}
    representation_quality: dict[str, FileQuality] = defaultdict(FileQuality)
    representation_rows: Counter[str] = Counter()
    store = BotLineageStore(temp_dir, BOT_TOTAL)
    all_order = 1
    full_order = 1
    full_seen = np.memmap(
        temp_dir / "bot_full_seen.bin", dtype=np.uint8, mode="w+", shape=(BOT_TOTAL + 1,)
    )
    train_seen = np.memmap(
        temp_dir / "bot_train_seen.bin", dtype=np.uint8, mode="w+", shape=(BOT_TOTAL + 1,)
    )
    test_seen = np.memmap(
        temp_dir / "bot_test_seen.bin", dtype=np.uint8, mode="w+", shape=(BOT_TOTAL + 1,)
    )
    unnamed_seen = np.memmap(
        temp_dir / "bot_unnamed_seen.bin", dtype=np.uint8, mode="w+", shape=(BOT_TOTAL,)
    )
    for array in (full_seen, train_seen, test_seen, unnamed_seen):
        array[:] = 0

    lineage = {
        "all_features": {
            "row_count": 0,
            "pk_missing_count": 0,
            "pk_numeric_parse_failure_count": 0,
            "pk_duplicate_count": 0,
            "pk_min": None,
            "pk_max": None,
        },
        "ten_best_full": {
            "row_count": 0,
            "pk_missing_count": 0,
            "pk_numeric_parse_failure_count": 0,
            "pk_duplicate_count": 0,
            "pk_min": None,
            "pk_max": None,
            "matched_ids": 0,
            "records_all_19_fields_equal": 0,
            "records_with_field_differences": 0,
            "difference_count_per_field": {field_name: 0 for field_name in LINEAGE_FIELDS},
            "row_order_matches_all_features": True,
        },
        "ten_best_predefined_train": {
            "row_count": 0,
            "pk_missing_count": 0,
            "pk_numeric_parse_failure_count": 0,
            "pk_duplicate_count": 0,
            "pk_min": None,
            "pk_max": None,
            "matched_ids": 0,
            "records_all_19_fields_equal": 0,
            "records_with_field_differences": 0,
            "difference_count_per_field": {field_name: 0 for field_name in LINEAGE_FIELDS},
            "preserves_full_relative_order": True,
            "previous_full_order": 0,
        },
        "ten_best_predefined_test": {
            "row_count": 0,
            "pk_missing_count": 0,
            "pk_numeric_parse_failure_count": 0,
            "pk_duplicate_count": 0,
            "pk_min": None,
            "pk_max": None,
            "matched_ids": 0,
            "records_all_19_fields_equal": 0,
            "records_with_field_differences": 0,
            "difference_count_per_field": {field_name: 0 for field_name in LINEAGE_FIELDS},
            "preserves_full_relative_order": True,
            "previous_full_order": 0,
        },
        "unnamed_leading_column": {
            "row_count": 0,
            "numeric_parse_failure_count": 0,
            "integer_count": 0,
            "min": None,
            "max": None,
            "duplicate_count": 0,
            "equals_zero_based_physical_row_position_count": 0,
            "strict_step_one_monotonic": True,
            "previous_value": None,
        },
    }

    for source in sources:
        representation = source["representation"]
        file_stats: dict[str, ColumnStats] | None = None
        file_quality = FileQuality()
        observed_rows = 0
        for frame in read_chunks(source["path"], source["delimiter"], chunk_size):
            frame = restore_unnamed_leading_header(frame.reset_index(drop=True))
            columns = list(frame.columns)
            if file_stats is None:
                numeric_columns = {column for column in columns if column not in BOT_STRING_COLUMNS}
                file_stats = new_column_stats(columns, numeric_columns)
            update_quality(frame, file_stats, file_quality)
            for scope, scope_columns in bot_scopes(representation, columns).items():
                upsert_hash_counts(
                    connection,
                    "bot_iot",
                    f"{representation}:{scope}",
                    source["source_id"],
                    candidate_hashes(frame, scope_columns),
                )

            if representation == "all_features_5pct_shards":
                identifiers = add_all_features_lineage(store, frame, all_order)
                entry = lineage["all_features"]
                entry["row_count"] += len(frame)
                entry["pk_min"] = int(identifiers.min()) if entry["pk_min"] is None else min(
                    entry["pk_min"], int(identifiers.min())
                )
                entry["pk_max"] = int(identifiers.max()) if entry["pk_max"] is None else max(
                    entry["pk_max"], int(identifiers.max())
                )
                all_order += len(frame)
            else:
                identifiers = parse_pkseqid(frame["pkSeqID"], BOT_TOTAL)
                entry = lineage[representation]
                target_seen = {
                    "ten_best_full": full_seen,
                    "ten_best_predefined_train": train_seen,
                    "ten_best_predefined_test": test_seen,
                }[representation]
                if len(np.unique(identifiers)) != len(identifiers):
                    entry["pk_duplicate_count"] += len(identifiers) - len(np.unique(identifiers))
                entry["pk_duplicate_count"] += int(target_seen[identifiers].sum())
                target_seen[identifiers] = 1
                entry["row_count"] += len(frame)
                entry["pk_min"] = int(identifiers.min()) if entry["pk_min"] is None else min(
                    entry["pk_min"], int(identifiers.min())
                )
                entry["pk_max"] = int(identifiers.max()) if entry["pk_max"] is None else max(
                    entry["pk_max"], int(identifiers.max())
                )
                ensure_ids_present(store, identifiers)
                differences, records_different = compare_lineage_chunk(store, frame, identifiers)
                merge_difference_counts(entry["difference_count_per_field"], differences)
                entry["matched_ids"] += len(frame)
                entry["records_with_field_differences"] += records_different
                entry["records_all_19_fields_equal"] += len(frame) - records_different
                full_orders = store.order[identifiers].astype(np.int64)
                if representation == "ten_best_full":
                    if not physical_order_matches(store, identifiers, full_order):
                        entry["row_order_matches_all_features"] = False
                    full_order += len(frame)
                    unnamed = pd.to_numeric(frame[""], errors="coerce").to_numpy(
                        dtype=np.float64
                    )
                    unnamed_entry = lineage["unnamed_leading_column"]
                    unnamed_entry["row_count"] += len(frame)
                    valid = np.isfinite(unnamed)
                    unnamed_entry["numeric_parse_failure_count"] += int((~valid).sum())
                    integer = valid & np.equal(unnamed, np.floor(unnamed))
                    unnamed_entry["integer_count"] += int(integer.sum())
                    if valid.any():
                        current_min = float(unnamed[valid].min())
                        current_max = float(unnamed[valid].max())
                        unnamed_entry["min"] = (
                            current_min
                            if unnamed_entry["min"] is None
                            else min(unnamed_entry["min"], current_min)
                        )
                        unnamed_entry["max"] = (
                            current_max
                            if unnamed_entry["max"] is None
                            else max(unnamed_entry["max"], current_max)
                        )
                    global_positions = np.arange(
                        unnamed_entry["row_count"] - len(frame),
                        unnamed_entry["row_count"],
                        dtype=np.float64,
                    )
                    unnamed_entry["equals_zero_based_physical_row_position_count"] += int(
                        (valid & (unnamed == global_positions)).sum()
                    )
                    if integer.all() and (unnamed >= 0).all() and (unnamed < BOT_TOTAL).all():
                        unnamed_ids = unnamed.astype(np.int64)
                        if len(np.unique(unnamed_ids)) != len(unnamed_ids):
                            unnamed_entry["duplicate_count"] += len(unnamed_ids) - len(
                                np.unique(unnamed_ids)
                            )
                        unnamed_entry["duplicate_count"] += int(
                            unnamed_seen[unnamed_ids].sum()
                        )
                        unnamed_seen[unnamed_ids] = 1
                    else:
                        raise ValueError(
                            "Unnamed 10-best column is not an integer within expected bounds"
                        )
                    if len(unnamed):
                        previous = unnamed_entry["previous_value"]
                        if previous is not None and unnamed[0] != previous + 1:
                            unnamed_entry["strict_step_one_monotonic"] = False
                        if len(unnamed) > 1 and not np.all(np.diff(unnamed) == 1):
                            unnamed_entry["strict_step_one_monotonic"] = False
                        unnamed_entry["previous_value"] = float(unnamed[-1])
                else:
                    previous_order = entry["previous_full_order"]
                    if len(full_orders):
                        if previous_order and full_orders[0] <= previous_order:
                            entry["preserves_full_relative_order"] = False
                        if len(full_orders) > 1 and not np.all(np.diff(full_orders) > 0):
                            entry["preserves_full_relative_order"] = False
                        entry["previous_full_order"] = int(full_orders[-1])
            observed_rows += len(frame)

        if file_stats is None or observed_rows != source["expected_rows"]:
            raise ValueError(f"Bot-IoT scan row mismatch: {source['logical_id']}")
        if representation not in aggregate:
            aggregate[representation] = new_column_stats(
                list(file_stats),
                {column for column in file_stats if column not in BOT_STRING_COLUMNS},
            )
        for column, stats in file_stats.items():
            aggregate[representation][column].merge(stats)
            quality_rows.append(
                quality_column_row(
                    record_type="file_column",
                    representation=representation,
                    logical_id=source["logical_id"],
                    column=column,
                    stats=stats,
                )
            )
        quality_rows.append(quality_file_row(representation, source["logical_id"], file_quality))
        representation_rows[representation] += observed_rows
        rep_quality = representation_quality[representation]
        rep_quality.row_count += file_quality.row_count
        rep_quality.missing_any_count += file_quality.missing_any_count
        rep_quality.nonfinite_any_count += file_quality.nonfinite_any_count
        rep_quality.parse_failure_any_count += file_quality.parse_failure_any_count
        connection.commit()

    expected_rows = {
        "all_features_5pct_shards": BOT_TOTAL,
        "ten_best_full": BOT_TOTAL,
        "ten_best_predefined_train": 2_934_817,
        "ten_best_predefined_test": 733_705,
    }
    if dict(representation_rows) != expected_rows:
        raise ValueError(f"Bot-IoT representation rows do not reconcile: {representation_rows}")
    if int(store.seen.sum()) != BOT_TOTAL:
        raise ValueError("All-features pkSeqID does not cover exactly the expected total")
    if int(full_seen.sum()) != BOT_TOTAL:
        raise ValueError("10-best full pkSeqID set is incomplete")
    if int(train_seen.sum()) != 2_934_817 or int(test_seen.sum()) != 733_705:
        raise ValueError("Predefined split pkSeqID sets do not reconcile")

    for representation, columns in aggregate.items():
        for column, stats in columns.items():
            quality_rows.append(
                quality_column_row(
                    record_type="column",
                    representation=representation,
                    logical_id="",
                    column=column,
                    stats=stats,
                )
            )

    full_missing_from_all = int(np.logical_and(full_seen, np.logical_not(store.seen)).sum())
    all_missing_from_full = int(np.logical_and(store.seen, np.logical_not(full_seen)).sum())
    lineage["pkseqid_sets"] = {
        "all_features_vs_ten_best_full_missing_from_all_features": full_missing_from_all,
        "all_features_vs_ten_best_full_missing_from_ten_best_full": all_missing_from_full,
        **partition_set_summary(train_seen, test_seen, full_seen),
    }
    lineage["all_features"]["pk_unique_count"] = int(store.seen.sum())
    lineage["ten_best_full"]["pk_unique_count"] = int(full_seen.sum())
    lineage["ten_best_predefined_train"]["pk_unique_count"] = int(train_seen.sum())
    lineage["ten_best_predefined_test"]["pk_unique_count"] = int(test_seen.sum())
    lineage["unnamed_leading_column"]["unique_count"] = int(unnamed_seen.sum())
    lineage["unnamed_leading_column"]["equals_zero_based_physical_row_position"] = (
        lineage["unnamed_leading_column"][
            "equals_zero_based_physical_row_position_count"
        ]
        == BOT_TOTAL
    )
    for split in ("ten_best_predefined_train", "ten_best_predefined_test"):
        lineage[split].pop("previous_full_order")

    store.flush()
    for array in (full_seen, train_seen, test_seen, unnamed_seen):
        array.flush()
    quality_summary = {
        representation: {
            "row_count": representation_rows[representation],
            "column_count": len(aggregate[representation]),
            "missing_any_rows": representation_quality[representation].missing_any_count,
            "nonfinite_any_rows": representation_quality[representation].nonfinite_any_count,
            "parse_failure_any_rows": representation_quality[
                representation
            ].parse_failure_any_count,
        }
        for representation in expected_rows
    }
    return quality_rows, aggregate, quality_summary, store, lineage


def insert_exact_rows(
    connection: sqlite3.Connection, rows: list[tuple[Any, ...]]
) -> None:
    if not rows:
        return
    connection.executemany(
        """
        INSERT INTO exact_rows(
            dataset, scope, exact_hash, exact_blob, source_id, row_number,
            attack, category, subcategory, binary_label, family_label, fine_label
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )


def scan_exact_candidates(
    connection: sqlite3.Connection,
    n_sources: list[dict[str, Any]],
    bot_sources: list[dict[str, Any]],
    n_chunk_size: int,
    bot_chunk_size: int,
) -> dict[str, int]:
    candidate_sets: dict[tuple[str, str], set[int]] = {}
    scopes = [("n_baiot", "all_115_features")]
    for source in bot_sources:
        for scope in bot_scopes(source["representation"], source["header"]):
            key = ("bot_iot", f"{source['representation']}:{scope}")
            if key not in scopes:
                scopes.append(key)
    for key in scopes:
        candidate_sets[key] = get_candidate_set(connection, *key)

    inserted: Counter[str] = Counter()
    for source in n_sources:
        row_offset = 0
        key = ("n_baiot", "all_115_features")
        candidates = candidate_sets[key]
        for frame in read_chunks(source["path"], ",", n_chunk_size):
            frame = frame.reset_index(drop=True)
            hashes = candidate_hashes(frame, list(frame.columns))
            positions = np.flatnonzero(pd.Series(hashes).isin(candidates).to_numpy())
            batch: list[tuple[Any, ...]] = []
            for position in positions:
                exact_hash, exact_blob = encode_exact_row(
                    str(value) for value in frame.iloc[int(position)].tolist()
                )
                batch.append(
                    (
                        "n_baiot",
                        "all_115_features",
                        exact_hash,
                        exact_blob,
                        source["source_id"],
                        row_offset + int(position) + 1,
                        "",
                        "",
                        "",
                        source["binary"],
                        source["family"],
                        source["fine"],
                    )
                )
            insert_exact_rows(connection, batch)
            inserted["n_baiot:all_115_features"] += len(batch)
            row_offset += len(frame)
        connection.commit()

    for source in bot_sources:
        scope_map = bot_scopes(source["representation"], source["header"])
        if not scope_map:
            continue
        row_offset = 0
        for frame in read_chunks(source["path"], source["delimiter"], bot_chunk_size):
            frame = restore_unnamed_leading_header(frame.reset_index(drop=True))
            scope_hashes = {
                scope: candidate_hashes(frame, columns) for scope, columns in scope_map.items()
            }
            batch = []
            for scope, columns in scope_map.items():
                stored_scope = f"{source['representation']}:{scope}"
                candidates = candidate_sets[("bot_iot", stored_scope)]
                positions = np.flatnonzero(
                    pd.Series(scope_hashes[scope]).isin(candidates).to_numpy()
                )
                for position in positions:
                    row = frame.iloc[int(position)]
                    exact_hash, exact_blob = encode_exact_row(
                        str(row[column]) for column in columns
                    )
                    batch.append(
                        (
                            "bot_iot",
                            stored_scope,
                            exact_hash,
                            exact_blob,
                            source["source_id"],
                            row_offset + int(position) + 1,
                            str(row["attack"]),
                            str(row["category"]),
                            str(row["subcategory"]),
                            "",
                            "",
                            "",
                        )
                    )
                inserted[f"bot_iot:{stored_scope}"] += len(positions)
            insert_exact_rows(connection, batch)
            row_offset += len(frame)
        connection.commit()
    connection.execute(
        "CREATE INDEX exact_group_idx "
        "ON exact_rows(dataset, scope, exact_hash, exact_blob, source_id)"
    )
    connection.commit()
    return dict(inserted)


def materialize_exact_group_stats(connection: sqlite3.Connection) -> None:
    """Build exact-group facts once for reuse by every downstream metric.

    The exact-row table is several gigabytes. Repeating GROUP BY and DISTINCT over it
    for each reported relationship causes hundreds of gigabytes of redundant reads.
    This compact table preserves exact-blob grouping semantics while making subsequent
    aggregates and bounded-example selection operate on one row per confirmed group.
    """
    connection.execute("DELETE FROM exact_group_stats")
    connection.execute(
        """
        INSERT INTO exact_group_stats(
            dataset,
            scope,
            exact_hash,
            exact_blob,
            occurrence_count,
            source_count,
            device_count,
            binary_count,
            family_count,
            fine_count,
            attack_count,
            category_count,
            subcategory_count,
            label_tuple_count
        )
        SELECT rows.dataset,
               rows.scope,
               rows.exact_hash,
               rows.exact_blob,
               COUNT(*) AS occurrence_count,
               COUNT(DISTINCT rows.source_id) AS source_count,
               COUNT(DISTINCT CASE
                   WHEN rows.dataset='n_baiot' THEN metadata.device
               END) AS device_count,
               COUNT(DISTINCT rows.binary_label) AS binary_count,
               COUNT(DISTINCT rows.family_label) AS family_count,
               COUNT(DISTINCT rows.fine_label) AS fine_count,
               COUNT(DISTINCT rows.attack) AS attack_count,
               COUNT(DISTINCT rows.category) AS category_count,
               COUNT(DISTINCT rows.subcategory) AS subcategory_count,
               COUNT(DISTINCT (
                   rows.attack || char(0) || rows.category || char(0) || rows.subcategory
               )) AS label_tuple_count
        FROM exact_rows AS rows
        LEFT JOIN n_source_metadata AS metadata
          ON rows.dataset='n_baiot' AND metadata.source_id=rows.source_id
        GROUP BY rows.dataset, rows.scope, rows.exact_hash, rows.exact_blob
        """
    )
    connection.commit()


def scalar(connection: sqlite3.Connection, query: str, parameters: tuple[Any, ...]) -> int:
    value = connection.execute(query, parameters).fetchone()[0]
    return int(value or 0)


def duplicate_group_totals(
    connection: sqlite3.Connection,
    dataset: str,
    scope: str,
    total_rows: int,
) -> dict[str, Any]:
    (
        candidate_rows,
        unique_candidate_vectors,
        duplicate_groups,
        duplicate_occurrences,
        duplicate_excess,
    ) = connection.execute(
        """
        SELECT COALESCE(SUM(occurrence_count), 0),
               COUNT(*),
               COALESCE(SUM(CASE WHEN occurrence_count > 1 THEN 1 ELSE 0 END), 0),
               COALESCE(SUM(CASE
                   WHEN occurrence_count > 1 THEN occurrence_count ELSE 0
               END), 0),
               COALESCE(SUM(CASE
                   WHEN occurrence_count > 1 THEN occurrence_count - 1 ELSE 0
               END), 0)
        FROM exact_group_stats
        WHERE dataset=? AND scope=?
        """,
        (dataset, scope),
    ).fetchone()
    unique_rows = total_rows - candidate_rows + unique_candidate_vectors
    return {
        "total_rows": total_rows,
        "unique_records": int(unique_rows),
        "duplicate_group_count": int(duplicate_groups or 0),
        "duplicate_row_occurrences": int(duplicate_occurrences or 0),
        "duplicate_excess_rows": int(duplicate_excess or 0),
        "duplicate_excess_ratio_percent": percentage(int(duplicate_excess or 0), total_rows),
        "candidate_rows_exactly_reconciled": candidate_rows,
        "candidate_detection": "pandas deterministic 64-bit candidate hash",
        "exact_confirmation": (
            "length-prefixed UTF-8 source-field tuples grouped by exact compressed bytes; "
            "SHA-256 is retained only as a compact group identifier"
        ),
    }


def grouped_condition_metrics(
    connection: sqlite3.Connection,
    dataset: str,
    scope: str,
    condition: str,
) -> dict[str, int]:
    query = f"""
        SELECT COUNT(*),
               COALESCE(SUM(occurrence_count), 0),
               COALESCE(SUM(occurrence_count - 1), 0)
        FROM exact_group_stats
        WHERE dataset=? AND scope=? AND occurrence_count > 1 AND ({condition})
    """
    groups, occurrences, excess = connection.execute(query, (dataset, scope)).fetchone()
    return {
        "group_count": int(groups or 0),
        "row_occurrences": int(occurrences or 0),
        "excess_rows": int(excess or 0),
    }


def within_source_excess(
    connection: sqlite3.Connection, dataset: str, scope: str
) -> int:
    return sum(duplicate_excess_by_source(connection, dataset, scope).values())


def duplicate_excess_by_source(
    connection: sqlite3.Connection, dataset: str, scope: str
) -> dict[int, int]:
    """Return within-source duplicate excess with one grouped database scan.

    Running one GROUP BY query per source makes SQLite prefer the exact-group index to
    avoid sorting, which rereads the full multi-gigabyte exact-row table for every source.
    Aggregate all sources together so the exact-row data is scanned only once.
    """
    rows = connection.execute(
        """
        SELECT source_id, COALESCE(SUM(n - 1), 0)
        FROM (
            SELECT source_id, COUNT(*) AS n FROM exact_rows
            WHERE dataset=? AND scope=?
            GROUP BY exact_hash, exact_blob, source_id
            HAVING n > 1
        )
        GROUP BY source_id
        """,
        (dataset, scope),
    ).fetchall()
    return {int(source_id): int(excess) for source_id, excess in rows}


def n_group_relationship_metrics(
    connection: sqlite3.Connection, dataset: str, scope: str
) -> dict[str, dict[str, int]]:
    """Compute every N-BaIoT group relationship in one exact-row scan."""
    conditions = (
        ("across_logical_csvs", "source_count > 1"),
        ("across_devices", "device_count > 1"),
        ("same_feature_same_fine_label", "fine_count = 1"),
        ("same_feature_different_fine_label", "fine_count > 1"),
        ("same_feature_different_family", "family_count > 1"),
        ("same_feature_benign_malicious_conflict", "binary_count > 1"),
    )
    projections = []
    for _, condition in conditions:
        projections.extend(
            (
                f"COALESCE(SUM(CASE WHEN {condition} THEN 1 ELSE 0 END), 0)",
                (
                    "COALESCE(SUM(CASE WHEN "
                    f"{condition} THEN occurrence_count ELSE 0 END), 0)"
                ),
                (
                    "COALESCE(SUM(CASE WHEN "
                    f"{condition} THEN occurrence_count - 1 ELSE 0 END), 0)"
                ),
            )
        )
    query = f"""
        SELECT {", ".join(projections)}
        FROM exact_group_stats
        WHERE dataset=? AND scope=? AND occurrence_count > 1
    """
    values = connection.execute(
        query,
        (dataset, scope),
    ).fetchone()
    result = {}
    for index, (name, _) in enumerate(conditions):
        offset = index * 3
        result[name] = {
            "group_count": int(values[offset] or 0),
            "row_occurrences": int(values[offset + 1] or 0),
            "excess_rows": int(values[offset + 2] or 0),
        }
    return result


def n_duplicate_summary(
    connection: sqlite3.Connection, sources: list[dict[str, Any]]
) -> dict[str, Any]:
    dataset, scope = "n_baiot", "all_115_features"
    source_excess = duplicate_excess_by_source(connection, dataset, scope)
    relationship_metrics = n_group_relationship_metrics(connection, dataset, scope)
    result = duplicate_group_totals(connection, dataset, scope, N_TOTAL)
    result.update(
        {
            "within_same_logical_csv_duplicate_excess_rows": sum(source_excess.values()),
            **relationship_metrics,
        }
    )
    per_file = {}
    for source in sources:
        per_file[source["logical_id"]] = {
            "row_count": source["expected_rows"],
            "within_file_duplicate_excess_rows": source_excess.get(
                source["source_id"], 0
            ),
        }
    result["by_logical_csv"] = per_file
    return result


def bot_duplicate_summary(
    connection: sqlite3.Connection, sources: list[dict[str, Any]]
) -> dict[str, Any]:
    representation_totals = {
        "all_features_5pct_shards": BOT_TOTAL,
        "ten_best_full": BOT_TOTAL,
    }
    scopes = {
        "all_features_5pct_shards": (
            "full_46_observed_fields",
            "all_43_observed_non_label_fields",
        ),
        "ten_best_full": (
            "full_20_observed_fields",
            "all_17_observed_non_label_fields_including_unnamed",
            "named_16_non_label_fields_excluding_unnamed",
        ),
    }
    result: dict[str, Any] = {}
    for representation, scope_names in scopes.items():
        rep_result: dict[str, Any] = {}
        for scope_name in scope_names:
            scope = f"{representation}:{scope_name}"
            source_excess = duplicate_excess_by_source(connection, "bot_iot", scope)
            metrics = duplicate_group_totals(
                connection, "bot_iot", scope, representation_totals[representation]
            )
            metrics["within_source_file_duplicate_excess_rows"] = sum(
                source_excess.values()
            )
            metrics["across_source_files"] = grouped_condition_metrics(
                connection, "bot_iot", scope, "source_count > 1"
            )
            if "non_label" in scope_name:
                metrics["same_labels"] = grouped_condition_metrics(
                    connection, "bot_iot", scope, "label_tuple_count = 1"
                )
                metrics["different_attack"] = grouped_condition_metrics(
                    connection, "bot_iot", scope, "attack_count > 1"
                )
                metrics["different_category"] = grouped_condition_metrics(
                    connection, "bot_iot", scope, "category_count > 1"
                )
                metrics["different_subcategory"] = grouped_condition_metrics(
                    connection, "bot_iot", scope, "subcategory_count > 1"
                )
            by_source = {}
            for source in sources:
                if source["representation"] != representation:
                    continue
                by_source[source["logical_id"]] = {
                    "row_count": source["expected_rows"],
                    "within_file_duplicate_excess_rows": source_excess.get(
                        source["source_id"], 0
                    ),
                }
            metrics["by_source_file"] = by_source
            rep_result[scope_name] = metrics
        result[representation] = rep_result
    return result


def create_n_source_metadata_table(
    connection: sqlite3.Connection, sources: list[dict[str, Any]]
) -> None:
    connection.execute("DELETE FROM n_source_metadata")
    connection.executemany(
        "INSERT INTO n_source_metadata(source_id, device) VALUES (?, ?)",
        ((source["source_id"], source["device"]) for source in sources),
    )
    connection.commit()


def select_example_pair(
    members: list[sqlite3.Row], difference_field: str | None
) -> tuple[sqlite3.Row, sqlite3.Row] | None:
    if len(members) < 2:
        return None
    if difference_field is None:
        return members[0], members[1]
    for first in members:
        for second in members:
            if first[difference_field] != second[difference_field]:
                return first, second
    return None


def collect_flagged_examples(
    connection: sqlite3.Connection,
    n_sources: list[dict[str, Any]],
    bot_sources: list[dict[str, Any]],
    limit: int = 40,
) -> list[dict[str, Any]]:
    connection.row_factory = sqlite3.Row
    source_maps = {
        "n_baiot": {source["source_id"]: source for source in n_sources},
        "bot_iot": {source["source_id"]: source for source in bot_sources},
    }
    requests = [
        (
            "n_baiot",
            "all_115_features",
            "same_feature_same_fine_label",
            "fine_count = 1",
            None,
        ),
        ("n_baiot", "all_115_features", "different_fine_label", "fine_count > 1", "fine_label"),
        ("n_baiot", "all_115_features", "different_family", "family_count > 1", "family_label"),
        (
            "n_baiot",
            "all_115_features",
            "benign_malicious_conflict",
            "binary_count > 1",
            "binary_label",
        ),
        (
            "bot_iot",
            "all_features_5pct_shards:all_43_observed_non_label_fields",
            "same_non_label_record_same_labels",
            "label_tuple_count = 1",
            None,
        ),
        (
            "bot_iot",
            "all_features_5pct_shards:all_43_observed_non_label_fields",
            "same_non_label_record_different_attack",
            "attack_count > 1",
            "attack",
        ),
        (
            "bot_iot",
            "all_features_5pct_shards:full_46_observed_fields",
            "full_row_duplicate",
            "1 = 1",
            None,
        ),
        (
            "bot_iot",
            "ten_best_full:named_16_non_label_fields_excluding_unnamed",
            "ten_best_named_non_label_duplicate",
            "1 = 1",
            None,
        ),
    ]
    examples: list[dict[str, Any]] = []
    seen_groups: set[tuple[str, str, bytes, bytes]] = set()
    for dataset, scope, finding, condition, difference_field in requests:
        query = f"""
            SELECT exact_hash, exact_blob
            FROM exact_group_stats
            WHERE dataset=? AND scope=? AND occurrence_count > 1 AND ({condition})
            ORDER BY exact_hash, exact_blob
            LIMIT 3
        """
        for group in connection.execute(query, (dataset, scope)).fetchall():
            group_key = (dataset, scope, group["exact_hash"], group["exact_blob"])
            if group_key in seen_groups or len(examples) >= limit:
                continue
            members = connection.execute(
                """
                SELECT * FROM exact_rows
                WHERE dataset=? AND scope=? AND exact_hash=? AND exact_blob=?
                ORDER BY source_id, row_number LIMIT 100
                """,
                (dataset, scope, group["exact_hash"], group["exact_blob"]),
            ).fetchall()
            pair = select_example_pair(members, difference_field)
            if pair is None:
                continue
            first, second = pair
            first_source = source_maps[dataset][first["source_id"]]
            second_source = source_maps[dataset][second["source_id"]]
            row = {field_name: "" for field_name in EXAMPLE_FIELDS}
            row.update(
                {
                    "dataset": dataset,
                    "representation": (
                        first_source["representation"] if dataset == "bot_iot" else "device_traffic"
                    ),
                    "scope": scope,
                    "finding_type": finding,
                    "exact_group_sha256": bytes(first["exact_hash"]).hex(),
                }
            )
            for prefix, member, source in (
                ("first", first, first_source),
                ("second", second, second_source),
            ):
                row[f"{prefix}_logical_id"] = source["logical_id"]
                row[f"{prefix}_source_root_kind"] = source["root_kind"]
                row[f"{prefix}_source_relative_path"] = source["relative_path"]
                row[f"{prefix}_data_row"] = member["row_number"]
                row[f"{prefix}_binary"] = member["binary_label"]
                row[f"{prefix}_family"] = member["family_label"]
                row[f"{prefix}_fine_label"] = member["fine_label"]
                row[f"{prefix}_attack"] = member["attack"]
                row[f"{prefix}_category"] = member["category"]
                row[f"{prefix}_subcategory"] = member["subcategory"]
            examples.append(row)
            seen_groups.add(group_key)
    connection.row_factory = None
    return examples


def aggregate_quality_findings(
    aggregate: dict[str, ColumnStats], total_rows: int
) -> dict[str, Any]:
    def affected(attribute: str) -> list[str]:
        return sorted(column for column, stats in aggregate.items() if getattr(stats, attribute))

    return {
        "row_count": total_rows,
        "column_count": len(aggregate),
        "empty_field_total": sum(stats.empty_field_count for stats in aggregate.values()),
        "explicit_null_token_total": sum(
            stats.explicit_null_token_count for stats in aggregate.values()
        ),
        "nan_total": sum(stats.nan_count for stats in aggregate.values()),
        "positive_inf_total": sum(stats.positive_inf_count for stats in aggregate.values()),
        "negative_inf_total": sum(stats.negative_inf_count for stats in aggregate.values()),
        "numeric_parse_failure_total": sum(
            stats.numeric_parse_failure_count for stats in aggregate.values()
        ),
        "outer_whitespace_total": sum(
            stats.outer_whitespace_count for stats in aggregate.values()
        ),
        "columns_with_empty_fields": affected("empty_field_count"),
        "columns_with_explicit_null_tokens": affected("explicit_null_token_count"),
        "columns_with_nan": affected("nan_count"),
        "columns_with_positive_inf": affected("positive_inf_count"),
        "columns_with_negative_inf": affected("negative_inf_count"),
        "columns_with_numeric_parse_failures": affected("numeric_parse_failure_count"),
        "columns_with_outer_whitespace": affected("outer_whitespace_count"),
        "columns_with_negative_finite_values": affected("negative_value_count"),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-baiot-root", type=Path, required=True)
    parser.add_argument("--bot-iot-root", type=Path, required=True)
    parser.add_argument("--n-baiot-extracted-root", type=Path, required=True)
    parser.add_argument("--temp-dir", type=Path, default=DEFAULT_TEMP_DIR)
    parser.add_argument("--n-chunk-size", type=int, default=20_000)
    parser.add_argument("--bot-chunk-size", type=int, default=50_000)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    n_root = args.n_baiot_root.resolve()
    bot_root = args.bot_iot_root.resolve()
    extracted_root = args.n_baiot_extracted_root.resolve()
    temp_dir = args.temp_dir.resolve()
    for root in (n_root, bot_root, extracted_root):
        if not root.is_dir():
            raise FileNotFoundError(f"Required root does not exist: {root}")
    for protected in (n_root, bot_root, extracted_root, PROJECT_ROOT):
        if temp_dir == protected or protected in temp_dir.parents or temp_dir in protected.parents:
            raise ValueError(f"Unsafe A4 temporary directory relative to {protected}: {temp_dir}")
    temp_dir.mkdir(parents=True, exist_ok=True)
    if any(temp_dir.iterdir()):
        raise ValueError(f"A4 temporary directory must be empty: {temp_dir}")
    free_before = shutil.disk_usage(temp_dir).free

    database_path = temp_dir / "a4_audit.sqlite"
    connection = initialize_database(database_path)
    n_sources = build_n_sources(n_root, extracted_root)
    bot_sources = build_bot_sources(bot_root)
    try:
        phase_name = "scan N-BaIoT quality and candidate hashes"
        phase_time = phase_started(phase_name)
        n_quality_rows, n_aggregate, n_file_summary = scan_n_baiot_first_pass(
            n_sources, connection, args.n_chunk_size
        )
        phase_finished(phase_name, phase_time)

        phase_name = "scan Bot-IoT quality, lineage, and candidate hashes"
        phase_time = phase_started(phase_name)
        (
            bot_quality_rows,
            bot_aggregate,
            bot_file_summary,
            lineage_store,
            lineage_summary,
        ) = scan_bot_first_pass(
            bot_sources, connection, temp_dir, args.bot_chunk_size
        )
        create_n_source_metadata_table(connection, n_sources)
        phase_finished(phase_name, phase_time)

        phase_name = "confirm exact candidate rows and create exact-group index"
        phase_time = phase_started(phase_name)
        candidate_rows = scan_exact_candidates(
            connection,
            n_sources,
            bot_sources,
            args.n_chunk_size,
            args.bot_chunk_size,
        )
        phase_finished(phase_name, phase_time)

        phase_name = "materialize reusable exact-group statistics"
        phase_time = phase_started(phase_name)
        materialize_exact_group_stats(connection)
        phase_finished(phase_name, phase_time)

        phase_name = "aggregate duplicate statistics"
        phase_time = phase_started(phase_name)
        n_duplicates = n_duplicate_summary(connection, n_sources)
        bot_duplicates = bot_duplicate_summary(connection, bot_sources)
        phase_finished(phase_name, phase_time)

        phase_name = "collect bounded flagged examples"
        phase_time = phase_started(phase_name)
        examples = collect_flagged_examples(connection, n_sources, bot_sources)
        phase_finished(phase_name, phase_time)
        lineage_store.flush()
    finally:
        connection.close()

    n_quality_path = AUDIT_DIR / "n_baiot_quality_summary.csv"
    bot_quality_path = AUDIT_DIR / "bot_iot_quality_summary.csv"
    n_duplicate_path = AUDIT_DIR / "n_baiot_duplicate_summary.json"
    bot_duplicate_path = AUDIT_DIR / "bot_iot_duplicate_summary.json"
    lineage_path = AUDIT_DIR / "bot_iot_lineage_summary.json"
    examples_path = AUDIT_DIR / "a4_flagged_examples.csv"
    summary_path = AUDIT_DIR / "a4_audit_summary.json"

    phase_name = "write compact A4 evidence"
    phase_time = phase_started(phase_name)
    write_csv_atomic(
        n_quality_path,
        QUALITY_FIELDS,
        sorted(
            n_quality_rows,
            key=lambda row: (
                row["record_type"],
                row["representation"],
                row["logical_id"],
                row["column_name"],
            ),
        ),
    )
    write_csv_atomic(
        bot_quality_path,
        QUALITY_FIELDS,
        sorted(
            bot_quality_rows,
            key=lambda row: (
                row["record_type"],
                row["representation"],
                row["logical_id"],
                row["column_name"],
            ),
        ),
    )
    write_json_atomic(n_duplicate_path, n_duplicates)
    write_json_atomic(bot_duplicate_path, bot_duplicates)

    full_lineage = lineage_summary["ten_best_full"]
    split_lineage_ok = all(
        lineage_summary[representation]["records_with_field_differences"] == 0
        and lineage_summary[representation]["pk_duplicate_count"] == 0
        for representation in (
            "ten_best_predefined_train",
            "ten_best_predefined_test",
        )
    )
    lineage_summary["conclusions"] = {
        "ten_best_full_is_exact_observed_all_features_projection": (
            full_lineage["records_with_field_differences"] == 0
            and full_lineage["pk_duplicate_count"] == 0
            and lineage_summary["pkseqid_sets"][
                "all_features_vs_ten_best_full_missing_from_all_features"
            ]
            == 0
            and lineage_summary["pkseqid_sets"][
                "all_features_vs_ten_best_full_missing_from_ten_best_full"
            ]
            == 0
        ),
        "predefined_train_test_are_exact_observed_partition_of_ten_best_full": (
            split_lineage_ok
            and lineage_summary["pkseqid_sets"]["train_test_are_disjoint"]
            and lineage_summary["pkseqid_sets"]["train_test_union_equals_full"]
        ),
        "comparison_semantics": (
            "pkSeqID is an integer key; documented numeric fields are compared as finite "
            "IEEE-754 values so 1 and 1.0 compare equal; proto/address/port/category/"
            "subcategory fields are compared as exact source strings because local port "
            "values include nonnumeric lexical forms"
        ),
        "feature_selection_process_inferred": False,
        "split_suitability_or_leakage_freedom_inferred": False,
    }
    write_json_atomic(lineage_path, lineage_summary)
    write_csv_atomic(examples_path, EXAMPLE_FIELDS, examples)

    n_quality_findings = aggregate_quality_findings(n_aggregate, N_TOTAL)
    bot_quality_findings = {
        representation: {
            **aggregate_quality_findings(columns, bot_file_summary[representation]["row_count"]),
            **bot_file_summary[representation],
        }
        for representation, columns in bot_aggregate.items()
    }
    evidence_paths = (
        n_quality_path,
        n_duplicate_path,
        bot_quality_path,
        bot_duplicate_path,
        lineage_path,
        examples_path,
    )
    summary = {
        "audit_batch": "A4",
        "generated_at_utc": datetime.now(tz=UTC).isoformat(),
        "status_semantics": (
            "PASS means the audit completed and reconciled; it does not mean no quality "
            "or duplicate findings were observed."
        ),
        "quality_findings": {
            "n_baiot": {**n_quality_findings, **n_file_summary},
            "bot_iot": bot_quality_findings,
            "negative_finite_values_are_observations_not_automatically_invalid": True,
        },
        "duplicate_findings": {
            "n_baiot": n_duplicates,
            "bot_iot": bot_duplicates,
            "candidate_rows_exactly_reconciled": candidate_rows,
        },
        "lineage_findings": lineage_summary,
        "temporary_data": {
            "directory": str(temp_dir),
            "database": str(database_path),
            "free_bytes_before": free_before,
            "free_bytes_after_primary_audit": shutil.disk_usage(temp_dir).free,
            "retention_status": "retained_until_independent_verification",
        },
        "scope_exclusions": [
            "no cleaning, imputation, row or column removal",
            "no deduplication or feature selection",
            "no train/test split selection or validation",
            "no class balancing, scaling, encoding, or model training",
            "no primary/secondary dataset decision",
        ],
        "artifact_sha256": {
            path.relative_to(PROJECT_ROOT).as_posix(): sha256_file(path)
            for path in evidence_paths
        },
        "overall_status": "PASS",
    }
    write_json_atomic(summary_path, summary)
    phase_finished(phase_name, phase_time)
    print(f"Wrote A4 evidence to: {AUDIT_DIR}")
    print(f"Temporary verification data retained at: {temp_dir}")
    print("Overall status: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        OSError,
        UnicodeError,
        csv.Error,
        ValueError,
        sqlite3.Error,
        pd.errors.ParserError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
