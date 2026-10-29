"""Run the A5 imbalance, leakage, and split-feasibility audit.

The audit is diagnostic. It does not create processed datasets, select predictors,
adopt a split, or train a model. Large row-level state remains outside the repository.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import shutil
import sqlite3
import subprocess
import time
import zlib
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = PROJECT_ROOT / "artifacts" / "audit"
N_TOTAL = 7_062_606
BOT_TOTAL = 3_668_522
A4_COMMIT_SHA = "6bf4505fc01000a99f31ed7de3b41c56f058def4"
N_SCOPE = "all_115_features"
LABEL_FIELDS = ("attack", "category", "subcategory")
N_SEEDS = (1729, 2027, 4099)
SPLIT_TEST_FRACTION = 0.20
BOT_LINEAGE_FIELDS = ("stddev", "min", "mean", "drate", "srate", "max")
BOT_ENTITY_FIELDS = ("saddr", "daddr", "sport", "dport", "proto", "state", "flgs")
BOT_ENTITY_COMBINATIONS = (
    ("saddr", "daddr"),
    ("saddr", "dport"),
    ("saddr", "proto"),
    ("daddr", "proto"),
)
BOT_DUPLICATE_SCOPES = {
    "all_non_label_excluding_pkseqid_with_seq": BOT_TOTAL,
    "all_non_label_excluding_pkseqid_without_seq": BOT_TOTAL,
    "ten_best_non_label_excluding_pkseqid_index_with_seq": BOT_TOTAL,
    "ten_best_non_label_excluding_pkseqid_index_without_seq": BOT_TOTAL,
}
HEX_PORT = re.compile(r"^0[xX][0-9a-fA-F]+$")
DECIMAL_PORT = re.compile(r"^[0-9]+$")
NEGATIVE_DECIMAL_PORT = re.compile(r"^-[0-9]+$")

A5_ARTIFACT_NAMES = (
    "n_baiot_effective_imbalance.csv",
    "n_baiot_split_leakage_summary.json",
    "n_baiot_device_holdout_matrix.csv",
    "bot_iot_effective_imbalance.csv",
    "bot_iot_field_risk_profile.csv",
    "bot_iot_entity_overlap_summary.json",
    "bot_iot_identity_free_duplicate_summary.json",
    "bot_iot_port_encoding_summary.json",
    "bot_iot_numeric_lineage_analysis.json",
    "bot_iot_split_feasibility.json",
    "candidate_split_comparison.csv",
)


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv_atomic(path: Path, fieldnames: Sequence[str], rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="raise")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    temporary.replace(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def percentage(numerator: int | float, denominator: int | float) -> float:
    return 0.0 if denominator == 0 else 100.0 * float(numerator) / float(denominator)


def phase_started(name: str) -> float:
    print(f"[A5] START {name}", flush=True)
    return time.perf_counter()


def phase_finished(name: str, started_at: float) -> None:
    print(f"[A5] DONE  {name} ({time.perf_counter() - started_at:.1f}s)", flush=True)


def read_chunks(path: Path, delimiter: str, chunk_size: int) -> Iterator[pd.DataFrame]:
    yield from pd.read_csv(
        path,
        sep=delimiter,
        dtype=str,
        keep_default_na=False,
        na_filter=False,
        chunksize=chunk_size,
        low_memory=False,
    )


def restore_unnamed_leading_header(frame: pd.DataFrame) -> pd.DataFrame:
    if len(frame.columns) and frame.columns[0] == "Unnamed: 0":
        return frame.rename(columns={frame.columns[0]: ""})
    return frame


def encode_exact_row(values: Iterable[str]) -> tuple[bytes, bytes]:
    serialized = bytearray()
    for value in values:
        encoded = value.encode("utf-8")
        serialized.extend(len(encoded).to_bytes(4, "big"))
        serialized.extend(encoded)
    raw = bytes(serialized)
    return hashlib.sha256(raw).digest(), zlib.compress(raw, level=1)


def candidate_hashes(frame: pd.DataFrame, columns: list[str]) -> np.ndarray:
    hashes = pd.util.hash_pandas_object(frame[columns], index=False).to_numpy(np.uint64)
    return hashes.view(np.int64)


def entropy_bits(counter: Counter[str]) -> float:
    total = sum(counter.values())
    if total == 0:
        return 0.0
    return -sum((count / total) * math.log2(count / total) for count in counter.values() if count)


def label_aggregates(fine_counts: Counter[str]) -> dict[str, Counter[str]]:
    binary: Counter[str] = Counter()
    family: Counter[str] = Counter()
    for fine, count in fine_counts.items():
        if fine == "benign":
            binary["benign"] += count
            family["benign"] += count
        else:
            binary["malicious"] += count
            family[fine.split("_", 1)[0]] += count
    return {"binary": binary, "family": family, "fine_class": fine_counts}


def stratified_masks(class_sizes: dict[str, int], seed: int) -> dict[str, np.ndarray]:
    rng = np.random.default_rng(seed)
    result = {}
    for label, size in sorted(class_sizes.items()):
        test_size = int(round(size * SPLIT_TEST_FRACTION))
        mask = np.zeros(size, dtype=np.bool_)
        mask[rng.choice(size, size=test_size, replace=False)] = True
        result[label] = mask
    return result


def three_way_lineage_classification(
    all_value: float, full_value: float, split_value: float
) -> str:
    equals_all = split_value == all_value
    equals_full = split_value == full_value
    if equals_all and equals_full:
        return "equals_both"
    if equals_all:
        return "equals_all_features_only"
    if equals_full:
        return "equals_ten_best_full_only"
    return "equals_neither"


def classify_port_token(token: str) -> str:
    if HEX_PORT.fullmatch(token):
        return "hexadecimal_style"
    if NEGATIVE_DECIMAL_PORT.fullmatch(token):
        return "negative_decimal"
    if DECIMAL_PORT.fullmatch(token):
        return "decimal_integer"
    return "other"


def decimal_parseable(token: str) -> bool:
    try:
        value = Decimal(token)
    except InvalidOperation:
        return False
    return value.is_finite()


@dataclass
class PortProfile:
    total: int = 0
    categories: Counter[str] = field(default_factory=Counter)
    negative_tokens: Counter[str] = field(default_factory=Counter)
    other_tokens: Counter[str] = field(default_factory=Counter)
    hex_tokens: Counter[str] = field(default_factory=Counter)
    hex_min: int | None = None
    hex_max: int | None = None

    def observe(self, token: str, count: int = 1) -> None:
        category = classify_port_token(token)
        self.total += count
        self.categories[category] += count
        if category == "negative_decimal":
            self.negative_tokens[token] += count
        elif category == "other":
            self.other_tokens[token] += count
        elif category == "hexadecimal_style":
            self.hex_tokens[token] += count
            value = int(token, 16)
            self.hex_min = value if self.hex_min is None else min(self.hex_min, value)
            self.hex_max = value if self.hex_max is None else max(self.hex_max, value)

    def as_dict(self) -> dict[str, Any]:
        out_of_standard_range = sum(
            count for token, count in self.hex_tokens.items() if int(token, 16) > 65535
        )
        return {
            "total_values": self.total,
            "lexical_category_counts": dict(sorted(self.categories.items())),
            "unique_negative_tokens": dict(sorted(self.negative_tokens.items())),
            "bounded_other_token_examples": dict(self.other_tokens.most_common(20)),
            "hexadecimal_unique_token_count": len(self.hex_tokens),
            "hexadecimal_parses_losslessly_as_base16": True,
            "hexadecimal_parsed_min": self.hex_min,
            "hexadecimal_parsed_max": self.hex_max,
            "hexadecimal_values_above_65535": out_of_standard_range,
        }


@dataclass
class EntityAccumulator:
    binary: dict[str, Counter[str]] = field(default_factory=dict)
    category: dict[str, Counter[str]] = field(default_factory=dict)
    subcategory: dict[str, Counter[str]] = field(default_factory=dict)

    def observe(
        self,
        key: str,
        attack: str,
        category: str,
        subcategory: str = "",
        count: int = 1,
    ) -> None:
        self.binary.setdefault(key, Counter())[attack] += count
        self.category.setdefault(key, Counter())[category] += count
        if subcategory:
            self.subcategory.setdefault(key, Counter())[subcategory] += count

    def summary(self, low_frequency_threshold: int = 5) -> dict[str, Any]:
        total = sum(sum(counts.values()) for counts in self.binary.values())
        binary_pure = sum(len(counts) == 1 for counts in self.binary.values())
        category_pure = sum(len(counts) == 1 for counts in self.category.values())
        weighted_binary_purity = sum(max(counts.values()) for counts in self.binary.values())
        weighted_category_purity = sum(max(counts.values()) for counts in self.category.values())
        low_frequency_values = sum(
            sum(counts.values()) < low_frequency_threshold for counts in self.binary.values()
        )
        low_frequency_rows = sum(
            sum(counts.values())
            for counts in self.binary.values()
            if sum(counts.values()) < low_frequency_threshold
        )
        return {
            "unique_value_count": len(self.binary),
            "row_count": total,
            "binary_pure_value_count": binary_pure,
            "category_pure_value_count": category_pure,
            "weighted_binary_purity": (weighted_binary_purity / total if total else 0.0),
            "weighted_category_purity": (weighted_category_purity / total if total else 0.0),
            "weighted_binary_entropy_bits": (
                sum(sum(counts.values()) * entropy_bits(counts) for counts in self.binary.values())
                / total
                if total
                else 0.0
            ),
            "weighted_category_entropy_bits": (
                sum(
                    sum(counts.values()) * entropy_bits(counts) for counts in self.category.values()
                )
                / total
                if total
                else 0.0
            ),
            "low_frequency_threshold": low_frequency_threshold,
            "low_frequency_value_count": low_frequency_values,
            "low_frequency_row_count": low_frequency_rows,
            "interpretation": "potential context memorization / scenario dependence",
        }


@dataclass
class SplitEntityOverlap:
    """Track row-weighted test overlap without depending on stream order."""

    train_values: set[str] = field(default_factory=set)
    test_rows_by_value: Counter[str] = field(default_factory=Counter)
    train_rows: int = 0
    test_rows: int = 0

    def observe(self, value: str, is_test: bool) -> None:
        if is_test:
            self.test_rows += 1
            self.test_rows_by_value[value] += 1
        else:
            self.train_rows += 1
            self.train_values.add(value)

    def summary(self) -> dict[str, Any]:
        seen = sum(
            count for value, count in self.test_rows_by_value.items() if value in self.train_values
        )
        return {
            "train_rows": self.train_rows,
            "test_rows": self.test_rows,
            "test_rows_with_value_seen_in_train": seen,
            "test_row_overlap_percent": percentage(seen, self.test_rows),
            "train_unique_values": len(self.train_values),
            "test_unique_values": len(self.test_rows_by_value),
            "shared_unique_values": sum(
                value in self.train_values for value in self.test_rows_by_value
            ),
        }


@dataclass(frozen=True)
class BotSource:
    logical_id: str
    representation: str
    path: Path
    delimiter: str
    row_count: int


class CandidateHashStore:
    """Persist 64-bit candidate hashes and retain only repeated hash values."""

    def __init__(self, temp_dir: Path, scope_sizes: dict[str, int]) -> None:
        self.maps = {
            scope: np.memmap(
                temp_dir / f"a5_candidate_{scope}.bin",
                dtype=np.int64,
                mode="w+",
                shape=(size,),
            )
            for scope, size in scope_sizes.items()
        }
        self.offsets = Counter()
        self.duplicate_hashes: dict[str, np.ndarray] = {}

    def append(self, scope: str, hashes: np.ndarray) -> None:
        start = self.offsets[scope]
        stop = start + len(hashes)
        if stop > len(self.maps[scope]):
            raise ValueError(f"candidate hash store overflow for {scope}")
        self.maps[scope][start:stop] = hashes
        self.offsets[scope] = stop

    def finalize(self) -> dict[str, int]:
        candidate_group_counts = {}
        for scope, values in self.maps.items():
            if self.offsets[scope] != len(values):
                raise ValueError(f"candidate hash store incomplete for {scope}")
            values.flush()
            values.sort()
            if len(values) == 0:
                repeated = np.array([], dtype=np.int64)
            else:
                change = np.empty(len(values), dtype=np.bool_)
                change[0] = True
                change[1:] = values[1:] != values[:-1]
                starts = np.flatnonzero(change)
                counts = np.diff(np.append(starts, len(values)))
                repeated = np.asarray(values[starts[counts > 1]], dtype=np.int64)
            self.duplicate_hashes[scope] = repeated
            candidate_group_counts[scope] = len(repeated)
        return candidate_group_counts

    def candidate_mask(self, scope: str, hashes: np.ndarray) -> np.ndarray:
        repeated = self.duplicate_hashes[scope]
        if not len(repeated):
            return np.zeros(len(hashes), dtype=np.bool_)
        positions = np.searchsorted(repeated, hashes)
        valid = positions < len(repeated)
        result = np.zeros(len(hashes), dtype=np.bool_)
        result[valid] = repeated[positions[valid]] == hashes[valid]
        return result


def initialize_a5_database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=120)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute("PRAGMA temp_store=FILE")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS bot_exact_rows (
            scope TEXT NOT NULL,
            exact_hash BLOB NOT NULL,
            exact_blob BLOB NOT NULL,
            pkseqid INTEGER NOT NULL,
            attack TEXT NOT NULL,
            category TEXT NOT NULL,
            subcategory TEXT NOT NULL
        )
        """
    )
    return connection


def insert_exact_candidates(
    connection: sqlite3.Connection,
    scope: str,
    frame: pd.DataFrame,
    columns: list[str],
    mask: np.ndarray,
) -> int:
    if not mask.any():
        return 0
    selected = frame.loc[mask, ["pkSeqID", *columns, *LABEL_FIELDS]]
    rows = []
    for values in selected.itertuples(index=False, name=None):
        exact_hash, exact_blob = encode_exact_row(values[1 : len(columns) + 1])
        rows.append(
            (
                scope,
                exact_hash,
                exact_blob,
                int(values[0]),
                *values[len(columns) + 1 :],
            )
        )
    connection.executemany("INSERT INTO bot_exact_rows VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
    return len(rows)


def summarize_exact_candidates(
    connection: sqlite3.Connection, scope_totals: dict[str, int]
) -> dict[str, Any]:
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS bot_exact_group_idx
        ON bot_exact_rows(scope, exact_hash, exact_blob)
        """
    )
    connection.commit()
    result = {}
    for scope, total in scope_totals.items():
        row = connection.execute(
            """
            SELECT
                COALESCE(SUM(group_size - 1), 0),
                COALESCE(SUM(group_size), 0),
                COUNT(*),
                COALESCE(SUM(attack_count > 1), 0),
                COALESCE(SUM(category_count > 1), 0),
                COALESCE(SUM(subcategory_count > 1), 0)
            FROM (
                SELECT COUNT(*) AS group_size,
                       COUNT(DISTINCT attack) AS attack_count,
                       COUNT(DISTINCT category) AS category_count,
                       COUNT(DISTINCT subcategory) AS subcategory_count
                FROM bot_exact_rows
                WHERE scope=?
                GROUP BY exact_hash, exact_blob
                HAVING COUNT(*) > 1
            )
            """,
            (scope,),
        ).fetchone()
        duplicate_excess, duplicate_rows, duplicate_groups, attack, category, subcategory = map(
            int, row
        )
        result[scope] = {
            "total_rows": total,
            "unique_tuples": total - duplicate_excess,
            "duplicate_excess": duplicate_excess,
            "duplicate_groups": duplicate_groups,
            "rows_in_duplicate_groups": duplicate_rows,
            "conflicting_attack_groups": attack,
            "conflicting_category_groups": category,
            "conflicting_subcategory_groups": subcategory,
        }
    return result


@dataclass(frozen=True)
class NSource:
    source_id: int
    logical_id: str
    device: str
    binary: str
    family: str
    fine: str
    row_count: int
    class_offset: int


def build_n_sources() -> list[NSource]:
    mapping = sorted(
        load_csv(AUDIT_DIR / "n_baiot_label_mapping.csv"),
        key=lambda row: row["logical_id"],
    )
    offsets: Counter[str] = Counter()
    sources = []
    for source_id, row in enumerate(mapping):
        fine = row["canonical_fine_class"]
        source = NSource(
            source_id=source_id,
            logical_id=row["logical_id"],
            device=row["device"],
            binary=row["canonical_binary"],
            family=row["canonical_family"],
            fine=fine,
            row_count=int(row["row_count"]),
            class_offset=offsets[fine],
        )
        sources.append(source)
        offsets[fine] += source.row_count
    if len(sources) != 89 or sum(source.row_count for source in sources) != N_TOTAL:
        raise ValueError("N-BaIoT source metadata does not reconcile")
    return sources


def imbalance_rows(
    dataset: str,
    representation: str,
    views: dict[str, dict[str, Counter[str]]],
    test_representation: bool = False,
) -> list[dict[str, Any]]:
    rows = []
    for view, levels in views.items():
        for level, counts in levels.items():
            total = sum(counts.values())
            majority = max(counts.values(), default=0)
            minority = min((count for count in counts.values() if count), default=0)
            for label, count in sorted(counts.items()):
                rows.append(
                    {
                        "dataset": dataset,
                        "representation": representation,
                        "view": view,
                        "label_level": level,
                        "label": label,
                        "count": count,
                        "percentage": percentage(count, total),
                        "majority_to_class_ratio": (
                            majority / count if count else "not applicable"
                        ),
                        "majority_to_minority_ratio": (
                            majority / minority if minority else "not applicable"
                        ),
                        "one_error_granularity_percent": (
                            100.0 / count if test_representation and count else "not applicable"
                        ),
                    }
                )
    return rows


def deterministic_group_to_test(exact_hash: bytes, exact_blob: bytes, seed: int) -> bool:
    digest = hashlib.sha256(seed.to_bytes(8, "big") + exact_hash + exact_blob).digest()
    score = int.from_bytes(digest[:8], "big")
    return score < int(SPLIT_TEST_FRACTION * (1 << 64))


def exact_group_boundary_metrics(
    group_test_memberships: Sequence[Sequence[bool]],
) -> dict[str, int]:
    spanning = 0
    test_rows_with_train_match = 0
    for memberships in group_test_memberships:
        test_rows = sum(memberships)
        if test_rows and test_rows < len(memberships):
            spanning += 1
            test_rows_with_train_match += test_rows
    return {
        "spanning_groups": spanning,
        "test_rows_with_train_vector": test_rows_with_train_match,
    }


def device_holdout_overlap_metrics(
    group_devices: Sequence[Sequence[str]], held_out_device: str
) -> dict[str, int | float]:
    test_rows = 0
    matching_test_rows = 0
    test_unique = 0
    seen_in_train = 0
    affected_train_rows = 0
    for devices in group_devices:
        held_count = sum(device == held_out_device for device in devices)
        if not held_count:
            continue
        test_rows += held_count
        test_unique += 1
        outside = len(devices) - held_count
        if outside:
            matching_test_rows += held_count
            seen_in_train += 1
            affected_train_rows += outside
    return {
        "test_rows": test_rows,
        "test_unique_vectors": test_unique,
        "test_rows_with_exact_train_vector": matching_test_rows,
        "test_unique_vectors_seen_in_train": seen_in_train,
        "novel_test_vectors": test_unique - seen_in_train,
        "novel_test_row_percent": percentage(test_rows - matching_test_rows, test_rows),
        "isolation_train_rows_affected": affected_train_rows,
    }


def raw_and_unique_label_counts(
    exact_groups: Sequence[tuple[str, int]], singletons: Counter[str] | None = None
) -> tuple[Counter[str], Counter[str]]:
    raw = Counter(singletons or {})
    unique = Counter(singletons or {})
    for label, size in exact_groups:
        raw[label] += size
        unique[label] += 1
    return raw, unique


def decimal_rounding_explains(first: np.ndarray, second: np.ndarray, digits: int) -> np.ndarray:
    return (np.round(first, digits) == second) | (np.round(second, digits) == first)


def chronological_class_counts(
    times: Sequence[float], labels: Sequence[str], threshold: float
) -> dict[str, Counter[str]]:
    if len(times) != len(labels):
        raise ValueError("times and labels must have equal length")
    result = {"train": Counter(), "test": Counter()}
    for timestamp, label in zip(times, labels, strict=True):
        partition = "test" if timestamp >= threshold else "train"
        result[partition][label] += 1
    return result


def analyze_n_baiot(
    a4_database: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    sources = build_n_sources()
    source_by_id = {source.source_id: source for source in sources}
    raw_fine = Counter()
    raw_device_fine: dict[str, Counter[str]] = defaultdict(Counter)
    for source in sources:
        raw_fine[source.fine] += source.row_count
        raw_device_fine[source.device][source.fine] += source.row_count
    masks = {seed: stratified_masks(dict(raw_fine), seed) for seed in N_SEEDS}

    candidate_fine: Counter[str] = Counter()
    candidate_groups_fine: Counter[str] = Counter()
    candidate_device: Counter[str] = Counter()
    candidate_groups_device: Counter[str] = Counter()
    naive = {seed: {"spanning_groups": 0, "test_rows_with_train_vector": 0} for seed in N_SEEDS}
    group_test_rows: Counter[str] = Counter()
    group_test_groups: Counter[str] = Counter()
    shared_groups_device: Counter[str] = Counter()
    matched_test_rows_device: Counter[str] = Counter()
    affected_train_rows_device: Counter[str] = Counter()
    affected_train_fine: dict[str, Counter[str]] = defaultdict(Counter)
    group_digest = hashlib.sha256()

    connection = sqlite3.connect(f"file:{a4_database.as_posix()}?mode=ro", uri=True, timeout=30)
    try:
        candidate_count, group_count = connection.execute(
            """
            SELECT COALESCE(SUM(occurrence_count), 0), COUNT(*)
            FROM exact_group_stats
            WHERE dataset='n_baiot' AND scope=?
            """,
            (N_SCOPE,),
        ).fetchone()
        if int(candidate_count) != 6_471_566 or int(group_count) != 1_891_636:
            raise ValueError("A4 exact group membership does not match the accepted checkpoint")
        cursor = connection.execute(
            """
            SELECT exact_hash, exact_blob, source_id, row_number, fine_label
            FROM exact_rows INDEXED BY exact_group_idx
            WHERE dataset='n_baiot' AND scope=?
            ORDER BY exact_hash, exact_blob, source_id, row_number
            """,
            (N_SCOPE,),
        )
        current_key: tuple[bytes, bytes] | None = None
        members: list[tuple[int, int, str]] = []

        def consume_group(key: tuple[bytes, bytes], group: list[tuple[int, int, str]]) -> None:
            fine_labels = {member[2] for member in group}
            if len(fine_labels) != 1:
                raise ValueError("A4 exact group crosses N-BaIoT fine labels")
            fine = next(iter(fine_labels))
            size = len(group)
            candidate_fine[fine] += size
            candidate_groups_fine[fine] += 1
            device_counts: Counter[str] = Counter()
            for source_id, _, _ in group:
                device_counts[source_by_id[source_id].device] += 1
            for device, count in device_counts.items():
                candidate_device[device] += count
                candidate_groups_device[device] += 1
                outside = size - count
                if outside:
                    shared_groups_device[device] += 1
                    matched_test_rows_device[device] += count
                    affected_train_rows_device[device] += outside
                    affected_train_fine[device][fine] += outside
            for seed in N_SEEDS:
                test_count = 0
                mask = masks[seed][fine]
                for source_id, row_number, _ in group:
                    source = source_by_id[source_id]
                    test_count += int(mask[source.class_offset + row_number - 1])
                if test_count and test_count < size:
                    naive[seed]["spanning_groups"] += 1
                    naive[seed]["test_rows_with_train_vector"] += test_count
            if deterministic_group_to_test(key[0], key[1], N_SEEDS[0]):
                group_test_rows[fine] += size
                group_test_groups[fine] += 1
            group_digest.update(key[0])
            group_digest.update(hashlib.sha256(key[1]).digest())
            group_digest.update(size.to_bytes(8, "big"))

        for exact_hash, exact_blob, source_id, row_number, fine in cursor:
            key = (bytes(exact_hash), bytes(exact_blob))
            if current_key is not None and key != current_key:
                consume_group(current_key, members)
                members = []
            current_key = key
            members.append((int(source_id), int(row_number), str(fine)))
        if current_key is not None:
            consume_group(current_key, members)
    finally:
        connection.close()

    unique_fine = Counter(
        {
            fine: raw_fine[fine] - candidate_fine[fine] + candidate_groups_fine[fine]
            for fine in raw_fine
        }
    )
    raw_levels = label_aggregates(raw_fine)
    unique_levels = label_aggregates(unique_fine)
    imbalance = []
    for level in ("binary", "family", "fine_class"):
        raw_counts = raw_levels[level]
        unique_counts = unique_levels[level]
        raw_total = sum(raw_counts.values())
        unique_total = sum(unique_counts.values())
        raw_majority = max(raw_counts.values())
        raw_minority = min(raw_counts.values())
        unique_majority = max(unique_counts.values())
        unique_minority = min(unique_counts.values())
        for label in sorted(raw_counts):
            imbalance.append(
                {
                    "dataset": "n_baiot",
                    "label_level": level,
                    "label": label,
                    "raw_row_count": raw_counts[label],
                    "unique_vector_count": unique_counts[label],
                    "duplicate_excess": raw_counts[label] - unique_counts[label],
                    "raw_percentage": percentage(raw_counts[label], raw_total),
                    "unique_vector_percentage": percentage(unique_counts[label], unique_total),
                    "duplication_factor": raw_counts[label] / unique_counts[label],
                    "raw_majority_to_minority_ratio": raw_majority / raw_minority,
                    "unique_majority_to_minority_ratio": (unique_majority / unique_minority),
                }
            )

    naive_runs = []
    test_fine = Counter(
        {fine: int(round(count * SPLIT_TEST_FRACTION)) for fine, count in raw_fine.items()}
    )
    test_total = sum(test_fine.values())
    for seed in N_SEEDS:
        finding = naive[seed]
        naive_runs.append(
            {
                "seed": seed,
                "train_rows": N_TOTAL - test_total,
                "test_rows": test_total,
                "test_rows_with_exact_train_vector": finding["test_rows_with_train_vector"],
                "test_rows_with_exact_train_vector_percent": percentage(
                    finding["test_rows_with_train_vector"], test_total
                ),
                "exact_feature_groups_spanning_train_test": finding["spanning_groups"],
                "train_fine_distribution": dict(raw_fine - test_fine),
                "test_fine_distribution": dict(test_fine),
            }
        )

    group_test_fine: Counter[str] = Counter()
    group_test_unique: Counter[str] = Counter()
    for fine, raw_count in raw_fine.items():
        target = int(round(raw_count * SPLIT_TEST_FRACTION))
        singleton_count = raw_count - candidate_fine[fine]
        singleton_test = max(0, min(singleton_count, target - group_test_rows[fine]))
        group_test_fine[fine] = group_test_rows[fine] + singleton_test
        group_test_unique[fine] = group_test_groups[fine] + singleton_test
    group_train_fine = raw_fine - group_test_fine
    group_unique_train = unique_fine - group_test_unique

    device_rows = []
    for device in sorted(raw_device_fine):
        raw_counts = raw_device_fine[device]
        total = sum(raw_counts.values())
        unique_total = total - candidate_device[device] + candidate_groups_device[device]
        shared_rows = matched_test_rows_device[device]
        shared_groups = shared_groups_device[device]
        train_rows = N_TOTAL - total
        affected_train = affected_train_rows_device[device]
        remaining_train_fine = Counter(
            {
                fine: raw_fine[fine] - raw_counts[fine] - affected_train_fine[device][fine]
                for fine in raw_fine
            }
        )
        remaining_levels = label_aggregates(remaining_train_fine)
        device_rows.append(
            {
                "device": device,
                "test_rows": total,
                "test_unique_vectors": unique_total,
                "duplicate_fraction_percent": percentage(total - unique_total, total),
                "binary_coverage": "|".join(sorted(label_aggregates(raw_counts)["binary"])),
                "family_coverage": "|".join(sorted(label_aggregates(raw_counts)["family"])),
                "fine_coverage": "|".join(sorted(raw_counts)),
                "test_rows_with_exact_train_vector": shared_rows,
                "test_rows_with_exact_train_vector_percent": percentage(shared_rows, total),
                "test_unique_vectors_seen_in_train": shared_groups,
                "genuinely_novel_test_vectors": unique_total - shared_groups,
                "genuinely_novel_test_rows": total - shared_rows,
                "genuinely_novel_test_row_percent": percentage(total - shared_rows, total),
                "isolation_train_rows_affected": affected_train,
                "isolation_train_rows_affected_percent": percentage(affected_train, train_rows),
                "isolation_train_unique_vectors_excluded": shared_groups,
                "isolated_test_rows_exact_vector_novel": total,
                "isolated_test_novel_row_percent": 100.0,
                "remaining_train_binary_coverage": "|".join(sorted(remaining_levels["binary"])),
                "remaining_train_family_coverage": "|".join(sorted(remaining_levels["family"])),
                "remaining_train_fine_coverage": "|".join(
                    sorted(label for label, count in remaining_train_fine.items() if count > 0)
                ),
                "coverage_note": (
                    "No observed Mirai archive; coverage limitation, not corruption."
                    if device in {"Ennio_Doorbell", "Samsung_SNH_1011_N_Webcam"}
                    else ""
                ),
            }
        )

    naive_percentages = [row["test_rows_with_exact_train_vector_percent"] for row in naive_runs]
    split_summary = {
        "raw_fine_class_counts": dict(sorted(raw_fine.items())),
        "unique_vector_fine_class_counts": dict(sorted(unique_fine.items())),
        "effective_imbalance_ratios": {
            level: {
                "raw_majority_to_minority": max(raw_levels[level].values())
                / min(raw_levels[level].values()),
                "unique_vector_majority_to_minority": max(unique_levels[level].values())
                / min(unique_levels[level].values()),
            }
            for level in ("binary", "family", "fine_class")
        },
        "exact_group_membership_digest": group_digest.hexdigest(),
        "naive_stratified_row_random": {
            "split": "80% train / 20% test, stratified by canonical fine class",
            "runs": naive_runs,
            "overlap_percent_mean": float(np.mean(naive_percentages)),
            "overlap_percent_min": min(naive_percentages),
            "overlap_percent_max": max(naive_percentages),
            "recommendation_status": "diagnostic only; not adopted",
        },
        "exact_feature_group_aware": {
            "seed": N_SEEDS[0],
            "assignment": (
                "confirmed multi-row exact groups assigned by deterministic SHA-256 score; "
                "singleton vectors fill remaining per-class test target where possible"
            ),
            "train_rows": sum(group_train_fine.values()),
            "test_rows": sum(group_test_fine.values()),
            "train_unique_vectors": sum(group_unique_train.values()),
            "test_unique_vectors": sum(group_test_unique.values()),
            "train_fine_distribution": dict(sorted(group_train_fine.items())),
            "test_fine_distribution": dict(sorted(group_test_fine.items())),
            "exact_feature_overlap_groups": 0,
            "exact_feature_overlap_rows": 0,
            "distribution_drift_percentage_points": {
                fine: percentage(group_test_fine[fine], sum(group_test_fine.values()))
                - percentage(raw_fine[fine], N_TOTAL)
                for fine in sorted(raw_fine)
            },
            "recommendation_status": "diagnostic only; not adopted",
        },
        "leave_one_device_out": {row["device"]: row for row in device_rows},
        "device_holdout_vector_isolation": {
            "semantics": (
                "counterfactual exclusion of every training occurrence whose exact vector "
                "appears in the held-out device; no cleaned split was written"
            )
        },
    }

    candidate_rows = []
    for run in naive_runs:
        candidate_rows.append(
            {
                "dataset": "n_baiot",
                "candidate_name": f"N1 naive stratified row random seed {run['seed']}",
                "train_rows": run["train_rows"],
                "test_rows": run["test_rows"],
                "binary_class_coverage": "benign|malicious",
                "fine_or_category_coverage": len(raw_fine),
                "exact_feature_overlap_percent": run["test_rows_with_exact_train_vector_percent"],
                "entity_overlap_percent": "not applicable",
                "temporal_overlap_finding": "not applicable",
                "rare_class_min_support": min(test_fine.values()),
                "major_limitation": "duplicate leakage across row-random boundaries",
                "status": "diagnostic only",
            }
        )
    candidate_rows.append(
        {
            "dataset": "n_baiot",
            "candidate_name": "N2 exact-feature-group-aware",
            "train_rows": sum(group_train_fine.values()),
            "test_rows": sum(group_test_fine.values()),
            "binary_class_coverage": "benign|malicious",
            "fine_or_category_coverage": sum(value > 0 for value in group_test_fine.values()),
            "exact_feature_overlap_percent": 0.0,
            "entity_overlap_percent": "not applicable",
            "temporal_overlap_finding": "not applicable",
            "rare_class_min_support": min(group_test_fine.values()),
            "major_limitation": "does not independently test unseen devices or contexts",
            "status": "diagnostic only",
        }
    )
    for row in device_rows:
        candidate_rows.extend(
            [
                {
                    "dataset": "n_baiot",
                    "candidate_name": f"N3 leave-one-device-out: {row['device']}",
                    "train_rows": N_TOTAL - row["test_rows"],
                    "test_rows": row["test_rows"],
                    "binary_class_coverage": row["binary_coverage"],
                    "fine_or_category_coverage": len(row["fine_coverage"].split("|")),
                    "exact_feature_overlap_percent": row[
                        "test_rows_with_exact_train_vector_percent"
                    ],
                    "entity_overlap_percent": "not applicable",
                    "temporal_overlap_finding": "not applicable",
                    "rare_class_min_support": "not summarized; see device matrix",
                    "major_limitation": (
                        "device-specific class coverage and cross-device duplicate leakage"
                    ),
                    "status": "diagnostic only",
                },
                {
                    "dataset": "n_baiot",
                    "candidate_name": (f"N4 device holdout plus vector isolation: {row['device']}"),
                    "train_rows": (
                        N_TOTAL - row["test_rows"] - row["isolation_train_rows_affected"]
                    ),
                    "test_rows": row["test_rows"],
                    "binary_class_coverage": row["binary_coverage"],
                    "fine_or_category_coverage": len(row["fine_coverage"].split("|")),
                    "exact_feature_overlap_percent": 0.0,
                    "entity_overlap_percent": "not applicable",
                    "temporal_overlap_finding": "not applicable",
                    "rare_class_min_support": "not summarized; see device matrix",
                    "major_limitation": (
                        "counterfactual removes matching training rows; no split materialized"
                    ),
                    "status": "diagnostic only",
                },
            ]
        )
    return imbalance, split_summary, device_rows, candidate_rows


def build_bot_sources(bot_root: Path) -> dict[str, list[BotSource]]:
    grouped: dict[str, list[BotSource]] = defaultdict(list)
    for row in load_csv(AUDIT_DIR / "bot_iot_csv_structure.csv"):
        delimiter = {"comma": ",", "semicolon": ";"}[row["delimiter"]]
        path = bot_root / Path(row["source_relative_path"])
        if not path.is_file():
            raise FileNotFoundError(path)
        if path.stat().st_size != int(row["size_bytes"]):
            raise ValueError(f"Bot-IoT source size changed: {path}")
        grouped[row["representation"]].append(
            BotSource(
                logical_id=row["logical_id"],
                representation=row["representation"],
                path=path,
                delimiter=delimiter,
                row_count=int(row["row_count"]),
            )
        )
    for sources in grouped.values():
        sources.sort(key=lambda source: source.logical_id)
    expected = {
        "all_features_5pct_shards": BOT_TOTAL,
        "ten_best_full": BOT_TOTAL,
        "ten_best_predefined_train": 2_934_817,
        "ten_best_predefined_test": 733_705,
    }
    observed = {
        representation: sum(source.row_count for source in sources)
        for representation, sources in grouped.items()
    }
    if observed != expected:
        raise ValueError(f"Bot-IoT structure metadata does not reconcile: {observed}")
    return dict(grouped)


def normalized_attack(value: str) -> str:
    return {"0": "benign", "1": "malicious"}.get(value, value.casefold())


def update_label_counts(counts: dict[str, Counter[str]], frame: pd.DataFrame) -> None:
    counts["binary"].update(
        {
            normalized_attack(str(key)): int(value)
            for key, value in frame["attack"].value_counts().items()
        }
    )
    counts["category"].update(
        {str(key).casefold(): int(value) for key, value in frame["category"].value_counts().items()}
    )
    counts["subcategory"].update(
        {
            str(key).casefold(): int(value)
            for key, value in frame["subcategory"].value_counts().items()
        }
    )


def entity_key_from_values(values: Sequence[str]) -> str:
    return "\x1f".join(values)


def update_entity_accumulator(
    accumulator: EntityAccumulator,
    frame: pd.DataFrame,
    fields: tuple[str, ...],
) -> None:
    columns = [*fields, *LABEL_FIELDS]
    grouped = frame.groupby(columns, sort=False, dropna=False).size()
    for keys, count in grouped.items():
        if not isinstance(keys, tuple):
            keys = (keys,)
        entity_values = tuple(str(value) for value in keys[: len(fields)])
        attack, category, subcategory = (str(value) for value in keys[len(fields) :])
        accumulator.observe(
            entity_key_from_values(entity_values),
            normalized_attack(attack),
            category.casefold(),
            subcategory.casefold(),
            int(count),
        )


def update_port_profiles(
    sport: PortProfile,
    dport: PortProfile,
    frame: pd.DataFrame,
    cooccurrence: Counter[str],
) -> None:
    for token, count in frame["sport"].value_counts().items():
        sport.observe(str(token), int(count))
    for token, count in frame["dport"].value_counts().items():
        dport.observe(str(token), int(count))
    sport_failure = ~frame["sport"].map(decimal_parseable).to_numpy()
    dport_failure = ~frame["dport"].map(decimal_parseable).to_numpy()
    cooccurrence["sport_parse_failure_rows"] += int(sport_failure.sum())
    cooccurrence["dport_parse_failure_rows"] += int(dport_failure.sum())
    cooccurrence["both_parse_failure_rows"] += int((sport_failure & dport_failure).sum())
    cooccurrence["either_parse_failure_rows"] += int((sport_failure | dport_failure).sum())


def range_update(
    target: dict[str, dict[str, float | int | None]],
    key: str,
    values: np.ndarray,
) -> None:
    if not len(values):
        return
    profile = target.setdefault(key, {"rows": 0, "min": None, "max": None})
    minimum = float(np.min(values))
    maximum = float(np.max(values))
    profile["rows"] = int(profile["rows"] or 0) + len(values)
    profile["min"] = minimum if profile["min"] is None else min(float(profile["min"]), minimum)
    profile["max"] = maximum if profile["max"] is None else max(float(profile["max"]), maximum)


def fixed_range_bin(identifier: int, total: int, bins: int = 20) -> int:
    if identifier < 1 or identifier > total:
        raise ValueError(f"identifier outside 1..{total}: {identifier}")
    return min(bins - 1, (identifier - 1) * bins // total)


def range_label_summary(
    profiles: dict[int, dict[str, Counter[str]]], total: int, bins: int = 20
) -> dict[str, Any]:
    rows = []
    for bin_number in range(bins):
        start = bin_number * total // bins + 1
        stop = (bin_number + 1) * total // bins
        levels = profiles.get(bin_number, {})
        rows.append(
            {
                "bin": bin_number,
                "inclusive_start": start,
                "inclusive_end": stop,
                "binary_counts": dict(sorted(levels.get("binary", Counter()).items())),
                "category_counts": dict(sorted(levels.get("category", Counter()).items())),
                "subcategory_counts": dict(sorted(levels.get("subcategory", Counter()).items())),
            }
        )
    concentration = {}
    for level in ("binary", "category", "subcategory"):
        label_bins: dict[str, Counter[int]] = defaultdict(Counter)
        for bin_number, level_counts in profiles.items():
            for label, count in level_counts.get(level, {}).items():
                label_bins[label][bin_number] += count
        concentration[level] = {
            label: {
                "total": sum(counts.values()),
                "largest_single_bin_fraction": max(counts.values()) / sum(counts.values()),
                "occupied_bins": len(counts),
            }
            for label, counts in sorted(label_bins.items())
        }
    return {"bin_count": bins, "bins": rows, "label_range_concentration": concentration}


def order_alignment_finding(summary: dict[str, Any]) -> dict[str, Any]:
    concentrated = []
    for level, labels in summary["label_range_concentration"].items():
        for label, profile in labels.items():
            if profile["largest_single_bin_fraction"] >= 0.8 or profile["occupied_bins"] <= 2:
                concentrated.append(
                    {
                        "label_level": level,
                        "label": label,
                        **profile,
                    }
                )
    return {
        "strong_range_alignment_observed": bool(concentrated),
        "criterion": "largest bin contains >=80% of a label or label occupies <=2 of 20 bins",
        "concentrated_labels": concentrated,
        "interpretation": "IDENTIFIER LEAKAGE RISK, not a model result",
    }


def update_range_profile(
    profiles: dict[int, dict[str, Counter[str]]],
    identifiers: np.ndarray,
    frame: pd.DataFrame,
) -> None:
    bins = np.minimum(19, (identifiers - 1) * 20 // BOT_TOTAL)
    temporary = pd.DataFrame(
        {
            "bin": bins,
            "binary": frame["attack"].map(normalized_attack).to_numpy(),
            "category": frame["category"].str.casefold().to_numpy(),
            "subcategory": frame["subcategory"].str.casefold().to_numpy(),
        }
    )
    for (bin_number, binary, category, subcategory), count in temporary.value_counts().items():
        profile = profiles.setdefault(
            int(bin_number),
            {"binary": Counter(), "category": Counter(), "subcategory": Counter()},
        )
        profile["binary"][str(binary)] += int(count)
        profile["category"][str(category)] += int(count)
        profile["subcategory"][str(subcategory)] += int(count)


class NumericLineageAccumulator:
    def __init__(self, temp_dir: Path, a4_temp_dir: Path) -> None:
        self.all_values = {
            name: np.memmap(
                a4_temp_dir / f"bot_all_numeric_{name}.bin",
                dtype=np.float64,
                mode="r",
                shape=(BOT_TOTAL + 1,),
            )
            for name in BOT_LINEAGE_FIELDS
        }
        self.full_values = {
            name: np.memmap(
                temp_dir / f"bot_ten_best_full_{name}.bin",
                dtype=np.float64,
                mode="w+",
                shape=(BOT_TOTAL + 1,),
            )
            for name in BOT_LINEAGE_FIELDS
        }
        self.absolute_deltas = {
            name: np.memmap(
                temp_dir / f"bot_abs_delta_{name}.bin",
                dtype=np.float64,
                mode="w+",
                shape=(BOT_TOTAL,),
            )
            for name in BOT_LINEAGE_FIELDS
        }
        self.relative_deltas = {
            name: np.memmap(
                temp_dir / f"bot_rel_delta_{name}.bin",
                dtype=np.float64,
                mode="w+",
                shape=(BOT_TOTAL,),
            )
            for name in BOT_LINEAGE_FIELDS
        }
        self.difference_counts = Counter()
        self.relative_counts = Counter()
        self.rounding_matches = {
            name: {digits: 0 for digits in range(13)} for name in BOT_LINEAGE_FIELDS
        }
        self.examples: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def compare_full_chunk(self, frame: pd.DataFrame) -> None:
        identifiers = frame["pkSeqID"].to_numpy(np.int64)
        for name in BOT_LINEAGE_FIELDS:
            all_values = np.asarray(self.all_values[name][identifiers])
            full_values = frame[name].to_numpy(np.float64)
            self.full_values[name][identifiers] = full_values
            differs = all_values != full_values
            count = int(differs.sum())
            if not count:
                continue
            start = self.difference_counts[name]
            stop = start + count
            absolute = np.abs(all_values[differs] - full_values[differs])
            self.absolute_deltas[name][start:stop] = absolute
            denominator = np.abs(all_values[differs])
            meaningful = denominator > 0
            relative = absolute[meaningful] / denominator[meaningful]
            relative_start = self.relative_counts[name]
            self.relative_deltas[name][relative_start : relative_start + len(relative)] = relative
            self.relative_counts[name] += len(relative)
            self.difference_counts[name] = stop
            for digits in range(13):
                self.rounding_matches[name][digits] += int(
                    decimal_rounding_explains(
                        all_values[differs], full_values[differs], digits
                    ).sum()
                )
            if len(self.examples[name]) < 10:
                indices = np.flatnonzero(differs)[: 10 - len(self.examples[name])]
                for index in indices:
                    self.examples[name].append(
                        {
                            "pkSeqID": int(identifiers[index]),
                            "all_features": float(all_values[index]),
                            "ten_best_full": float(full_values[index]),
                            "absolute_delta": float(abs(all_values[index] - full_values[index])),
                        }
                    )

    def summarize(self) -> dict[str, Any]:
        fields = {}
        for name in BOT_LINEAGE_FIELDS:
            count = self.difference_counts[name]
            relative_count = self.relative_counts[name]
            absolute = np.asarray(self.absolute_deltas[name][:count])
            relative = np.asarray(self.relative_deltas[name][:relative_count])
            perfect_rounding = [
                digits
                for digits, matches in self.rounding_matches[name].items()
                if count and matches == count
            ]
            fields[name] = {
                "differing_rows": count,
                "absolute_delta": distribution_summary(absolute),
                "relative_delta_where_all_features_nonzero": distribution_summary(relative),
                "bounded_examples": self.examples[name],
                "rounding_rule_candidate_digits_with_all_differences_explained": perfect_rounding,
                "rounding_conclusion": (
                    "consistent decimal rounding candidate observed; not adopted"
                    if perfect_rounding
                    else (
                        "not explained by one tested symmetric decimal-rounding rule (0..12 digits)"
                    )
                ),
            }
        return fields


def distribution_summary(values: np.ndarray) -> dict[str, Any]:
    if not len(values):
        return {"count": 0, "min": None, "p50": None, "p90": None, "p99": None, "max": None}
    quantiles = np.quantile(values, [0.5, 0.9, 0.99])
    return {
        "count": len(values),
        "min": float(np.min(values)),
        "p50": float(quantiles[0]),
        "p90": float(quantiles[1]),
        "p99": float(quantiles[2]),
        "max": float(np.max(values)),
    }


def duplicate_scope_columns(frame: pd.DataFrame, representation: str) -> dict[str, list[str]]:
    named = [column for column in frame.columns if column not in {"", *LABEL_FIELDS}]
    with_seq = [column for column in named if column != "pkSeqID"]
    without_seq = [column for column in with_seq if column != "seq"]
    if representation == "all_features_5pct_shards":
        return {
            "all_non_label_excluding_pkseqid_with_seq": with_seq,
            "all_non_label_excluding_pkseqid_without_seq": without_seq,
        }
    if representation == "ten_best_full":
        return {
            "ten_best_non_label_excluding_pkseqid_index_with_seq": with_seq,
            "ten_best_non_label_excluding_pkseqid_index_without_seq": without_seq,
        }
    raise ValueError(f"no duplicate scopes for {representation}")


def update_split_overlap_chunk(
    accumulator: SplitEntityOverlap,
    values: pd.Series,
    test_mask: np.ndarray,
) -> None:
    temporary = pd.DataFrame({"value": values.astype(str).to_numpy(), "is_test": test_mask})
    for (value, is_test), count in temporary.value_counts(sort=False).items():
        count = int(count)
        if bool(is_test):
            accumulator.test_rows += count
            accumulator.test_rows_by_value[str(value)] += count
        else:
            accumulator.train_rows += count
            accumulator.train_values.add(str(value))


def combined_series(frame: pd.DataFrame, fields: tuple[str, ...]) -> pd.Series:
    if len(fields) == 1:
        return frame[fields[0]].astype(str)
    return frame.loc[:, list(fields)].astype(str).agg("\x1f".join, axis=1)


def deterministic_entity_test(value: str, seed: int = N_SEEDS[0]) -> bool:
    digest = hashlib.sha256(seed.to_bytes(8, "big") + value.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") < int(SPLIT_TEST_FRACTION * (1 << 64))


def entity_group_split(accumulator: EntityAccumulator) -> dict[str, Any]:
    train = {
        "binary": Counter(),
        "category": Counter(),
        "subcategory": Counter(),
    }
    test = {
        "binary": Counter(),
        "category": Counter(),
        "subcategory": Counter(),
    }
    for value, binary_counts in accumulator.binary.items():
        target = test if deterministic_entity_test(value) else train
        target["binary"].update(binary_counts)
        target["category"].update(accumulator.category[value])
        target["subcategory"].update(accumulator.subcategory[value])
    train_rows = sum(train["binary"].values())
    test_rows = sum(test["binary"].values())
    return {
        "assignment": "deterministic SHA-256 grouping at nominal 20% test",
        "train_rows": train_rows,
        "test_rows": test_rows,
        "test_fraction_percent": percentage(test_rows, train_rows + test_rows),
        "train_distributions": {
            level: dict(sorted(values.items())) for level, values in train.items()
        },
        "test_distributions": {
            level: dict(sorted(values.items())) for level, values in test.items()
        },
        "test_binary_coverage": len(test["binary"]),
        "test_category_coverage": len(test["category"]),
        "test_subcategory_coverage": len(test["subcategory"]),
        "minimum_test_subcategory_support": min(test["subcategory"].values(), default=0),
    }


def field_risk_rows(all_columns: list[str]) -> list[dict[str, Any]]:
    rows = []
    for field_name in [*all_columns, ""]:
        if field_name in LABEL_FIELDS:
            role = "label/target metadata"
            risk = "DIRECT TARGET LEAKAGE"
            evidence = "Observed target field in every representation."
        elif field_name == "pkSeqID":
            role = "explicit identifier/index"
            risk = "IDENTIFIER LEAKAGE RISK"
            evidence = "Feature workbook defines pkSeqID as Row Identifier; A4 proved uniqueness."
        elif field_name == "":
            role = "explicit identifier/index"
            risk = "IDENTIFIER LEAKAGE RISK"
            evidence = (
                "A4 proved the 10-best leading value equals zero-based physical row position."
            )
        elif field_name in {"stime", "ltime", "seq"}:
            role = "temporal/order field"
            risk = "TEMPORAL LEAKAGE RISK"
            definitions = {
                "stime": "Record start time",
                "ltime": "Record last time",
                "seq": "Argus sequence number",
            }
            evidence = f"Feature workbook definition: {definitions[field_name]}."
        elif field_name in {"saddr", "daddr", "sport", "dport"}:
            role = "network entity/context field"
            risk = "ENTITY/CONTEXT MEMORIZATION RISK"
            evidence = (
                "Documented address/port context; predictiveness alone is not called leakage."
            )
        else:
            role = "behavioral/statistical field"
            risk = "audit role only; no final predictor decision"
            evidence = "Documented traffic-derived or encoded protocol/state statistic."
        rows.append(
            {
                "field_name": field_name if field_name else "<unnamed_leading_index>",
                "observed_in": "all_features" if field_name else "ten_best_full",
                "audit_role": role,
                "risk_terminology": risk,
                "documentation_evidence": evidence,
                "final_predictor_status": "unresolved; A5 diagnostic only",
            }
        )
    return rows


def new_label_levels() -> dict[str, Counter[str]]:
    return {"binary": Counter(), "category": Counter(), "subcategory": Counter()}


def update_three_way_counts(
    counts: dict[str, Counter[str]],
    lineage: NumericLineageAccumulator,
    frame: pd.DataFrame,
) -> None:
    identifiers = frame["pkSeqID"].to_numpy(np.int64)
    for field_name in BOT_LINEAGE_FIELDS:
        all_values = np.asarray(lineage.all_values[field_name][identifiers])
        full_values = np.asarray(lineage.full_values[field_name][identifiers])
        split_values = frame[field_name].to_numpy(np.float64)
        equals_all = split_values == all_values
        equals_full = split_values == full_values
        counts[field_name]["equals_both"] += int((equals_all & equals_full).sum())
        counts[field_name]["equals_all_features_only"] += int((equals_all & ~equals_full).sum())
        counts[field_name]["equals_ten_best_full_only"] += int((~equals_all & equals_full).sum())
        counts[field_name]["equals_neither"] += int((~equals_all & ~equals_full).sum())


def analyze_bot_iot(
    bot_root: Path,
    temp_dir: Path,
    a4_temp_dir: Path,
    chunk_size: int,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    list[dict[str, Any]],
]:
    sources = build_bot_sources(bot_root)
    a4_database = a4_temp_dir / "a4_audit.sqlite"
    if not a4_database.is_file():
        raise FileNotFoundError(a4_database)
    hash_store = CandidateHashStore(temp_dir, BOT_DUPLICATE_SCOPES)
    database_path = temp_dir / "a5_bot_identity_free.sqlite"
    if database_path.exists():
        raise FileExistsError(f"refusing to overwrite A5 temporary database: {database_path}")
    connection = initialize_a5_database(database_path)
    lineage = NumericLineageAccumulator(temp_dir, a4_temp_dir)
    stime_by_id = np.memmap(
        temp_dir / "bot_all_stime.bin",
        dtype=np.float64,
        mode="w+",
        shape=(BOT_TOTAL + 1,),
    )
    ltime_by_id = np.memmap(
        temp_dir / "bot_all_ltime.bin",
        dtype=np.float64,
        mode="w+",
        shape=(BOT_TOTAL + 1,),
    )
    label_counts = {
        representation: new_label_levels()
        for representation in (
            "all_features_5pct_shards",
            "ten_best_full",
            "ten_best_predefined_train",
            "ten_best_predefined_test",
        )
    }
    entity_accumulators = {
        field_name: EntityAccumulator()
        for field_name in (*BOT_ENTITY_FIELDS, *BOT_ENTITY_COMBINATIONS)
    }
    sport_profile = PortProfile()
    dport_profile = PortProfile()
    port_cooccurrence: Counter[str] = Counter()
    pk_profiles: dict[int, dict[str, Counter[str]]] = {}
    index_profiles: dict[int, dict[str, Counter[str]]] = {}
    temporal_by_category: dict[str, dict[str, float | int | None]] = {}
    temporal_by_binary: dict[str, dict[str, float | int | None]] = {}
    temporal_by_source: dict[str, dict[str, float | int | None]] = {}
    temporal_global = {"stime_min": None, "stime_max": None, "ltime_min": None, "ltime_max": None}
    monotonic_violations = 0
    prior_stime: float | None = None
    all_columns: list[str] = []
    all_scope_columns: dict[str, list[str]] = {}
    full_scope_columns: dict[str, list[str]] = {}

    started = phase_started("scan Bot-IoT all-features audit surfaces and candidate hashes")
    all_rows = 0
    for source in sources["all_features_5pct_shards"]:
        source_rows = 0
        source_stime_min: float | None = None
        source_stime_max: float | None = None
        source_ltime_min: float | None = None
        source_ltime_max: float | None = None
        for frame in read_chunks(source.path, source.delimiter, chunk_size):
            frame = restore_unnamed_leading_header(frame)
            if not all_columns:
                all_columns = list(frame.columns)
                all_scope_columns = duplicate_scope_columns(frame, source.representation)
            identifiers = frame["pkSeqID"].to_numpy(np.int64)
            if identifiers.min() < 1 or identifiers.max() > BOT_TOTAL:
                raise ValueError("Bot-IoT pkSeqID outside accepted range")
            update_label_counts(label_counts[source.representation], frame)
            update_range_profile(pk_profiles, identifiers, frame)
            update_port_profiles(sport_profile, dport_profile, frame, port_cooccurrence)
            for field_name in BOT_ENTITY_FIELDS:
                update_entity_accumulator(entity_accumulators[field_name], frame, (field_name,))
            for fields in BOT_ENTITY_COMBINATIONS:
                update_entity_accumulator(entity_accumulators[fields], frame, fields)
            stime = frame["stime"].to_numpy(np.float64)
            ltime = frame["ltime"].to_numpy(np.float64)
            stime_by_id[identifiers] = stime
            ltime_by_id[identifiers] = ltime
            if prior_stime is not None:
                monotonic_violations += int(stime[0] < prior_stime)
            monotonic_violations += int((stime[1:] < stime[:-1]).sum())
            prior_stime = float(stime[-1])
            source_stime_min = (
                float(stime.min())
                if source_stime_min is None
                else min(source_stime_min, float(stime.min()))
            )
            source_stime_max = (
                float(stime.max())
                if source_stime_max is None
                else max(source_stime_max, float(stime.max()))
            )
            source_ltime_min = (
                float(ltime.min())
                if source_ltime_min is None
                else min(source_ltime_min, float(ltime.min()))
            )
            source_ltime_max = (
                float(ltime.max())
                if source_ltime_max is None
                else max(source_ltime_max, float(ltime.max()))
            )
            temporal_global["stime_min"] = (
                float(stime.min())
                if temporal_global["stime_min"] is None
                else min(float(temporal_global["stime_min"]), float(stime.min()))
            )
            temporal_global["stime_max"] = (
                float(stime.max())
                if temporal_global["stime_max"] is None
                else max(float(temporal_global["stime_max"]), float(stime.max()))
            )
            temporal_global["ltime_min"] = (
                float(ltime.min())
                if temporal_global["ltime_min"] is None
                else min(float(temporal_global["ltime_min"]), float(ltime.min()))
            )
            temporal_global["ltime_max"] = (
                float(ltime.max())
                if temporal_global["ltime_max"] is None
                else max(float(temporal_global["ltime_max"]), float(ltime.max()))
            )
            for category, indices in frame.groupby(
                frame["category"].str.casefold()
            ).indices.items():
                range_update(temporal_by_category, str(category), stime[indices])
            normalized_binary = frame["attack"].map(normalized_attack)
            for binary, indices in frame.groupby(normalized_binary).indices.items():
                range_update(temporal_by_binary, str(binary), stime[indices])
            for scope, columns in all_scope_columns.items():
                hash_store.append(scope, candidate_hashes(frame, columns))
            all_rows += len(frame)
            source_rows += len(frame)
        if source_rows != source.row_count:
            raise ValueError(f"row count changed for {source.path}")
        temporal_by_source[source.logical_id] = {
            "rows": source_rows,
            "stime_min": source_stime_min,
            "stime_max": source_stime_max,
            "ltime_min": source_ltime_min,
            "ltime_max": source_ltime_max,
        }
    if all_rows != BOT_TOTAL:
        raise ValueError("Bot-IoT all-features row total does not reconcile")
    stime_by_id.flush()
    ltime_by_id.flush()
    phase_finished("scan Bot-IoT all-features audit surfaces and candidate hashes", started)

    started = phase_started("scan Bot-IoT 10-best full candidate hashes and numeric lineage")
    full_rows = 0
    for source in sources["ten_best_full"]:
        for frame in read_chunks(source.path, source.delimiter, chunk_size):
            frame = restore_unnamed_leading_header(frame)
            if not full_scope_columns:
                full_scope_columns = duplicate_scope_columns(frame, source.representation)
            expected_index = np.arange(full_rows, full_rows + len(frame), dtype=np.int64)
            if not np.array_equal(frame[""].to_numpy(np.int64), expected_index):
                raise ValueError("10-best unnamed index no longer equals physical row position")
            identifiers = frame["pkSeqID"].to_numpy(np.int64)
            update_label_counts(label_counts[source.representation], frame)
            update_range_profile(index_profiles, expected_index + 1, frame)
            lineage.compare_full_chunk(frame)
            for scope, columns in full_scope_columns.items():
                hash_store.append(scope, candidate_hashes(frame, columns))
            full_rows += len(frame)
    if full_rows != BOT_TOTAL:
        raise ValueError("Bot-IoT 10-best full row total does not reconcile")
    for values in lineage.full_values.values():
        values.flush()
    phase_finished("scan Bot-IoT 10-best full candidate hashes and numeric lineage", started)

    candidate_hash_groups = hash_store.finalize()

    supplied_fields: tuple[str | tuple[str, ...], ...] = (
        "saddr",
        "daddr",
        "sport",
        "dport",
        "proto",
        *BOT_ENTITY_COMBINATIONS,
    )
    supplied_train_values: dict[str | tuple[str, ...], set[str]] = {
        field_name: set() for field_name in supplied_fields
    }
    supplied_overlap_rows: Counter[str | tuple[str, ...]] = Counter()
    supplied_test_rows = 0
    supplied_temporal = {
        "train": {"min": None, "max": None, "rows": 0},
        "test": {"min": None, "max": None, "rows": 0, "within_train_range": 0},
    }
    three_way = {
        "ten_best_predefined_train": {name: Counter() for name in BOT_LINEAGE_FIELDS},
        "ten_best_predefined_test": {name: Counter() for name in BOT_LINEAGE_FIELDS},
    }

    started = phase_started("scan supplied Bot-IoT train split")
    for source in sources["ten_best_predefined_train"]:
        for frame in read_chunks(source.path, source.delimiter, chunk_size):
            update_label_counts(label_counts[source.representation], frame)
            identifiers = frame["pkSeqID"].to_numpy(np.int64)
            stime = np.asarray(stime_by_id[identifiers])
            range_update({"train": supplied_temporal["train"]}, "train", stime)
            for key in supplied_train_values:
                fields = (key,) if isinstance(key, str) else key
                supplied_train_values[key].update(combined_series(frame, fields).unique())
            update_three_way_counts(three_way[source.representation], lineage, frame)
    phase_finished("scan supplied Bot-IoT train split", started)

    started = phase_started("scan supplied Bot-IoT test split")
    train_min = float(supplied_temporal["train"]["min"])
    train_max = float(supplied_temporal["train"]["max"])
    for source in sources["ten_best_predefined_test"]:
        for frame in read_chunks(source.path, source.delimiter, chunk_size):
            update_label_counts(label_counts[source.representation], frame)
            identifiers = frame["pkSeqID"].to_numpy(np.int64)
            stime = np.asarray(stime_by_id[identifiers])
            range_update({"test": supplied_temporal["test"]}, "test", stime)
            supplied_temporal["test"]["within_train_range"] += int(
                ((stime >= train_min) & (stime <= train_max)).sum()
            )
            for key, train_values in supplied_train_values.items():
                fields = (key,) if isinstance(key, str) else key
                values = combined_series(frame, fields)
                supplied_overlap_rows[key] += int(values.isin(train_values).sum())
            supplied_test_rows += len(frame)
            update_three_way_counts(three_way[source.representation], lineage, frame)
    phase_finished("scan supplied Bot-IoT test split", started)
    if supplied_test_rows != 733_705:
        raise ValueError("supplied Bot-IoT test row total does not reconcile")
    expected_representation_rows = {
        "all_features_5pct_shards": BOT_TOTAL,
        "ten_best_full": BOT_TOTAL,
        "ten_best_predefined_train": 2_934_817,
        "ten_best_predefined_test": 733_705,
    }
    for representation, expected_rows in expected_representation_rows.items():
        for level, counts_at_level in label_counts[representation].items():
            if sum(counts_at_level.values()) != expected_rows:
                raise ValueError(f"{representation} {level} label total does not reconcile")
    for representation, expected_rows in (
        ("ten_best_predefined_train", 2_934_817),
        ("ten_best_predefined_test", 733_705),
    ):
        for field_name in BOT_LINEAGE_FIELDS:
            if sum(three_way[representation][field_name].values()) != expected_rows:
                raise ValueError(
                    f"{representation} {field_name} three-way lineage total does not reconcile"
                )
    if sport_profile.total != BOT_TOTAL or dport_profile.total != BOT_TOTAL:
        raise ValueError("Bot-IoT port profile totals do not reconcile")

    chronological_threshold = float(np.quantile(np.asarray(stime_by_id[1:]), 0.8))
    random_masks = stratified_masks(
        dict(label_counts["all_features_5pct_shards"]["subcategory"]), N_SEEDS[0]
    )
    random_offsets: Counter[str] = Counter()
    random_distributions = {"train": new_label_levels(), "test": new_label_levels()}
    chronological_distributions = {"train": new_label_levels(), "test": new_label_levels()}
    random_overlap = {fields: SplitEntityOverlap() for fields in (("saddr",), ("saddr", "daddr"))}
    chronological_overlap = {
        fields: SplitEntityOverlap() for fields in (("saddr",), ("saddr", "daddr"))
    }

    started = phase_started("confirm identity-free duplicates and diagnostic Bot-IoT splits")
    for source in sources["all_features_5pct_shards"]:
        for frame in read_chunks(source.path, source.delimiter, chunk_size):
            for scope, columns in all_scope_columns.items():
                hashes = candidate_hashes(frame, columns)
                mask = hash_store.candidate_mask(scope, hashes)
                insert_exact_candidates(connection, scope, frame, columns, mask)
            identifiers = frame["pkSeqID"].to_numpy(np.int64)
            subcategories = frame["subcategory"].str.casefold().to_numpy()
            random_test = np.zeros(len(frame), dtype=np.bool_)
            for subcategory in np.unique(subcategories):
                local = np.flatnonzero(subcategories == subcategory)
                start = random_offsets[str(subcategory)]
                stop = start + len(local)
                random_test[local] = random_masks[str(subcategory)][start:stop]
                random_offsets[str(subcategory)] = stop
            chronological_test = np.asarray(stime_by_id[identifiers]) >= chronological_threshold
            for name, mask, distributions, overlaps in (
                ("random", random_test, random_distributions, random_overlap),
                (
                    "chronological",
                    chronological_test,
                    chronological_distributions,
                    chronological_overlap,
                ),
            ):
                del name
                for partition, select in (("test", mask), ("train", ~mask)):
                    if select.any():
                        update_label_counts(distributions[partition], frame.loc[select])
                for fields, accumulator in overlaps.items():
                    update_split_overlap_chunk(accumulator, combined_series(frame, fields), mask)
            connection.commit()
    for source in sources["ten_best_full"]:
        for frame in read_chunks(source.path, source.delimiter, chunk_size):
            frame = restore_unnamed_leading_header(frame)
            for scope, columns in full_scope_columns.items():
                hashes = candidate_hashes(frame, columns)
                mask = hash_store.candidate_mask(scope, hashes)
                insert_exact_candidates(connection, scope, frame, columns, mask)
            connection.commit()
    identity_duplicates = summarize_exact_candidates(connection, BOT_DUPLICATE_SCOPES)
    connection.close()
    phase_finished("confirm identity-free duplicates and diagnostic Bot-IoT splits", started)

    for label, offset in random_offsets.items():
        if offset != label_counts["all_features_5pct_shards"]["subcategory"][label]:
            raise ValueError(f"random split offset does not reconcile for {label}")

    imbalance = []
    for representation, levels in label_counts.items():
        imbalance.extend(
            imbalance_rows(
                "bot_iot",
                representation,
                {"raw_rows": levels},
                test_representation=representation == "ten_best_predefined_test",
            )
        )

    entity_purity = {
        (key if isinstance(key, str) else "+".join(key)): accumulator.summary()
        for key, accumulator in entity_accumulators.items()
    }
    supplied_overlap = {
        (key if isinstance(key, str) else "+".join(key)): {
            "train_unique_values": len(supplied_train_values[key]),
            "test_rows": supplied_test_rows,
            "test_rows_with_value_seen_in_train": supplied_overlap_rows[key],
            "test_row_overlap_percent": percentage(supplied_overlap_rows[key], supplied_test_rows),
        }
        for key in supplied_train_values
    }
    supplied_overlap["pkSeqID"] = {
        "test_rows": supplied_test_rows,
        "test_rows_with_value_seen_in_train": 0,
        "test_row_overlap_percent": 0.0,
        "interpretation": "disjoint unique identifiers do not establish leakage-free entities",
    }
    entity_summary = {
        "risk_terminology": "ENTITY/CONTEXT MEMORIZATION RISK",
        "all_features_label_purity": entity_purity,
        "supplied_train_test_row_weighted_overlap": supplied_overlap,
        "low_frequency_caveat": (
            "Pure low-frequency values may be unstable and are reported separately."
        ),
        "interpretation": (
            "High purity indicates potential context memorization/scenario dependence, "
            "not automatic causal leakage."
        ),
    }

    port_summary = {
        "source_representation": "all_features_5pct_shards",
        "sport": sport_profile.as_dict(),
        "dport": dport_profile.as_dict(),
        "decimal_parse_failure_cooccurrence": dict(port_cooccurrence),
        "both_failures_are_same_9052_rows": (
            port_cooccurrence["sport_parse_failure_rows"] == 9_052
            and port_cooccurrence["dport_parse_failure_rows"] == 9_052
            and port_cooccurrence["both_parse_failure_rows"] == 9_052
        ),
        "negative_token_semantics": "UNKNOWN SEMANTICS; source feature documentation is silent",
        "standard_port_range_reference": (
            "0..65535 used only as protocol-range check; source documentation supplies "
            "no alternate range"
        ),
        "non_binding_preprocessing_contract_candidate": (
            "Preserve raw lexical token; deterministically parse decimal or 0x-prefixed base-16; "
            "represent documented sentinel separately if later source evidence defines one."
        ),
        "implementation_status": "not implemented; A5 diagnostic only",
    }

    lineage_summary = {
        "all_features_vs_ten_best_full": lineage.summarize(),
        "three_way_supplied_split": {
            representation: {name: dict(sorted(values.items())) for name, values in fields.items()}
            for representation, fields in three_way.items()
        },
        "classification_definitions": {
            "equals_both": "supplied value equals All-features and 10-best full",
            "equals_all_features_only": "supplied value equals only All-features",
            "equals_ten_best_full_only": "supplied value equals only 10-best full",
            "equals_neither": "supplied value equals neither representation",
        },
        "upstream_processing_conclusion": "No unobserved upstream transformation is inferred.",
    }

    random_summary = {
        "seed": N_SEEDS[0],
        "stratification": "subcategory",
        "train_distributions": {
            level: dict(sorted(values.items()))
            for level, values in random_distributions["train"].items()
        },
        "test_distributions": {
            level: dict(sorted(values.items()))
            for level, values in random_distributions["test"].items()
        },
        "entity_overlap": {
            "+".join(fields): accumulator.summary()
            for fields, accumulator in random_overlap.items()
        },
    }
    chronological_summary = {
        "stime_interpretation": "numeric/order only; no calendar/clock semantics inferred",
        "test_rule": f"stime >= observed 80th-percentile threshold {chronological_threshold!r}",
        "threshold": chronological_threshold,
        "train_distributions": {
            level: dict(sorted(values.items()))
            for level, values in chronological_distributions["train"].items()
        },
        "test_distributions": {
            level: dict(sorted(values.items()))
            for level, values in chronological_distributions["test"].items()
        },
        "entity_overlap": {
            "+".join(fields): accumulator.summary()
            for fields, accumulator in chronological_overlap.items()
        },
    }
    entity_grouped = {
        "saddr": entity_group_split(entity_accumulators["saddr"]),
        "saddr+daddr": entity_group_split(entity_accumulators[("saddr", "daddr")]),
    }
    pk_range_summary = range_label_summary(pk_profiles, BOT_TOTAL)
    index_range_summary = range_label_summary(index_profiles, BOT_TOTAL)
    pk_range_summary["finding"] = order_alignment_finding(pk_range_summary)
    index_range_summary["finding"] = order_alignment_finding(index_range_summary)
    split_feasibility = {
        "field_order_diagnostics": {
            "pkSeqID": pk_range_summary,
            "unnamed_ten_best_index": index_range_summary,
            "risk": "IDENTIFIER LEAKAGE RISK",
        },
        "temporal_audit": {
            "documentation": {
                "stime": "Record start time",
                "ltime": "Record last time",
                "seq": "Argus sequence number",
            },
            "semantic_limit": "numeric/order relationships only; no calendar/clock interpretation",
            "global_numeric_ranges": temporal_global,
            "physical_order_stime_decrease_count": monotonic_violations,
            "stime_ranges_by_binary": temporal_by_binary,
            "ranges_by_category": temporal_by_category,
            "ranges_by_source_shard": temporal_by_source,
            "supplied_train_test": {
                **supplied_temporal,
                "test_rows_within_train_numeric_range_percent": percentage(
                    int(supplied_temporal["test"]["within_train_range"]), supplied_test_rows
                ),
                "temporally_interleaved": bool(
                    float(supplied_temporal["test"]["min"])
                    <= float(supplied_temporal["train"]["max"])
                    and float(supplied_temporal["train"]["min"])
                    <= float(supplied_temporal["test"]["max"])
                ),
            },
        },
        "candidate_B1_supplied": {
            "class_distributions": {
                partition: {
                    level: dict(sorted(label_counts[representation][level].items()))
                    for level in label_counts[representation]
                }
                for partition, representation in (
                    ("train", "ten_best_predefined_train"),
                    ("test", "ten_best_predefined_test"),
                )
            },
            "entity_overlap": supplied_overlap,
            "temporal_overlap": supplied_temporal,
            "id_order_risk": (
                "pkSeqID sets are disjoint but label concentration by range is audited"
            ),
            "numeric_representation_differs_from_full": any(
                values["equals_neither"] or values["equals_all_features_only"]
                for fields in three_way.values()
                for values in fields.values()
            ),
            "status": "diagnostic only; not adopted",
        },
        "candidate_B2_random_stratified": random_summary,
        "candidate_B3_temporal": chronological_summary,
        "candidate_B4_entity_grouped": entity_grouped,
    }

    candidate_rows = []
    supplied_test_sub = label_counts["ten_best_predefined_test"]["subcategory"]
    candidate_rows.append(
        {
            "dataset": "bot_iot",
            "candidate_name": "B1 supplied train/test",
            "train_rows": 2_934_817,
            "test_rows": 733_705,
            "binary_class_coverage": len(label_counts["ten_best_predefined_test"]["binary"]),
            "fine_or_category_coverage": len(label_counts["ten_best_predefined_test"]["category"]),
            "exact_feature_overlap_percent": "not measured for supplied derived representation",
            "entity_overlap_percent": supplied_overlap["saddr+daddr"]["test_row_overlap_percent"],
            "temporal_overlap_finding": "interleaved"
            if split_feasibility["temporal_audit"]["supplied_train_test"]["temporally_interleaved"]
            else "non-overlapping numeric ranges",
            "rare_class_min_support": min(supplied_test_sub.values()),
            "major_limitation": "familiar entities/order risk and representation differences",
            "status": "diagnostic only",
        }
    )
    for candidate_name, summary, limitation in (
        (
            "B2 random stratified record",
            random_summary,
            "high familiar-entity overlap may not test scenario generalization",
        ),
        (
            "B3 chronological numeric-order",
            chronological_summary,
            "numeric time semantics only; class coverage may drift",
        ),
    ):
        test_dist = summary["test_distributions"]
        train_rows = sum(summary["train_distributions"]["binary"].values())
        test_rows = sum(test_dist["binary"].values())
        candidate_rows.append(
            {
                "dataset": "bot_iot",
                "candidate_name": candidate_name,
                "train_rows": train_rows,
                "test_rows": test_rows,
                "binary_class_coverage": len(test_dist["binary"]),
                "fine_or_category_coverage": len(test_dist["category"]),
                "exact_feature_overlap_percent": "not applicable",
                "entity_overlap_percent": summary["entity_overlap"]["saddr+daddr"][
                    "test_row_overlap_percent"
                ],
                "temporal_overlap_finding": "not applicable"
                if candidate_name.startswith("B2")
                else "ordered by stime numeric value",
                "rare_class_min_support": min(test_dist["subcategory"].values(), default=0),
                "major_limitation": limitation,
                "status": "diagnostic only",
            }
        )
    for grouping, summary in entity_grouped.items():
        candidate_rows.append(
            {
                "dataset": "bot_iot",
                "candidate_name": f"B4 entity grouped by {grouping}",
                "train_rows": summary["train_rows"],
                "test_rows": summary["test_rows"],
                "binary_class_coverage": summary["test_binary_coverage"],
                "fine_or_category_coverage": summary["test_category_coverage"],
                "exact_feature_overlap_percent": "not applicable",
                "entity_overlap_percent": 0.0,
                "temporal_overlap_finding": "not constrained",
                "rare_class_min_support": summary["minimum_test_subcategory_support"],
                "major_limitation": "group count/exclusivity may cause size and class imbalance",
                "status": "diagnostic only",
            }
        )

    identity_summary = {
        "candidate_hash_groups": candidate_hash_groups,
        "exact_confirmation": identity_duplicates,
        "view_definitions": {
            "all_non_label_excluding_pkseqid_with_seq": (
                "all All-features fields except labels and pkSeqID; seq retained"
            ),
            "all_non_label_excluding_pkseqid_without_seq": (
                "same diagnostic view with documented Argus sequence number removed"
            ),
            "ten_best_non_label_excluding_pkseqid_index_with_seq": (
                "named 10-best fields except labels and pkSeqID; unnamed physical index "
                "excluded; seq retained"
            ),
            "ten_best_non_label_excluding_pkseqid_index_without_seq": (
                "same diagnostic view with seq removed"
            ),
        },
        "eligibility_status": "diagnostic views only; no final predictor set selected",
    }
    return (
        imbalance,
        field_risk_rows(all_columns),
        entity_summary,
        identity_summary,
        port_summary,
        lineage_summary,
        split_feasibility,
        candidate_rows,
    )


def source_tree_snapshot(root: Path) -> dict[str, Any]:
    files = []
    digest = hashlib.sha256()
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=str):
        stat = path.stat()
        relative = path.relative_to(root).as_posix()
        item = {"relative_path": relative, "size_bytes": stat.st_size, "mtime_ns": stat.st_mtime_ns}
        files.append(item)
        digest.update(relative.encode("utf-8"))
        digest.update(stat.st_size.to_bytes(8, "big"))
        digest.update(stat.st_mtime_ns.to_bytes(8, "big", signed=True))
    return {
        "root": str(root),
        "file_count": len(files),
        "total_size_bytes": sum(item["size_bytes"] for item in files),
        "metadata_digest_sha256": digest.hexdigest(),
    }


def ensure_a4_checkpoint(a4_temp_dir: Path) -> None:
    verification = json.loads(
        (AUDIT_DIR / "a4_evidence_verification.json").read_text(encoding="utf-8")
    )
    if verification.get("overall_status") != "PASS":
        raise ValueError("A4 evidence verification is not PASS")
    database = a4_temp_dir / "a4_audit.sqlite"
    if not database.is_file():
        raise FileNotFoundError(database)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if head != A4_COMMIT_SHA:
        raise ValueError(f"expected A4 checkpoint {A4_COMMIT_SHA}, observed HEAD {head}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-baiot-root", type=Path, required=True)
    parser.add_argument("--bot-iot-root", type=Path, required=True)
    parser.add_argument("--n-baiot-extracted-root", type=Path, required=True)
    parser.add_argument("--a4-temp-dir", type=Path, required=True)
    parser.add_argument("--temp-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=AUDIT_DIR)
    parser.add_argument("--chunk-size", type=int, default=100_000)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.chunk_size <= 0:
        raise ValueError("--chunk-size must be positive")
    ensure_a4_checkpoint(args.a4_temp_dir)
    for root in (args.n_baiot_root, args.bot_iot_root, args.n_baiot_extracted_root):
        if not root.is_dir():
            raise FileNotFoundError(root)
    before_sources = {
        "n_baiot_raw": source_tree_snapshot(args.n_baiot_root),
        "n_baiot_extracted": source_tree_snapshot(args.n_baiot_extracted_root),
        "bot_iot_raw": source_tree_snapshot(args.bot_iot_root),
    }
    free_before = shutil.disk_usage(args.temp_dir.parent).free
    if free_before < 15 * 1024**3:
        raise OSError(
            f"unsafe free space before A5: {free_before / 1024**3:.3f} GiB; require at least 15 GiB"
        )
    args.temp_dir.mkdir(parents=True, exist_ok=True)
    if any(args.temp_dir.iterdir()):
        raise FileExistsError(f"A5 temp directory must be empty: {args.temp_dir}")

    started = phase_started("analyze N-BaIoT effective imbalance and split leakage")
    n_imbalance, n_splits, n_devices, candidate_rows = analyze_n_baiot(
        args.a4_temp_dir / "a4_audit.sqlite"
    )
    phase_finished("analyze N-BaIoT effective imbalance and split leakage", started)

    (
        bot_imbalance,
        field_risks,
        entity_summary,
        identity_summary,
        port_summary,
        lineage_summary,
        split_feasibility,
        bot_candidate_rows,
    ) = analyze_bot_iot(args.bot_iot_root, args.temp_dir, args.a4_temp_dir, args.chunk_size)
    candidate_rows.extend(bot_candidate_rows)

    output_dir = args.output_dir
    started = phase_started("write compact A5 evidence")
    n_imbalance_fields = [
        "dataset",
        "label_level",
        "label",
        "raw_row_count",
        "unique_vector_count",
        "duplicate_excess",
        "raw_percentage",
        "unique_vector_percentage",
        "duplication_factor",
        "raw_majority_to_minority_ratio",
        "unique_majority_to_minority_ratio",
    ]
    bot_imbalance_fields = [
        "dataset",
        "representation",
        "view",
        "label_level",
        "label",
        "count",
        "percentage",
        "majority_to_class_ratio",
        "majority_to_minority_ratio",
        "one_error_granularity_percent",
    ]
    write_csv_atomic(
        output_dir / "n_baiot_effective_imbalance.csv",
        n_imbalance_fields,
        n_imbalance,
    )
    write_json_atomic(output_dir / "n_baiot_split_leakage_summary.json", n_splits)
    write_csv_atomic(
        output_dir / "n_baiot_device_holdout_matrix.csv",
        list(n_devices[0]),
        n_devices,
    )
    write_csv_atomic(
        output_dir / "bot_iot_effective_imbalance.csv",
        bot_imbalance_fields,
        bot_imbalance,
    )
    write_csv_atomic(
        output_dir / "bot_iot_field_risk_profile.csv",
        list(field_risks[0]),
        field_risks,
    )
    write_json_atomic(output_dir / "bot_iot_entity_overlap_summary.json", entity_summary)
    write_json_atomic(output_dir / "bot_iot_identity_free_duplicate_summary.json", identity_summary)
    write_json_atomic(output_dir / "bot_iot_port_encoding_summary.json", port_summary)
    write_json_atomic(output_dir / "bot_iot_numeric_lineage_analysis.json", lineage_summary)
    write_json_atomic(output_dir / "bot_iot_split_feasibility.json", split_feasibility)
    write_csv_atomic(
        output_dir / "candidate_split_comparison.csv",
        list(candidate_rows[0]),
        candidate_rows,
    )
    after_sources = {
        "n_baiot_raw": source_tree_snapshot(args.n_baiot_root),
        "n_baiot_extracted": source_tree_snapshot(args.n_baiot_extracted_root),
        "bot_iot_raw": source_tree_snapshot(args.bot_iot_root),
    }
    source_safety = {
        name: {
            "before": before_sources[name],
            "after": after_sources[name],
            "metadata_unchanged": before_sources[name] == after_sources[name],
        }
        for name in before_sources
    }
    if not all(item["metadata_unchanged"] for item in source_safety.values()):
        raise ValueError("source metadata changed during A5")
    artifact_hashes = {name: sha256_file(output_dir / name) for name in A5_ARTIFACT_NAMES}
    free_after = shutil.disk_usage(args.temp_dir.parent).free
    summary = {
        "audit_batch": "A5",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "overall_status": "PASS",
        "pass_semantics": "Audit completed and reconciled; PASS does not mean datasets are safe.",
        "a4_checkpoint_commit": A4_COMMIT_SHA,
        "scope": (
            "diagnostic only; no final split, predictors, preprocessing, or dataset roles selected"
        ),
        "n_baiot": {
            "total_rows": N_TOTAL,
            "unique_exact_vectors": sum(n_splits["unique_vector_fine_class_counts"].values()),
            "naive_random_overlap_percent_range": [
                n_splits["naive_stratified_row_random"]["overlap_percent_min"],
                n_splits["naive_stratified_row_random"]["overlap_percent_max"],
            ],
            "group_aware_exact_overlap_groups": n_splits["exact_feature_group_aware"][
                "exact_feature_overlap_groups"
            ],
        },
        "bot_iot": {
            "total_rows": BOT_TOTAL,
            "identity_free_views": identity_summary["exact_confirmation"],
            "port_parse_failures_cooccur_on_same_9052_rows": port_summary[
                "both_failures_are_same_9052_rows"
            ],
            "numeric_lineage_fields": list(BOT_LINEAGE_FIELDS),
        },
        "artifact_sha256": artifact_hashes,
        "source_safety": source_safety,
        "temporary_state": {
            "path": str(args.temp_dir),
            "retention": "retain until independent A5 verification passes",
            "free_bytes_before": free_before,
            "free_bytes_after": free_after,
            "consumed_bytes": free_before - free_after,
        },
        "risk_terminology": [
            "DIRECT TARGET LEAKAGE",
            "IDENTIFIER LEAKAGE RISK",
            "ENTITY/CONTEXT MEMORIZATION RISK",
            "DUPLICATE LEAKAGE",
            "TEMPORAL LEAKAGE RISK",
            "CLASS IMBALANCE",
        ],
        "unresolved": [
            "final predictor set",
            "final preprocessing policy",
            "final train/validation/test split",
            "final dataset representation",
            "primary/secondary dataset roles",
        ],
    }
    write_json_atomic(output_dir / "a5_audit_summary.json", summary)
    phase_finished("write compact A5 evidence", started)
    print(f"Wrote A5 evidence to: {output_dir}")
    print(f"Temporary verification data retained at: {args.temp_dir}")
    print("Overall status: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
