"""Independently verify compact A5 evidence without importing the primary audit."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import sqlite3
import time
import zlib
from collections import Counter, defaultdict
from collections.abc import Iterator
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = PROJECT_ROOT / "artifacts" / "audit"
N_TOTAL = 7_062_606
N_EXACT_CANDIDATE_ROWS = 6_471_566
N_EXACT_GROUPS = 1_891_636
BOT_TOTAL = 3_668_522
N_SEEDS = (1729, 2027, 4099)
N_SCOPE = "all_115_features"
BOT_LINEAGE_FIELDS = ("stddev", "min", "mean", "drate", "srate", "max")
LABEL_FIELDS = ("attack", "category", "subcategory")
HEX_PORT = re.compile(r"^0[xX][0-9a-fA-F]+$")
DECIMAL_PORT = re.compile(r"^[0-9]+$")
NEGATIVE_PORT = re.compile(r"^-[0-9]+$")
BOT_DUPLICATE_SCOPES = {
    "all_non_label_excluding_pkseqid_with_seq": BOT_TOTAL,
    "all_non_label_excluding_pkseqid_without_seq": BOT_TOTAL,
    "ten_best_non_label_excluding_pkseqid_index_with_seq": BOT_TOTAL,
    "ten_best_non_label_excluding_pkseqid_index_without_seq": BOT_TOTAL,
}
REQUIRED_ARTIFACTS = (
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
    "a5_audit_summary.json",
)


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    temporary.replace(path)


def phase_started(name: str) -> float:
    print(f"[A5-VERIFY] START {name}", flush=True)
    return time.perf_counter()


def phase_finished(name: str, started_at: float) -> None:
    print(
        f"[A5-VERIFY] DONE  {name} ({time.perf_counter() - started_at:.1f}s)",
        flush=True,
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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


def restore_unnamed(frame: pd.DataFrame) -> pd.DataFrame:
    if len(frame.columns) and frame.columns[0] == "Unnamed: 0":
        return frame.rename(columns={frame.columns[0]: ""})
    return frame


def normalized_attack(value: str) -> str:
    return {"0": "benign", "1": "malicious"}.get(value, value.casefold())


def new_levels() -> dict[str, Counter[str]]:
    return {"binary": Counter(), "category": Counter(), "subcategory": Counter()}


def update_levels(levels: dict[str, Counter[str]], frame: pd.DataFrame) -> None:
    levels["binary"].update(
        {
            normalized_attack(str(label)): int(count)
            for label, count in frame["attack"].value_counts().items()
        }
    )
    levels["category"].update(
        {
            str(label).casefold(): int(count)
            for label, count in frame["category"].value_counts().items()
        }
    )
    levels["subcategory"].update(
        {
            str(label).casefold(): int(count)
            for label, count in frame["subcategory"].value_counts().items()
        }
    )


def classify_port(token: str) -> str:
    if HEX_PORT.fullmatch(token):
        return "hexadecimal_style"
    if NEGATIVE_PORT.fullmatch(token):
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


def decimal_failure_mask(values: pd.Series) -> np.ndarray:
    unique_values = values.unique()
    failures = {str(value) for value in unique_values if not decimal_parseable(str(value))}
    if not failures:
        return np.zeros(len(values), dtype=np.bool_)
    return values.isin(failures).to_numpy()


def encode_exact(values: list[str]) -> tuple[bytes, bytes]:
    serialized = bytearray()
    for value in values:
        encoded = value.encode("utf-8")
        serialized.extend(len(encoded).to_bytes(4, "big"))
        serialized.extend(encoded)
    raw = bytes(serialized)
    return hashlib.sha256(raw).digest(), zlib.compress(raw, level=1)


def duplicate_columns(frame: pd.DataFrame, representation: str) -> dict[str, list[str]]:
    named = [column for column in frame.columns if column not in {"", *LABEL_FIELDS}]
    with_seq = [column for column in named if column != "pkSeqID"]
    without_seq = [column for column in with_seq if column != "seq"]
    if representation == "all_features_5pct_shards":
        return {
            "all_non_label_excluding_pkseqid_with_seq": with_seq,
            "all_non_label_excluding_pkseqid_without_seq": without_seq,
        }
    return {
        "ten_best_non_label_excluding_pkseqid_index_with_seq": with_seq,
        "ten_best_non_label_excluding_pkseqid_index_without_seq": without_seq,
    }


def candidate_hashes(frame: pd.DataFrame, columns: list[str]) -> np.ndarray:
    hashes = pd.util.hash_pandas_object(frame[columns], index=False).to_numpy(np.uint64)
    return hashes.view(np.int64)


class IndependentCandidateHashStore:
    def __init__(self, temp_dir: Path, scope_sizes: dict[str, int] | None = None) -> None:
        configured_sizes = scope_sizes or BOT_DUPLICATE_SCOPES
        self.maps = {
            scope: np.memmap(
                temp_dir / f"a5_verify_candidate_{scope}.bin",
                dtype=np.int64,
                mode="w+",
                shape=(size,),
            )
            for scope, size in configured_sizes.items()
        }
        self.offsets = Counter()

    def append(self, scope: str, values: np.ndarray) -> None:
        start = self.offsets[scope]
        stop = start + len(values)
        if stop > len(self.maps[scope]):
            raise ValueError(f"verification candidate store overflow for {scope}")
        self.maps[scope][start:stop] = values
        self.offsets[scope] = stop

    def repeated_group_counts(self) -> dict[str, int]:
        result = {}
        for scope, values in self.maps.items():
            if self.offsets[scope] != len(values):
                raise ValueError(f"verification candidate store incomplete for {scope}")
            values.flush()
            values.sort()
            same_as_previous = values[1:] == values[:-1]
            first_repeat_in_group = np.empty(len(same_as_previous), dtype=np.bool_)
            if len(first_repeat_in_group):
                first_repeat_in_group[0] = same_as_previous[0]
                first_repeat_in_group[1:] = same_as_previous[1:] & (values[1:-1] != values[:-2])
            result[scope] = int(first_repeat_in_group.sum())
        return result


def update_pk_bin_profiles(
    profiles: dict[int, dict[str, Counter[str]]], frame: pd.DataFrame
) -> None:
    identifiers = frame["pkSeqID"].to_numpy(np.int64)
    temporary = pd.DataFrame(
        {
            "bin": np.minimum(19, (identifiers - 1) * 20 // BOT_TOTAL),
            "binary": frame["attack"].map(normalized_attack).to_numpy(),
            "category": frame["category"].str.casefold().to_numpy(),
            "subcategory": frame["subcategory"].str.casefold().to_numpy(),
        }
    )
    for (bin_number, binary, category, subcategory), count in temporary.value_counts(
        sort=False
    ).items():
        profile = profiles[int(bin_number)]
        profile["binary"][str(binary)] += int(count)
        profile["category"][str(category)] += int(count)
        profile["subcategory"][str(subcategory)] += int(count)


def collect_selected_values(
    frame: pd.DataFrame,
    identifiers: set[int],
    fields: tuple[str, ...],
) -> dict[int, dict[str, str]]:
    if not identifiers:
        return {}
    numeric_ids = frame["pkSeqID"].to_numpy(np.int64)
    selected = frame.loc[np.isin(numeric_ids, list(identifiers)), ["pkSeqID", *fields]]
    return {
        int(row[0]): {
            field_name: str(value) for field_name, value in zip(fields, row[1:], strict=True)
        }
        for row in selected.itertuples(index=False, name=None)
    }


def verify_identity_samples_in_chunk(
    frame: pd.DataFrame,
    scope_columns: dict[str, list[str]],
    expectations_by_pk: dict[int, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    if not expectations_by_pk:
        return []
    numeric_ids = frame["pkSeqID"].to_numpy(np.int64)
    selected = frame.loc[np.isin(numeric_ids, list(expectations_by_pk))]
    results = []
    for record in selected.to_dict("records"):
        identifier = int(record["pkSeqID"])
        for expectation in expectations_by_pk[identifier]:
            scope = expectation["scope"]
            if scope not in scope_columns:
                continue
            exact_hash, exact_blob = encode_exact(
                [str(record[column]) for column in scope_columns[scope]]
            )
            results.append(
                {
                    "scope": scope,
                    "pkSeqID": identifier,
                    "direct_source_values_match_persisted_exact_group": (
                        exact_hash == expectation["exact_hash"]
                        and exact_blob == expectation["exact_blob"]
                    ),
                }
            )
    return results


def stratified_masks(class_sizes: dict[str, int], seed: int) -> dict[str, np.ndarray]:
    rng = np.random.default_rng(seed)
    result = {}
    for label, size in sorted(class_sizes.items()):
        mask = np.zeros(size, dtype=np.bool_)
        mask[rng.choice(size, size=int(round(size * 0.2)), replace=False)] = True
        result[label] = mask
    return result


def canonical_fine_aggregates(fine: Counter[str]) -> dict[str, Counter[str]]:
    binary: Counter[str] = Counter()
    family: Counter[str] = Counter()
    for label, count in fine.items():
        if label == "benign":
            binary["benign"] += count
            family["benign"] += count
        else:
            binary["malicious"] += count
            family[label.split("_", 1)[0]] += count
    return {"binary": binary, "family": family, "fine_class": fine}


def verify_n_baiot(
    a4_database: Path,
    imbalance_rows: list[dict[str, str]],
    split_report: dict[str, Any],
    device_rows: list[dict[str, str]],
) -> dict[str, Any]:
    mapping = sorted(
        load_csv(AUDIT_DIR / "n_baiot_label_mapping.csv"),
        key=lambda row: row["logical_id"],
    )
    raw_fine: Counter[str] = Counter()
    offsets: Counter[str] = Counter()
    source_meta = {}
    for source_id, row in enumerate(mapping):
        fine = row["canonical_fine_class"]
        count = int(row["row_count"])
        source_meta[source_id] = {
            "fine": fine,
            "device": row["device"],
            "offset": offsets[fine],
        }
        offsets[fine] += count
        raw_fine[fine] += count
    masks = {seed: stratified_masks(dict(raw_fine), seed) for seed in N_SEEDS}
    duplicate_rows: Counter[str] = Counter()
    duplicate_groups: Counter[str] = Counter()
    random_results = {seed: {"spanning_groups": 0, "matched_test_rows": 0} for seed in N_SEEDS}
    device_candidate_rows: Counter[str] = Counter()
    device_groups: Counter[str] = Counter()
    device_shared_groups: Counter[str] = Counter()
    device_matched_rows: Counter[str] = Counter()
    connection = sqlite3.connect(f"file:{a4_database.as_posix()}?mode=ro", uri=True, timeout=60)
    cursor = connection.execute(
        """
        SELECT exact_hash, exact_blob, source_id, row_number, fine_label
        FROM exact_rows INDEXED BY exact_group_idx
        WHERE dataset='n_baiot' AND scope=?
        ORDER BY exact_hash, exact_blob, source_id, row_number
        """,
        (N_SCOPE,),
    )
    current: tuple[bytes, bytes] | None = None
    group: list[tuple[int, int, str]] = []
    candidate_rows_seen = 0
    exact_groups_seen = 0

    def consume(members: list[tuple[int, int, str]]) -> None:
        nonlocal exact_groups_seen
        exact_groups_seen += 1
        labels = {item[2] for item in members}
        if len(labels) != 1:
            raise ValueError("independent N-BaIoT scan found a cross-label exact group")
        fine = next(iter(labels))
        duplicate_rows[fine] += len(members)
        duplicate_groups[fine] += 1
        devices: Counter[str] = Counter(
            source_meta[source_id]["device"] for source_id, _, _ in members
        )
        for device, count in devices.items():
            device_candidate_rows[device] += count
            device_groups[device] += 1
            if count < len(members):
                device_shared_groups[device] += 1
                device_matched_rows[device] += count
        for seed, seed_masks in masks.items():
            test_count = 0
            for source_id, row_number, _ in members:
                position = source_meta[source_id]["offset"] + row_number - 1
                test_count += int(seed_masks[fine][position])
            if test_count and test_count < len(members):
                random_results[seed]["spanning_groups"] += 1
                random_results[seed]["matched_test_rows"] += test_count

    for exact_hash, exact_blob, source_id, row_number, fine in cursor:
        candidate_rows_seen += 1
        if candidate_rows_seen % 1_000_000 == 0:
            print(
                "[A5-VERIFY] PROGRESS N-BaIoT exact candidate rows "
                f"{candidate_rows_seen:,}/{N_EXACT_CANDIDATE_ROWS:,}",
                flush=True,
            )
        key = (bytes(exact_hash), bytes(exact_blob))
        if current is not None and key != current:
            consume(group)
            group = []
        current = key
        group.append((int(source_id), int(row_number), str(fine)))
    if group:
        consume(group)
    connection.close()
    if candidate_rows_seen != N_EXACT_CANDIDATE_ROWS or exact_groups_seen != N_EXACT_GROUPS:
        raise ValueError("A4 N-BaIoT exact-group state does not match the accepted A5 checkpoint")
    unique_fine = Counter(
        {
            label: raw_fine[label] - duplicate_rows[label] + duplicate_groups[label]
            for label in raw_fine
        }
    )
    reported_imbalance = {(row["label_level"], row["label"]): row for row in imbalance_rows}
    imbalance_match = True
    for level, counts in canonical_fine_aggregates(raw_fine).items():
        unique_counts = canonical_fine_aggregates(unique_fine)[level]
        for label, count in counts.items():
            row = reported_imbalance[(level, label)]
            imbalance_match &= int(row["raw_row_count"]) == count
            imbalance_match &= int(row["unique_vector_count"]) == unique_counts[label]
    reported_runs = {
        int(run["seed"]): run for run in split_report["naive_stratified_row_random"]["runs"]
    }
    random_match = all(
        random_results[seed]["spanning_groups"]
        == int(reported_runs[seed]["exact_feature_groups_spanning_train_test"])
        and random_results[seed]["matched_test_rows"]
        == int(reported_runs[seed]["test_rows_with_exact_train_vector"])
        for seed in N_SEEDS
    )
    reported_devices = {row["device"]: row for row in device_rows}
    device_match = all(
        int(reported_devices[device]["test_rows_with_exact_train_vector"])
        == device_matched_rows[device]
        and int(reported_devices[device]["test_unique_vectors_seen_in_train"])
        == device_shared_groups[device]
        for device in reported_devices
    )
    group_aware = split_report["exact_feature_group_aware"]
    group_aware_whole_dataset_reconciles = (
        int(group_aware["exact_feature_overlap_groups"]) == 0
        and int(group_aware["train_rows"]) + int(group_aware["test_rows"]) == N_TOTAL
        and int(group_aware["train_unique_vectors"]) + int(group_aware["test_unique_vectors"])
        == sum(unique_fine.values())
    )
    return {
        "raw_and_unique_class_counts_match": imbalance_match,
        "random_split_runs_match": random_match,
        "leave_one_device_out_results_match": device_match,
        "group_aware_whole_dataset_zero_overlap_reconciles": (group_aware_whole_dataset_reconciles),
        "independent_raw_rows": sum(raw_fine.values()),
        "independent_unique_vectors": sum(unique_fine.values()),
        "status": (
            "PASS"
            if all(
                (
                    imbalance_match,
                    random_match,
                    device_match,
                    group_aware_whole_dataset_reconciles,
                )
            )
            else "FAIL"
        ),
    }


def bot_sources(bot_root: Path) -> dict[str, list[tuple[Path, str]]]:
    result: dict[str, list[tuple[Path, str]]] = defaultdict(list)
    for row in load_csv(AUDIT_DIR / "bot_iot_csv_structure.csv"):
        delimiter = {"comma": ",", "semicolon": ";"}[row["delimiter"]]
        path = bot_root / Path(row["source_relative_path"])
        if not path.is_file():
            raise FileNotFoundError(path)
        if path.stat().st_size != int(row["size_bytes"]):
            raise ValueError(f"Bot-IoT source size changed: {path}")
        result[row["representation"]].append((path, delimiter))
    for values in result.values():
        values.sort(key=lambda item: str(item[0]))
    return dict(result)


def sample_split_rows(
    sources: list[tuple[Path, str]], sample_size: int = 16
) -> dict[int, dict[str, str]]:
    result = {}
    for path, delimiter in sources:
        frame = next(read_chunks(path, delimiter, sample_size))
        for row in frame.to_dict("records"):
            result[int(row["pkSeqID"])] = row
            if len(result) >= sample_size:
                return result
    return result


def aggregate_identity_database(database: Path) -> dict[str, dict[str, int]]:
    connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
    scopes = [
        row[0]
        for row in connection.execute("SELECT DISTINCT scope FROM bot_exact_rows ORDER BY scope")
    ]
    result = {}
    for scope in scopes:
        row = connection.execute(
            """
            SELECT COALESCE(SUM(n-1), 0), COALESCE(SUM(n), 0), COUNT(*),
                   COALESCE(SUM(na>1), 0), COALESCE(SUM(nc>1), 0),
                   COALESCE(SUM(ns>1), 0)
            FROM (
                SELECT COUNT(*) n, COUNT(DISTINCT attack) na,
                       COUNT(DISTINCT category) nc,
                       COUNT(DISTINCT subcategory) ns
                FROM bot_exact_rows WHERE scope=?
                GROUP BY exact_hash, exact_blob HAVING COUNT(*)>1
            )
            """,
            (scope,),
        ).fetchone()
        result[scope] = {
            "duplicate_excess": int(row[0]),
            "rows_in_duplicate_groups": int(row[1]),
            "duplicate_groups": int(row[2]),
            "conflicting_attack_groups": int(row[3]),
            "conflicting_category_groups": int(row[4]),
            "conflicting_subcategory_groups": int(row[5]),
        }
    connection.close()
    return result


def identity_exact_samples(database: Path, groups_per_scope: int = 3) -> list[dict[str, Any]]:
    connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
    scopes = [
        row[0]
        for row in connection.execute("SELECT DISTINCT scope FROM bot_exact_rows ORDER BY scope")
    ]
    samples = []
    for scope in scopes:
        groups = connection.execute(
            """
            SELECT exact_hash, exact_blob
            FROM bot_exact_rows
            WHERE scope=?
            GROUP BY exact_hash, exact_blob
            HAVING COUNT(*) > 1
            ORDER BY exact_hash, exact_blob
            LIMIT ?
            """,
            (scope, groups_per_scope),
        ).fetchall()
        for exact_hash, exact_blob in groups:
            members = connection.execute(
                """
                SELECT pkseqid FROM bot_exact_rows
                WHERE scope=? AND exact_hash=? AND exact_blob=?
                ORDER BY pkseqid LIMIT 2
                """,
                (scope, exact_hash, exact_blob),
            ).fetchall()
            for (identifier,) in members:
                samples.append(
                    {
                        "scope": scope,
                        "pkSeqID": int(identifier),
                        "exact_hash": bytes(exact_hash),
                        "exact_blob": bytes(exact_blob),
                    }
                )
    connection.close()
    return samples


def verify_bot_iot(
    bot_root: Path,
    a5_temp_dir: Path,
    chunk_size: int,
    imbalance_rows: list[dict[str, str]],
    entity_report: dict[str, Any],
    identity_report: dict[str, Any],
    port_report: dict[str, Any],
    lineage_report: dict[str, Any],
    split_report: dict[str, Any],
) -> dict[str, Any]:
    sources = bot_sources(bot_root)
    candidate_store = IndependentCandidateHashStore(a5_temp_dir)
    identity_database = a5_temp_dir / "a5_bot_identity_free.sqlite"
    identity_samples = identity_exact_samples(identity_database)
    identity_by_pk: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for sample in identity_samples:
        identity_by_pk[sample["pkSeqID"]].append(sample)
    direct_identity_results = []
    train_sample_rows = sample_split_rows(sources["ten_best_predefined_train"])
    test_sample_rows = sample_split_rows(sources["ten_best_predefined_test"])
    sample_rows = {**train_sample_rows, **test_sample_rows}
    sample_ids = set(sample_rows)
    all_samples: dict[int, dict[str, str]] = {}
    full_samples: dict[int, dict[str, str]] = {}
    counts = {representation: new_levels() for representation in sources}
    port_counts = {"sport": Counter(), "dport": Counter()}
    negative_tokens = {"sport": Counter(), "dport": Counter()}
    port_failure_cooccurrence = Counter()
    pk_bins: dict[int, dict[str, Counter[str]]] = defaultdict(new_levels)
    threshold = float(split_report["candidate_B3_temporal"]["threshold"])
    chronological = {"train": new_levels(), "test": new_levels()}
    train_entities: dict[str, set[str]] = {
        key: set() for key in ("saddr", "daddr", "sport", "dport", "proto")
    }
    train_entities.update(
        {key: set() for key in ("saddr+daddr", "saddr+dport", "saddr+proto", "daddr+proto")}
    )
    overlap_rows = Counter()
    test_rows = 0

    started = phase_started("stream Bot-IoT all-features evidence and candidate hashes")
    for path, delimiter in sources["all_features_5pct_shards"]:
        for frame in read_chunks(path, delimiter, chunk_size):
            scope_columns = duplicate_columns(frame, "all_features_5pct_shards")
            for scope, columns in scope_columns.items():
                candidate_store.append(scope, candidate_hashes(frame, columns))
            update_levels(counts["all_features_5pct_shards"], frame)
            all_samples.update(collect_selected_values(frame, sample_ids, BOT_LINEAGE_FIELDS))
            direct_identity_results.extend(
                verify_identity_samples_in_chunk(frame, scope_columns, identity_by_pk)
            )
            update_pk_bin_profiles(pk_bins, frame)
            for field in ("sport", "dport"):
                for token, count in frame[field].value_counts().items():
                    category = classify_port(str(token))
                    port_counts[field][category] += int(count)
                    if category == "negative_decimal":
                        negative_tokens[field][str(token)] += int(count)
            sport_failure = decimal_failure_mask(frame["sport"])
            dport_failure = decimal_failure_mask(frame["dport"])
            port_failure_cooccurrence["sport_parse_failure_rows"] += int(sport_failure.sum())
            port_failure_cooccurrence["dport_parse_failure_rows"] += int(dport_failure.sum())
            port_failure_cooccurrence["both_parse_failure_rows"] += int(
                (sport_failure & dport_failure).sum()
            )
            port_failure_cooccurrence["either_parse_failure_rows"] += int(
                (sport_failure | dport_failure).sum()
            )
            temporal_test = frame["stime"].to_numpy(np.float64) >= threshold
            for partition, mask in (("test", temporal_test), ("train", ~temporal_test)):
                if mask.any():
                    update_levels(chronological[partition], frame.loc[mask])
    phase_finished("stream Bot-IoT all-features evidence and candidate hashes", started)

    started = phase_started("stream Bot-IoT 10-best full evidence and candidate hashes")
    for path, delimiter in sources["ten_best_full"]:
        for frame in read_chunks(path, delimiter, chunk_size):
            frame = restore_unnamed(frame)
            scope_columns = duplicate_columns(frame, "ten_best_full")
            for scope, columns in scope_columns.items():
                candidate_store.append(scope, candidate_hashes(frame, columns))
            update_levels(counts["ten_best_full"], frame)
            full_samples.update(collect_selected_values(frame, sample_ids, BOT_LINEAGE_FIELDS))
            direct_identity_results.extend(
                verify_identity_samples_in_chunk(frame, scope_columns, identity_by_pk)
            )
    phase_finished("stream Bot-IoT 10-best full evidence and candidate hashes", started)

    started = phase_started("stream supplied Bot-IoT train entity sets")
    for path, delimiter in sources["ten_best_predefined_train"]:
        for frame in read_chunks(path, delimiter, chunk_size):
            update_levels(counts["ten_best_predefined_train"], frame)
            for field in ("saddr", "daddr", "sport", "dport", "proto"):
                train_entities[field].update(frame[field].unique())
            train_entities["saddr+daddr"].update(
                (frame["saddr"] + "\x1f" + frame["daddr"]).unique()
            )
            train_entities["saddr+dport"].update(
                (frame["saddr"] + "\x1f" + frame["dport"]).unique()
            )
            train_entities["saddr+proto"].update(
                (frame["saddr"] + "\x1f" + frame["proto"]).unique()
            )
            train_entities["daddr+proto"].update(
                (frame["daddr"] + "\x1f" + frame["proto"]).unique()
            )
    phase_finished("stream supplied Bot-IoT train entity sets", started)

    started = phase_started("stream supplied Bot-IoT test entity overlap")
    for path, delimiter in sources["ten_best_predefined_test"]:
        for frame in read_chunks(path, delimiter, chunk_size):
            update_levels(counts["ten_best_predefined_test"], frame)
            values = {
                field: frame[field] for field in ("saddr", "daddr", "sport", "dport", "proto")
            }
            values.update(
                {
                    "saddr+daddr": frame["saddr"] + "\x1f" + frame["daddr"],
                    "saddr+dport": frame["saddr"] + "\x1f" + frame["dport"],
                    "saddr+proto": frame["saddr"] + "\x1f" + frame["proto"],
                    "daddr+proto": frame["daddr"] + "\x1f" + frame["proto"],
                }
            )
            for key, series in values.items():
                overlap_rows[key] += int(series.isin(train_entities[key]).sum())
            test_rows += len(frame)
    phase_finished("stream supplied Bot-IoT test entity overlap", started)

    reported_counts = {
        (row["representation"], row["label_level"], row["label"]): int(row["count"])
        for row in imbalance_rows
    }
    class_support_match = all(
        reported_counts[(representation, level, label)] == count
        for representation, levels in counts.items()
        for level, labels in levels.items()
        for label, count in labels.items()
    )
    reported_overlap = entity_report["supplied_train_test_row_weighted_overlap"]
    entity_overlap_match = all(
        int(reported_overlap[key]["test_rows_with_value_seen_in_train"]) == overlap_rows[key]
        for key in overlap_rows
    )
    port_match = all(
        dict(port_counts[field]) == port_report[field]["lexical_category_counts"]
        and dict(negative_tokens[field]) == port_report[field]["unique_negative_tokens"]
        for field in ("sport", "dport")
    ) and all(
        int(port_report["decimal_parse_failure_cooccurrence"][key]) == value
        for key, value in port_failure_cooccurrence.items()
    )
    reported_chronological = split_report["candidate_B3_temporal"]
    chronological_match = all(
        dict(sorted(chronological[partition][level].items()))
        == reported_chronological[f"{partition}_distributions"][level]
        for partition in ("train", "test")
        for level in chronological[partition]
    )
    reported_bins = split_report["field_order_diagnostics"]["pkSeqID"]["bins"]
    pk_bin_match = all(
        dict(sorted(pk_bins[index][level].items())) == reported_bins[index][f"{level}_counts"]
        for index in range(20)
        for level in ("binary", "category", "subcategory")
    )
    direct_lineage_samples = []
    sample_classification_match = True
    for identifier in sorted(sample_ids):
        if identifier not in all_samples or identifier not in full_samples:
            sample_classification_match = False
            continue
        split = sample_rows[identifier]
        classifications = {}
        deltas = {}
        representation = (
            "ten_best_predefined_train"
            if identifier in train_sample_rows
            else "ten_best_predefined_test"
        )
        for field in BOT_LINEAGE_FIELDS:
            all_value = float(all_samples[identifier][field])
            full_value = float(full_samples[identifier][field])
            split_value = float(split[field])
            equals_all = split_value == all_value
            equals_full = split_value == full_value
            classification = (
                "equals_both"
                if equals_all and equals_full
                else "equals_all_features_only"
                if equals_all
                else "equals_ten_best_full_only"
                if equals_full
                else "equals_neither"
            )
            classifications[field] = classification
            deltas[field] = abs(all_value - full_value)
            reported_field = lineage_report["three_way_supplied_split"][representation][field]
            sample_classification_match &= reported_field[classification] > 0
        direct_lineage_samples.append(
            {
                "pkSeqID": identifier,
                "representation": representation,
                "classifications": classifications,
                "absolute_all_vs_full_deltas": deltas,
            }
        )
    started = phase_started("sort and reconcile independent identity-free candidate hashes")
    independent_candidate_groups = candidate_store.repeated_group_counts()
    reported_candidate_groups = identity_report["candidate_hash_groups"]
    candidate_hash_groups_match = all(
        independent_candidate_groups[scope] == int(reported_candidate_groups[scope])
        for scope in BOT_DUPLICATE_SCOPES
    )
    independent_identity = aggregate_identity_database(identity_database)
    reported_identity = identity_report["exact_confirmation"]
    zero_exact_metrics = {
        "duplicate_excess": 0,
        "rows_in_duplicate_groups": 0,
        "duplicate_groups": 0,
        "conflicting_attack_groups": 0,
        "conflicting_category_groups": 0,
        "conflicting_subcategory_groups": 0,
    }
    identity_match = all(
        all(
            int(reported_identity[scope][key]) == value
            for key, value in independent_identity.get(scope, zero_exact_metrics).items()
        )
        and int(reported_identity[scope]["unique_tuples"])
        == BOT_TOTAL - independent_identity.get(scope, zero_exact_metrics)["duplicate_excess"]
        for scope in BOT_DUPLICATE_SCOPES
    )
    direct_identity_match = len(direct_identity_results) == len(identity_samples) and all(
        result["direct_source_values_match_persisted_exact_group"]
        for result in direct_identity_results
    )
    phase_finished("sort and reconcile independent identity-free candidate hashes", started)
    checks = {
        "class_support_match": class_support_match,
        "pkseqid_order_bin_profiles_match": pk_bin_match,
        "supplied_entity_overlap_match": entity_overlap_match,
        "identity_free_exact_database_reconciles": identity_match,
        "identity_free_whole_dataset_candidate_scan_matches": candidate_hash_groups_match,
        "identity_free_direct_source_samples_match": direct_identity_match,
        "port_lexical_profiles_match": port_match,
        "numeric_lineage_samples_supported": sample_classification_match,
        "temporal_split_counts_match": chronological_match,
    }
    return {
        **checks,
        "direct_numeric_lineage_samples": direct_lineage_samples,
        "direct_identity_free_duplicate_samples": direct_identity_results,
        "independent_candidate_hash_groups": independent_candidate_groups,
        "identity_verification_method": (
            "independent SQL grouping over retained collision-confirmed exact rows; "
            "candidate hash counts are separately persisted by the primary audit"
        ),
        "status": "PASS" if all(checks.values()) else "FAIL",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bot-iot-root", type=Path, required=True)
    parser.add_argument("--a4-temp-dir", type=Path, required=True)
    parser.add_argument("--a5-temp-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=AUDIT_DIR / "a5_evidence_verification.json")
    parser.add_argument("--chunk-size", type=int, default=100_000)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.chunk_size <= 0:
        raise ValueError("--chunk-size must be positive")
    if not args.bot_iot_root.is_dir():
        raise FileNotFoundError(args.bot_iot_root)
    if not args.a4_temp_dir.is_dir():
        raise FileNotFoundError(args.a4_temp_dir)
    if not args.a5_temp_dir.is_dir():
        raise FileNotFoundError(args.a5_temp_dir)
    free_before = shutil.disk_usage(args.a5_temp_dir).free
    if free_before < 1024**3:
        raise OSError(f"unsafe free space before A5 verification: {free_before / 1024**3:.3f} GiB")
    started = phase_started("validate A5 artifact set and hashes")
    summary = load_json(AUDIT_DIR / "a5_audit_summary.json")
    missing = [name for name in REQUIRED_ARTIFACTS if not (AUDIT_DIR / name).is_file()]
    if missing:
        raise FileNotFoundError(f"missing A5 artifacts: {missing}")
    observed_hashes = {name: sha256_file(AUDIT_DIR / name) for name in summary["artifact_sha256"]}
    artifact_hashes_match = observed_hashes == summary["artifact_sha256"]
    phase_finished("validate A5 artifact set and hashes", started)
    started = phase_started("independently verify N-BaIoT exact-group diagnostics")
    n_result = verify_n_baiot(
        args.a4_temp_dir / "a4_audit.sqlite",
        load_csv(AUDIT_DIR / "n_baiot_effective_imbalance.csv"),
        load_json(AUDIT_DIR / "n_baiot_split_leakage_summary.json"),
        load_csv(AUDIT_DIR / "n_baiot_device_holdout_matrix.csv"),
    )
    phase_finished("independently verify N-BaIoT exact-group diagnostics", started)
    started = phase_started("independently verify Bot-IoT diagnostics")
    bot_result = verify_bot_iot(
        args.bot_iot_root,
        args.a5_temp_dir,
        args.chunk_size,
        load_csv(AUDIT_DIR / "bot_iot_effective_imbalance.csv"),
        load_json(AUDIT_DIR / "bot_iot_entity_overlap_summary.json"),
        load_json(AUDIT_DIR / "bot_iot_identity_free_duplicate_summary.json"),
        load_json(AUDIT_DIR / "bot_iot_port_encoding_summary.json"),
        load_json(AUDIT_DIR / "bot_iot_numeric_lineage_analysis.json"),
        load_json(AUDIT_DIR / "bot_iot_split_feasibility.json"),
    )
    phase_finished("independently verify Bot-IoT diagnostics", started)
    overall = (
        artifact_hashes_match and n_result["status"] == "PASS" and bot_result["status"] == "PASS"
    )
    result = {
        "audit_batch": "A5 independent verification",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "artifact_hashes_match": artifact_hashes_match,
        "verification_free_space": {
            "free_bytes_before": free_before,
            "free_bytes_after": shutil.disk_usage(args.a5_temp_dir).free,
        },
        "n_baiot": n_result,
        "bot_iot": bot_result,
        "verification_independence": (
            "This verifier does not import scripts/dataset_leakage_audit.py. It independently "
            "recomputes N-BaIoT group membership diagnostics, streams Bot-IoT labels, ports, "
            "identifier bins, entity overlap, temporal counts, and direct lineage samples."
        ),
        "overall_status": "PASS" if overall else "FAIL",
    }
    write_json(args.output, result)
    print(f"Wrote: {args.output}")
    print(f"Overall status: {result['overall_status']}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
