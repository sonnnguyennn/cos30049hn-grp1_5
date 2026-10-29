"""Independently verify A4 quality, duplicate, lineage, and source-safety evidence."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import sqlite3
import sys
from collections import Counter
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = PROJECT_ROOT / "artifacts" / "audit"
MANIFEST_DIR = PROJECT_ROOT / "artifacts" / "manifests"
OUTPUT = AUDIT_DIR / "a4_evidence_verification.json"
N_TOTAL = 7_062_606
BOT_TOTAL = 3_668_522
LABEL_FIELDS = {"attack", "category", "subcategory"}
NULL_TOKENS = {"na", "n/a", "null", "none"}
POSITIVE_INFINITY_TOKENS = {"inf", "+inf", "infinity", "+infinity"}
NEGATIVE_INFINITY_TOKENS = {"-inf", "-infinity"}
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
QUALITY_COUNT_FIELDS = (
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
)
N_QUALITY_SAMPLE_COLUMNS = (
    "MI_dir_L5_weight",
    "HH_L0.01_covariance",
    "HH_L0.01_pcc",
    "HpHp_L5_covariance",
    "HpHp_L0.01_mean",
)
BOT_QUALITY_SAMPLE_COLUMNS = ("pkSeqID", "sport", "dport", "proto", "attack")


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    return value


def write_json_atomic(payload: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f"{output.name}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        temporary.replace(output)
    finally:
        if temporary.exists():
            temporary.unlink()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def binary_data_row_count(path: Path) -> int:
    newline_count = 0
    final_byte = b""
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            newline_count += block.count(b"\n")
            final_byte = block[-1:]
    physical_records = newline_count + int(bool(final_byte) and final_byte != b"\n")
    return max(physical_records - 1, 0)


def source_path(
    structure_row: dict[str, str], n_root: Path, extracted_root: Path
) -> Path:
    relative = structure_row["source_relative_path"]
    if relative:
        return n_root / Path(relative)
    return extracted_root / Path(structure_row["extracted_relative_path"])


def new_quality_counts(numeric: bool) -> dict[str, Any]:
    return {
        "numeric_candidate": numeric,
        "total_values": 0,
        "empty_field_count": 0,
        "explicit_null_token_count": 0,
        "nan_count": 0,
        "positive_inf_count": 0,
        "negative_inf_count": 0,
        "numeric_parse_failure_count": 0,
        "finite_count": 0,
        "negative_value_count": 0,
        "zero_value_count": 0,
        "outer_whitespace_count": 0,
        "min_finite": None,
        "max_finite": None,
        "explicit_null_tokens": Counter(),
        "nan_tokens": Counter(),
        "inf_tokens": Counter(),
        "parse_failure_examples": Counter(),
    }


def observe_value(value: str, counts: dict[str, Any]) -> None:
    counts["total_values"] += 1
    folded = value.casefold()
    empty = value == ""
    null_token = folded in NULL_TOKENS
    nan_token = folded == "nan"
    positive_inf = folded in POSITIVE_INFINITY_TOKENS
    negative_inf = folded in NEGATIVE_INFINITY_TOKENS
    counts["empty_field_count"] += int(empty)
    counts["explicit_null_token_count"] += int(null_token)
    counts["nan_count"] += int(nan_token)
    counts["positive_inf_count"] += int(positive_inf)
    counts["negative_inf_count"] += int(negative_inf)
    counts["outer_whitespace_count"] += int(value != value.strip())
    if null_token:
        counts["explicit_null_tokens"][value] += 1
    if nan_token:
        counts["nan_tokens"][value] += 1
    if positive_inf or negative_inf:
        counts["inf_tokens"][value] += 1
    if not counts["numeric_candidate"] or any(
        (empty, null_token, nan_token, positive_inf, negative_inf)
    ):
        return
    try:
        numeric = float(value)
    except ValueError:
        counts["numeric_parse_failure_count"] += 1
        counts["parse_failure_examples"][value] += 1
        return
    if not math.isfinite(numeric):
        return
    counts["finite_count"] += 1
    counts["negative_value_count"] += int(numeric < 0)
    counts["zero_value_count"] += int(numeric == 0)
    current_min = counts["min_finite"]
    current_max = counts["max_finite"]
    counts["min_finite"] = numeric if current_min is None else min(current_min, numeric)
    counts["max_finite"] = numeric if current_max is None else max(current_max, numeric)


def profile_selected_columns(
    path: Path,
    delimiter: str,
    selected_roles: dict[str, bool],
) -> dict[str, Any]:
    counts = {
        column: new_quality_counts(numeric) for column, numeric in selected_roles.items()
    }
    row_count = 0
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle, delimiter=delimiter)
        header = next(reader)
        indices = {column: header.index(column) for column in selected_roles}
        for row in reader:
            row_count += 1
            if len(row) != len(header):
                raise ValueError(f"Width mismatch while independently profiling {path}")
            for column, index in indices.items():
                observe_value(row[index], counts[column])
    return {"row_count": row_count, "columns": counts}


def artifact_quality_index(rows: list[dict[str, str]]) -> dict[tuple[str, str], dict[str, str]]:
    return {
        (row["logical_id"], row["column_name"]): row
        for row in rows
        if row["record_type"] == "file_column"
    }


def compare_quality_profile(
    logical_id: str,
    profile: dict[str, Any],
    persisted: dict[tuple[str, str], dict[str, str]],
) -> dict[str, Any]:
    compared: dict[str, Any] = {}
    for column, observed in profile["columns"].items():
        expected = persisted[(logical_id, column)]
        fields = list(QUALITY_COUNT_FIELDS)
        if not observed["numeric_candidate"]:
            fields = [
                field
                for field in fields
                if field
                not in {
                    "numeric_parse_failure_count",
                    "finite_count",
                    "negative_value_count",
                    "zero_value_count",
                }
            ]
        mismatches = {
            field: {"expected": int(expected[field]), "observed": int(observed[field])}
            for field in fields
            if int(expected[field]) != int(observed[field])
        }
        compared[column] = {
            "counts_match": not mismatches,
            "mismatches": mismatches,
            "observed_counts": {field: int(observed[field]) for field in fields},
            "observed_token_spellings": {
                "explicit_null": dict(sorted(observed["explicit_null_tokens"].items())),
                "nan": dict(sorted(observed["nan_tokens"].items())),
                "infinity": dict(sorted(observed["inf_tokens"].items())),
                "parse_failures": dict(
                    sorted(observed["parse_failure_examples"].items())[:10]
                ),
            },
        }
    return {
        "logical_id": logical_id,
        "row_count": profile["row_count"],
        "selected_columns": compared,
        "all_selected_counts_match": all(
            result["counts_match"] for result in compared.values()
        ),
    }


def verify_quality(
    n_root: Path,
    bot_root: Path,
    extracted_root: Path,
) -> dict[str, Any]:
    n_structure = load_csv(AUDIT_DIR / "n_baiot_csv_structure.csv")
    bot_structure = load_csv(AUDIT_DIR / "bot_iot_csv_structure.csv")
    n_quality = load_csv(AUDIT_DIR / "n_baiot_quality_summary.csv")
    bot_quality = load_csv(AUDIT_DIR / "bot_iot_quality_summary.csv")
    n_file_rows = {row["logical_id"]: row for row in n_quality if row["record_type"] == "file"}
    bot_file_rows = {
        row["logical_id"]: row for row in bot_quality if row["record_type"] == "file"
    }

    n_physical_rows: dict[str, int] = {}
    for source in n_structure:
        n_physical_rows[source["logical_id"]] = binary_data_row_count(
            source_path(source, n_root, extracted_root)
        )
    n_total = sum(n_physical_rows.values())
    n_file_row_mismatches = sorted(
        logical_id
        for logical_id, count in n_physical_rows.items()
        if count != int(n_file_rows[logical_id]["row_count"])
    )

    raw_sources = [row for row in n_structure if row["source_relative_path"]]
    attack_sources = [row for row in n_structure if row["extracted_relative_path"]]
    selected_n = [
        min(raw_sources, key=lambda row: int(row["row_count"])),
        min(attack_sources, key=lambda row: int(row["row_count"])),
        sorted(attack_sources, key=lambda row: (row["device"], row["logical_id"]))[-1],
    ]
    n_index = artifact_quality_index(n_quality)
    n_samples = []
    for source in selected_n:
        profile = profile_selected_columns(
            source_path(source, n_root, extracted_root),
            ",",
            dict.fromkeys(N_QUALITY_SAMPLE_COLUMNS, True),
        )
        n_samples.append(compare_quality_profile(source["logical_id"], profile, n_index))

    all_shards = sorted(
        (row for row in bot_structure if row["representation"] == "all_features_5pct_shards"),
        key=lambda row: row["logical_id"],
    )
    selected_bot = [all_shards[0], all_shards[-1]]
    bot_index = artifact_quality_index(bot_quality)
    bot_roles = {
        column: bot_index[(selected_bot[0]["logical_id"], column)]["observed_role"]
        == "numeric_candidate"
        for column in BOT_QUALITY_SAMPLE_COLUMNS
    }
    bot_samples = []
    for source in selected_bot:
        delimiter = {"comma": ",", "semicolon": ";"}[source["delimiter"]]
        profile = profile_selected_columns(
            bot_root / Path(source["source_relative_path"]), delimiter, bot_roles
        )
        bot_samples.append(compare_quality_profile(source["logical_id"], profile, bot_index))

    representation_rows = Counter()
    for row in bot_file_rows.values():
        representation_rows[row["representation"]] += int(row["row_count"])
    expected_representation_rows = {
        "all_features_5pct_shards": BOT_TOTAL,
        "ten_best_full": BOT_TOTAL,
        "ten_best_predefined_train": 2_934_817,
        "ten_best_predefined_test": 733_705,
    }
    return {
        "n_baiot": {
            "method": (
                "binary physical-line reconciliation for all 89 logical CSVs plus "
                "independent csv-module lexical profiles"
            ),
            "logical_csv_count": len(n_structure),
            "independent_total_rows": n_total,
            "expected_total_rows": N_TOTAL,
            "file_row_mismatches": n_file_row_mismatches,
            "selected_file_column_profiles": n_samples,
            "status": (
                "PASS"
                if n_total == N_TOTAL
                and not n_file_row_mismatches
                and all(sample["all_selected_counts_match"] for sample in n_samples)
                else "FAIL"
            ),
        },
        "bot_iot": {
            "method": (
                "independent csv-module lexical profiles for selected columns on the "
                "first and final All-features shards"
            ),
            "artifact_representation_row_counts": dict(sorted(representation_rows.items())),
            "expected_representation_row_counts": expected_representation_rows,
            "selected_shard_column_profiles": bot_samples,
            "status": (
                "PASS"
                if dict(representation_rows) == expected_representation_rows
                and all(sample["all_selected_counts_match"] for sample in bot_samples)
                else "FAIL"
            ),
        },
    }


def read_target_rows(path: Path, delimiter: str, targets: set[int]) -> dict[int, list[str]]:
    found: dict[int, list[str]] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle, delimiter=delimiter)
        next(reader)
        for row_number, row in enumerate(reader, start=1):
            if row_number in targets:
                found[row_number] = row
                if len(found) == len(targets):
                    break
    if set(found) != targets:
        raise ValueError(f"Could not locate requested data rows in {path}")
    return found


def resolve_example_path(
    root_kind: str, relative_path: str, n_root: Path, extracted_root: Path
) -> Path:
    if "extracted" in root_kind:
        return extracted_root / Path(relative_path)
    return n_root / Path(relative_path)


def verify_n_duplicate_examples(n_root: Path, extracted_root: Path) -> list[dict[str, Any]]:
    examples = [
        row
        for row in load_csv(AUDIT_DIR / "a4_flagged_examples.csv")
        if row["dataset"] == "n_baiot"
    ][:5]
    results = []
    for example in examples:
        first_path = resolve_example_path(
            example["first_source_root_kind"],
            example["first_source_relative_path"],
            n_root,
            extracted_root,
        )
        second_path = resolve_example_path(
            example["second_source_root_kind"],
            example["second_source_relative_path"],
            n_root,
            extracted_root,
        )
        first_number = int(example["first_data_row"])
        second_number = int(example["second_data_row"])
        first = read_target_rows(first_path, ",", {first_number})[first_number]
        second = read_target_rows(second_path, ",", {second_number})[second_number]
        results.append(
            {
                "finding_type": example["finding_type"],
                "first_logical_id": example["first_logical_id"],
                "first_data_row": first_number,
                "second_logical_id": example["second_logical_id"],
                "second_data_row": second_number,
                "field_count": len(first),
                "direct_source_values_equal": first == second,
            }
        )
    return results


def reconcile_duplicate_metrics(summary: dict[str, Any]) -> dict[str, Any]:
    total = int(summary["total_rows"])
    unique = int(summary["unique_records"])
    excess = int(summary["duplicate_excess_rows"])
    occurrences = int(summary["duplicate_row_occurrences"])
    groups = int(summary["duplicate_group_count"])
    return {
        "total_equals_unique_plus_excess": total == unique + excess,
        "duplicate_occurrences_not_less_than_excess": occurrences >= excess,
        "duplicate_occurrences_zero_iff_groups_zero": (occurrences == 0) == (groups == 0),
        "duplicate_groups_not_greater_than_occurrences": groups <= occurrences,
    }


def temp_candidate_counts(database_path: Path) -> dict[str, int]:
    if not database_path.is_file():
        raise FileNotFoundError(f"Primary A4 temporary database is absent: {database_path}")
    connection = sqlite3.connect(f"file:{database_path.as_posix()}?mode=ro", uri=True)
    try:
        rows = connection.execute(
            """
            SELECT dataset || ':' || scope, COUNT(*)
            FROM (
                SELECT dataset, scope, h
                FROM hash_counts
                GROUP BY dataset, scope, h
                HAVING SUM(count) > 1
            )
            GROUP BY dataset, scope
            """
        ).fetchall()
        exact_rows = connection.execute(
            "SELECT dataset || ':' || scope, COUNT(*) FROM exact_rows GROUP BY dataset, scope"
        ).fetchall()
    finally:
        connection.close()
    result = {f"candidate_hash_groups:{key}": int(value) for key, value in rows}
    result.update({f"exact_candidate_rows:{key}": int(value) for key, value in exact_rows})
    return dict(sorted(result.items()))


def first_pk_ids(path: Path, delimiter: str, count: int = 48) -> list[int]:
    identifiers = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle, delimiter=delimiter)
        header = next(reader)
        index = header.index("pkSeqID")
        for row in reader:
            identifiers.append(int(row[index]))
            if len(identifiers) == count:
                break
    return identifiers


def length_prefixed_digest(values: list[str]) -> str:
    digest = hashlib.sha256()
    for value in values:
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def scan_bot_representation(
    sources: list[dict[str, str]],
    bot_root: Path,
    sample_ids: set[int],
    duplicate_sample: bool = False,
) -> dict[str, Any]:
    seen = bytearray(BOT_TOTAL + 1)
    row_count = 0
    duplicate_pk_count = 0
    missing_pk_count = 0
    parse_failure_count = 0
    minimum: int | None = None
    maximum: int | None = None
    order_digest = hashlib.sha256()
    previous_pk: int | None = None
    strictly_increasing = True
    samples: dict[int, dict[str, str]] = {}
    full_hashes: dict[str, tuple[str, ...]] = {}
    non_label_hashes: dict[str, tuple[str, ...]] = {}
    full_sample_duplicates = 0
    non_label_sample_duplicates = 0
    sampled_rows = 0
    unnamed_seen = bytearray(BOT_TOTAL)
    unnamed_parse_failures = 0
    unnamed_position_mismatches = 0
    unnamed_duplicates = 0
    unnamed_min: int | None = None
    unnamed_max: int | None = None

    for source in sources:
        delimiter = {"comma": ",", "semicolon": ";"}[source["delimiter"]]
        path = bot_root / Path(source["source_relative_path"])
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle, delimiter=delimiter)
            header = next(reader)
            pk_index = header.index("pkSeqID")
            field_indices = {field: header.index(field) for field in LINEAGE_FIELDS}
            unnamed_index = 0 if header and header[0] == "" else None
            non_label_indices = [
                index for index, name in enumerate(header) if name not in LABEL_FIELDS
            ]
            for row in reader:
                row_count += 1
                raw_pk = row[pk_index]
                try:
                    pk = int(raw_pk)
                except ValueError:
                    try:
                        decimal_pk = Decimal(raw_pk)
                    except InvalidOperation:
                        parse_failure_count += 1
                        continue
                    if decimal_pk != decimal_pk.to_integral_value():
                        parse_failure_count += 1
                        continue
                    pk = int(decimal_pk)
                if pk < 1 or pk > BOT_TOTAL:
                    parse_failure_count += 1
                    continue
                if seen[pk]:
                    duplicate_pk_count += 1
                else:
                    seen[pk] = 1
                minimum = pk if minimum is None else min(minimum, pk)
                maximum = pk if maximum is None else max(maximum, pk)
                order_digest.update(pk.to_bytes(8, "big", signed=False))
                if previous_pk is not None and pk <= previous_pk:
                    strictly_increasing = False
                previous_pk = pk
                if pk in sample_ids:
                    samples[pk] = {
                        field: row[index] for field, index in field_indices.items()
                    }
                if duplicate_sample and (row_count <= 64 or row_count % 4096 == 0):
                    sampled_rows += 1
                    full_tuple = tuple(row)
                    non_label_tuple = tuple(row[index] for index in non_label_indices)
                    full_hash = length_prefixed_digest(list(full_tuple))
                    non_label_hash = length_prefixed_digest(list(non_label_tuple))
                    if full_hash in full_hashes and full_hashes[full_hash] == full_tuple:
                        full_sample_duplicates += 1
                    else:
                        full_hashes[full_hash] = full_tuple
                    if (
                        non_label_hash in non_label_hashes
                        and non_label_hashes[non_label_hash] == non_label_tuple
                    ):
                        non_label_sample_duplicates += 1
                    else:
                        non_label_hashes[non_label_hash] = non_label_tuple
                if unnamed_index is not None:
                    raw_unnamed = row[unnamed_index]
                    try:
                        unnamed = int(raw_unnamed)
                    except ValueError:
                        unnamed_parse_failures += 1
                    else:
                        if unnamed < 0 or unnamed >= BOT_TOTAL:
                            unnamed_parse_failures += 1
                        else:
                            if unnamed_seen[unnamed]:
                                unnamed_duplicates += 1
                            unnamed_seen[unnamed] = 1
                            unnamed_min = (
                                unnamed if unnamed_min is None else min(unnamed_min, unnamed)
                            )
                            unnamed_max = (
                                unnamed if unnamed_max is None else max(unnamed_max, unnamed)
                            )
                            unnamed_position_mismatches += int(unnamed != row_count - 1)
    return {
        "row_count": row_count,
        "pk_missing_count": missing_pk_count,
        "pk_numeric_parse_failure_count": parse_failure_count,
        "pk_duplicate_count": duplicate_pk_count,
        "pk_unique_count": sum(seen),
        "pk_min": minimum,
        "pk_max": maximum,
        "pk_order_sha256": order_digest.hexdigest(),
        "pk_strictly_increasing": strictly_increasing,
        "sample_rows": samples,
        "seen": seen,
        "duplicate_sample": {
            "method": (
                "exact length-prefixed SHA-256 over the first 64 and every 4096th "
                "physical row; digest matches were confirmed by tuple equality"
            ),
            "sampled_rows": sampled_rows,
            "full_row_duplicate_excess_in_sample": full_sample_duplicates,
            "non_label_duplicate_excess_in_sample": non_label_sample_duplicates,
        },
        "unnamed_leading_column": (
            {
                "numeric_parse_failure_count": unnamed_parse_failures,
                "duplicate_count": unnamed_duplicates,
                "unique_count": sum(unnamed_seen),
                "min": unnamed_min,
                "max": unnamed_max,
                "physical_position_mismatch_count": unnamed_position_mismatches,
            }
            if any(source["representation"] == "ten_best_full" for source in sources)
            else None
        ),
    }


def values_equal(field: str, first: str, second: str) -> bool:
    if field in LINEAGE_STRING_FIELDS:
        return first == second
    try:
        return Decimal(first) == Decimal(second)
    except InvalidOperation:
        return False


def compare_lineage_samples(
    reference: dict[int, dict[str, str]],
    candidate: dict[int, dict[str, str]],
    identifiers: list[int],
) -> dict[str, Any]:
    differences = Counter()
    different_records = 0
    examples = []
    compared = 0
    missing = []
    for identifier in identifiers:
        if identifier not in reference or identifier not in candidate:
            missing.append(identifier)
            continue
        compared += 1
        fields = [
            field
            for field in LINEAGE_FIELDS
            if not values_equal(field, reference[identifier][field], candidate[identifier][field])
        ]
        if fields:
            different_records += 1
            differences.update(fields)
            if len(examples) < 10:
                examples.append({"pkSeqID": identifier, "differing_fields": fields})
    return {
        "requested_sample_count": len(identifiers),
        "compared_sample_count": compared,
        "missing_sample_ids": missing,
        "records_with_differences": different_records,
        "difference_count_per_field": dict(sorted(differences.items())),
        "bounded_difference_examples": examples,
    }


def strip_scan_result(result: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in result.items() if key not in {"seen", "sample_rows"}}


def verify_bot_lineage(bot_root: Path) -> dict[str, Any]:
    structure = load_csv(AUDIT_DIR / "bot_iot_csv_structure.csv")
    grouped: dict[str, list[dict[str, str]]] = {}
    for row in structure:
        grouped.setdefault(row["representation"], []).append(row)
    for rows in grouped.values():
        rows.sort(key=lambda row: row["logical_id"])

    train_path = bot_root / Path(grouped["ten_best_predefined_train"][0]["source_relative_path"])
    test_path = bot_root / Path(grouped["ten_best_predefined_test"][0]["source_relative_path"])
    train_ids = first_pk_ids(train_path, ",")
    test_ids = first_pk_ids(test_path, ",")
    fixed_ids = list(range(1, BOT_TOTAL + 1, 100_000)) + [BOT_TOTAL]
    target_ids = set(fixed_ids + train_ids + test_ids)

    all_features = scan_bot_representation(
        grouped["all_features_5pct_shards"], bot_root, target_ids, duplicate_sample=True
    )
    full = scan_bot_representation(grouped["ten_best_full"], bot_root, target_ids)
    train = scan_bot_representation(grouped["ten_best_predefined_train"], bot_root, target_ids)
    test = scan_bot_representation(grouped["ten_best_predefined_test"], bot_root, target_ids)

    all_seen = all_features["seen"]
    full_seen = full["seen"]
    train_seen = train["seen"]
    test_seen = test["seen"]
    missing_from_all = 0
    missing_from_full = 0
    intersection = 0
    union_count = 0
    union_differs_from_full = 0
    for identifier in range(1, BOT_TOTAL + 1):
        in_all = bool(all_seen[identifier])
        in_full = bool(full_seen[identifier])
        in_train = bool(train_seen[identifier])
        in_test = bool(test_seen[identifier])
        missing_from_all += int(in_full and not in_all)
        missing_from_full += int(in_all and not in_full)
        intersection += int(in_train and in_test)
        in_union = in_train or in_test
        union_count += int(in_union)
        union_differs_from_full += int(in_union != in_full)

    full_sample_ids = sorted(target_ids)
    train_sample_ids = [identifier for identifier in train_ids if identifier in target_ids]
    test_sample_ids = [identifier for identifier in test_ids if identifier in target_ids]
    comparisons = {
        "all_features_vs_ten_best_full": compare_lineage_samples(
            all_features["sample_rows"], full["sample_rows"], full_sample_ids
        ),
        "ten_best_full_vs_predefined_train": compare_lineage_samples(
            full["sample_rows"], train["sample_rows"], train_sample_ids
        ),
        "ten_best_full_vs_predefined_test": compare_lineage_samples(
            full["sample_rows"], test["sample_rows"], test_sample_ids
        ),
    }
    persisted = load_json(AUDIT_DIR / "bot_iot_lineage_summary.json")
    independent = {
        "all_features": all_features,
        "ten_best_full": full,
        "ten_best_predefined_train": train,
        "ten_best_predefined_test": test,
    }
    persisted_pk_matches = {}
    for representation, observed in independent.items():
        expected = persisted[representation]
        fields = (
            "row_count",
            "pk_missing_count",
            "pk_numeric_parse_failure_count",
            "pk_duplicate_count",
            "pk_unique_count",
            "pk_min",
            "pk_max",
        )
        persisted_pk_matches[representation] = all(
            observed[field] == expected[field] for field in fields
        )

    unnamed = full["unnamed_leading_column"]
    expected_unnamed = persisted["unnamed_leading_column"]
    unnamed_matches = bool(
        unnamed
        and unnamed["numeric_parse_failure_count"]
        == expected_unnamed["numeric_parse_failure_count"]
        and unnamed["duplicate_count"] == expected_unnamed["duplicate_count"]
        and unnamed["unique_count"] == expected_unnamed["unique_count"]
        and unnamed["min"] == expected_unnamed["min"]
        and unnamed["max"] == expected_unnamed["max"]
        and unnamed["physical_position_mismatch_count"] == 0
    )
    pk_sets = {
        "all_features_vs_ten_best_full_missing_from_all_features": missing_from_all,
        "all_features_vs_ten_best_full_missing_from_ten_best_full": missing_from_full,
        "train_test_intersection_count": intersection,
        "train_test_union_count": union_count,
        "train_test_union_equals_full": union_differs_from_full == 0,
        "whole_dataset_method": "independent byte-per-ID membership maps over every source record",
    }
    expected_sets = persisted["pkseqid_sets"]
    pk_sets_match = all(
        pk_sets[key] == expected_sets[key]
        for key in (
            "all_features_vs_ten_best_full_missing_from_all_features",
            "all_features_vs_ten_best_full_missing_from_ten_best_full",
            "train_test_intersection_count",
            "train_test_union_count",
            "train_test_union_equals_full",
        )
    )
    sample_supports_nonexact = (
        comparisons["all_features_vs_ten_best_full"]["records_with_differences"] > 0
        and comparisons["ten_best_full_vs_predefined_train"]["records_with_differences"] > 0
        and comparisons["ten_best_full_vs_predefined_test"]["records_with_differences"] > 0
    )
    status = (
        "PASS"
        if all(persisted_pk_matches.values())
        and pk_sets_match
        and unnamed_matches
        and sample_supports_nonexact
        else "FAIL"
    )
    return {
        "method": (
            "Python csv-module full pkSeqID scans, independent membership maps, order "
            "digests, Decimal-aware sample comparisons, and exact sampled-row hashing"
        ),
        "representations": {
            representation: strip_scan_result(result)
            for representation, result in independent.items()
        },
        "persisted_pk_profiles_match": persisted_pk_matches,
        "pkseqid_set_reconciliation": pk_sets,
        "pkseqid_set_reconciliation_matches_artifact": pk_sets_match,
        "all_features_and_ten_best_pk_order_matches": (
            all_features["pk_order_sha256"] == full["pk_order_sha256"]
        ),
        "sample_comparisons": comparisons,
        "samples_support_reported_nonexact_value_lineage": sample_supports_nonexact,
        "unnamed_leading_column_matches_artifact": unnamed_matches,
        "status": status,
    }


def verify_duplicates(
    n_root: Path, extracted_root: Path, temp_dir: Path, lineage: dict[str, Any]
) -> dict[str, Any]:
    n_summary = load_json(AUDIT_DIR / "n_baiot_duplicate_summary.json")
    bot_summary = load_json(AUDIT_DIR / "bot_iot_duplicate_summary.json")
    n_math = reconcile_duplicate_metrics(n_summary)
    bot_math = {
        "all_features_full_46": reconcile_duplicate_metrics(
            bot_summary["all_features_5pct_shards"]["full_46_observed_fields"]
        ),
        "all_features_non_label_43": reconcile_duplicate_metrics(
            bot_summary["all_features_5pct_shards"][
                "all_43_observed_non_label_fields"
            ]
        ),
        "ten_best_full_20": reconcile_duplicate_metrics(
            bot_summary["ten_best_full"]["full_20_observed_fields"]
        ),
        "ten_best_named_non_label_16": reconcile_duplicate_metrics(
            bot_summary["ten_best_full"]["named_16_non_label_fields_excluding_unnamed"]
        ),
    }
    examples = verify_n_duplicate_examples(n_root, extracted_root)
    candidate_counts = temp_candidate_counts(temp_dir / "a4_audit.sqlite")
    bot_sample = lineage["representations"]["all_features"]["duplicate_sample"]
    n_conflicts_zero = all(
        n_summary[key]["group_count"] == 0
        for key in (
            "same_feature_different_fine_label",
            "same_feature_different_family",
            "same_feature_benign_malicious_conflict",
        )
    )
    bot_conflicts_zero = all(
        bot_summary["all_features_5pct_shards"]["all_43_observed_non_label_fields"][key][
            "group_count"
        ]
        == 0
        for key in ("different_attack", "different_category", "different_subcategory")
    )
    bot_candidate_groups_zero = all(
        value == 0
        for key, value in candidate_counts.items()
        if key.startswith("candidate_hash_groups:bot_iot:")
    )
    status = "PASS" if (
        all(n_math.values())
        and all(all(result.values()) for result in bot_math.values())
        and examples
        and all(example["direct_source_values_equal"] for example in examples)
        and n_conflicts_zero
        and bot_conflicts_zero
        and bot_candidate_groups_zero
        and bot_sample["full_row_duplicate_excess_in_sample"] == 0
        and bot_sample["non_label_duplicate_excess_in_sample"] == 0
    ) else "FAIL"
    return {
        "n_baiot_mathematical_reconciliation": n_math,
        "n_baiot_direct_original_row_duplicate_checks": examples,
        "n_baiot_reported_cross_label_conflict_groups_are_zero": n_conflicts_zero,
        "bot_iot_mathematical_reconciliation": bot_math,
        "bot_iot_reported_conflicting_label_groups_are_zero": bot_conflicts_zero,
        "primary_candidate_database_reconciliation": candidate_counts,
        "bot_iot_candidate_hash_groups_are_zero": bot_candidate_groups_zero,
        "bot_iot_independent_exact_sample": bot_sample,
        "status": status,
    }


def discover_metadata(root: Path) -> dict[str, dict[str, Any]]:
    observed = {}
    for current_root, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_root)
        directory_names[:] = sorted(
            name for name in directory_names if not (current / name).is_symlink()
        )
        for file_name in sorted(file_names):
            path = current / file_name
            if path.is_symlink() or not path.is_file():
                continue
            stat = path.stat()
            observed[path.relative_to(root).as_posix()] = {
                "size_bytes": stat.st_size,
                "modified_time_utc": datetime.fromtimestamp(stat.st_mtime, tz=UTC).isoformat(),
            }
    return observed


def reconcile_manifest(root: Path, manifest_path: Path, relative_field: str) -> dict[str, Any]:
    rows = load_csv(manifest_path)
    expected = {row[relative_field]: row for row in rows}
    observed = discover_metadata(root)
    missing = sorted(set(expected) - set(observed))
    unexpected = sorted(set(observed) - set(expected))
    size_mismatches = sorted(
        path
        for path in set(expected) & set(observed)
        if int(expected[path]["size_bytes"]) != observed[path]["size_bytes"]
    )
    timestamp_mismatches = []
    if "modified_time_utc" in rows[0]:
        timestamp_mismatches = sorted(
            path
            for path in set(expected) & set(observed)
            if expected[path]["modified_time_utc"] != observed[path]["modified_time_utc"]
        )
    return {
        "root": str(root),
        "expected_file_count": len(expected),
        "observed_file_count": len(observed),
        "missing_paths": missing,
        "unexpected_paths": unexpected,
        "size_mismatches": size_mismatches,
        "modified_time_mismatches": timestamp_mismatches,
        "metadata_match": not (
            missing or unexpected or size_mismatches or timestamp_mismatches
        ),
    }


def verify_artifacts() -> dict[str, Any]:
    summary_path = AUDIT_DIR / "a4_audit_summary.json"
    summary = load_json(summary_path)
    parsed_json = []
    for name in (
        "a4_audit_summary.json",
        "n_baiot_duplicate_summary.json",
        "bot_iot_duplicate_summary.json",
        "bot_iot_lineage_summary.json",
    ):
        load_json(AUDIT_DIR / name)
        parsed_json.append(f"artifacts/audit/{name}")
    hash_results = {}
    for relative_path, expected in summary["artifact_sha256"].items():
        observed = sha256_file(PROJECT_ROOT / Path(relative_path))
        hash_results[relative_path] = {
            "expected_sha256": expected,
            "observed_sha256": observed,
            "match": expected == observed,
        }
    n_quality = load_csv(AUDIT_DIR / "n_baiot_quality_summary.csv")
    bot_quality = load_csv(AUDIT_DIR / "bot_iot_quality_summary.csv")
    counts = {
        "n_baiot_quality_record_types": dict(Counter(row["record_type"] for row in n_quality)),
        "bot_iot_quality_record_types": dict(
            Counter(row["record_type"] for row in bot_quality)
        ),
        "flagged_example_rows": len(load_csv(AUDIT_DIR / "a4_flagged_examples.csv")),
    }
    expected_counts = {
        "n_baiot_quality_record_types": {"column": 115, "file": 89, "file_column": 10_235},
        "bot_iot_quality_record_types": {"column": 104, "file": 7, "file_column": 242},
    }
    return {
        "parsed_json_artifacts": parsed_json,
        "artifact_hashes": hash_results,
        "artifact_row_counts": counts,
        "expected_quality_record_type_counts": expected_counts,
        "all_hashes_match": all(result["match"] for result in hash_results.values()),
        "quality_record_type_counts_match": all(
            counts[key] == expected for key, expected in expected_counts.items()
        ),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-baiot-root", type=Path, required=True)
    parser.add_argument("--bot-iot-root", type=Path, required=True)
    parser.add_argument("--n-baiot-extracted-root", type=Path, required=True)
    parser.add_argument("--temp-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    n_root = args.n_baiot_root.resolve()
    bot_root = args.bot_iot_root.resolve()
    extracted_root = args.n_baiot_extracted_root.resolve()
    temp_dir = args.temp_dir.resolve()
    for root in (n_root, bot_root, extracted_root, temp_dir):
        if not root.is_dir():
            raise FileNotFoundError(f"Required directory does not exist: {root}")

    artifacts = verify_artifacts()
    quality = verify_quality(n_root, bot_root, extracted_root)
    lineage = verify_bot_lineage(bot_root)
    duplicates = verify_duplicates(n_root, extracted_root, temp_dir, lineage)
    source_safety = {
        "n_baiot_raw": reconcile_manifest(
            n_root, MANIFEST_DIR / "n_baiot_raw_manifest.csv", "relative_path"
        ),
        "bot_iot_raw": reconcile_manifest(
            bot_root, MANIFEST_DIR / "bot_iot_raw_manifest.csv", "relative_path"
        ),
        "n_baiot_extracted": reconcile_manifest(
            extracted_root,
            MANIFEST_DIR / "n_baiot_extracted_manifest.csv",
            "extracted_relative_path",
        ),
    }
    checks = [
        artifacts["all_hashes_match"],
        artifacts["quality_record_type_counts_match"],
        quality["n_baiot"]["status"] == "PASS",
        quality["bot_iot"]["status"] == "PASS",
        lineage["status"] == "PASS",
        duplicates["status"] == "PASS",
        all(result["metadata_match"] for result in source_safety.values()),
    ]
    payload = {
        "audit_batch": "A4",
        "generated_at_utc": datetime.now(tz=UTC).isoformat(),
        "verification_independence": (
            "The verifier uses Python's csv module, binary line counts, Decimal-aware value "
            "comparisons, independent byte-per-ID membership maps, direct original-row "
            "comparisons, and cryptographic sampled-row digests. It does not import the "
            "primary A4 implementation. The retained primary SQLite database is consulted "
            "only to reconcile candidate-selection counts, not to establish row equality."
        ),
        "artifact_reconciliation": artifacts,
        "quality_verification": quality,
        "duplicate_verification": duplicates,
        "lineage_verification": lineage,
        "source_safety": source_safety,
        "overall_status": "PASS" if all(checks) else "FAIL",
    }
    write_json_atomic(payload, args.output.resolve())
    print(f"Wrote: {args.output.resolve()}")
    print(f"Overall status: {payload['overall_status']}")
    return 0 if payload["overall_status"] == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, csv.Error, json.JSONDecodeError, sqlite3.Error) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
