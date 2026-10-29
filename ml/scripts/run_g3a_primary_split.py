"""Build compact G3A primary split evidence without materializing split rows."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import sqlite3
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any

from iotguard.data.contracts import load_contract
from iotguard.data.n_baiot import iter_n_baiot_records
from iotguard.data.split import (
    EVALUATION_GROUP_SCHEME,
    MEMBERSHIP_DIGEST_SCHEME,
    SPLIT_NAMES,
    SPLIT_NAMESPACE,
    SPLIT_VERSION,
    TRAIN_BOUNDARY,
    UINT64_SPACE,
    VALIDATION_BOUNDARY,
    acceptance_status,
    assign_evaluation_group,
    class_coverage_passes,
    evaluation_group_id,
    prevalence_drift_percentage_points,
    update_membership_digest,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = PROJECT_ROOT / "artifacts" / "audit"
CONTRACT_DIR = PROJECT_ROOT / "artifacts" / "contracts"
MANIFEST_DIR = PROJECT_ROOT / "artifacts" / "manifests"
TRAVERSAL_PATH = MANIFEST_DIR / "n_baiot_canonical_traversal_v1.csv"
CONTRACT_PATH = CONTRACT_DIR / "n_baiot_primary_split_contract_v1.json"
NUMERIC_PATH = AUDIT_DIR / "g3a_numeric_equivalence_summary.json"
SUMMARY_PATH = AUDIT_DIR / "g3a_primary_split_summary.json"
CLASS_PATH = AUDIT_DIR / "g3a_class_distribution.csv"
DEVICE_PATH = AUDIT_DIR / "g3a_device_split_summary.csv"
DEFAULT_WORK_DIR = Path(r"E:\Document\iotguard_dataset_work\g3a_split_v1")
EXPECTED_ROWS = 7_062_606
EXPECTED_SOURCES = 89
EXPECTED_G2_MANIFEST_SHA256 = (
    "86f967843a32ee084c319986dee74772e93ecc43d0ad6159cac986318c9af687"
)
EXPECTED_TRAVERSAL_SHA256 = (
    "599a3ecaa251e9f91e6a2124dee49ffd1fd0ecfc2c3499779caa59bfcfdf44bb"
)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def traversal_rows() -> list[dict[str, str]]:
    with TRAVERSAL_PATH.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != EXPECTED_SOURCES:
        raise ValueError(f"Expected {EXPECTED_SOURCES} traversal sources, found {len(rows)}")
    if sum(int(row["expected_row_count"]) for row in rows) != EXPECTED_ROWS:
        raise ValueError("Traversal expected rows do not reconcile")
    if rows != sorted(rows, key=lambda row: row["logical_id"]):
        raise ValueError("Traversal is not in canonical logical-ID order")
    return rows


def configured_roots() -> dict[str, Path]:
    source_safety = load_json(AUDIT_DIR / "a4_evidence_verification.json")["source_safety"]
    return {name: Path(details["root"]) for name, details in source_safety.items()}


def source_snapshot(root: Path) -> dict[str, object]:
    digest = hashlib.sha256()
    count = 0
    total = 0
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=str):
        stat = path.stat()
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(stat.st_size.to_bytes(8, "big"))
        digest.update(stat.st_mtime_ns.to_bytes(8, "big", signed=True))
        count += 1
        total += stat.st_size
    return {
        "file_count": count,
        "total_size_bytes": total,
        "metadata_digest_sha256": digest.hexdigest(),
    }


def source_snapshots(roots: dict[str, Path]) -> dict[str, dict[str, object]]:
    return {name: source_snapshot(root) for name, root in sorted(roots.items())}


def database_size(work_dir: Path) -> int:
    return sum(path.stat().st_size for path in work_dir.glob("g3a_primary.sqlite*"))


def initialize_database(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(f"{path}{suffix}")
        if candidate.exists():
            candidate.unlink()
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        PRAGMA temp_store=MEMORY;
        PRAGMA cache_size=-200000;
        CREATE TABLE evaluation_labels (
            evaluation_group_id TEXT NOT NULL,
            binary_label TEXT NOT NULL,
            family_label TEXT NOT NULL,
            fine_label TEXT NOT NULL,
            split_name TEXT NOT NULL,
            observation_count INTEGER NOT NULL,
            PRIMARY KEY (evaluation_group_id, binary_label, family_label, fine_label)
        ) WITHOUT ROWID;
        CREATE TABLE lexical_groups (
            duplicate_group_id TEXT NOT NULL,
            evaluation_group_id TEXT NOT NULL,
            observation_count INTEGER NOT NULL,
            PRIMARY KEY (duplicate_group_id, evaluation_group_id)
        ) WITHOUT ROWID;
        """
    )
    return connection


def flush_groups(
    connection: sqlite3.Connection,
    evaluation_batch: Counter[tuple[str, str, str, str, str]],
    lexical_batch: Counter[tuple[str, str]],
) -> None:
    connection.executemany(
        """
        INSERT INTO evaluation_labels VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(evaluation_group_id, binary_label, family_label, fine_label)
        DO UPDATE SET observation_count = observation_count + excluded.observation_count
        """,
        ((*key, count) for key, count in evaluation_batch.items()),
    )
    connection.executemany(
        """
        INSERT INTO lexical_groups VALUES (?, ?, ?)
        ON CONFLICT(duplicate_group_id, evaluation_group_id)
        DO UPDATE SET observation_count = observation_count + excluded.observation_count
        """,
        ((*key, count) for key, count in lexical_batch.items()),
    )
    connection.commit()
    evaluation_batch.clear()
    lexical_batch.clear()


def analyze_database(connection: sqlite3.Connection) -> dict[str, Any]:
    unique_evaluation = connection.execute(
        "SELECT COUNT(DISTINCT evaluation_group_id) FROM evaluation_labels"
    ).fetchone()[0]
    unique_lexical = connection.execute(
        "SELECT COUNT(DISTINCT duplicate_group_id) FROM lexical_groups"
    ).fetchone()[0]
    merged = connection.execute(
        """
        SELECT COUNT(*), COALESCE(SUM(lexical_count), 0),
               COALESCE(SUM(observation_count), 0)
        FROM (
            SELECT evaluation_group_id, COUNT(*) AS lexical_count,
                   SUM(observation_count) AS observation_count
            FROM lexical_groups
            GROUP BY evaluation_group_id
            HAVING COUNT(*) > 1
        )
        """
    ).fetchone()
    conflicts = connection.execute(
        """
        SELECT evaluation_group_id,
               COUNT(DISTINCT binary_label), COUNT(DISTINCT family_label),
               COUNT(DISTINCT fine_label), SUM(observation_count)
        FROM evaluation_labels
        GROUP BY evaluation_group_id
        HAVING COUNT(DISTINCT binary_label) > 1
            OR COUNT(DISTINCT family_label) > 1
            OR COUNT(DISTINCT fine_label) > 1
        ORDER BY evaluation_group_id
        """
    ).fetchall()
    merge_examples = connection.execute(
        """
        SELECT evaluation_group_id, COUNT(*) AS lexical_count,
               SUM(observation_count) AS observation_count
        FROM lexical_groups
        GROUP BY evaluation_group_id
        HAVING COUNT(*) > 1
        ORDER BY evaluation_group_id
        LIMIT 10
        """
    ).fetchall()
    evaluation_overlap = connection.execute(
        """
        SELECT COUNT(*) FROM (
            SELECT evaluation_group_id
            FROM evaluation_labels
            GROUP BY evaluation_group_id
            HAVING COUNT(DISTINCT split_name) > 1
        )
        """
    ).fetchone()[0]
    duplicate_overlap = connection.execute(
        """
        SELECT COUNT(*) FROM (
            SELECT duplicate_group_id
            FROM lexical_groups AS lexical
            JOIN evaluation_labels AS evaluation USING (evaluation_group_id)
            GROUP BY duplicate_group_id
            HAVING COUNT(DISTINCT split_name) > 1
        )
        """
    ).fetchone()[0]
    lexical_to_multiple_numeric = connection.execute(
        """
        SELECT COUNT(*) FROM (
            SELECT duplicate_group_id
            FROM lexical_groups
            GROUP BY duplicate_group_id
            HAVING COUNT(DISTINCT evaluation_group_id) > 1
        )
        """
    ).fetchone()[0]
    return {
        "unique_duplicate_group_count": unique_lexical,
        "unique_evaluation_group_count": unique_evaluation,
        "numeric_groups_merging_lexical_groups": merged[0],
        "lexical_groups_in_numeric_merges": merged[1],
        "lexical_groups_eliminated_by_numeric_equivalence": unique_lexical - unique_evaluation,
        "observations_in_numeric_merges": merged[2],
        "cross_label_numeric_group_count": len(conflicts),
        "cross_label_conflict_examples": [
            {
                "evaluation_group_id": row[0],
                "binary_label_count": row[1],
                "family_label_count": row[2],
                "fine_label_count": row[3],
                "observation_count": row[4],
            }
            for row in conflicts[:10]
        ],
        "numeric_merge_examples": [
            {
                "evaluation_group_id": row[0],
                "lexical_group_count": row[1],
                "observation_count": row[2],
            }
            for row in merge_examples
        ],
        "evaluation_group_cross_partition_overlap_count": evaluation_overlap,
        "duplicate_group_cross_partition_overlap_count": duplicate_overlap,
        "lexical_groups_mapping_to_multiple_numeric_groups": lexical_to_multiple_numeric,
    }


def nested_class_counts(
    counts: Counter[tuple[str, str, str]], levels: dict[str, list[str]]
) -> dict[str, dict[str, dict[str, int]]]:
    return {
        split: {
            level: {label: counts[(split, level, label)] for label in labels}
            for level, labels in levels.items()
        }
        for split in SPLIT_NAMES
    }


def build_class_rows(
    split_counts: Counter[str],
    class_counts: Counter[tuple[str, str, str]],
    full_counts: Counter[tuple[str, str]],
    levels: dict[str, list[str]],
    total_rows: int,
) -> tuple[list[dict[str, object]], float, float]:
    rows: list[dict[str, object]] = []
    max_fine = 0.0
    max_all = 0.0
    for level, labels in levels.items():
        for label in labels:
            full_count = full_counts[(level, label)]
            for split in SPLIT_NAMES:
                count = class_counts[(split, level, label)]
                drift = prevalence_drift_percentage_points(
                    count, split_counts[split], full_count, total_rows
                )
                max_all = max(max_all, drift)
                if level == "fine":
                    max_fine = max(max_fine, drift)
                rows.append(
                    {
                        "level": level,
                        "class": label,
                        "split": split,
                        "row_count": count,
                        "percentage_within_split": 100 * count / split_counts[split],
                        "percentage_of_class_assigned_to_split": 100 * count / full_count,
                        "full_prevalence_percentage": 100 * full_count / total_rows,
                        "absolute_prevalence_drift_percentage_points": drift,
                    }
                )
    return rows, max_fine, max_all


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--full", action="store_true", help="scan all 7,062,606 rows")
    parser.add_argument("--max-rows-per-source", type=int, default=10)
    parser.add_argument("--work-dir", type=Path, default=DEFAULT_WORK_DIR)
    parser.add_argument("--n-baiot-raw-root", type=Path)
    parser.add_argument("--n-baiot-extracted-root", type=Path)
    parser.add_argument("--bot-iot-root", type=Path)
    args = parser.parse_args()
    if not args.full and args.max_rows_per_source < 1:
        parser.error("--max-rows-per-source must be positive")

    if sha256_file(TRAVERSAL_PATH) != EXPECTED_TRAVERSAL_SHA256:
        raise ValueError("Canonical traversal hash changed")
    g2_manifest_path = MANIFEST_DIR / "g2_preprocessing_reproducibility_manifest.json"
    if sha256_file(g2_manifest_path) != EXPECTED_G2_MANIFEST_SHA256:
        raise ValueError("G2 reproducibility manifest hash changed")

    rows = traversal_rows()
    roots = configured_roots()
    for name, path in (
        ("n_baiot_raw", args.n_baiot_raw_root),
        ("n_baiot_extracted", args.n_baiot_extracted_root),
        ("bot_iot_raw", args.bot_iot_root),
    ):
        if path is not None:
            roots[name] = path.expanduser().resolve()
    source_before = source_snapshots(roots)
    expected_source = load_json(AUDIT_DIR / "g2c_bounded_materialization_smoke.json")[
        "source_safety"
    ]["expected_a5_baseline"]
    if source_before != expected_source:
        raise ValueError("Source metadata differs from the locked A5/G2 baseline")

    database_path = args.work_dir / "g3a_primary.sqlite"
    connection = initialize_database(database_path) if args.full else sqlite3.connect(":memory:")
    if not args.full:
        connection.executescript(
            """
            CREATE TABLE evaluation_labels (
                evaluation_group_id TEXT, binary_label TEXT, family_label TEXT,
                fine_label TEXT, split_name TEXT, observation_count INTEGER,
                PRIMARY KEY (evaluation_group_id, binary_label, family_label, fine_label)
            );
            CREATE TABLE lexical_groups (
                duplicate_group_id TEXT, evaluation_group_id TEXT, observation_count INTEGER,
                PRIMARY KEY (duplicate_group_id, evaluation_group_id)
            );
            """
        )

    started = perf_counter()
    disk_volume = args.work_dir.parent if args.work_dir.parent.exists() else PROJECT_ROOT
    disk_before = shutil.disk_usage(disk_volume)
    membership = hashlib.sha256()
    split_counts: Counter[str] = Counter()
    class_counts: Counter[tuple[str, str, str]] = Counter()
    full_counts: Counter[tuple[str, str]] = Counter()
    device_counts: Counter[tuple[str, str]] = Counter()
    source_counts: Counter[tuple[str, str, str]] = Counter()
    evaluation_batch: Counter[tuple[str, str, str, str, str]] = Counter()
    lexical_batch: Counter[tuple[str, str]] = Counter()
    golden: dict[str, list[dict[str, object]]] = {split: [] for split in SPLIT_NAMES}
    total_rows = 0
    completed_sources = 0

    for traversal in rows:
        path = roots[traversal["source_root_kind"]] / Path(traversal["source_relative_path"])
        source_rows = 0
        for record in iter_n_baiot_records(path, traversal["logical_id"]):
            if not args.full and source_rows >= args.max_rows_per_source:
                break
            source_rows += 1
            total_rows += 1
            group_id = evaluation_group_id(record.features)
            split = assign_evaluation_group(group_id)
            update_membership_digest(
                membership,
                record.source_logical_id,
                record.data_row_index or 0,
                group_id,
                split,
            )
            evaluation_batch[
                (group_id, record.target_binary, record.label_family, record.label_fine, split)
            ] += 1
            lexical_batch[(record.duplicate_group_id, group_id)] += 1
            split_counts[split] += 1
            for level, label in (
                ("binary", record.target_binary),
                ("family", record.label_family),
                ("fine", record.label_fine),
            ):
                class_counts[(split, level, label)] += 1
                full_counts[(level, label)] += 1
            device_counts[(record.device, split)] += 1
            source_counts[(record.source_logical_id, record.device, split)] += 1
            if len(golden[split]) < 5:
                golden[split].append(
                    {
                        "source_logical_id": record.source_logical_id,
                        "source_data_row_index": record.data_row_index,
                        "evaluation_group_id_v1": group_id,
                        "duplicate_group_id": record.duplicate_group_id,
                        "split": split,
                        "target_binary": record.target_binary,
                        "label_family": record.label_family,
                        "label_fine": record.label_fine,
                    }
                )
            if len(evaluation_batch) >= 50_000:
                flush_groups(connection, evaluation_batch, lexical_batch)
        if args.full and source_rows != int(traversal["expected_row_count"]):
            raise ValueError(f"Source row mismatch: {traversal['logical_id']}")
        completed_sources += 1
        if args.full:
            print(
                f"[{completed_sources:02d}/{EXPECTED_SOURCES}] "
                f"{traversal['logical_id']}: {source_rows} rows",
                flush=True,
            )
    flush_groups(connection, evaluation_batch, lexical_batch)
    database = analyze_database(connection)
    connection.close()

    source_after = source_snapshots(roots)
    if source_after != source_before:
        raise ValueError("Source metadata changed during G3A scan")
    elapsed = perf_counter() - started
    disk_after = shutil.disk_usage(disk_volume)
    levels = load_contract("n_baiot_label_contract_v1.json")["levels"]

    if not args.full:
        result = {
            "mode": "BOUNDED",
            "logical_sources": completed_sources,
            "rows": total_rows,
            "split_counts": dict(split_counts),
            "database_analysis": database,
            "membership_digest": membership.hexdigest(),
            "golden_examples": golden,
            "runtime_seconds": elapsed,
            "source_metadata_unchanged": source_before == source_after,
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0

    if completed_sources != EXPECTED_SOURCES or total_rows != EXPECTED_ROWS:
        raise ValueError("Full scan did not reconcile to 89 sources and 7,062,606 rows")

    nested_counts = nested_class_counts(class_counts, levels)
    class_rows, max_fine_drift, max_all_drift = build_class_rows(
        split_counts, class_counts, full_counts, levels, total_rows
    )
    minimum_validation_fine = min(
        class_counts[("VALIDATION", "fine", label)] for label in levels["fine"]
    )
    minimum_test_fine = min(
        class_counts[("TEST", "fine", label)] for label in levels["fine"]
    )
    fractions = {split: split_counts[split] / total_rows for split in SPLIT_NAMES}
    gates = {
        "total_rows_exact": total_rows == EXPECTED_ROWS,
        "train_fraction_69_5_to_70_5_percent": 0.695 <= fractions["TRAIN"] <= 0.705,
        "validation_fraction_14_5_to_15_5_percent": (
            0.145 <= fractions["VALIDATION"] <= 0.155
        ),
        "test_fraction_14_5_to_15_5_percent": 0.145 <= fractions["TEST"] <= 0.155,
        "all_class_coverage": class_coverage_passes(nested_counts, levels),
        "validation_minimum_fine_support_25000": minimum_validation_fine >= 25_000,
        "test_minimum_fine_support_25000": minimum_test_fine >= 25_000,
        "validation_benign_support_50000": (
            class_counts[("VALIDATION", "fine", "benign")] >= 50_000
        ),
        "test_benign_support_50000": class_counts[("TEST", "fine", "benign")] >= 50_000,
        "maximum_fine_prevalence_drift_0_25_percentage_points": max_fine_drift <= 0.25,
        "evaluation_group_overlap_zero": (
            database["evaluation_group_cross_partition_overlap_count"] == 0
        ),
        "duplicate_group_overlap_zero": (
            database["duplicate_group_cross_partition_overlap_count"] == 0
        ),
        "cross_label_numeric_groups_zero": database["cross_label_numeric_group_count"] == 0,
        "lexical_group_maps_to_one_numeric_group": (
            database["lexical_groups_mapping_to_multiple_numeric_groups"] == 0
        ),
        "source_metadata_unchanged": source_before == source_after == expected_source,
    }
    devices = sorted({device for device, _ in device_counts})
    all_devices_have_all_splits = all(
        device_counts[(device, split)] > 0 for device in devices for split in SPLIT_NAMES
    )
    all_sources_have_all_splits = all(
        source_counts[(source, device, split)] > 0
        for source, device in {(source, device) for source, device, _ in source_counts}
        for split in SPLIT_NAMES
    )
    gates["all_nine_devices_have_all_partitions"] = (
        len(devices) == 9 and all_devices_have_all_splits
    )
    status = acceptance_status(gates)

    numeric_summary = {
        "audit_batch": "G3A numeric-equivalence audit",
        "evaluation_group_scheme": {
            "name": EVALUATION_GROUP_SCHEME,
            "feature_count": 115,
            "finite_required": True,
            "signed_zero_rule": "value == 0.0 is encoded as positive +0.0",
            "value_encoding": "IEEE-754 binary64 big-endian",
            "vector_encoding": "concatenation of 115 ordered 8-byte values",
            "hash": "SHA-256",
            "identifier_format": "sha256:<64 lowercase hex>",
            "predictor_eligible": False,
        },
        **database,
        "overall_status": "PASS" if database["cross_label_numeric_group_count"] == 0 else "STOP",
    }
    summary = {
        "audit_batch": "G3A final primary evaluation split assignment",
        "overall_status": status,
        "logical_sources": completed_sources,
        "total_rows": total_rows,
        "split_counts": {
            split: {"row_count": split_counts[split], "fraction": fractions[split]}
            for split in SPLIT_NAMES
        },
        "class_counts": nested_counts,
        "minimum_validation_fine_support": minimum_validation_fine,
        "minimum_test_fine_support": minimum_test_fine,
        "maximum_fine_prevalence_drift_percentage_points": max_fine_drift,
        "maximum_all_level_prevalence_drift_percentage_points": max_all_drift,
        "acceptance_gates": gates,
        "coverage_diagnostics": {
            "device_count": len(devices),
            "all_nine_devices_have_all_partitions": (
                len(devices) == 9 and all_devices_have_all_splits
            ),
            "all_89_sources_have_all_partitions": all_sources_have_all_splits,
            "source_design_absences": {
                "Ennio_Doorbell_mirai": "ABSENT_BY_SOURCE_DESIGN",
                "Samsung_SNH_1011_N_Webcam_mirai": "ABSENT_BY_SOURCE_DESIGN",
            },
            "main_split_is_device_held_out": False,
            "source_identity_leakage_claimed": False,
        },
        "membership_digest": {
            "scheme": MEMBERSHIP_DIGEST_SCHEME,
            "sha256": membership.hexdigest(),
            "order": "canonical traversal: ascending logical ID, then physical data-row order",
            "fields": [
                "source_logical_id",
                "source_data_row_index",
                "evaluation_group_id_v1",
                "split_name",
            ],
        },
        "golden_examples": golden,
        "execution": {
            "runtime_seconds": elapsed,
            "temporary_database": str(database_path),
            "temporary_database_size_bytes": database_size(args.work_dir),
            "disk_free_bytes_before": disk_before.free,
            "disk_free_bytes_after": disk_after.free,
            "row_scale_split_artifact_written": False,
            "learned_transform_fit": False,
            "resampling_performed": False,
            "model_training_runs": 0,
            "clustering_runs": 0,
        },
        "source_safety": {
            "before": source_before,
            "after": source_after,
            "unchanged": source_before == source_after,
        },
    }

    device_rows: list[dict[str, object]] = []
    for device in devices:
        for split in SPLIT_NAMES:
            device_rows.append(
                {
                    "record_type": "device",
                    "device": device,
                    "source_logical_id": "",
                    "split": split,
                    "row_count": device_counts[(device, split)],
                }
            )
    sources = sorted({(source, device) for source, device, _ in source_counts})
    for source, device in sources:
        for split in SPLIT_NAMES:
            device_rows.append(
                {
                    "record_type": "source",
                    "device": device,
                    "source_logical_id": source,
                    "split": split,
                    "row_count": source_counts[(source, device, split)],
                }
            )

    write_json(NUMERIC_PATH, numeric_summary)
    write_json(SUMMARY_PATH, summary)
    write_csv(CLASS_PATH, list(class_rows[0]), class_rows)
    write_csv(
        DEVICE_PATH,
        ["record_type", "device", "source_logical_id", "split", "row_count"],
        device_rows,
    )

    if status == "ADOPTED":
        g2_manifest = load_json(g2_manifest_path)
        contract = {
            "contract_name": "n_baiot_primary_split_contract",
            "contract_version": "1.0.0",
            "split_version": SPLIT_VERSION,
            "status": "ADOPTED",
            "primary_dataset": "N-BaIoT",
            "feature_contract_hash": g2_manifest["g2a_contract_artifact_sha256"][
                "artifacts/contracts/n_baiot_feature_contract_v1.json"
            ],
            "feature_schema_hash": g2_manifest["feature_schema_sha256"],
            "label_contract_hash": g2_manifest["label_contract_sha256"],
            "evaluation_group_scheme": numeric_summary["evaluation_group_scheme"],
            "split_namespace": SPLIT_NAMESPACE,
            "delimiter": "ASCII Unit Separator U+001F encoded as one byte 0x1f",
            "split_hash_input": (
                "UTF-8 namespace + 0x1f + ASCII evaluation_group_id_v1 text"
            ),
            "hash_algorithm": "SHA-256; first 8 bytes as unsigned big-endian uint64",
            "thresholds": {
                "conceptual": {
                    "TRAIN": "u < 0.70",
                    "VALIDATION": "0.70 <= u < 0.85",
                    "TEST": "u >= 0.85",
                },
                "integer_train_upper_exclusive": TRAIN_BOUNDARY,
                "integer_validation_upper_exclusive": VALIDATION_BOUNDARY,
                "uint64_space": UINT64_SPACE,
            },
            "target_fractions": {"TRAIN": 0.70, "VALIDATION": 0.15, "TEST": 0.15},
            "acceptance_gates": gates,
            "observed_counts": summary["split_counts"],
            "observed_class_counts": nested_counts,
            "observed_drift": {
                "maximum_fine_percentage_points": max_fine_drift,
                "maximum_all_levels_percentage_points": max_all_drift,
            },
            "membership_digest": summary["membership_digest"],
            "source_manifest_hashes": g2_manifest["primary_source_manifest_sha256"],
            "canonical_traversal_sha256": EXPECTED_TRAVERSAL_SHA256,
            "g2_reproducibility_manifest_sha256": EXPECTED_G2_MANIFEST_SHA256,
            "test_set_status": "SEALED",
            "learned_transform_fit_partition": "TRAIN",
            "validation_policy": (
                "hyperparameter selection, model comparison, preprocessing choice, and later "
                "explicit threshold choice only"
            ),
            "test_access_policy": (
                "no access until one candidate configuration is frozen under G3B"
            ),
            "created_at_utc": datetime.now(UTC).isoformat(),
        }
        write_json(CONTRACT_PATH, contract)

    print(f"G3A primary status: {status}")
    print(f"Rows: {total_rows}; split counts: {dict(split_counts)}")
    print(f"Membership SHA-256: {membership.hexdigest()}")
    print(f"Temporary database retained at: {database_path}")
    return 0 if status == "ADOPTED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
