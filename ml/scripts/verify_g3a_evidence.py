"""Independently rescan and verify G3A split evidence and whole-corpus boundaries."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import sqlite3
import struct
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from iotguard.data.contracts import load_contract
from iotguard.data.n_baiot import iter_n_baiot_records

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = PROJECT_ROOT / "artifacts" / "audit"
CONTRACT_DIR = PROJECT_ROOT / "artifacts" / "contracts"
MANIFEST_DIR = PROJECT_ROOT / "artifacts" / "manifests"
TRAVERSAL_PATH = MANIFEST_DIR / "n_baiot_canonical_traversal_v1.csv"
SUMMARY_PATH = AUDIT_DIR / "g3a_primary_split_summary.json"
NUMERIC_PATH = AUDIT_DIR / "g3a_numeric_equivalence_summary.json"
CONTRACT_PATH = CONTRACT_DIR / "n_baiot_primary_split_contract_v1.json"
OUTPUT_PATH = AUDIT_DIR / "g3a_evidence_verification.json"
DEFAULT_WORK_DIR = Path(r"E:\Document\iotguard_dataset_work\g3a_split_v1")
EXPECTED_ROWS = 7_062_606
EXPECTED_SOURCES = 89
EXPECTED_G2_MANIFEST_SHA256 = (
    "86f967843a32ee084c319986dee74772e93ecc43d0ad6159cac986318c9af687"
)
EXPECTED_TRAVERSAL_SHA256 = (
    "599a3ecaa251e9f91e6a2124dee49ffd1fd0ecfc2c3499779caa59bfcfdf44bb"
)
NAMESPACE = b"iotguard-primary-split-v1"
DELIMITER = b"\x1f"
UINT64_SPACE = 1 << 64
TRAIN_BOUNDARY = (70 * UINT64_SPACE + 99) // 100
VALIDATION_BOUNDARY = (85 * UINT64_SPACE + 99) // 100
SPLITS = ("TRAIN", "VALIDATION", "TEST")


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


def independent_evaluation_group(features: tuple[float, ...]) -> str:
    if len(features) != 115:
        raise ValueError("Independent verifier expected 115 features")
    encoded = bytearray()
    for value in features:
        if not math.isfinite(value):
            raise ValueError("Independent verifier found a non-finite value")
        encoded.extend(struct.pack(">d", 0.0 if value == 0.0 else value))
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def independent_split(group_id: str) -> str:
    digest = hashlib.sha256(NAMESPACE + DELIMITER + group_id.encode("ascii")).digest()
    value = int.from_bytes(digest[:8], "big", signed=False)
    if value < TRAIN_BOUNDARY:
        return "TRAIN"
    if value < VALIDATION_BOUNDARY:
        return "VALIDATION"
    return "TEST"


def update_digest(
    digest: Any, source_id: str, row_index: int, group_id: str, split: str
) -> None:
    encoded_source = source_id.encode("utf-8")
    digest.update(len(encoded_source).to_bytes(4, "big", signed=False))
    digest.update(encoded_source)
    digest.update(row_index.to_bytes(8, "big", signed=False))
    for value in (group_id, split):
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big", signed=False))
        digest.update(encoded)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


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


def traversal_rows() -> list[dict[str, str]]:
    with TRAVERSAL_PATH.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


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
        CREATE TABLE groups (
            evaluation_group_id TEXT NOT NULL,
            duplicate_group_id TEXT NOT NULL,
            binary_label TEXT NOT NULL,
            family_label TEXT NOT NULL,
            fine_label TEXT NOT NULL,
            split_name TEXT NOT NULL,
            observation_count INTEGER NOT NULL,
            PRIMARY KEY (
                evaluation_group_id, duplicate_group_id,
                binary_label, family_label, fine_label
            )
        ) WITHOUT ROWID;
        """
    )
    return connection


def flush(
    connection: sqlite3.Connection,
    batch: Counter[tuple[str, str, str, str, str, str]],
) -> None:
    connection.executemany(
        """
        INSERT INTO groups VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(
            evaluation_group_id, duplicate_group_id,
            binary_label, family_label, fine_label
        ) DO UPDATE SET observation_count = observation_count + excluded.observation_count
        """,
        ((*key, count) for key, count in batch.items()),
    )
    connection.commit()
    batch.clear()


def forbidden_outputs() -> list[str]:
    forbidden: list[str] = []
    scan_roots = [PROJECT_ROOT / "artifacts", PROJECT_ROOT / "data" / "processed"]
    row_names = {
        "train.csv",
        "validation.csv",
        "test.csv",
        "x_train.npy",
        "x_validation.npy",
        "x_test.npy",
    }
    model_suffixes = {".joblib", ".pkl", ".pickle", ".onnx", ".pt", ".pth", ".h5"}
    for root in scan_roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and (
                path.name.lower() in row_names or path.suffix.lower() in model_suffixes
            ):
                forbidden.append(path.relative_to(PROJECT_ROOT).as_posix())
    return sorted(forbidden)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--max-rows-per-source", type=int, default=10)
    parser.add_argument("--work-dir", type=Path, default=DEFAULT_WORK_DIR)
    parser.add_argument("--n-baiot-raw-root", type=Path)
    parser.add_argument("--n-baiot-extracted-root", type=Path)
    parser.add_argument("--bot-iot-root", type=Path)
    args = parser.parse_args()
    if not args.full and args.max_rows_per_source < 1:
        parser.error("--max-rows-per-source must be positive")

    g2_manifest_path = MANIFEST_DIR / "g2_preprocessing_reproducibility_manifest.json"
    g2_manifest = load_json(g2_manifest_path)
    g2a_evidence = load_json(AUDIT_DIR / "g2a_evidence_verification.json")
    checks: dict[str, bool] = {
        "g2_reproducibility_manifest_hash_unchanged": sha256_file(
            g2_manifest_path
        )
        == EXPECTED_G2_MANIFEST_SHA256,
        "canonical_traversal_hash_unchanged": (
            sha256_file(TRAVERSAL_PATH) == EXPECTED_TRAVERSAL_SHA256
        ),
        "g2a_contract_manifest_hash_unchanged": (
            g2a_evidence["contract_manifest_sha256"]
            == "8c387493caaddd10ceab1f95ca0b9cb40318e23b6a9d68c3a1f3b6242fb5548e"
        ),
        "all_g2a_contract_artifact_hashes_unchanged": all(
            sha256_file(PROJECT_ROOT / relative_path) == expected_hash
            for relative_path, expected_hash in g2_manifest[
                "g2a_contract_artifact_sha256"
            ].items()
        ),
        "primary_source_manifest_hashes_unchanged": (
            sha256_file(MANIFEST_DIR / "n_baiot_extracted_manifest.csv")
            == g2_manifest["primary_source_manifest_sha256"]["extracted"]
            and sha256_file(MANIFEST_DIR / "n_baiot_raw_manifest.csv")
            == g2_manifest["primary_source_manifest_sha256"]["raw"]
        ),
    }
    rows = traversal_rows()
    checks["canonical_source_count_is_89"] = len(rows) == EXPECTED_SOURCES
    checks["canonical_expected_rows_are_7062606"] = (
        sum(int(row["expected_row_count"]) for row in rows) == EXPECTED_ROWS
    )

    summary = load_json(SUMMARY_PATH) if args.full else {}
    numeric = load_json(NUMERIC_PATH) if args.full else {}
    contract = load_json(CONTRACT_PATH) if args.full else {}
    golden_lookup: dict[tuple[str, int], dict[str, Any]] = {}
    if args.full:
        for examples in summary["golden_examples"].values():
            for example in examples:
                golden_lookup[
                    (example["source_logical_id"], example["source_data_row_index"])
                ] = example

    database_path = args.work_dir / "g3a_verify.sqlite"
    connection = initialize_database(database_path)
    roots = configured_roots()
    for name, path in (
        ("n_baiot_raw", args.n_baiot_raw_root),
        ("n_baiot_extracted", args.n_baiot_extracted_root),
        ("bot_iot_raw", args.bot_iot_root),
    ):
        if path is not None:
            roots[name] = path.expanduser().resolve()
    source_before = {name: source_snapshot(root) for name, root in sorted(roots.items())}
    expected_source = load_json(AUDIT_DIR / "g2c_bounded_materialization_smoke.json")[
        "source_safety"
    ]["expected_a5_baseline"]
    membership = hashlib.sha256()
    split_counts: Counter[str] = Counter()
    class_counts: Counter[tuple[str, str, str]] = Counter()
    full_counts: Counter[tuple[str, str]] = Counter()
    device_counts: Counter[tuple[str, str]] = Counter()
    source_counts: Counter[tuple[str, str, str]] = Counter()
    batch: Counter[tuple[str, str, str, str, str, str]] = Counter()
    golden_matches: dict[tuple[str, int], bool] = {}
    total_rows = 0

    for traversal in rows:
        path = roots[traversal["source_root_kind"]] / Path(traversal["source_relative_path"])
        source_rows = 0
        for record in iter_n_baiot_records(path, traversal["logical_id"]):
            if not args.full and source_rows >= args.max_rows_per_source:
                break
            source_rows += 1
            total_rows += 1
            group_id = independent_evaluation_group(record.features)
            split = independent_split(group_id)
            update_digest(
                membership,
                record.source_logical_id,
                record.data_row_index or 0,
                group_id,
                split,
            )
            batch[
                (
                    group_id,
                    record.duplicate_group_id,
                    record.target_binary,
                    record.label_family,
                    record.label_fine,
                    split,
                )
            ] += 1
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
            coordinate = (record.source_logical_id, record.data_row_index or 0)
            if coordinate in golden_lookup:
                expected = golden_lookup[coordinate]
                golden_matches[coordinate] = (
                    expected["evaluation_group_id_v1"] == group_id
                    and expected["duplicate_group_id"] == record.duplicate_group_id
                    and expected["split"] == split
                )
            if len(batch) >= 50_000:
                flush(connection, batch)
        if args.full and source_rows != int(traversal["expected_row_count"]):
            raise ValueError(f"Source row mismatch: {traversal['logical_id']}")
        if args.full:
            print(
                f"[verify {int(traversal['traversal_ordinal']):02d}/{EXPECTED_SOURCES}] "
                f"{traversal['logical_id']}: {source_rows} rows",
                flush=True,
            )
    flush(connection, batch)

    conflicts = connection.execute(
        """
        SELECT COUNT(*) FROM (
            SELECT evaluation_group_id
            FROM groups
            GROUP BY evaluation_group_id
            HAVING COUNT(DISTINCT binary_label) > 1
                OR COUNT(DISTINCT family_label) > 1
                OR COUNT(DISTINCT fine_label) > 1
        )
        """
    ).fetchone()[0]
    evaluation_overlap = connection.execute(
        """
        SELECT COUNT(*) FROM (
            SELECT evaluation_group_id
            FROM groups
            GROUP BY evaluation_group_id
            HAVING COUNT(DISTINCT split_name) > 1
        )
        """
    ).fetchone()[0]
    duplicate_overlap = connection.execute(
        """
        SELECT COUNT(*) FROM (
            SELECT duplicate_group_id
            FROM groups
            GROUP BY duplicate_group_id
            HAVING COUNT(DISTINCT split_name) > 1
        )
        """
    ).fetchone()[0]
    unique_evaluation = connection.execute(
        "SELECT COUNT(DISTINCT evaluation_group_id) FROM groups"
    ).fetchone()[0]
    unique_duplicate = connection.execute(
        "SELECT COUNT(DISTINCT duplicate_group_id) FROM groups"
    ).fetchone()[0]
    connection.close()

    bounded_result = {
        "mode": "BOUNDED",
        "rows": total_rows,
        "split_counts": dict(split_counts),
        "cross_label_numeric_group_count": conflicts,
        "evaluation_group_overlap_count": evaluation_overlap,
        "duplicate_group_overlap_count": duplicate_overlap,
        "unique_evaluation_group_count": unique_evaluation,
        "unique_duplicate_group_count": unique_duplicate,
        "membership_sha256": membership.hexdigest(),
    }
    if not args.full:
        print(json.dumps(bounded_result, indent=2, sort_keys=True))
        return 0

    levels = load_contract("n_baiot_label_contract_v1.json")["levels"]
    fractions = {split: split_counts[split] / total_rows for split in SPLITS}
    maximum_fine_drift = max(
        abs(
            100 * class_counts[(split, "fine", label)] / split_counts[split]
            - 100 * full_counts[("fine", label)] / total_rows
        )
        for split in SPLITS
        for label in levels["fine"]
    )
    minimum_validation_fine = min(
        class_counts[("VALIDATION", "fine", label)] for label in levels["fine"]
    )
    minimum_test_fine = min(
        class_counts[("TEST", "fine", label)] for label in levels["fine"]
    )
    expected_counts = summary["class_counts"]
    recomputed_counts = {
        split: {
            level: {label: class_counts[(split, level, label)] for label in labels}
            for level, labels in levels.items()
        }
        for split in SPLITS
    }
    devices = sorted({device for device, _ in device_counts})
    all_devices_have_all_splits = all(
        device_counts[(device, split)] > 0 for device in devices for split in SPLITS
    )
    all_sources_have_all_splits = all(
        source_counts[(source, device, split)] > 0
        for source, device in {(source, device) for source, device, _ in source_counts}
        for split in SPLITS
    )
    source_after = {name: source_snapshot(root) for name, root in sorted(roots.items())}
    checks.update(
        {
            "primary_source_total_is_7062606": total_rows == EXPECTED_ROWS,
            "split_counts_sum_exactly": sum(split_counts.values()) == EXPECTED_ROWS,
            "split_counts_match_primary_evidence": all(
                split_counts[split] == summary["split_counts"][split]["row_count"]
                for split in SPLITS
            ),
            "train_fraction_passes": 0.695 <= fractions["TRAIN"] <= 0.705,
            "validation_fraction_passes": 0.145 <= fractions["VALIDATION"] <= 0.155,
            "test_fraction_passes": 0.145 <= fractions["TEST"] <= 0.155,
            "binary_coverage_2_of_2_each_split": all(
                class_counts[(split, "binary", label)] > 0
                for split in SPLITS
                for label in levels["binary"]
            ),
            "family_coverage_3_of_3_each_split": all(
                class_counts[(split, "family", label)] > 0
                for split in SPLITS
                for label in levels["family"]
            ),
            "fine_coverage_11_of_11_each_split": all(
                class_counts[(split, "fine", label)] > 0
                for split in SPLITS
                for label in levels["fine"]
            ),
            "validation_minimum_fine_support_passes": minimum_validation_fine >= 25_000,
            "test_minimum_fine_support_passes": minimum_test_fine >= 25_000,
            "validation_benign_support_passes": (
                class_counts[("VALIDATION", "fine", "benign")] >= 50_000
            ),
            "test_benign_support_passes": (
                class_counts[("TEST", "fine", "benign")] >= 50_000
            ),
            "maximum_fine_prevalence_drift_passes": maximum_fine_drift <= 0.25,
            "evaluation_group_overlap_zero": evaluation_overlap == 0,
            "duplicate_group_overlap_zero": duplicate_overlap == 0,
            "cross_label_numeric_group_conflict_zero": conflicts == 0,
            "membership_digest_reproducible": (
                membership.hexdigest() == summary["membership_digest"]["sha256"]
            ),
            "bounded_examples_independently_reproduce": (
                set(golden_matches) == set(golden_lookup) and all(golden_matches.values())
            ),
            "class_counts_match_primary_evidence": recomputed_counts == expected_counts,
            "numeric_group_count_matches_primary_evidence": (
                unique_evaluation == numeric["unique_evaluation_group_count"]
            ),
            "lexical_group_count_matches_primary_evidence": (
                unique_duplicate == numeric["unique_duplicate_group_count"]
            ),
            "contract_is_adopted_and_test_is_sealed": (
                contract["status"] == "ADOPTED"
                and contract["test_set_status"] == "SEALED"
                and contract["learned_transform_fit_partition"] == "TRAIN"
            ),
            "all_nine_devices_have_all_partitions": (
                len(devices) == 9 and all_devices_have_all_splits
            ),
            "all_89_sources_have_all_partitions": (
                len({source for source, _, _ in source_counts}) == 89
                and all_sources_have_all_splits
            ),
            "source_metadata_unchanged": (
                source_before == source_after == expected_source
            ),
            "no_final_model_preprocessor_or_row_split_files": not forbidden_outputs(),
        }
    )
    result = {
        "audit_batch": "G3A independent whole-corpus split verification",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "overall_status": "PASS" if all(checks.values()) else "FAIL",
        "checks": checks,
        "recomputed": {
            "total_rows": total_rows,
            "split_counts": dict(split_counts),
            "minimum_validation_fine_support": minimum_validation_fine,
            "minimum_test_fine_support": minimum_test_fine,
            "maximum_fine_prevalence_drift_percentage_points": maximum_fine_drift,
            "evaluation_group_overlap_count": evaluation_overlap,
            "duplicate_group_overlap_count": duplicate_overlap,
            "cross_label_numeric_group_count": conflicts,
            "unique_evaluation_group_count": unique_evaluation,
            "unique_duplicate_group_count": unique_duplicate,
            "membership_sha256": membership.hexdigest(),
            "golden_examples_checked": len(golden_matches),
            "device_count": len(devices),
            "all_sources_have_all_partitions": all_sources_have_all_splits,
            "source_metadata": source_after,
            "forbidden_outputs": forbidden_outputs(),
        },
        "verification_independence": (
            "This verifier does not import the G3A driver or split module. It independently "
            "implements binary64 serialization, split hashing, membership framing, full class "
            "counts, and SQLite whole-corpus group reconciliation."
        ),
        "temporary_database_retained": str(database_path),
    }
    write_json(OUTPUT_PATH, result)
    print(f"Wrote: {OUTPUT_PATH}")
    print(f"Overall status: {result['overall_status']}")
    return 0 if result["overall_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
