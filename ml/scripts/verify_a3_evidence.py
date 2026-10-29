"""Independently verify A3 label evidence with pandas chunk aggregation."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = PROJECT_ROOT / "artifacts" / "audit"
MANIFEST_DIR = PROJECT_ROOT / "artifacts" / "manifests"
OUTPUT = AUDIT_DIR / "a3_evidence_verification.json"
LABEL_FIELDS = ("attack", "category", "subcategory")
EXPECTED_N_FINE = {
    "benign": 555_932,
    "gafgyt_combo": 515_156,
    "gafgyt_junk": 261_789,
    "gafgyt_scan": 255_111,
    "gafgyt_tcp": 859_850,
    "gafgyt_udp": 946_366,
    "mirai_ack": 643_821,
    "mirai_scan": 537_979,
    "mirai_syn": 733_299,
    "mirai_udp": 1_229_999,
    "mirai_udpplain": 523_304,
}
EXPECTED_MEMBERS = {
    "gafgyt_attacks": {"combo", "junk", "scan", "tcp", "udp"},
    "mirai_attacks": {"ack", "scan", "syn", "udp", "udpplain"},
}


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


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


def independent_n_label(row: dict[str, str]) -> tuple[str, str, str]:
    source_kind = row["source_kind"]
    if source_kind == "immutable_benign_source":
        if (
            row["archive_family_hint"]
            or row["parent_archive_relative_path"]
            or PurePosixPath(row["source_relative_path"]).name != "benign_traffic.csv"
        ):
            raise ValueError(f"Invalid benign provenance: {row['logical_id']}")
        return "benign", "benign", "benign"
    if source_kind != "derived_extracted_attack":
        raise ValueError(f"Unknown source kind: {source_kind}")
    family_hint = row["archive_family_hint"]
    if family_hint not in EXPECTED_MEMBERS:
        raise ValueError(f"Unknown attack archive family: {family_hint}")
    family = family_hint.removesuffix("_attacks")
    member = PurePosixPath(row["extracted_relative_path"])
    if member.suffix != ".csv" or member.stem not in EXPECTED_MEMBERS[family_hint]:
        raise ValueError(f"Unknown attack member: {member.name}")
    if PurePosixPath(row["parent_archive_relative_path"]).stem != family_hint:
        raise ValueError(f"Archive family conflict: {row['logical_id']}")
    return "malicious", family, f"{family}_{member.stem}"


def verify_n_baiot() -> dict[str, Any]:
    structure = load_csv(AUDIT_DIR / "n_baiot_csv_structure.csv")
    mapping = load_csv(AUDIT_DIR / "n_baiot_label_mapping.csv")
    if len(structure) != 89 or len(mapping) != 89:
        raise ValueError("N-BaIoT evidence does not contain exactly 89 mappings")
    structure_ids = [row["logical_id"] for row in structure]
    mapping_ids = [row["logical_id"] for row in mapping]
    if len(set(structure_ids)) != 89 or len(set(mapping_ids)) != 89:
        raise ValueError("N-BaIoT logical IDs are not unique")
    if set(structure_ids) != set(mapping_ids):
        raise ValueError("N-BaIoT structure and mapping logical IDs differ")

    binary: Counter[str] = Counter()
    family: Counter[str] = Counter()
    fine: Counter[str] = Counter()
    independently_mapped: dict[str, tuple[str, str, str]] = {}
    for row in structure:
        labels = independent_n_label(row)
        independently_mapped[row["logical_id"]] = labels
        count = int(row["row_count"])
        binary[labels[0]] += count
        family[labels[1]] += count
        fine[labels[2]] += count

    persisted = {row["logical_id"]: row for row in mapping}
    mismatches = []
    for logical_id, labels in independently_mapped.items():
        row = persisted[logical_id]
        observed = (
            row["canonical_binary"],
            row["canonical_family"],
            row["canonical_fine_class"],
        )
        if labels != observed:
            mismatches.append(logical_id)
    if mismatches:
        raise ValueError(f"N-BaIoT persisted mappings differ: {mismatches}")
    if dict(fine) != EXPECTED_N_FINE:
        raise ValueError("N-BaIoT independent fine counts differ from A2 targets")
    if dict(binary) != {"benign": 555_932, "malicious": 6_506_674}:
        raise ValueError("N-BaIoT independent binary counts differ from A2 targets")
    if sum(fine.values()) != 7_062_606:
        raise ValueError("N-BaIoT independent fine counts do not reconcile")
    if fine["gafgyt_scan"] == 0 or fine["mirai_scan"] == 0:
        raise ValueError("N-BaIoT scan labels were not preserved by family")
    if fine["gafgyt_udp"] == 0 or fine["mirai_udp"] == 0:
        raise ValueError("N-BaIoT UDP labels were not preserved by family")
    if len(fine) != len(set(fine)):
        raise ValueError("N-BaIoT canonical fine labels collide")

    return {
        "method": "independent strict provenance mapper over A2 structure evidence",
        "logical_csv_count": len(structure),
        "all_logical_csvs_map_once": True,
        "mapping_mismatch_count": 0,
        "binary_distribution": dict(sorted(binary.items())),
        "family_distribution": dict(sorted(family.items())),
        "fine_class_distribution": dict(sorted(fine.items())),
        "fine_class_total": sum(fine.values()),
        "collision_free": True,
        "family_qualified_scan_and_udp_preserved": True,
        "status": "PASS",
    }


def new_profile() -> dict[str, Any]:
    return {
        "row_count": 0,
        "value_counts": {field: Counter() for field in LABEL_FIELDS},
        "joint": Counter(),
        "invalid_or_missing_label_rows": 0,
    }


def pandas_label_profile(path: Path, delimiter: str, chunk_size: int = 250_000) -> dict[str, Any]:
    profile = new_profile()
    try:
        chunks = pd.read_csv(
            path,
            sep=delimiter,
            usecols=list(LABEL_FIELDS),
            dtype=str,
            keep_default_na=False,
            na_filter=False,
            encoding="utf-8-sig",
            chunksize=chunk_size,
        )
        for chunk in chunks:
            profile["row_count"] += len(chunk)
            invalid = chunk[list(LABEL_FIELDS)].apply(
                lambda column: column.isna() | column.str.strip().eq("")
            )
            profile["invalid_or_missing_label_rows"] += int(invalid.any(axis=1).sum())
            for field in LABEL_FIELDS:
                profile["value_counts"][field].update(
                    {
                        str(value): int(count)
                        for value, count in chunk[field].value_counts(
                            dropna=False, sort=False
                        ).items()
                    }
                )
            grouped = chunk.groupby(list(LABEL_FIELDS), dropna=False, sort=False).size()
            profile["joint"].update(
                {
                    tuple(str(value) for value in key): int(count)
                    for key, count in grouped.items()
                }
            )
    except ValueError as exc:
        if "Usecols do not match" in str(exc):
            raise ValueError(f"Required Bot-IoT label column absent in {path}: {exc}") from exc
        raise
    return profile


def merge_profiles(profiles: list[dict[str, Any]]) -> dict[str, Any]:
    merged = new_profile()
    for profile in profiles:
        merged["row_count"] += profile["row_count"]
        merged["invalid_or_missing_label_rows"] += profile[
            "invalid_or_missing_label_rows"
        ]
        for field in LABEL_FIELDS:
            merged["value_counts"][field].update(profile["value_counts"][field])
        merged["joint"].update(profile["joint"])
    return merged


def persisted_bot_counters() -> dict[str, dict[str, Counter[Any]]]:
    result: dict[str, dict[str, Counter[Any]]] = defaultdict(
        lambda: {
            "attack": Counter(),
            "category": Counter(),
            "subcategory": Counter(),
            "joint": Counter(),
        }
    )
    for row in load_csv(AUDIT_DIR / "bot_iot_label_distribution.csv"):
        representation = row["representation"]
        level = row["distribution_level"]
        count = int(row["count"])
        if level == "attack":
            result[representation]["attack"][row["raw_attack"]] = count
        elif level == "category":
            result[representation]["category"][row["raw_category"]] = count
        elif level == "subcategory":
            result[representation]["subcategory"][row["raw_subcategory"]] = count
        elif level == "attack_category_subcategory":
            key = (row["raw_attack"], row["raw_category"], row["raw_subcategory"])
            result[representation]["joint"][key] = count
    return dict(result)


def verify_bot_iot(bot_root: Path) -> dict[str, Any]:
    structure = load_csv(AUDIT_DIR / "bot_iot_csv_structure.csv")
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in structure:
        grouped[row["representation"]].append(row)
    profiles: dict[str, dict[str, Any]] = {}
    first_all_shard: dict[str, Any] | None = None
    for representation in sorted(grouped):
        file_profiles = []
        for row in sorted(grouped[representation], key=lambda value: value["logical_id"]):
            delimiter = {"comma": ",", "semicolon": ";"}[row["delimiter"]]
            path = bot_root / Path(row["source_relative_path"])
            profile = pandas_label_profile(path, delimiter)
            if profile["row_count"] != int(row["row_count"]):
                raise ValueError(f"Independent Bot-IoT row mismatch for {path}")
            if representation == "all_features_5pct_shards" and first_all_shard is None:
                first_all_shard = {
                    "relative_path": row["source_relative_path"],
                    "row_count": profile["row_count"],
                    "attack_counts": dict(sorted(profile["value_counts"]["attack"].items())),
                    "category_counts": dict(
                        sorted(profile["value_counts"]["category"].items())
                    ),
                    "subcategory_counts": dict(
                        sorted(profile["value_counts"]["subcategory"].items())
                    ),
                }
            file_profiles.append(profile)
        profiles[representation] = merge_profiles(file_profiles)

    expected_rows = {
        "all_features_5pct_shards": 3_668_522,
        "ten_best_full": 3_668_522,
        "ten_best_predefined_train": 2_934_817,
        "ten_best_predefined_test": 733_705,
    }
    for representation, expected in expected_rows.items():
        profile = profiles[representation]
        if profile["row_count"] != expected:
            raise ValueError(f"Independent row total differs for {representation}")
        if profile["invalid_or_missing_label_rows"]:
            raise ValueError(f"Independent label scan found invalid rows in {representation}")
        for field in LABEL_FIELDS:
            if sum(profile["value_counts"][field].values()) != expected:
                raise ValueError(f"Independent {field} counts do not reconcile")
        if sum(profile["joint"].values()) != expected:
            raise ValueError("Independent joint counts do not reconcile")

    persisted = persisted_bot_counters()
    artifact_mismatches: list[str] = []
    for representation, profile in profiles.items():
        actual = {
            "attack": profile["value_counts"]["attack"],
            "category": profile["value_counts"]["category"],
            "subcategory": profile["value_counts"]["subcategory"],
            "joint": profile["joint"],
        }
        for level, counter in actual.items():
            if counter != persisted[representation][level]:
                artifact_mismatches.append(f"{representation}:{level}")
    if artifact_mismatches:
        raise ValueError(f"Independent Bot-IoT counts differ: {artifact_mismatches}")

    all_features = profiles["all_features_5pct_shards"]
    full = profiles["ten_best_full"]
    train = profiles["ten_best_predefined_train"]
    test = profiles["ten_best_predefined_test"]
    comparisons: dict[str, dict[str, bool]] = {}
    for level, selector in {
        "attack": lambda profile: profile["value_counts"]["attack"],
        "category": lambda profile: profile["value_counts"]["category"],
        "subcategory": lambda profile: profile["value_counts"]["subcategory"],
        "attack_category_subcategory": lambda profile: profile["joint"],
    }.items():
        split = selector(train) + selector(test)
        comparisons[level] = {
            "all_features_matches_ten_best_full": selector(all_features) == selector(full),
            "train_plus_test_matches_ten_best_full": split == selector(full),
        }
    if not all(value for row in comparisons.values() for value in row.values()):
        raise ValueError("Independent Bot-IoT representation comparison failed")

    return {
        "method": "pandas chunked usecols aggregation with string dtype and NA coercion disabled",
        "first_all_features_shard_independent_profile": first_all_shard,
        "representation_row_counts": {
            representation: profile["row_count"]
            for representation, profile in sorted(profiles.items())
        },
        "all_features_attack_counts": dict(
            sorted(all_features["value_counts"]["attack"].items())
        ),
        "all_features_category_counts": dict(
            sorted(all_features["value_counts"]["category"].items())
        ),
        "all_features_subcategory_counts": dict(
            sorted(all_features["value_counts"]["subcategory"].items())
        ),
        "invalid_or_missing_label_rows": {
            representation: profile["invalid_or_missing_label_rows"]
            for representation, profile in sorted(profiles.items())
        },
        "artifact_distribution_mismatch_count": 0,
        "aggregate_distribution_comparisons": comparisons,
        "record_identity_proven": False,
        "status": "PASS",
    }


def discover_source_metadata(root: Path) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for current_root, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(current_root)
        directory_names[:] = sorted(
            name for name in directory_names if not (current / name).is_symlink()
        )
        for file_name in sorted(file_names):
            path = current / file_name
            if path.is_symlink() or not path.is_file():
                continue
            file_stat = path.stat()
            records[path.relative_to(root).as_posix()] = {
                "size_bytes": file_stat.st_size,
                "modified_time_utc": datetime.fromtimestamp(
                    file_stat.st_mtime, tz=UTC
                ).isoformat(),
            }
    return records


def reconcile_raw_source(root: Path, manifest_path: Path) -> dict[str, Any]:
    manifest = {row["relative_path"]: row for row in load_csv(manifest_path)}
    observed = discover_source_metadata(root)
    missing = sorted(set(manifest) - set(observed))
    unexpected = sorted(set(observed) - set(manifest))
    size_mismatches = sorted(
        relative_path
        for relative_path in set(manifest) & set(observed)
        if int(manifest[relative_path]["size_bytes"])
        != observed[relative_path]["size_bytes"]
    )
    time_mismatches = sorted(
        relative_path
        for relative_path in set(manifest) & set(observed)
        if manifest[relative_path]["modified_time_utc"]
        != observed[relative_path]["modified_time_utc"]
    )
    return {
        "root": str(root),
        "expected_file_count": len(manifest),
        "observed_file_count": len(observed),
        "missing_paths": missing,
        "unexpected_paths": unexpected,
        "size_mismatches": size_mismatches,
        "modified_time_mismatches": time_mismatches,
        "metadata_match": not (missing or unexpected or size_mismatches or time_mismatches),
    }


def reconcile_extracted_source(root: Path) -> dict[str, Any]:
    manifest = {
        row["extracted_relative_path"]: row
        for row in load_csv(MANIFEST_DIR / "n_baiot_extracted_manifest.csv")
    }
    observed = discover_source_metadata(root)
    missing = sorted(set(manifest) - set(observed))
    unexpected = sorted(set(observed) - set(manifest))
    size_mismatches = sorted(
        relative_path
        for relative_path in set(manifest) & set(observed)
        if int(manifest[relative_path]["size_bytes"])
        != observed[relative_path]["size_bytes"]
    )
    return {
        "root": str(root),
        "expected_file_count": len(manifest),
        "observed_file_count": len(observed),
        "missing_paths": missing,
        "unexpected_paths": unexpected,
        "size_mismatches": size_mismatches,
        "metadata_match": not (missing or unexpected or size_mismatches),
        "note": "The extraction manifest stores hashes and sizes but not timestamps.",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-baiot-root", type=Path, required=True)
    parser.add_argument("--bot-iot-root", type=Path, required=True)
    parser.add_argument("--n-baiot-extracted-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    n_root = args.n_baiot_root.resolve()
    bot_root = args.bot_iot_root.resolve()
    extracted_root = args.n_baiot_extracted_root.resolve()
    for root in (n_root, bot_root, extracted_root):
        if not root.is_dir():
            raise FileNotFoundError(f"Required root does not exist: {root}")

    n_result = verify_n_baiot()
    bot_result = verify_bot_iot(bot_root)
    source_safety = {
        "n_baiot_raw": reconcile_raw_source(
            n_root, MANIFEST_DIR / "n_baiot_raw_manifest.csv"
        ),
        "bot_iot_raw": reconcile_raw_source(
            bot_root, MANIFEST_DIR / "bot_iot_raw_manifest.csv"
        ),
        "n_baiot_extracted": reconcile_extracted_source(extracted_root),
    }
    if not all(result["metadata_match"] for result in source_safety.values()):
        raise ValueError("Source-tree metadata changed relative to A1/A2 manifests")

    evidence_paths = sorted(
        path
        for path in AUDIT_DIR.glob("*label*")
        if path.is_file() and path.name != args.output.name
    )
    payload = {
        "audit_batch": "A3",
        "generated_at_utc": datetime.now(tz=UTC).isoformat(),
        "n_baiot": n_result,
        "bot_iot": bot_result,
        "source_safety": source_safety,
        "evidence_sha256": {
            path.relative_to(PROJECT_ROOT).as_posix(): sha256_file(path)
            for path in evidence_paths
        },
        "overall_status": "PASS",
    }
    write_json_atomic(payload, args.output.resolve())
    print(f"Wrote: {args.output.resolve()}")
    print("Overall status: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, csv.Error, ValueError, pd.errors.ParserError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
