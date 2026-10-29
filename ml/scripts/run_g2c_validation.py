"""Generate deterministic G2C evidence; full mode streams all primary observations."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any

from iotguard.data.bot_iot import (
    BotIoTParseError,
    parse_bot_iot_record,
)
from iotguard.data.contracts import bot_iot_source_columns, load_contract, n_baiot_feature_names
from iotguard.data.n_baiot import (
    NBaiotParseError,
    feature_array,
    iter_n_baiot_records,
    parse_n_baiot_record,
)
from iotguard.data.reproducibility import (
    RECORD_DIGEST_SCHEME,
    ROW_IDENTITY_SCHEME,
    canonical_record_digest,
    deterministic_traversal_rows,
    g2_closure_status,
    source_observation_identity,
    traversal_expected_row_count,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = PROJECT_ROOT / "artifacts" / "audit"
MANIFEST_DIR = PROJECT_ROOT / "artifacts" / "manifests"
CONTRACT_DIR = PROJECT_ROOT / "artifacts" / "contracts"

TRAVERSAL_PATH = MANIFEST_DIR / "n_baiot_canonical_traversal_v1.csv"
DRY_RUN_PATH = AUDIT_DIR / "g2c_primary_dry_run_summary.json"
BOUNDED_PATH = AUDIT_DIR / "g2c_bounded_materialization_smoke.json"
REPRODUCIBILITY_PATH = MANIFEST_DIR / "g2_preprocessing_reproducibility_manifest.json"
CLOSURE_PATH = AUDIT_DIR / "g2_closure_checklist.json"

G2B_COMMIT = "9468f96bb6e0d2f2df14a80d6e9cbf10814541ed"
PIPELINE_VERSION = "1.0.0"
EXPECTED_LOGICAL_SOURCES = 89
EXPECTED_PRIMARY_ROWS = 7_062_606
HEX_PORT_COORDINATE = 632_280

TRAVERSAL_FIELDS = (
    "traversal_ordinal",
    "logical_id",
    "device",
    "source_kind",
    "source_root_kind",
    "source_relative_path",
    "canonical_binary",
    "canonical_family",
    "canonical_fine_class",
    "expected_row_count",
    "source_content_sha256",
    "parent_archive_sha256",
)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return payload


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json_bytes(payload: Any) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def write_bytes_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    try:
        temporary.write_bytes(content)
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    write_bytes_atomic(path, canonical_json_bytes(payload))


def traversal_csv_bytes(rows: list[dict[str, object]]) -> bytes:
    import io

    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=TRAVERSAL_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def configured_roots() -> dict[str, Path]:
    source_safety = load_json(AUDIT_DIR / "a4_evidence_verification.json")["source_safety"]
    return {name: Path(details["root"]) for name, details in source_safety.items()}


def build_traversal_rows() -> list[dict[str, object]]:
    label_rows = load_csv(AUDIT_DIR / "n_baiot_label_mapping.csv")
    raw_manifest = {
        row["relative_path"]: row for row in load_csv(MANIFEST_DIR / "n_baiot_raw_manifest.csv")
    }
    extracted_manifest = {
        row["extracted_relative_path"]: row
        for row in load_csv(MANIFEST_DIR / "n_baiot_extracted_manifest.csv")
    }
    rows: list[dict[str, object]] = []
    for label in label_rows:
        if label["source_kind"] == "immutable_benign_source":
            root_kind = "n_baiot_raw"
            relative = label["raw_source_relative_path"]
            source_hash = raw_manifest[relative]["sha256"]
            parent_hash = ""
        elif label["source_kind"] == "derived_extracted_attack":
            root_kind = "n_baiot_extracted"
            relative = label["raw_extracted_relative_path"]
            source_hash = extracted_manifest[relative]["sha256"]
            parent_hash = extracted_manifest[relative]["parent_archive_sha256"]
        else:
            raise ValueError(f"Unexpected source kind: {label['source_kind']}")
        rows.append(
            {
                "logical_id": label["logical_id"],
                "device": label["device"],
                "source_kind": label["source_kind"],
                "source_root_kind": root_kind,
                "source_relative_path": relative,
                "canonical_binary": label["canonical_binary"],
                "canonical_family": label["canonical_family"],
                "canonical_fine_class": label["canonical_fine_class"],
                "expected_row_count": int(label["row_count"]),
                "source_content_sha256": source_hash,
                "parent_archive_sha256": parent_hash,
            }
        )
    ordered = deterministic_traversal_rows(rows)
    if len(ordered) != EXPECTED_LOGICAL_SOURCES:
        raise ValueError(f"Expected 89 logical sources, found {len(ordered)}")
    if traversal_expected_row_count(ordered) != EXPECTED_PRIMARY_ROWS:
        raise ValueError("Traversal row counts do not reconcile to 7,062,606")
    return ordered


def write_and_recheck_traversal() -> tuple[list[dict[str, object]], dict[str, Any]]:
    first_rows = build_traversal_rows()
    first_bytes = traversal_csv_bytes(first_rows)
    write_bytes_atomic(TRAVERSAL_PATH, first_bytes)
    second_rows = build_traversal_rows()
    second_bytes = traversal_csv_bytes(second_rows)
    first_hash = hashlib.sha256(first_bytes).hexdigest()
    second_hash = hashlib.sha256(second_bytes).hexdigest()
    evidence = {
        "logical_source_count": len(first_rows),
        "expected_row_count": traversal_expected_row_count(first_rows),
        "ordering_rule": "ascending exact logical_id; then physical data-row order",
        "traversal_ordinal_base": 1,
        "first_generation_sha256": first_hash,
        "second_generation_sha256": second_hash,
        "byte_identical_rerun": first_bytes == second_bytes,
    }
    if not evidence["byte_identical_rerun"]:
        raise ValueError("Traversal generation is nondeterministic")
    return first_rows, evidence


def source_tree_snapshot(root: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    count = 0
    total_size = 0
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=str):
        stat = path.stat()
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(stat.st_size.to_bytes(8, "big"))
        digest.update(stat.st_mtime_ns.to_bytes(8, "big", signed=True))
        count += 1
        total_size += stat.st_size
    return {
        "file_count": count,
        "total_size_bytes": total_size,
        "metadata_digest_sha256": digest.hexdigest(),
    }


def all_source_snapshots(roots: dict[str, Path]) -> dict[str, dict[str, Any]]:
    return {name: source_tree_snapshot(root) for name, root in sorted(roots.items())}


def expected_source_snapshots() -> dict[str, dict[str, Any]]:
    source_safety = load_json(AUDIT_DIR / "a5_audit_summary.json")["source_safety"]
    keys = ("file_count", "total_size_bytes", "metadata_digest_sha256")
    return {
        name: {key: details["after"][key] for key in keys}
        for name, details in source_safety.items()
    }


def path_for_traversal(row: dict[str, object], roots: dict[str, Path]) -> Path:
    return roots[str(row["source_root_kind"])] / Path(str(row["source_relative_path"]))


def read_n_rows_at(path: Path, indexes: set[int]) -> dict[int, list[str]]:
    if not indexes or min(indexes) < 1:
        raise ValueError("N-BaIoT row coordinates must be positive")
    expected_header = n_baiot_feature_names()
    found: dict[int, list[str]] = {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        header = tuple(next(reader))
        if header != expected_header:
            raise ValueError(f"N-BaIoT header mismatch: {path}")
        maximum = max(indexes)
        for data_row_index, row in enumerate(reader, start=1):
            if data_row_index in indexes:
                found[data_row_index] = row
            if data_row_index >= maximum:
                break
    if set(found) != indexes:
        raise ValueError(f"Missing requested rows in {path}: {indexes - set(found)}")
    return found


def compact_record(record: Any) -> dict[str, Any]:
    logical_id, row_index = source_observation_identity(record)
    return {
        "source_logical_id": logical_id,
        "source_data_row_index": row_index,
        "target_binary": record.target_binary,
        "label_family": record.label_family,
        "label_fine": record.label_fine,
        "feature_count": len(feature_array(record)),
        "duplicate_group_id": record.duplicate_group_id,
        "canonical_record_digest": canonical_record_digest(record),
    }


def selected_primary_records(
    traversal: list[dict[str, object]], roots: dict[str, Path]
) -> tuple[dict[tuple[str, int], tuple[list[str], Any]], list[dict[str, str]]]:
    by_logical = {str(row["logical_id"]): row for row in traversal}
    coordinates: set[tuple[str, int]] = set()
    fine_seen: set[str] = set()
    for row in traversal:
        fine = str(row["canonical_fine_class"])
        if fine not in fine_seen:
            coordinates.add((str(row["logical_id"]), 1))
            fine_seen.add(fine)

    duplicate_rows = [
        row
        for row in load_csv(AUDIT_DIR / "a4_flagged_examples.csv")
        if row["dataset"] == "n_baiot"
    ][:3]
    if len(duplicate_rows) != 3:
        raise ValueError("Expected at least three verified N-BaIoT duplicate examples")
    for example in duplicate_rows:
        coordinates.add((example["first_logical_id"], int(example["first_data_row"])))
        coordinates.add((example["second_logical_id"], int(example["second_data_row"])))

    grouped: dict[str, set[int]] = defaultdict(set)
    for logical_id, row_index in coordinates:
        grouped[logical_id].add(row_index)
    selected: dict[tuple[str, int], tuple[list[str], Any]] = {}
    for logical_id in sorted(grouped):
        traversal_row = by_logical[logical_id]
        raw_rows = read_n_rows_at(
            path_for_traversal(traversal_row, roots), grouped[logical_id]
        )
        for row_index, raw in raw_rows.items():
            record = parse_n_baiot_record(raw, logical_id, data_row_index=row_index)
            selected[(logical_id, row_index)] = (raw, record)
    return selected, duplicate_rows


def verify_duplicate_examples(
    selected: dict[tuple[str, int], tuple[list[str], Any]],
    duplicate_rows: list[dict[str, str]],
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for example in duplicate_rows:
        first_key = (example["first_logical_id"], int(example["first_data_row"]))
        second_key = (example["second_logical_id"], int(example["second_data_row"]))
        first_raw, first_record = selected[first_key]
        second_raw, second_record = selected[second_key]
        exact_tuple_equal = first_raw == second_raw
        group_equal = first_record.duplicate_group_id == second_record.duplicate_group_id
        a4_digest_match = (
            first_record.duplicate_group_id.removeprefix("sha256:")
            == example["exact_group_sha256"]
        )
        evidence.append(
            {
                "a4_exact_group_sha256": example["exact_group_sha256"],
                "first_source_observation": list(first_key),
                "second_source_observation": list(second_key),
                "independent_exact_source_tuple_equal": exact_tuple_equal,
                "g2b_duplicate_group_id": first_record.duplicate_group_id,
                "g2b_group_ids_equal": group_equal,
                "g2b_digest_matches_a4": a4_digest_match,
            }
        )
    return evidence


def lexical_numeric_evidence() -> list[dict[str, Any]]:
    logical_id = "n_baiot:source:Danmini_Doorbell/benign_traffic.csv"
    results = []
    for lexical in ("1", "1.0", "1e0"):
        raw = [lexical] * 115
        record = parse_n_baiot_record(raw, logical_id, data_row_index=1)
        results.append(
            {
                "source_lexeme": lexical,
                "parsed_value": record.features[0],
                "duplicate_group_id": record.duplicate_group_id,
            }
        )
    if len({item["parsed_value"] for item in results}) != 1:
        raise ValueError("Lexical forms did not parse to equal numeric values")
    if len({item["duplicate_group_id"] for item in results}) != 3:
        raise ValueError("Lexical forms unexpectedly collapsed to one exact group")
    return results


def bot_header_and_port_evidence(
    bot_root: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    contract = load_contract("bot_iot_secondary_source_contract_v1.json")
    expected_header = bot_iot_source_columns()
    headers: list[dict[str, Any]] = []
    for relative in contract["canonical_source_files"]:
        path = bot_root / Path(relative)
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            header = tuple(next(reader))
            first_row = next(reader)
        accepted = header == expected_header
        if not accepted:
            raise ValueError(f"Bot-IoT canonical header mismatch: {relative}")
        parse_bot_iot_record(first_row, relative, data_row_index=1)
        headers.append(
            {
                "source_relative_path": relative,
                "column_count": len(header),
                "header_order_exact": accepted,
                "canonical_source_accepted": True,
            }
        )

    first_relative = contract["canonical_source_files"][0]
    first_path = bot_root / Path(first_relative)
    wanted = {1, 2, HEX_PORT_COORDINATE}
    rows: dict[int, list[str]] = {}
    with first_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        header = tuple(next(reader))
        if header != expected_header:
            raise ValueError("Bot-IoT header changed during bounded port read")
        for index, row in enumerate(reader, start=1):
            if index in wanted:
                rows[index] = row
            if index >= HEX_PORT_COORDINATE:
                break
    if set(rows) != wanted:
        raise ValueError("Known Bot-IoT port coordinates are unavailable")
    ports: list[dict[str, Any]] = []
    examples = ((1, "decimal"), (2, "unresolved_sentinel"), (HEX_PORT_COORDINATE, "hex"))
    for index, expected_kind in examples:
        record = parse_bot_iot_record(rows[index], first_relative, data_row_index=index)
        matching = {
            name: {"raw": parsed.raw, "kind": parsed.kind, "value": parsed.value}
            for name, parsed in record.ports.items()
            if parsed.kind == expected_kind
        }
        if not matching:
            raise ValueError(f"Expected {expected_kind} port at row {index}")
        ports.append(
            {
                "source_logical_id": record.source_logical_id,
                "source_data_row_index": index,
                "expected_kind": expected_kind,
                "matching_ports": matching,
            }
        )
    return headers, ports


def run_bounded(
    traversal: list[dict[str, object]],
    traversal_evidence: dict[str, Any],
    roots: dict[str, Path],
) -> dict[str, Any]:
    before = all_source_snapshots(roots)
    selected_first, duplicate_rows = selected_primary_records(traversal, roots)
    first_compact = [
        compact_record(selected_first[key][1]) for key in sorted(selected_first)
    ]
    duplicate_evidence = verify_duplicate_examples(selected_first, duplicate_rows)

    selected_second, _ = selected_primary_records(traversal, roots)
    second_compact = [
        compact_record(selected_second[key][1]) for key in sorted(selected_second)
    ]
    first_digest = hashlib.sha256(canonical_json_bytes(first_compact)).hexdigest()
    second_digest = hashlib.sha256(canonical_json_bytes(second_compact)).hexdigest()

    bot_headers, port_evidence = bot_header_and_port_evidence(roots["bot_iot_raw"])
    after = all_source_snapshots(roots)
    expected_snapshots = expected_source_snapshots()
    payload = {
        "audit_batch": "G2C bounded canonical materialization and compatibility checks",
        "stable_source_observation_identity": {
            "scheme": ROW_IDENTITY_SCHEME,
            "fields": ["source_logical_id", "source_data_row_index"],
            "row_index_base": 1,
            "header_excluded": True,
            "predictor_eligible": False,
            "distinct_from_duplicate_group_id": True,
        },
        "traversal": traversal_evidence,
        "known_a4_duplicate_pairs": duplicate_evidence,
        "lexical_numeric_distinction": lexical_numeric_evidence(),
        "bot_iot_canonical_headers": bot_headers,
        "bot_iot_reference_policy": {
            "canonical_shards_accepted": len(bot_headers),
            "ten_best_full_canonical": False,
            "supplied_train_test_is_official_split": False,
        },
        "real_bot_port_examples": port_evidence,
        "bounded_materialization": {
            "selection_rule": (
                "first source-row for every fine label plus both observations from the first "
                "three verified A4 cross-file duplicate pairs"
            ),
            "record_count": len(first_compact),
            "records": first_compact,
            "canonical_record_digest_scheme": RECORD_DIGEST_SCHEME,
            "first_run_sha256": first_digest,
            "second_run_sha256": second_digest,
            "rerun_identical": first_compact == second_compact and first_digest == second_digest,
            "raw_feature_rows_persisted": False,
        },
        "source_safety": {
            "before": before,
            "after": after,
            "expected_a5_baseline": expected_snapshots,
            "unchanged_during_run": before == after,
            "matches_a5_baseline": after == expected_snapshots,
        },
        "execution_boundaries": {
            "full_processed_dataset_written": False,
            "split_selected_or_written": False,
            "learned_transform_fit": False,
            "resampling_performed": False,
            "deduplication_performed": False,
            "model_training_runs": 0,
            "clustering_runs": 0,
        },
    }
    mandatory = [
        traversal_evidence["byte_identical_rerun"],
        len(first_compact) >= 11,
        payload["bounded_materialization"]["rerun_identical"],
        all(
            item["independent_exact_source_tuple_equal"]
            and item["g2b_group_ids_equal"]
            and item["g2b_digest_matches_a4"]
            for item in duplicate_evidence
        ),
        len(bot_headers) == 4,
        {item["expected_kind"] for item in port_evidence}
        == {"decimal", "hex", "unresolved_sentinel"},
        before == after == expected_snapshots,
    ]
    payload["overall_status"] = "PASS" if all(mandatory) else "FAIL"
    write_json_atomic(BOUNDED_PATH, payload)
    return payload


def classify_parse_error(error: NBaiotParseError) -> str:
    message = str(error)
    if "Header" in message:
        return "schema_errors"
    if "Non-finite" in message:
        return "nonfinite_errors"
    if "Numeric parse failed" in message:
        return "numeric_parse_errors"
    if "provenance" in message.lower():
        return "provenance_mapping_errors"
    if "fields" in message:
        return "record_width_errors"
    return "other_parse_errors"


def dry_validation(
    traversal: list[dict[str, object]], roots: dict[str, Path]
) -> dict[str, Any]:
    before = all_source_snapshots(roots)
    started_at = datetime.now(UTC).isoformat()
    started = perf_counter()
    binary: Counter[str] = Counter()
    family: Counter[str] = Counter()
    fine: Counter[str] = Counter()
    error_counts: Counter[str] = Counter(
        {
            "schema_errors": 0,
            "numeric_parse_errors": 0,
            "nonfinite_errors": 0,
            "provenance_mapping_errors": 0,
            "record_width_errors": 0,
            "source_identity_errors": 0,
            "source_row_count_errors": 0,
            "other_parse_errors": 0,
        }
    )
    total_rows = 0
    completed_sources = 0
    failure: str | None = None
    for traversal_row in traversal:
        logical_id = str(traversal_row["logical_id"])
        source_rows = 0
        try:
            for record in iter_n_baiot_records(
                path_for_traversal(traversal_row, roots), logical_id
            ):
                source_rows += 1
                total_rows += 1
                feature_array(record)
                identity = source_observation_identity(record)
                if identity != (logical_id, source_rows):
                    error_counts["source_identity_errors"] += 1
                    raise ValueError(f"Source identity mismatch: {identity}")
                binary[record.target_binary] += 1
                family[record.label_family] += 1
                fine[record.label_fine] += 1
        except NBaiotParseError as error:
            error_counts[classify_parse_error(error)] += 1
            failure = str(error)
            break
        except ValueError as error:
            failure = str(error)
            break
        if source_rows != int(traversal_row["expected_row_count"]):
            error_counts["source_row_count_errors"] += 1
            failure = f"Row-count mismatch for {logical_id}: {source_rows}"
            break
        completed_sources += 1

    runtime_seconds = perf_counter() - started
    after = all_source_snapshots(roots)
    expected_labels = load_json(AUDIT_DIR / "label_audit_summary.json")["n_baiot"]
    deterministic_result = {
        "logical_sources_completed": completed_sources,
        "total_rows": total_rows,
        "feature_count_per_record": 115,
        "binary_counts": dict(sorted(binary.items())),
        "family_counts": dict(sorted(family.items())),
        "fine_counts": dict(sorted(fine.items())),
        "error_counts": dict(sorted(error_counts.items())),
        "failure": failure,
        "source_metadata_unchanged": before == after == expected_source_snapshots(),
    }
    reconciled = (
        completed_sources == EXPECTED_LOGICAL_SOURCES
        and total_rows == EXPECTED_PRIMARY_ROWS
        and deterministic_result["binary_counts"] == expected_labels["binary_distribution"]
        and deterministic_result["family_counts"] == expected_labels["family_distribution"]
        and deterministic_result["fine_counts"] == expected_labels["fine_class_distribution"]
        and not any(error_counts.values())
        and failure is None
        and deterministic_result["source_metadata_unchanged"]
    )
    deterministic_result["reconciliation_status"] = "PASS" if reconciled else "FAIL"
    result_hash = hashlib.sha256(canonical_json_bytes(deterministic_result)).hexdigest()
    payload = {
        "audit_batch": "G2C full primary streaming dry validation",
        "execution_metadata": {
            "started_at_utc": started_at,
            "runtime_seconds": runtime_seconds,
            "records_retained_after_validation": 0,
            "full_processed_dataset_written": False,
        },
        "deterministic_result": deterministic_result,
        "deterministic_result_sha256": result_hash,
        "overall_status": "PASS" if reconciled else "FAIL",
    }
    write_json_atomic(DRY_RUN_PATH, payload)
    return payload


def create_reproducibility_manifest(
    traversal: list[dict[str, object]], dry_run: dict[str, Any]
) -> dict[str, Any]:
    g2a_manifest = load_json(CONTRACT_DIR / "g2a_contract_manifest.json")
    payload = {
        "manifest_name": "IoTGuard G2 canonical preprocessing reproducibility manifest",
        "pipeline_version": PIPELINE_VERSION,
        "g2a_contract_artifact_sha256": g2a_manifest["artifact_sha256"],
        "g2b_checkpoint_commit": G2B_COMMIT,
        "primary_source_manifest_sha256": {
            "raw": sha256_file(MANIFEST_DIR / "n_baiot_raw_manifest.csv"),
            "extracted": sha256_file(MANIFEST_DIR / "n_baiot_extracted_manifest.csv"),
        },
        "canonical_traversal": {
            "path": "artifacts/manifests/n_baiot_canonical_traversal_v1.csv",
            "sha256": sha256_file(TRAVERSAL_PATH),
            "logical_source_count": len(traversal),
            "expected_row_count": traversal_expected_row_count(traversal),
            "ordering_rule": "ascending exact logical_id; then physical data-row order",
        },
        "feature_schema_sha256": load_json(
            CONTRACT_DIR / "n_baiot_feature_contract_v1.json"
        )["ordered_feature_schema_sha256"],
        "label_contract_sha256": sha256_file(
            CONTRACT_DIR / "n_baiot_label_contract_v1.json"
        ),
        "duplicate_group_scheme": (
            "sha256 over each exact UTF-8 source lexeme prefixed by unsigned 4-byte "
            "big-endian byte length, in 115-field contract order"
        ),
        "row_identity_scheme": ROW_IDENTITY_SCHEME,
        "canonical_record_digest_scheme": RECORD_DIGEST_SCHEME,
        "parser_semantics": {
            "numeric_runtime": "Python float; every value finite; no clipping or imputation",
            "header": "exact 115-field order",
            "labels": "exact A3 verified logical-source mapping",
            "streaming": True,
        },
        "source_file_count": len(traversal),
        "expected_row_count": traversal_expected_row_count(traversal),
        "dry_run_deterministic_result_sha256": dry_run["deterministic_result_sha256"],
        "software_runtime": {
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "csv_module": "Python standard library csv",
        },
        "no_learned_transform": True,
        "no_machine_specific_absolute_paths": True,
    }
    write_json_atomic(REPRODUCIBILITY_PATH, payload)
    return payload


def downstream_outputs_absent() -> dict[str, bool]:
    roots = [PROJECT_ROOT / "artifacts", PROJECT_ROOT / "data" / "processed"]
    files = [path for root in roots if root.exists() for path in root.rglob("*") if path.is_file()]
    learned_suffixes = {
        ".joblib",
        ".pkl",
        ".pickle",
        ".onnx",
        ".tflite",
        ".pt",
        ".pth",
        ".npy",
        ".npz",
        ".parquet",
    }
    split_names = {"train.csv", "validation.csv", "test.csv"}
    processed_names = {"full_processed.csv", "x.npy", "y.npy"}
    return {
        "no_learned_state": not any(path.suffix.lower() in learned_suffixes for path in files),
        "no_final_split": not any(path.name.lower() in split_names for path in files),
        "no_full_processed_dataset": not any(
            path.name.lower() in processed_names for path in files
        ),
    }


def closure_checklist(
    dry_run: dict[str, Any], bounded: dict[str, Any], roots: dict[str, Path]
) -> dict[str, Any]:
    output_safety = downstream_outputs_absent()
    checks = {
        "g1_role_decision_complete": True,
        "g2a_contracts_committed": True,
        "g2b_parser_implementation_committed": True,
        "primary_feature_contract_locked": True,
        "primary_label_contract_locked": True,
        "secondary_source_contract_locked": True,
        "stable_source_row_identity_defined": True,
        "canonical_traversal_defined": TRAVERSAL_PATH.is_file(),
        "primary_full_dry_validation_passed": dry_run["overall_status"] == "PASS",
        "primary_row_counts_reconciled": dry_run["deterministic_result"]["total_rows"]
        == EXPECTED_PRIMARY_ROWS,
        "primary_label_counts_reconciled": dry_run["deterministic_result"][
            "reconciliation_status"
        ]
        == "PASS",
        "exact_group_semantics_reconciled_with_a4_a5": all(
            pair["g2b_group_ids_equal"] and pair["g2b_digest_matches_a4"]
            for pair in bounded["known_a4_duplicate_pairs"]
        ),
        "secondary_four_shard_headers_validated": len(
            bounded["bot_iot_canonical_headers"]
        )
        == 4,
        "secondary_port_parser_real_examples_validated": {
            item["expected_kind"] for item in bounded["real_bot_port_examples"]
        }
        == {"decimal", "hex", "unresolved_sentinel"},
        "learned_transform_boundary_documented": (
            PROJECT_ROOT / "docs" / "protocols" / "preprocessing_contract.md"
        ).is_file(),
        "no_pre_split_fit": True,
        "no_full_processed_dataset": output_safety["no_full_processed_dataset"],
        "no_final_split": output_safety["no_final_split"],
        "no_model_training": output_safety["no_learned_state"],
        "reproducibility_manifest_created": REPRODUCIBILITY_PATH.is_file(),
        "source_data_immutable": all_source_snapshots(roots) == expected_source_snapshots(),
    }
    payload = {
        "gate": "G2",
        "checks": checks,
        "overall_status": g2_closure_status(checks),
        "completion_semantics": (
            "Canonical data layer reproducibility only; downstream split, learned transforms, "
            "resampling, predictor selection, model, clustering, and final dataset remain deferred."
        ),
    }
    write_json_atomic(CLOSURE_PATH, payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("bounded", "full"), default="bounded")
    parser.add_argument("--n-baiot-raw-root", type=Path)
    parser.add_argument("--n-baiot-extracted-root", type=Path)
    parser.add_argument("--bot-iot-root", type=Path)
    args = parser.parse_args()

    roots = configured_roots()
    if args.n_baiot_raw_root:
        roots["n_baiot_raw"] = args.n_baiot_raw_root.resolve()
    if args.n_baiot_extracted_root:
        roots["n_baiot_extracted"] = args.n_baiot_extracted_root.resolve()
    if args.bot_iot_root:
        roots["bot_iot_raw"] = args.bot_iot_root.resolve()

    traversal, traversal_evidence = write_and_recheck_traversal()
    bounded = run_bounded(traversal, traversal_evidence, roots)
    print(f"Traversal: {TRAVERSAL_PATH}")
    print(f"Bounded validation: {bounded['overall_status']}")
    if bounded["overall_status"] != "PASS":
        return 1
    if args.mode == "bounded":
        print("Full primary dry validation was not requested.")
        return 0

    dry_run = dry_validation(traversal, roots)
    print(f"Full dry validation: {dry_run['overall_status']}")
    print(f"Runtime seconds: {dry_run['execution_metadata']['runtime_seconds']:.3f}")
    if dry_run["overall_status"] != "PASS":
        return 1
    create_reproducibility_manifest(traversal, dry_run)
    checklist = closure_checklist(dry_run, bounded, roots)
    print(f"G2 closure: {checklist['overall_status']}")
    return 0 if checklist["overall_status"] == "COMPLETE" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BotIoTParseError, NBaiotParseError, OSError, ValueError) as error:
        print(f"G2C validation failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
