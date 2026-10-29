"""Independently verify G2C reproducibility evidence and the G2 closure gate."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import struct
import subprocess
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from iotguard.data.bot_iot import BotIoTParseError, parse_bot_iot_port
from iotguard.data.contracts import bot_iot_source_columns, n_baiot_feature_names
from iotguard.data.n_baiot import duplicate_group_id, parse_n_baiot_record
from iotguard.data.reproducibility import G2_CLOSURE_CHECKS, g2_closure_status

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = PROJECT_ROOT / "artifacts" / "audit"
MANIFEST_DIR = PROJECT_ROOT / "artifacts" / "manifests"
CONTRACT_DIR = PROJECT_ROOT / "artifacts" / "contracts"

TRAVERSAL_PATH = MANIFEST_DIR / "n_baiot_canonical_traversal_v1.csv"
DRY_RUN_PATH = AUDIT_DIR / "g2c_primary_dry_run_summary.json"
BOUNDED_PATH = AUDIT_DIR / "g2c_bounded_materialization_smoke.json"
REPRODUCIBILITY_PATH = MANIFEST_DIR / "g2_preprocessing_reproducibility_manifest.json"
CLOSURE_PATH = AUDIT_DIR / "g2_closure_checklist.json"
OUTPUT = AUDIT_DIR / "g2c_evidence_verification.json"

EXPECTED_G2A_MANIFEST_SHA256 = (
    "8c387493caaddd10ceab1f95ca0b9cb40318e23b6a9d68c3a1f3b6242fb5548e"
)
EXPECTED_G2B_COMMIT = "9468f96bb6e0d2f2df14a80d6e9cbf10814541ed"
EXPECTED_ROWS = 7_062_606
EXPECTED_SOURCES = 89
HEX_PORT_COORDINATE = 632_280
_RECORD_DOMAIN = b"IOTGUARD\x00CANONICAL_RECORD\x00V1"


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


def independent_group_id(raw_lexemes: list[str]) -> str:
    digest = hashlib.sha256()
    for lexeme in raw_lexemes:
        encoded = lexeme.encode("utf-8")
        digest.update(struct.pack(">I", len(encoded)))
        digest.update(encoded)
    return f"sha256:{digest.hexdigest()}"


def _update_text(digest: Any, value: str) -> None:
    encoded = value.encode("utf-8")
    digest.update(struct.pack(">I", len(encoded)))
    digest.update(encoded)


def independent_record_digest(record: Any) -> str:
    if record.data_row_index is None or record.data_row_index < 1:
        raise ValueError("Record lacks a valid 1-based source row")
    digest = hashlib.sha256()
    digest.update(_RECORD_DOMAIN)
    for value in (
        record.source_logical_id,
        record.target_binary,
        record.label_family,
        record.label_fine,
        record.device,
        record.archive_or_source_family,
        record.source_member_filename,
    ):
        _update_text(digest, value)
    digest.update(record.data_row_index.to_bytes(8, "big", signed=False))
    digest.update(len(record.features).to_bytes(4, "big", signed=False))
    for value in record.features:
        if not math.isfinite(value):
            raise ValueError("Non-finite feature in canonical record")
        digest.update(struct.pack(">d", value))
    _update_text(digest, record.duplicate_group_id)
    return f"sha256:canonical-record-v1:{digest.hexdigest()}"


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


def roots_and_expected_snapshots() -> tuple[dict[str, Path], dict[str, dict[str, Any]]]:
    roots_evidence = load_json(AUDIT_DIR / "a4_evidence_verification.json")["source_safety"]
    a5 = load_json(AUDIT_DIR / "a5_audit_summary.json")["source_safety"]
    roots = {name: Path(details["root"]) for name, details in roots_evidence.items()}
    keys = ("file_count", "total_size_bytes", "metadata_digest_sha256")
    expected = {
        name: {key: details["after"][key] for key in keys} for name, details in a5.items()
    }
    return roots, expected


def read_rows_at(path: Path, indexes: set[int]) -> dict[int, list[str]]:
    found: dict[int, list[str]] = {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        if tuple(next(reader)) != n_baiot_feature_names():
            raise ValueError(f"N-BaIoT header mismatch: {path}")
        maximum = max(indexes)
        for index, row in enumerate(reader, start=1):
            if index in indexes:
                found[index] = row
            if index >= maximum:
                break
    if set(found) != indexes:
        raise ValueError(f"Missing requested rows: {indexes - set(found)}")
    return found


def independently_rerun_bounded_records(
    traversal: list[dict[str, str]],
    bounded: dict[str, Any],
    roots: dict[str, Path],
) -> tuple[bool, list[dict[str, Any]]]:
    traversal_by_id = {row["logical_id"]: row for row in traversal}
    expected_records = bounded["bounded_materialization"]["records"]
    grouped: dict[str, set[int]] = defaultdict(set)
    for expected in expected_records:
        grouped[expected["source_logical_id"]].add(expected["source_data_row_index"])
    actual_by_identity: dict[tuple[str, int], dict[str, Any]] = {}
    for logical_id in sorted(grouped):
        traversal_row = traversal_by_id[logical_id]
        path = roots[traversal_row["source_root_kind"]] / Path(
            traversal_row["source_relative_path"]
        )
        rows = read_rows_at(path, grouped[logical_id])
        for index, raw in rows.items():
            record = parse_n_baiot_record(raw, logical_id, data_row_index=index)
            independently_grouped = independent_group_id(raw)
            if independently_grouped != duplicate_group_id(raw):
                raise ValueError("Independent exact-group calculation differs from G2B")
            actual_by_identity[(logical_id, index)] = {
                "source_logical_id": logical_id,
                "source_data_row_index": index,
                "target_binary": record.target_binary,
                "label_family": record.label_family,
                "label_fine": record.label_fine,
                "feature_count": len(record.features),
                "duplicate_group_id": independently_grouped,
                "canonical_record_digest": independent_record_digest(record),
            }
    actual = [
        actual_by_identity[
            (expected["source_logical_id"], expected["source_data_row_index"])
        ]
        for expected in expected_records
    ]
    return actual == expected_records, actual


def verify_bot_headers_and_ports(
    roots: dict[str, Path], bounded: dict[str, Any]
) -> tuple[bool, bool]:
    bot_root = roots["bot_iot_raw"]
    expected_header = bot_iot_source_columns()
    header_evidence = bounded["bot_iot_canonical_headers"]
    headers_ok = len(header_evidence) == 4
    for item in header_evidence:
        path = bot_root / Path(item["source_relative_path"])
        with path.open("r", encoding="utf-8", newline="") as handle:
            headers_ok &= tuple(next(csv.reader(handle))) == expected_header

    source = bounded["real_bot_port_examples"][0]["source_logical_id"].split(
        "bot_iot:all_features_5pct_shards:", 1
    )[1]
    wanted = {1, 2, HEX_PORT_COORDINATE}
    selected: dict[int, list[str]] = {}
    with (bot_root / Path(source)).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        next(reader)
        for index, row in enumerate(reader, start=1):
            if index in wanted:
                selected[index] = row
            if index >= HEX_PORT_COORDINATE:
                break
    sport_index = expected_header.index("sport")
    dport_index = expected_header.index("dport")
    expected_kinds = {1: "decimal", 2: "unresolved_sentinel", HEX_PORT_COORDINATE: "hex"}
    ports_ok = set(selected) == wanted
    for index, row in selected.items():
        parsed = [parse_bot_iot_port(row[position]) for position in (sport_index, dport_index)]
        ports_ok &= any(port.kind == expected_kinds[index] for port in parsed)
    try:
        parse_bot_iot_port("80.0")
        ports_ok = False
    except BotIoTParseError:
        pass
    return headers_ok, ports_ok


def no_forbidden_outputs() -> bool:
    prohibited_suffixes = {
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
    prohibited_names = {
        "full_processed.csv",
        "x.npy",
        "y.npy",
        "train.csv",
        "validation.csv",
        "test.csv",
    }
    roots = [PROJECT_ROOT / "artifacts", PROJECT_ROOT / "data" / "processed"]
    files = [path for root in roots if root.exists() for path in root.rglob("*") if path.is_file()]
    return not any(
        path.suffix.lower() in prohibited_suffixes or path.name.lower() in prohibited_names
        for path in files
    )


def verify() -> dict[str, Any]:
    traversal = load_csv(TRAVERSAL_PATH)
    dry = load_json(DRY_RUN_PATH)
    bounded = load_json(BOUNDED_PATH)
    reproducibility = load_json(REPRODUCIBILITY_PATH)
    closure = load_json(CLOSURE_PATH)
    g2a_manifest_path = CONTRACT_DIR / "g2a_contract_manifest.json"
    g2a_manifest = load_json(g2a_manifest_path)
    labels = load_json(AUDIT_DIR / "label_audit_summary.json")["n_baiot"]
    roots, expected_snapshots = roots_and_expected_snapshots()

    g2a_artifacts_match = all(
        sha256_file(PROJECT_ROOT / relative) == expected
        for relative, expected in g2a_manifest["artifact_sha256"].items()
    )
    logical_ids = [row["logical_id"] for row in traversal]
    ordinals = [int(row["traversal_ordinal"]) for row in traversal]
    expected_rows = sum(int(row["expected_row_count"]) for row in traversal)
    deterministic_result = dry["deterministic_result"]
    recomputed_result_hash = hashlib.sha256(canonical_json_bytes(deterministic_result)).hexdigest()
    bounded_rerun_ok, bounded_rerun = independently_rerun_bounded_records(
        traversal, bounded, roots
    )
    headers_ok, ports_ok = verify_bot_headers_and_ports(roots, bounded)

    lexical = bounded["lexical_numeric_distinction"]
    lexical_numeric_equal = len({item["parsed_value"] for item in lexical}) == 1
    lexical_groups_distinct = len({item["duplicate_group_id"] for item in lexical}) == 3
    duplicate_pairs_ok = all(
        pair["independent_exact_source_tuple_equal"]
        and pair["g2b_group_ids_equal"]
        and pair["g2b_digest_matches_a4"]
        for pair in bounded["known_a4_duplicate_pairs"]
    )
    current_snapshots = {name: source_tree_snapshot(root) for name, root in roots.items()}
    current_head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    closure_checks = closure.get("checks", {})
    checks = {
        "g2a_manifest_hash_unchanged": sha256_file(g2a_manifest_path)
        == EXPECTED_G2A_MANIFEST_SHA256,
        "g2a_artifact_hashes_match": g2a_artifacts_match,
        "g2b_checkpoint_reference_matches": reproducibility["g2b_checkpoint_commit"]
        == EXPECTED_G2B_COMMIT
        == current_head,
        "traversal_has_89_unique_sources": len(traversal)
        == len(set(logical_ids))
        == EXPECTED_SOURCES,
        "traversal_ordinals_are_deterministic": ordinals
        == list(range(1, EXPECTED_SOURCES + 1))
        and logical_ids == sorted(logical_ids),
        "traversal_rows_reconcile": expected_rows == EXPECTED_ROWS,
        "traversal_hash_matches_reproducibility_manifest": sha256_file(TRAVERSAL_PATH)
        == reproducibility["canonical_traversal"]["sha256"],
        "full_dry_run_passed": dry["overall_status"] == "PASS",
        "full_dry_run_row_count_matches": deterministic_result["total_rows"]
        == EXPECTED_ROWS,
        "full_dry_run_binary_counts_match_a3": deterministic_result["binary_counts"]
        == labels["binary_distribution"],
        "full_dry_run_family_counts_match_a3": deterministic_result["family_counts"]
        == labels["family_distribution"],
        "full_dry_run_fine_counts_match_a3": deterministic_result["fine_counts"]
        == labels["fine_class_distribution"],
        "full_dry_run_error_counters_zero": not any(
            deterministic_result["error_counts"].values()
        ),
        "dry_run_deterministic_hash_matches": recomputed_result_hash
        == dry["deterministic_result_sha256"]
        == reproducibility["dry_run_deterministic_result_sha256"],
        "known_a4_duplicate_pairs_reconciled": duplicate_pairs_ok,
        "lexical_numeric_distinction_preserved": lexical_numeric_equal
        and lexical_groups_distinct,
        "bounded_sample_independent_rerun_identical": bounded_rerun_ok,
        "bot_four_canonical_headers_valid": headers_ok,
        "real_decimal_hex_sentinel_ports_valid": ports_ok,
        "no_full_processed_or_learned_outputs": no_forbidden_outputs(),
        "source_metadata_unchanged": current_snapshots == expected_snapshots,
        "closure_checklist_has_exact_mandatory_keys": set(closure_checks)
        == set(G2_CLOSURE_CHECKS),
        "closure_checklist_all_true": g2_closure_status(closure_checks) == "COMPLETE",
        "g2_status_complete": closure.get("overall_status") == "COMPLETE",
    }
    return {
        "audit_batch": "G2C independent reproducibility and G2 closure verification",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "checks": checks,
        "recomputed": {
            "traversal_source_count": len(traversal),
            "traversal_expected_rows": expected_rows,
            "dry_run_result_sha256": recomputed_result_hash,
            "bounded_record_count": len(bounded_rerun),
            "reproducibility_manifest_sha256": sha256_file(REPRODUCIBILITY_PATH),
            "source_metadata": current_snapshots,
        },
        "verification_independence": (
            "This verifier does not import the G2C driver. It independently reads source "
            "coordinates, re-encodes exact groups and canonical record digests, rechecks all "
            "four Bot headers and real port examples, recomputes hashes/counts, and audits "
            "source metadata plus forbidden outputs."
        ),
        "overall_status": "PASS" if all(checks.values()) else "FAIL",
    }


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_name(f"{path.name}.tmp")
    try:
        temporary.write_bytes(canonical_json_bytes(payload))
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def main() -> int:
    payload = verify()
    write_json_atomic(OUTPUT, payload)
    print(f"Wrote: {OUTPUT}")
    print(f"Overall status: {payload['overall_status']}")
    return 0 if payload["overall_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
