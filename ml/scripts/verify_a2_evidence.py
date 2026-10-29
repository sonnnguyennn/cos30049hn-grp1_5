"""Independently verify A2 evidence and persisted source-safety checks."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = PROJECT_ROOT / "artifacts" / "audit"
MANIFEST_DIR = PROJECT_ROOT / "artifacts" / "manifests"
OUTPUT = AUDIT_DIR / "a2_evidence_verification.json"


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


def powershell_sha256(path: Path) -> str:
    powershell = shutil.which("pwsh.exe") or shutil.which("pwsh")
    if not powershell:
        raise FileNotFoundError("PowerShell 7 was not found for independent Get-FileHash checks.")
    escaped = str(path).replace("'", "''")
    command = (
        f"(Get-FileHash -LiteralPath '{escaped}' -Algorithm SHA256).Hash.ToLowerInvariant()"
    )
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        check=False,
    )
    if result.returncode != 0:
        raise OSError(f"Get-FileHash failed for {path}: {result.stderr.strip()}")
    value = result.stdout.strip()
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"Get-FileHash returned an invalid SHA-256 for {path}: {value!r}")
    return value


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
            relative_path = path.relative_to(root).as_posix()
            records[relative_path] = {
                "size_bytes": file_stat.st_size,
                "modified_time_utc": datetime.fromtimestamp(
                    file_stat.st_mtime, tz=UTC
                ).isoformat(),
            }
    return records


def reconcile_source(root: Path, manifest: Path) -> dict[str, Any]:
    rows = load_csv(manifest)
    expected = {row["relative_path"]: row for row in rows}
    actual = discover_source_metadata(root)
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    size_mismatches = [
        {
            "relative_path": relative_path,
            "expected": int(expected[relative_path]["size_bytes"]),
            "observed": actual[relative_path]["size_bytes"],
        }
        for relative_path in sorted(set(expected) & set(actual))
        if int(expected[relative_path]["size_bytes"])
        != int(actual[relative_path]["size_bytes"])
    ]
    timestamp_mismatches = [
        {
            "relative_path": relative_path,
            "expected": expected[relative_path]["modified_time_utc"],
            "observed": actual[relative_path]["modified_time_utc"],
        }
        for relative_path in sorted(set(expected) & set(actual))
        if expected[relative_path]["modified_time_utc"]
        != actual[relative_path]["modified_time_utc"]
    ]
    return {
        "root": str(root),
        "manifest": manifest.relative_to(PROJECT_ROOT).as_posix(),
        "expected_file_count": len(expected),
        "observed_file_count": len(actual),
        "relative_paths_match": not missing and not unexpected,
        "missing_paths": missing,
        "unexpected_paths": unexpected,
        "size_mismatches": size_mismatches,
        "modified_time_mismatches": timestamp_mismatches,
        "metadata_match": (
            not missing and not unexpected and not size_mismatches and not timestamp_mismatches
        ),
    }


def verify_hash_sample(
    root: Path, manifest_row: dict[str, str], relative_field: str
) -> dict[str, Any]:
    relative_path = manifest_row[relative_field]
    path = root / Path(relative_path)
    observed = powershell_sha256(path)
    expected = manifest_row["sha256"]
    return {
        "relative_path": relative_path,
        "expected_sha256": expected,
        "get_file_hash_sha256": observed,
        "match": observed == expected,
    }


def binary_physical_data_row_count(path: Path) -> int:
    newline_count = 0
    final_byte = b""
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            newline_count += block.count(b"\n")
            final_byte = block[-1:]
    record_count = newline_count + (1 if final_byte and final_byte != b"\n" else 0)
    return max(record_count - 1, 0)


def independent_header_signature(path: Path, delimiter: str) -> str:
    with path.open("rb") as handle:
        first_line = handle.readline()
    decoded = first_line.decode("utf-8-sig", errors="strict").rstrip("\r\n")
    header = decoded.split(delimiter)
    serialized = json.dumps(header, ensure_ascii=False, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(serialized.encode('utf-8')).hexdigest()}"


def verify_row_sample(
    path: Path,
    structure_row: dict[str, str],
    delimiter: str,
) -> dict[str, Any]:
    observed_rows = binary_physical_data_row_count(path)
    observed_signature = independent_header_signature(path, delimiter)
    return {
        "logical_id": structure_row["logical_id"],
        "path": str(path),
        "method": "binary physical-line count and direct first-line delimiter split",
        "expected_data_rows": int(structure_row["row_count"]),
        "observed_data_rows": observed_rows,
        "row_count_match": observed_rows == int(structure_row["row_count"]),
        "expected_schema_signature": structure_row["schema_signature"],
        "observed_schema_signature": observed_signature,
        "schema_signature_match": observed_signature == structure_row["schema_signature"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-baiot-root", type=Path, required=True)
    parser.add_argument("--bot-iot-root", type=Path, required=True)
    parser.add_argument("--n-baiot-extracted-root", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    n_root = args.n_baiot_root.resolve()
    b_root = args.bot_iot_root.resolve()
    extracted_root = args.n_baiot_extracted_root.resolve()

    n_raw_manifest_path = MANIFEST_DIR / "n_baiot_raw_manifest.csv"
    b_raw_manifest_path = MANIFEST_DIR / "bot_iot_raw_manifest.csv"
    extracted_manifest_path = MANIFEST_DIR / "n_baiot_extracted_manifest.csv"
    member_inventory_path = AUDIT_DIR / "n_baiot_archive_members.csv"
    n_structure_path = AUDIT_DIR / "n_baiot_csv_structure.csv"
    b_structure_path = AUDIT_DIR / "bot_iot_csv_structure.csv"

    n_raw = load_csv(n_raw_manifest_path)
    b_raw = load_csv(b_raw_manifest_path)
    extracted = load_csv(extracted_manifest_path)
    members = load_csv(member_inventory_path)
    n_structure = load_csv(n_structure_path)
    b_structure = load_csv(b_structure_path)

    n_archives = [row for row in n_raw if row["archive_format"] == "rar"]
    n_benign = [row for row in n_raw if row["relative_path"].endswith("/benign_traffic.csv")]
    b_csv = [row for row in b_raw if row["extension"] == ".csv"]
    source_hash_samples = {
        "n_baiot": [
            verify_hash_sample(n_root, n_archives[0], "relative_path"),
            verify_hash_sample(n_root, n_archives[-1], "relative_path"),
            verify_hash_sample(n_root, n_benign[0], "relative_path"),
        ],
        "bot_iot": [
            verify_hash_sample(
                b_root,
                next(row for row in b_csv if "/All features/" in row["relative_path"]),
                "relative_path",
            )
        ],
    }
    extracted_hash_samples = [
        verify_hash_sample(extracted_root, extracted[0], "extracted_relative_path"),
        verify_hash_sample(extracted_root, extracted[-1], "extracted_relative_path"),
    ]

    n_by_source = {
        row["source_relative_path"]: row
        for row in n_structure
        if row["source_relative_path"]
    }
    n_by_extracted = {
        row["extracted_relative_path"]: row
        for row in n_structure
        if row["extracted_relative_path"]
    }
    b_by_source = {row["source_relative_path"]: row for row in b_structure}
    n_benign_path = n_benign[0]["relative_path"]
    n_attack_path = extracted[0]["extracted_relative_path"]
    b_all_path = next(
        row["relative_path"] for row in b_csv if "/All features/" in row["relative_path"]
    )
    b_ten_path = next(
        row["relative_path"]
        for row in b_csv
        if row["relative_path"].endswith("10_Best.csv")
    )
    row_samples = [
        verify_row_sample(n_root / Path(n_benign_path), n_by_source[n_benign_path], ","),
        verify_row_sample(
            extracted_root / Path(n_attack_path), n_by_extracted[n_attack_path], ","
        ),
        verify_row_sample(b_root / Path(b_all_path), b_by_source[b_all_path], ","),
        verify_row_sample(b_root / Path(b_ten_path), b_by_source[b_ten_path], ";"),
    ]

    json_artifacts = [
        AUDIT_DIR / "source_inventory_summary.json",
        AUDIT_DIR / "n_baiot_extraction_summary.json",
        AUDIT_DIR / "n_baiot_schema.json",
        AUDIT_DIR / "bot_iot_schema.json",
        AUDIT_DIR / "structural_audit_summary.json",
    ]
    parsed_json = []
    for path in json_artifacts:
        with path.open("r", encoding="utf-8") as handle:
            json.load(handle)
        parsed_json.append(path.relative_to(PROJECT_ROOT).as_posix())

    artifact_reconciliation = {
        "archive_member_inventory_rows": len(members),
        "archive_member_inventory_unique_archives": len(
            {row["parent_archive_relative_path"] for row in members}
        ),
        "extracted_manifest_rows": len(extracted),
        "extracted_manifest_unique_members": len(
            {
                (row["parent_archive_relative_path"], row["member_relative_path"])
                for row in extracted
            }
        ),
        "n_baiot_structure_rows": len(n_structure),
        "n_baiot_unique_logical_ids": len({row["logical_id"] for row in n_structure}),
        "bot_iot_structure_rows": len(b_structure),
        "bot_iot_unique_logical_ids": len({row["logical_id"] for row in b_structure}),
        "json_artifacts_parsed": parsed_json,
    }
    artifact_reconciliation["counts_match_expected"] = (
        artifact_reconciliation["archive_member_inventory_rows"] == 80
        and artifact_reconciliation["archive_member_inventory_unique_archives"] == 16
        and artifact_reconciliation["extracted_manifest_rows"] == 80
        and artifact_reconciliation["extracted_manifest_unique_members"] == 80
        and artifact_reconciliation["n_baiot_structure_rows"] == 89
        and artifact_reconciliation["n_baiot_unique_logical_ids"] == 89
        and artifact_reconciliation["bot_iot_structure_rows"] == 7
        and artifact_reconciliation["bot_iot_unique_logical_ids"] == 7
    )

    source_safety = {
        "n_baiot": reconcile_source(n_root, n_raw_manifest_path),
        "bot_iot": reconcile_source(b_root, b_raw_manifest_path),
        "independent_hash_tool": "PowerShell 7 Get-FileHash -Algorithm SHA256",
        "hash_samples": source_hash_samples,
    }
    all_checks = [
        source_safety["n_baiot"]["metadata_match"],
        source_safety["bot_iot"]["metadata_match"],
        all(sample["match"] for samples in source_hash_samples.values() for sample in samples),
        all(sample["match"] for sample in extracted_hash_samples),
        all(sample["row_count_match"] for sample in row_samples),
        all(sample["schema_signature_match"] for sample in row_samples),
        artifact_reconciliation["counts_match_expected"],
    ]
    payload = {
        "audit_batch": "A2",
        "generated_at_utc": datetime.now(tz=UTC).isoformat(),
        "source_safety": source_safety,
        "extracted_member_hash_samples": extracted_hash_samples,
        "independent_row_and_schema_samples": row_samples,
        "artifact_reconciliation": artifact_reconciliation,
        "overall_status": "PASS" if all(all_checks) else "FAIL",
    }
    write_json_atomic(payload, OUTPUT)
    print(f"Wrote: {OUTPUT}")
    print(f"Overall status: {payload['overall_status']}")
    return 0 if payload["overall_status"] == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, csv.Error, json.JSONDecodeError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
