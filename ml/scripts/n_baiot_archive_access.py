"""List and safely extract N-BaIoT RAR members outside the repository.

Run ``--mode list`` first. Extraction refuses an absent/incomplete member
inventory, unsafe member paths, unsafe workspace locations, and insufficient
free-space margin.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RAW_MANIFEST = PROJECT_ROOT / "artifacts" / "manifests" / "n_baiot_raw_manifest.csv"
DEFAULT_MEMBER_INVENTORY = PROJECT_ROOT / "artifacts" / "audit" / "n_baiot_archive_members.csv"
DEFAULT_EXTRACTED_MANIFEST = (
    PROJECT_ROOT / "artifacts" / "manifests" / "n_baiot_extracted_manifest.csv"
)
DEFAULT_EXTRACTION_SUMMARY = (
    PROJECT_ROOT / "artifacts" / "audit" / "n_baiot_extraction_summary.json"
)
DEFAULT_WORK_BASE = Path(r"E:\Document\iotguard_dataset_work")
EXTRACTION_DIRECTORY_NAME = "n_baiot_extracted"
HASH_CHUNK_SIZE = 4 * 1024 * 1024
MINIMUM_FREE_AFTER_EXTRACTION = 10 * 1024**3

MEMBER_FIELDS = [
    "device",
    "parent_archive_relative_path",
    "parent_archive_sha256",
    "archive_family_hint",
    "member_relative_path",
    "member_filename",
    "member_type",
    "uncompressed_size_bytes",
    "listing_status",
    "listing_error",
]

EXTRACTED_FIELDS = [
    "device",
    "parent_archive_relative_path",
    "parent_archive_sha256",
    "member_relative_path",
    "extracted_relative_path",
    "size_bytes",
    "sha256",
    "extraction_status",
    "error",
]


def sha256_file(path: Path, chunk_size: int = HASH_CHUNK_SIZE) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(chunk_size), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_csv_atomic(rows: list[dict[str, Any]], fields: list[str], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f"{output.name}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        temporary.replace(output)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_member_inventory(rows: list[dict[str, Any]], output: Path) -> None:
    rows.sort(
        key=lambda row: (
            str(row["parent_archive_relative_path"]),
            str(row["member_relative_path"]),
        )
    )
    _write_csv_atomic(rows, MEMBER_FIELDS, output)


def write_extracted_manifest(rows: list[dict[str, Any]], output: Path) -> None:
    rows.sort(
        key=lambda row: (
            str(row["parent_archive_relative_path"]),
            str(row["member_relative_path"]),
        )
    )
    _write_csv_atomic(rows, EXTRACTED_FIELDS, output)


def _write_json_atomic(payload: dict[str, Any], output: Path) -> None:
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


def find_unrar(explicit: Path | None) -> Path:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit)
    for executable_name in ("UnRAR.exe", "unrar.exe"):
        located = shutil.which(executable_name)
        if located:
            candidates.append(Path(located))
    candidates.extend(
        [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
            / "WinRAR"
            / "UnRAR.exe",
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
            / "WinRAR"
            / "UnRAR.exe",
        ]
    )
    for candidate in candidates:
        resolved = candidate.expanduser().resolve()
        if resolved.is_file():
            return resolved
    raise FileNotFoundError("No UnRAR executable was found; provide --tool explicitly.")


def unrar_version(tool: Path) -> str:
    result = subprocess.run(
        [str(tool)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    combined = "\n".join((result.stdout, result.stderr))
    for line in combined.splitlines():
        if line.strip().upper().startswith("UNRAR "):
            return line.strip()
    return "unknown"


def parse_unrar_technical_listing(output: str) -> list[dict[str, Any]]:
    members: list[dict[str, Any]] = []
    current: dict[str, str] = {}

    def finish_member() -> None:
        nonlocal current
        if "Name" in current:
            size_text = current.get("Size", "")
            members.append(
                {
                    "member_relative_path": current["Name"].replace("\\", "/"),
                    "member_type": current.get("Type", "Unknown"),
                    "uncompressed_size_bytes": int(size_text) if size_text.isdigit() else None,
                }
            )
        current = {}

    for line in output.splitlines():
        match = re.match(r"^\s*(Name|Type|Size):\s*(.*)$", line)
        if not match:
            continue
        key, value = match.groups()
        if key == "Name" and "Name" in current:
            finish_member()
        current[key] = value.strip()
    finish_member()
    return members


def is_safe_member_path(member_path: str) -> bool:
    normalized = member_path.replace("\\", "/")
    pure_path = PurePosixPath(normalized)
    return (
        bool(normalized)
        and not pure_path.is_absolute()
        and ".." not in pure_path.parts
        and not re.match(r"^[A-Za-z]:", normalized)
    )


def load_rar_archives(raw_manifest: Path) -> list[dict[str, str]]:
    with raw_manifest.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    archives = [row for row in rows if row.get("archive_format") == "rar"]
    archives.sort(key=lambda row: row["relative_path"])
    if len(archives) != 16:
        raise ValueError(f"Expected 16 RAR archives in A1 manifest, found {len(archives)}.")
    if any(row.get("read_status") != "ok" or not row.get("sha256") for row in archives):
        raise ValueError("A1 manifest contains an unreadable or unhashed RAR archive.")
    return archives


def list_archives(
    tool: Path,
    source_root: Path,
    archives: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], list[str]]:
    inventory_rows: list[dict[str, Any]] = []
    errors: list[str] = []
    for archive in archives:
        relative_path = archive["relative_path"]
        archive_path = source_root / Path(relative_path)
        result = subprocess.run(
            [str(tool), "lt", "-c-", str(archive_path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        parsed_members = parse_unrar_technical_listing(result.stdout)
        device = PurePosixPath(relative_path).parts[0]
        family = Path(relative_path).stem
        if result.returncode != 0 or not parsed_members:
            error = (
                f"UnRAR exit {result.returncode}: "
                f"{(result.stderr or result.stdout).strip()[-1000:]}"
            )
            errors.append(f"{relative_path}: {error}")
            inventory_rows.append(
                {
                    "device": device,
                    "parent_archive_relative_path": relative_path,
                    "parent_archive_sha256": archive["sha256"],
                    "archive_family_hint": family,
                    "member_relative_path": "",
                    "member_filename": "",
                    "member_type": "",
                    "uncompressed_size_bytes": "",
                    "listing_status": "error",
                    "listing_error": error,
                }
            )
            continue

        for member in parsed_members:
            member_path = str(member["member_relative_path"])
            if not is_safe_member_path(member_path):
                error = f"Unsafe archive member path: {member_path!r}"
                errors.append(f"{relative_path}: {error}")
                status = "error"
            else:
                error = ""
                status = "ok"
            inventory_rows.append(
                {
                    "device": device,
                    "parent_archive_relative_path": relative_path,
                    "parent_archive_sha256": archive["sha256"],
                    "archive_family_hint": family,
                    "member_relative_path": member_path,
                    "member_filename": PurePosixPath(member_path).name,
                    "member_type": member["member_type"],
                    "uncompressed_size_bytes": member["uncompressed_size_bytes"],
                    "listing_status": status,
                    "listing_error": error,
                }
            )
    return inventory_rows, errors


def load_member_inventory(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows or any(row["listing_status"] != "ok" for row in rows):
        raise ValueError("Archive-member inventory is absent, empty, or contains listing errors.")
    archive_count = len({row["parent_archive_relative_path"] for row in rows})
    if archive_count != 16:
        raise ValueError(f"Member inventory covers {archive_count} archives instead of 16.")
    return rows


def ensure_safe_work_root(extraction_root: Path, source_root: Path) -> None:
    resolved = extraction_root.resolve()
    if resolved == PROJECT_ROOT or PROJECT_ROOT in resolved.parents:
        raise ValueError("Extraction root must be outside the Git repository.")
    if resolved == source_root.resolve() or source_root.resolve() in resolved.parents:
        raise ValueError("Extraction root must be outside the source dataset.")
    if extraction_root.exists() and any(extraction_root.iterdir()):
        raise FileExistsError(f"Extraction root is not empty: {extraction_root}")


def extract_archives(
    tool: Path,
    source_root: Path,
    extraction_root: Path,
    member_rows: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], list[str]]:
    by_archive: dict[str, list[dict[str, str]]] = {}
    for row in member_rows:
        by_archive.setdefault(row["parent_archive_relative_path"], []).append(row)

    errors: list[str] = []
    manifest_rows: list[dict[str, Any]] = []
    extraction_root.mkdir(parents=True, exist_ok=True)
    for relative_archive in sorted(by_archive):
        rows = by_archive[relative_archive]
        device = rows[0]["device"]
        family = rows[0]["archive_family_hint"]
        destination = extraction_root / device / family
        destination.mkdir(parents=True, exist_ok=True)
        archive_path = source_root / Path(relative_archive)
        result = subprocess.run(
            [str(tool), "x", "-idq", "-o-", "-y", str(archive_path), f"{destination}{os.sep}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if result.returncode != 0:
            errors.append(
                f"{relative_archive}: UnRAR exit {result.returncode}: "
                f"{(result.stderr or result.stdout).strip()[-1000:]}"
            )

        expected_files = {
            row["member_relative_path"]
            for row in rows
            if row["member_type"].casefold() == "file"
        }
        actual_files = {
            path.relative_to(destination).as_posix()
            for path in destination.rglob("*")
            if path.is_file() and not path.is_symlink()
        }
        if expected_files != actual_files:
            missing = sorted(expected_files - actual_files)
            extra = sorted(actual_files - expected_files)
            errors.append(f"{relative_archive}: member mismatch; missing={missing}, extra={extra}")

        for row in rows:
            if row["member_type"].casefold() != "file":
                continue
            member_path = row["member_relative_path"]
            extracted_path = destination / Path(member_path)
            extracted_relative = extracted_path.relative_to(extraction_root).as_posix()
            record: dict[str, Any] = {
                "device": device,
                "parent_archive_relative_path": relative_archive,
                "parent_archive_sha256": row["parent_archive_sha256"],
                "member_relative_path": member_path,
                "extracted_relative_path": extracted_relative,
                "size_bytes": None,
                "sha256": None,
                "extraction_status": "error",
                "error": "",
            }
            try:
                size = extracted_path.stat().st_size
                expected_size = int(row["uncompressed_size_bytes"])
                if size != expected_size:
                    raise OSError(
                        f"Extracted size {size} differs from listed size {expected_size}."
                    )
                record["size_bytes"] = size
                record["sha256"] = sha256_file(extracted_path)
                record["extraction_status"] = "ok"
            except (OSError, ValueError) as exc:
                record["error"] = f"{type(exc).__name__}: {exc}"
                errors.append(f"{extracted_relative}: {record['error']}")
            manifest_rows.append(record)
    return manifest_rows, errors


def resolve_source_root(argument: Path | None) -> Path:
    raw_value = argument or (
        Path(os.environ["IOTGUARD_NBAIOT_ROOT"])
        if os.environ.get("IOTGUARD_NBAIOT_ROOT")
        else None
    )
    if raw_value is None:
        raise ValueError("Configure N-BaIoT with --n-baiot-root or IOTGUARD_NBAIOT_ROOT.")
    root = raw_value.expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"N-BaIoT source root does not exist: {root}")
    return root


def resolve_work_base(argument: Path | None) -> Path:
    if argument is not None:
        return argument.expanduser().resolve()
    if os.environ.get("IOTGUARD_DATASET_WORK_ROOT"):
        return Path(os.environ["IOTGUARD_DATASET_WORK_ROOT"]).expanduser().resolve()
    return DEFAULT_WORK_BASE.resolve()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("list", "extract"), required=True)
    parser.add_argument("--n-baiot-root", type=Path)
    parser.add_argument("--work-root", type=Path)
    parser.add_argument("--tool", type=Path)
    parser.add_argument("--raw-manifest", type=Path, default=DEFAULT_RAW_MANIFEST)
    parser.add_argument("--member-inventory", type=Path, default=DEFAULT_MEMBER_INVENTORY)
    parser.add_argument("--extracted-manifest", type=Path, default=DEFAULT_EXTRACTED_MANIFEST)
    parser.add_argument("--summary", type=Path, default=DEFAULT_EXTRACTION_SUMMARY)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    source_root = resolve_source_root(args.n_baiot_root)
    raw_manifest = args.raw_manifest.resolve()
    member_inventory = args.member_inventory.resolve()
    tool = find_unrar(args.tool)
    tool_version = unrar_version(tool)
    archives = load_rar_archives(raw_manifest)

    if args.mode == "list":
        rows, errors = list_archives(tool, source_root, archives)
        write_member_inventory(rows, member_inventory)
        archive_count = len({row["parent_archive_relative_path"] for row in rows})
        file_rows = [row for row in rows if str(row["member_type"]).casefold() == "file"]
        total_bytes = sum(int(row["uncompressed_size_bytes"]) for row in file_rows)
        print(f"Tool: {tool} ({tool_version})")
        print(f"Listed archives: {archive_count}/16")
        print(f"Regular members: {len(file_rows)}")
        print(f"Estimated extracted bytes: {total_bytes}")
        print(f"Wrote: {member_inventory}")
        if errors:
            for error in errors:
                print(f"ERROR: {error}", file=sys.stderr)
            return 1
        return 0

    member_rows = load_member_inventory(member_inventory)
    work_base = resolve_work_base(args.work_root)
    extraction_root = work_base / EXTRACTION_DIRECTORY_NAME
    ensure_safe_work_root(extraction_root, source_root)
    listed_file_rows = [row for row in member_rows if row["member_type"].casefold() == "file"]
    estimated_bytes = sum(int(row["uncompressed_size_bytes"]) for row in listed_file_rows)
    disk = shutil.disk_usage(extraction_root.anchor)
    free_after_estimate = disk.free - estimated_bytes
    if free_after_estimate < MINIMUM_FREE_AFTER_EXTRACTION:
        raise OSError(
            "Insufficient safe free-space margin: "
            f"free={disk.free}, estimated={estimated_bytes}, "
            f"required_remaining={MINIMUM_FREE_AFTER_EXTRACTION}."
        )

    manifest_rows, errors = extract_archives(tool, source_root, extraction_root, member_rows)
    extracted_manifest = args.extracted_manifest.resolve()
    write_extracted_manifest(manifest_rows, extracted_manifest)
    success_rows = [row for row in manifest_rows if row["extraction_status"] == "ok"]
    hash_failures = sum(not row["sha256"] for row in manifest_rows)
    summary = {
        "audit_batch": "A2.0",
        "generated_at_utc": datetime.now(tz=UTC).isoformat(),
        "extraction_tool": {
            "name": "UnRAR",
            "executable": str(tool),
            "version": tool_version,
        },
        "work_root": str(extraction_root),
        "source_root": str(source_root),
        "archive_count": 16,
        "listed_archives": len({row["parent_archive_relative_path"] for row in member_rows}),
        "listed_regular_members": len(listed_file_rows),
        "extraction_success_count": len(success_rows),
        "extraction_failure_count": len(manifest_rows) - len(success_rows),
        "extracted_file_count": len(manifest_rows),
        "total_extracted_bytes": sum(int(row["size_bytes"] or 0) for row in success_rows),
        "hash_success_count": sum(bool(row["sha256"]) for row in manifest_rows),
        "hash_failure_count": hash_failures,
        "free_space_preflight_bytes": disk.free,
        "estimated_extraction_bytes": estimated_bytes,
        "estimated_free_after_extraction_bytes": free_after_estimate,
        "minimum_required_free_after_extraction_bytes": MINIMUM_FREE_AFTER_EXTRACTION,
        "parent_raw_manifest": raw_manifest.relative_to(PROJECT_ROOT).as_posix(),
        "parent_raw_manifest_sha256": sha256_file(raw_manifest),
        "member_inventory": member_inventory.relative_to(PROJECT_ROOT).as_posix(),
        "member_inventory_sha256": sha256_file(member_inventory),
        "extracted_manifest": extracted_manifest.relative_to(PROJECT_ROOT).as_posix(),
        "extracted_manifest_sha256": sha256_file(extracted_manifest),
        "errors": errors,
        "overall_status": "PASS" if not errors and not hash_failures else "INCOMPLETE",
    }
    _write_json_atomic(summary, args.summary.resolve())
    print(f"Extracted files: {len(success_rows)}/{len(manifest_rows)}")
    print(f"Extracted bytes: {summary['total_extracted_bytes']}")
    print(f"Work root: {extraction_root}")
    print(f"Overall status: {summary['overall_status']}")
    return 0 if summary["overall_status"] == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, csv.Error, subprocess.SubprocessError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
