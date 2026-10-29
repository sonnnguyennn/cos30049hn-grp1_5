"""Build deterministic, read-only inventories of the local source datasets.

The utility never extracts archives and refuses to place output inside either
source root. Dataset roots are resolved from CLI arguments, environment
variables, or an optional machine-local YAML configuration, in that order.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import stat
import sys
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "data_paths.local.yaml"
DEFAULT_MANIFEST_DIR = PROJECT_ROOT / "artifacts" / "manifests"
DEFAULT_SUMMARY = PROJECT_ROOT / "artifacts" / "audit" / "source_inventory_summary.json"
HASH_CHUNK_SIZE = 4 * 1024 * 1024

DATASET_SETTINGS = {
    "n_baiot": {
        "environment_variable": "IOTGUARD_NBAIOT_ROOT",
        "manifest_name": "n_baiot_raw_manifest.csv",
    },
    "bot_iot": {
        "environment_variable": "IOTGUARD_BOTIOT_ROOT",
        "manifest_name": "bot_iot_raw_manifest.csv",
    },
}

MANIFEST_FIELDS = [
    "dataset",
    "relative_path",
    "filename",
    "extension",
    "size_bytes",
    "sha256",
    "is_archive",
    "read_status",
    "error",
    "modified_time_utc",
    "archive_format",
    "archive_inspection_status",
    "archive_member_count",
    "archive_error",
]


class SourceChangedError(OSError):
    """Raised when a source file changes while it is being inspected."""


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def assert_outputs_are_safe(outputs: list[Path], source_roots: list[Path]) -> None:
    for output in outputs:
        resolved_output = output.resolve()
        for source_root in source_roots:
            if is_within(resolved_output, source_root):
                raise ValueError(f"Refusing to write inside source dataset: {source_root}")


def assert_output_is_safe(output: Path, source_roots: list[Path]) -> None:
    """Backward-compatible single-output safety check."""
    assert_outputs_are_safe([output], source_roots)


def sha256_file(path: Path, chunk_size: int = HASH_CHUNK_SIZE) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(chunk_size), b""):
            digest.update(block)
    return digest.hexdigest()


def source_extension(path: Path) -> str:
    lower_name = path.name.lower()
    for compound_extension in (".tar.gz",):
        if lower_name.endswith(compound_extension):
            return compound_extension
    return path.suffix.lower()


def archive_format(path: Path) -> str | None:
    lower_name = path.name.lower()
    for suffix, format_name in (
        (".tar.gz", "tar.gz"),
        (".tgz", "tgz"),
        (".zip", "zip"),
        (".rar", "rar"),
        (".7z", "7z"),
        (".tar", "tar"),
        (".gz", "gz"),
    ):
        if lower_name.endswith(suffix):
            return format_name
    return None


def inspect_archive(path: Path, format_name: str) -> tuple[str, int | None, str | None]:
    """Inspect member metadata without extracting archive content."""
    if format_name == "zip":
        try:
            with zipfile.ZipFile(path) as archive:
                return "inspected", len(archive.infolist()), None
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            return "error", None, f"{type(exc).__name__}: {exc}"

    if format_name in {"tar", "tar.gz", "tgz"}:
        try:
            with tarfile.open(path, mode="r:*") as archive:
                return "inspected", len(archive.getmembers()), None
        except (OSError, tarfile.TarError) as exc:
            return "error", None, f"{type(exc).__name__}: {exc}"

    return (
        "unsupported",
        None,
        f"Member listing for {format_name} archives is not supported by this utility.",
    )


def discover_regular_files(root: Path) -> tuple[list[Path], list[str], int]:
    """Return regular files, traversal errors, and skipped symlink count."""
    paths: list[Path] = []
    traversal_errors: list[str] = []
    skipped_symlinks = 0

    def record_walk_error(exc: OSError) -> None:
        traversal_errors.append(f"{type(exc).__name__}: {exc}")

    for current_root, directory_names, file_names in os.walk(
        root, topdown=True, onerror=record_walk_error, followlinks=False
    ):
        current = Path(current_root)
        retained_directories: list[str] = []
        for directory_name in sorted(directory_names):
            directory = current / directory_name
            try:
                if directory.is_symlink():
                    skipped_symlinks += 1
                else:
                    retained_directories.append(directory_name)
            except OSError as exc:
                traversal_errors.append(f"{directory}: {type(exc).__name__}: {exc}")
        directory_names[:] = retained_directories

        for file_name in sorted(file_names):
            path = current / file_name
            try:
                if path.is_symlink():
                    skipped_symlinks += 1
                elif path.is_file():
                    paths.append(path)
            except OSError as exc:
                traversal_errors.append(f"{path}: {type(exc).__name__}: {exc}")

    paths.sort(key=lambda item: item.relative_to(root).as_posix())
    return paths, traversal_errors, skipped_symlinks


def _stat_signature(file_stat: os.stat_result) -> tuple[int, int]:
    return file_stat.st_size, file_stat.st_mtime_ns


def inventory_file(dataset_name: str, root: Path, path: Path) -> dict[str, Any]:
    relative_path = path.relative_to(root).as_posix()
    format_name = archive_format(path)
    row: dict[str, Any] = {
        "dataset": dataset_name,
        "relative_path": relative_path,
        "filename": path.name,
        "extension": source_extension(path),
        "size_bytes": None,
        "sha256": None,
        "is_archive": format_name is not None,
        "read_status": "error",
        "error": None,
        "modified_time_utc": None,
        "archive_format": format_name,
        "archive_inspection_status": "not_applicable" if format_name is None else "not_attempted",
        "archive_member_count": None,
        "archive_error": None,
    }

    try:
        before = path.stat()
        if not stat.S_ISREG(before.st_mode):
            raise OSError("Source entry is no longer a regular file.")
        row["size_bytes"] = before.st_size
        row["modified_time_utc"] = datetime.fromtimestamp(before.st_mtime, tz=UTC).isoformat()
        row["sha256"] = sha256_file(path)
        after_hash = path.stat()
        if _stat_signature(before) != _stat_signature(after_hash):
            raise SourceChangedError("Source file changed while SHA-256 was being calculated.")

        if format_name is not None:
            inspection_status, member_count, archive_error = inspect_archive(path, format_name)
            row["archive_inspection_status"] = inspection_status
            row["archive_member_count"] = member_count
            row["archive_error"] = archive_error
            after_inspection = path.stat()
            if _stat_signature(after_hash) != _stat_signature(after_inspection):
                raise SourceChangedError("Source file changed during archive inspection.")

        row["read_status"] = "ok"
    except SourceChangedError as exc:
        row["sha256"] = None
        row["read_status"] = "changed_during_read"
        row["error"] = f"{type(exc).__name__}: {exc}"
    except OSError as exc:
        row["sha256"] = None
        row["read_status"] = "error"
        row["error"] = f"{type(exc).__name__}: {exc}"
    return row


def inventory_dataset(
    dataset_name: str, root: Path
) -> tuple[list[dict[str, Any]], list[str], int]:
    paths, traversal_errors, skipped_symlinks = discover_regular_files(root)
    rows = [inventory_file(dataset_name, root, path) for path in paths]
    rows.sort(key=lambda row: str(row["relative_path"]))
    return rows, traversal_errors, skipped_symlinks


def _write_csv_atomic(rows: list[dict[str, Any]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f"{output.name}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=MANIFEST_FIELDS, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        temporary.replace(output)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_manifest(rows: Any, output: Path) -> int:
    """Write a deterministic CSV manifest and return its row count."""
    materialized = list(rows)
    materialized.sort(key=lambda row: str(row["relative_path"]))
    _write_csv_atomic(materialized, output)
    return len(materialized)


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


def load_config_roots(config_path: Path) -> dict[str, Path]:
    with config_path.open("r", encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    datasets = config.get("datasets") if isinstance(config, dict) else None
    if not isinstance(datasets, dict):
        raise ValueError("Configuration must contain a 'datasets' mapping.")

    roots: dict[str, Path] = {}
    for dataset_name in DATASET_SETTINGS:
        settings = datasets.get(dataset_name)
        if isinstance(settings, dict) and settings.get("root"):
            roots[dataset_name] = Path(str(settings["root"])).expanduser()
    return roots


def resolve_dataset_roots(args: argparse.Namespace) -> tuple[dict[str, Path], dict[str, str]]:
    config_path = args.config
    if config_path is None and DEFAULT_CONFIG.is_file():
        config_path = DEFAULT_CONFIG
    config_roots = load_config_roots(config_path.resolve()) if config_path else {}

    cli_values = {
        "n_baiot": args.n_baiot_root,
        "bot_iot": args.bot_iot_root,
    }
    roots: dict[str, Path] = {}
    root_sources: dict[str, str] = {}
    missing: list[str] = []
    for dataset_name, settings in DATASET_SETTINGS.items():
        env_name = settings["environment_variable"]
        if cli_values[dataset_name] is not None:
            raw_root = cli_values[dataset_name]
            root_sources[dataset_name] = "command_line"
        elif os.environ.get(env_name):
            raw_root = Path(os.environ[env_name])
            root_sources[dataset_name] = f"environment:{env_name}"
        elif dataset_name in config_roots:
            raw_root = config_roots[dataset_name]
            root_sources[dataset_name] = f"config:{config_path.resolve()}"
        else:
            missing.append(f"{dataset_name} ({env_name})")
            continue

        root = Path(raw_root).expanduser().resolve()
        if not root.is_dir():
            raise FileNotFoundError(f"Dataset root does not exist: {root}")
        roots[dataset_name] = root

    if missing:
        raise ValueError(
            "Missing dataset root configuration for: "
            + ", ".join(missing)
            + ". Use CLI arguments, environment variables, or --config."
        )
    return roots, root_sources


def summarize_dataset(
    root: Path,
    root_source: str,
    rows: list[dict[str, Any]],
    traversal_errors: list[str],
    skipped_symlinks: int,
    manifest: Path,
) -> dict[str, Any]:
    hash_failures = sum(row["read_status"] != "ok" for row in rows)
    archive_rows = [row for row in rows if row["is_archive"]]
    return {
        "root": str(root),
        "root_configuration_source": root_source,
        "manifest": manifest.relative_to(PROJECT_ROOT).as_posix(),
        "manifest_sha256": sha256_file(manifest),
        "file_count": len(rows),
        "total_size_bytes": sum(
            int(row["size_bytes"]) for row in rows if row["size_bytes"] is not None
        ),
        "hashed_ok": sum(row["read_status"] == "ok" and row["sha256"] is not None for row in rows),
        "hash_failures": hash_failures,
        "archive_count": len(archive_rows),
        "archives_inspected": sum(
            row["archive_inspection_status"] == "inspected" for row in archive_rows
        ),
        "archive_inspection_unsupported": sum(
            row["archive_inspection_status"] == "unsupported" for row in archive_rows
        ),
        "archive_inspection_failures": sum(
            row["archive_inspection_status"] == "error" for row in archive_rows
        ),
        "traversal_errors": traversal_errors,
        "skipped_symlinks": skipped_symlinks,
    }


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-baiot-root", type=Path)
    parser.add_argument("--bot-iot-root", type=Path)
    parser.add_argument(
        "--config",
        type=Path,
        help="Optional YAML config; CLI values and environment variables take precedence.",
    )
    parser.add_argument("--manifest-dir", type=Path, default=DEFAULT_MANIFEST_DIR)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()
    roots, root_sources = resolve_dataset_roots(args)
    manifest_dir = args.manifest_dir.resolve()
    summary_path = args.summary.resolve()
    manifest_paths = {
        dataset_name: manifest_dir / str(settings["manifest_name"])
        for dataset_name, settings in DATASET_SETTINGS.items()
    }
    assert_outputs_are_safe(
        [*manifest_paths.values(), summary_path],
        list(roots.values()),
    )

    datasets_summary: dict[str, Any] = {}
    any_incomplete = False
    for dataset_name, root in roots.items():
        print(f"Inventorying {dataset_name}: {root}", flush=True)
        rows, traversal_errors, skipped_symlinks = inventory_dataset(dataset_name, root)
        manifest_path = manifest_paths[dataset_name]
        write_manifest(rows, manifest_path)
        dataset_summary = summarize_dataset(
            root,
            root_sources[dataset_name],
            rows,
            traversal_errors,
            skipped_symlinks,
            manifest_path,
        )
        datasets_summary[dataset_name] = dataset_summary
        if (
            dataset_summary["hash_failures"]
            or dataset_summary["archive_inspection_failures"]
            or dataset_summary["traversal_errors"]
        ):
            any_incomplete = True
        print(
            f"Wrote {dataset_summary['file_count']} records to {manifest_path}",
            flush=True,
        )

    summary = {
        "audit_type": "raw_source_inventory",
        "generated_at_utc": datetime.now(tz=UTC).isoformat(),
        "hash_algorithm": "sha256",
        "hash_chunk_size_bytes": HASH_CHUNK_SIZE,
        "traversal": {
            "recursive": True,
            "relative_path_style": "posix",
            "symlinks_followed": False,
            "manifest_sort_key": "relative_path",
        },
        "archive_policy": {
            "extraction_performed": False,
            "standard_library_inspection": ["zip", "tar", "tar.gz", "tgz"],
            "unsupported_member_listing": ["rar", "7z", "gz"],
        },
        "datasets": datasets_summary,
        "runtime": {
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "executable": sys.executable,
        },
        "implementation": {
            "script": Path(__file__).resolve().relative_to(PROJECT_ROOT).as_posix(),
            "script_sha256": sha256_file(Path(__file__).resolve()),
            "arguments": sys.argv[1:],
        },
        "overall_status": "INCOMPLETE" if any_incomplete else "PASS",
    }
    _write_json_atomic(summary, summary_path)
    print(f"Wrote audit summary to {summary_path}", flush=True)
    print(f"Overall status: {summary['overall_status']}", flush=True)
    return 1 if any_incomplete else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
