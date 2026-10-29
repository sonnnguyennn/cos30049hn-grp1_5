import csv
import hashlib
import importlib.util
import zipfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "dataset_inventory.py"
SPEC = importlib.util.spec_from_file_location("dataset_inventory", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
dataset_inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dataset_inventory)


def test_sha256_file_matches_known_digest(tmp_path: Path) -> None:
    source = tmp_path / "payload.bin"
    payload = b"IoTGuard\x00streaming-hash\n"
    source.write_bytes(payload)

    expected = hashlib.sha256(payload).hexdigest()
    assert dataset_inventory.sha256_file(source, chunk_size=3) == expected


def test_recursive_discovery_relative_paths_and_deterministic_sorting(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "nested").mkdir(parents=True)
    (source / "z.csv").write_text("z", encoding="utf-8")
    (source / "nested" / "a.txt").write_text("a", encoding="utf-8")

    rows, errors, skipped_symlinks = dataset_inventory.inventory_dataset("candidate", source)

    assert errors == []
    assert skipped_symlinks == 0
    assert [row["relative_path"] for row in rows] == ["nested/a.txt", "z.csv"]
    assert all(row["read_status"] == "ok" for row in rows)
    assert all(len(row["sha256"]) == 64 for row in rows)


def test_manifest_is_sorted_even_if_input_is_not(tmp_path: Path) -> None:
    output = tmp_path / "manifest.csv"
    rows = [
        {field: None for field in dataset_inventory.MANIFEST_FIELDS},
        {field: None for field in dataset_inventory.MANIFEST_FIELDS},
    ]
    rows[0]["relative_path"] = "z/file.csv"
    rows[1]["relative_path"] = "a/file.csv"

    count = dataset_inventory.write_manifest(rows, output)

    with output.open(encoding="utf-8", newline="") as handle:
        written = list(csv.DictReader(handle))
    assert count == 2
    assert [row["relative_path"] for row in written] == ["a/file.csv", "z/file.csv"]


def test_hash_error_is_recorded(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    source_file = source / "unreadable.csv"
    source_file.write_text("value\n1\n", encoding="utf-8")

    def deny_read(path: Path, chunk_size: int = dataset_inventory.HASH_CHUNK_SIZE) -> str:
        raise PermissionError(f"read denied: {path.name}")

    monkeypatch.setattr(dataset_inventory, "sha256_file", deny_read)
    row = dataset_inventory.inventory_file("candidate", source, source_file)

    assert row["read_status"] == "error"
    assert row["sha256"] is None
    assert "PermissionError" in row["error"]


def test_empty_directory_inventory(tmp_path: Path) -> None:
    rows, errors, skipped_symlinks = dataset_inventory.inventory_dataset("empty", tmp_path)

    assert rows == []
    assert errors == []
    assert skipped_symlinks == 0


def test_zip_archive_is_inspected_without_extraction(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    archive_path = source / "sample.zip"
    with zipfile.ZipFile(archive_path, mode="w") as archive:
        archive.writestr("nested/member.txt", "payload")

    row = dataset_inventory.inventory_file("candidate", source, archive_path)

    assert row["is_archive"] is True
    assert row["archive_format"] == "zip"
    assert row["archive_inspection_status"] == "inspected"
    assert row["archive_member_count"] == 1
    assert not (source / "nested").exists()


def test_inventory_reads_source_and_writes_only_to_separate_output(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    source_file = source / "flow.csv"
    source_file.write_text("label,value\nbenign,1\n", encoding="utf-8")
    before = source_file.read_bytes()
    before_mtime = source_file.stat().st_mtime_ns

    output = tmp_path / "repository-output" / "manifest.csv"
    dataset_inventory.assert_output_is_safe(output, [source])
    rows, _, _ = dataset_inventory.inventory_dataset("candidate", source)
    count = dataset_inventory.write_manifest(rows, output)

    assert count == 1
    assert output.is_file()
    assert source_file.read_bytes() == before
    assert source_file.stat().st_mtime_ns == before_mtime
    assert not (source / "manifest.csv").exists()


def test_inventory_rejects_output_inside_source_dataset(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()

    with pytest.raises(ValueError, match="Refusing to write inside source dataset"):
        dataset_inventory.assert_output_is_safe(source / "manifest.csv", [source])
