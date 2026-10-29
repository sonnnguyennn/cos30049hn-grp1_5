import csv
import importlib.util
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "n_baiot_archive_access.py"
SPEC = importlib.util.spec_from_file_location("n_baiot_archive_access", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
archive_access = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(archive_access)


def test_parse_unrar_technical_listing() -> None:
    output = """
        Name: nested\\combo.csv
        Type: File
        Size: 123

        Name: empty
        Type: Directory
        Size: 0
    """

    assert archive_access.parse_unrar_technical_listing(output) == [
        {
            "member_relative_path": "nested/combo.csv",
            "member_type": "File",
            "uncompressed_size_bytes": 123,
        },
        {
            "member_relative_path": "empty",
            "member_type": "Directory",
            "uncompressed_size_bytes": 0,
        },
    ]


def test_member_paths_reject_traversal_and_absolute_paths() -> None:
    assert archive_access.is_safe_member_path("nested/member.csv")
    assert not archive_access.is_safe_member_path("../member.csv")
    assert not archive_access.is_safe_member_path("C:/member.csv")
    assert not archive_access.is_safe_member_path("/member.csv")


def test_extraction_manifest_deterministic_sorting(tmp_path: Path) -> None:
    output = tmp_path / "manifest.csv"
    rows = []
    for archive, member in (("z.rar", "b.csv"), ("a.rar", "z.csv"), ("a.rar", "a.csv")):
        row = {field: "" for field in archive_access.EXTRACTED_FIELDS}
        row["parent_archive_relative_path"] = archive
        row["member_relative_path"] = member
        rows.append(row)

    archive_access.write_extracted_manifest(rows, output)

    with output.open("r", encoding="utf-8", newline="") as handle:
        written = list(csv.DictReader(handle))
    assert [
        (row["parent_archive_relative_path"], row["member_relative_path"])
        for row in written
    ] == [("a.rar", "a.csv"), ("a.rar", "z.csv"), ("z.rar", "b.csv")]
