"""Stream every logical A2 CSV and record exact structure and row counts."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import zipfile
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = PROJECT_ROOT / "artifacts" / "audit"
MANIFEST_DIR = PROJECT_ROOT / "artifacts" / "manifests"
DEFAULT_NBAIOT_RAW_MANIFEST = MANIFEST_DIR / "n_baiot_raw_manifest.csv"
DEFAULT_BOTIOT_RAW_MANIFEST = MANIFEST_DIR / "bot_iot_raw_manifest.csv"
DEFAULT_EXTRACTED_MANIFEST = MANIFEST_DIR / "n_baiot_extracted_manifest.csv"
DEFAULT_NBAIOT_STRUCTURE = AUDIT_DIR / "n_baiot_csv_structure.csv"
DEFAULT_BOTIOT_STRUCTURE = AUDIT_DIR / "bot_iot_csv_structure.csv"
DEFAULT_NBAIOT_SCHEMA = AUDIT_DIR / "n_baiot_schema.json"
DEFAULT_BOTIOT_SCHEMA = AUDIT_DIR / "bot_iot_schema.json"
DEFAULT_BOTIOT_COMPARISON = AUDIT_DIR / "bot_iot_representation_comparison.csv"
DEFAULT_SUMMARY = AUDIT_DIR / "structural_audit_summary.json"
HASH_CHUNK_SIZE = 4 * 1024 * 1024

STRUCTURE_FIELDS = [
    "logical_id",
    "dataset",
    "representation",
    "device",
    "archive_family_hint",
    "source_kind",
    "source_relative_path",
    "extracted_relative_path",
    "parent_archive_relative_path",
    "size_bytes",
    "row_count",
    "column_count",
    "delimiter",
    "header_columns",
    "header_sha256",
    "schema_signature",
    "parse_status",
    "parse_error",
    "width_mismatch_count",
]

COMPARISON_FIELDS = [
    "representation",
    "file_count",
    "total_rows",
    "column_counts",
    "schema_count",
    "ordered_schema_identical_within_group",
    "delimiters",
    "relationship_note",
]


def sha256_file(path: Path, chunk_size: int = HASH_CHUNK_SIZE) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(chunk_size), b""):
            digest.update(block)
    return digest.hexdigest()


def serialize_header(header: list[str]) -> str:
    return json.dumps(header, ensure_ascii=False, separators=(",", ":"))


def ordered_header_digest(header: list[str]) -> str:
    return hashlib.sha256(serialize_header(header).encode("utf-8")).hexdigest()


def detect_delimiter(path: Path) -> str:
    with path.open("r", encoding="utf-8-sig", errors="strict", newline="") as handle:
        first_record = handle.readline()
    if not first_record:
        return ","
    counts = {delimiter: first_record.count(delimiter) for delimiter in (",", ";", "\t", "|")}
    delimiter = max(counts, key=counts.get)
    return delimiter if counts[delimiter] else ","


def scan_csv(path: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    delimiter = detect_delimiter(path)
    row_count = 0
    width_mismatches = 0
    mismatch_examples: list[str] = []
    header: list[str] = []
    status = "ok"
    error = ""
    try:
        with path.open("r", encoding="utf-8-sig", errors="strict", newline="") as handle:
            reader = csv.reader(handle, delimiter=delimiter, strict=True)
            first = next(reader, None)
            if first is None:
                status = "empty"
                error = "CSV contains no header record."
            else:
                header = first
                expected_width = len(header)
                for row in reader:
                    row_count += 1
                    if len(row) != expected_width:
                        width_mismatches += 1
                        if len(mismatch_examples) < 5:
                            mismatch_examples.append(
                                f"data_row={row_count}, observed={len(row)}, "
                                f"expected={expected_width}"
                            )
                if width_mismatches:
                    status = "error"
                    error = (
                        f"{width_mismatches} row-width mismatch(es); "
                        + "; ".join(mismatch_examples)
                    )
    except (OSError, UnicodeError, csv.Error) as exc:
        status = "error"
        error = f"{type(exc).__name__}: {exc}"

    digest = ordered_header_digest(header)
    record = {field: "" for field in STRUCTURE_FIELDS}
    record.update(metadata)
    record.update(
        {
            "size_bytes": path.stat().st_size,
            "row_count": row_count,
            "column_count": len(header),
            "delimiter": {",": "comma", ";": "semicolon", "\t": "tab", "|": "pipe"}[
                delimiter
            ],
            "header_columns": serialize_header(header),
            "header_sha256": digest,
            "schema_signature": f"sha256:{digest}",
            "parse_status": status,
            "parse_error": error,
            "width_mismatch_count": width_mismatches,
        }
    )
    return record


def group_schemas(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[str(row["schema_signature"])].append(row)
    result: list[dict[str, Any]] = []
    for signature in sorted(groups):
        grouped_rows = groups[signature]
        result.append(
            {
                "schema_signature": signature,
                "header_sha256": grouped_rows[0]["header_sha256"],
                "column_count": grouped_rows[0]["column_count"],
                "ordered_columns": json.loads(str(grouped_rows[0]["header_columns"])),
                "file_count": len(grouped_rows),
                "logical_files": sorted(str(row["logical_id"]) for row in grouped_rows),
            }
        )
    return result


def classify_bot_iot_representation(relative_path: str) -> str:
    normalized = relative_path.replace("\\", "/")
    if normalized.startswith("Dataset/5%/All features/"):
        return "all_features_5pct_shards"
    if normalized.endswith("UNSW_2018_IoT_Botnet_Final_10_Best.csv"):
        return "ten_best_full"
    if normalized.endswith("UNSW_2018_IoT_Botnet_Final_10_best_Training.csv"):
        return "ten_best_predefined_train"
    if normalized.endswith("UNSW_2018_IoT_Botnet_Final_10_best_Testing.csv"):
        return "ten_best_predefined_test"
    raise ValueError(f"Unrecognized Bot-IoT CSV representation: {relative_path}")


def load_csv_manifest(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _assert_size(path: Path, expected_size: str) -> None:
    actual = path.stat().st_size
    if actual != int(expected_size):
        raise OSError(f"Size changed for {path}: expected {expected_size}, observed {actual}.")


def build_n_baiot_inputs(
    source_root: Path,
    extracted_root: Path,
    raw_manifest: Path,
    extracted_manifest: Path,
) -> list[tuple[Path, dict[str, Any]]]:
    raw_rows = load_csv_manifest(raw_manifest)
    benign_rows = [row for row in raw_rows if row["relative_path"].endswith("/benign_traffic.csv")]
    if len(benign_rows) != 9:
        raise ValueError(f"Expected 9 N-BaIoT benign CSVs, found {len(benign_rows)}.")

    inputs: list[tuple[Path, dict[str, Any]]] = []
    for row in benign_rows:
        relative_path = row["relative_path"]
        path = source_root / Path(relative_path)
        _assert_size(path, row["size_bytes"])
        device = relative_path.split("/", 1)[0]
        inputs.append(
            (
                path,
                {
                    "logical_id": f"n_baiot:source:{relative_path}",
                    "dataset": "n_baiot",
                    "representation": "device_traffic",
                    "device": device,
                    "archive_family_hint": "",
                    "source_kind": "immutable_benign_source",
                    "source_relative_path": relative_path,
                    "extracted_relative_path": "",
                    "parent_archive_relative_path": "",
                },
            )
        )

    extracted_rows = load_csv_manifest(extracted_manifest)
    successful = [row for row in extracted_rows if row["extraction_status"] == "ok"]
    if len(successful) != 80:
        raise ValueError(f"Expected 80 extracted N-BaIoT CSVs, found {len(successful)}.")
    for row in successful:
        relative_path = row["extracted_relative_path"]
        path = extracted_root / Path(relative_path)
        _assert_size(path, row["size_bytes"])
        parent_archive = row["parent_archive_relative_path"]
        inputs.append(
            (
                path,
                {
                    "logical_id": f"n_baiot:extracted:{relative_path}",
                    "dataset": "n_baiot",
                    "representation": "device_traffic",
                    "device": row["device"],
                    "archive_family_hint": Path(parent_archive).stem,
                    "source_kind": "derived_extracted_attack",
                    "source_relative_path": "",
                    "extracted_relative_path": relative_path,
                    "parent_archive_relative_path": parent_archive,
                },
            )
        )
    inputs.sort(key=lambda item: str(item[1]["logical_id"]))
    return inputs


def build_bot_iot_inputs(
    source_root: Path, raw_manifest: Path
) -> list[tuple[Path, dict[str, Any]]]:
    raw_rows = load_csv_manifest(raw_manifest)
    csv_rows = [row for row in raw_rows if row["extension"] == ".csv"]
    if len(csv_rows) != 7:
        raise ValueError(f"Expected 7 Bot-IoT CSVs, found {len(csv_rows)}.")
    inputs: list[tuple[Path, dict[str, Any]]] = []
    for row in csv_rows:
        relative_path = row["relative_path"]
        path = source_root / Path(relative_path)
        _assert_size(path, row["size_bytes"])
        representation = classify_bot_iot_representation(relative_path)
        inputs.append(
            (
                path,
                {
                    "logical_id": f"bot_iot:{representation}:{relative_path}",
                    "dataset": "bot_iot",
                    "representation": representation,
                    "device": "",
                    "archive_family_hint": "",
                    "source_kind": "immutable_source",
                    "source_relative_path": relative_path,
                    "extracted_relative_path": "",
                    "parent_archive_relative_path": "",
                },
            )
        )
    inputs.sort(key=lambda item: str(item[1]["logical_id"]))
    return inputs


def read_xlsx_feature_names(path: Path) -> list[str]:
    namespace = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    with zipfile.ZipFile(path) as workbook:
        shared_strings: list[str] = []
        if "xl/sharedStrings.xml" in workbook.namelist():
            root = ElementTree.fromstring(workbook.read("xl/sharedStrings.xml"))
            for item in root.findall(f"{namespace}si"):
                text = "".join(node.text or "" for node in item.iter(f"{namespace}t"))
                shared_strings.append(text)
        sheet_name = sorted(
            name for name in workbook.namelist() if name.startswith("xl/worksheets/sheet")
        )[0]
        sheet = ElementTree.fromstring(workbook.read(sheet_name))
        values: list[str] = []
        for cell in sheet.iter(f"{namespace}c"):
            reference = cell.attrib.get("r", "")
            if not reference.startswith("B"):
                continue
            value_node = cell.find(f"{namespace}v")
            if value_node is None or value_node.text is None:
                continue
            if cell.attrib.get("t") == "s":
                value = shared_strings[int(value_node.text)]
            else:
                value = value_node.text
            values.append(value)
    if "Feature" not in values:
        raise ValueError("Could not locate the Feature header in Bot-IoT documentation workbook.")
    start = values.index("Feature") + 1
    return values[start:]


def _write_csv(rows: list[dict[str, Any]], fields: list[str], output: Path) -> None:
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


def _write_json(payload: dict[str, Any], output: Path) -> None:
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


def audit_inputs(inputs: list[tuple[Path, dict[str, Any]]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, (path, metadata) in enumerate(inputs, 1):
        print(f"[{index}/{len(inputs)}] {metadata['logical_id']}", flush=True)
        rows.append(scan_csv(path, metadata))
    rows.sort(key=lambda row: str(row["logical_id"]))
    return rows


def source_family_subtotals(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row["source_kind"] == "immutable_benign_source":
            key = (str(row["device"]), "benign", "")
        else:
            key = (
                str(row["device"]),
                str(row["archive_family_hint"]),
                str(row["parent_archive_relative_path"]),
            )
        groups[key].append(row)
    return [
        {
            "device": key[0],
            "source_family_hint": key[1],
            "parent_archive_relative_path": key[2],
            "logical_csv_count": len(group),
            "total_data_rows": sum(int(row["row_count"]) for row in group),
        }
        for key, group in sorted(groups.items())
    ]


def build_representation_comparison(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    notes = {
        "all_features_5pct_shards": (
            "Four observed shards of one all-features 5% representation; do not concatenate "
            "with derived 10-best representations."
        ),
        "ten_best_full": (
            "Separate derived 10-best representation; semicolon-delimited local file includes "
            "an unnamed leading column."
        ),
        "ten_best_predefined_train": (
            "Supplied derived 10-best training representation; not adopted as an IoTGuard split."
        ),
        "ten_best_predefined_test": (
            "Supplied derived 10-best testing representation; not adopted as an IoTGuard split."
        ),
    }
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[str(row["representation"])].append(row)
    output: list[dict[str, Any]] = []
    for representation in sorted(groups):
        group = groups[representation]
        output.append(
            {
                "representation": representation,
                "file_count": len(group),
                "total_rows": sum(int(row["row_count"]) for row in group),
                "column_counts": json.dumps(
                    sorted({int(row["column_count"]) for row in group}), separators=(",", ":")
                ),
                "schema_count": len({row["schema_signature"] for row in group}),
                "ordered_schema_identical_within_group": (
                    len({row["schema_signature"] for row in group}) == 1
                ),
                "delimiters": json.dumps(
                    sorted({str(row["delimiter"]) for row in group}), separators=(",", ":")
                ),
                "relationship_note": notes[representation],
            }
        )
    return output


def _case_naming_differences(documented: list[str], observed: list[str]) -> list[dict[str, str]]:
    observed_by_fold = {column.casefold(): column for column in observed}
    return [
        {"documented": column, "observed": observed_by_fold[column.casefold()]}
        for column in documented
        if column.casefold() in observed_by_fold
        and column != observed_by_fold[column.casefold()]
    ]


def _casefold_order_differences(
    documented: list[str], observed: list[str]
) -> list[dict[str, Any]]:
    return [
        {
            "position_one_based": index,
            "documented": documented_column,
            "observed": observed_column,
        }
        for index, (documented_column, observed_column) in enumerate(
            zip(documented, observed, strict=False), start=1
        )
        if documented_column.casefold() != observed_column.casefold()
    ]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-baiot-root", type=Path)
    parser.add_argument("--bot-iot-root", type=Path)
    parser.add_argument("--n-baiot-extracted-root", type=Path)
    parser.add_argument("--n-baiot-raw-manifest", type=Path, default=DEFAULT_NBAIOT_RAW_MANIFEST)
    parser.add_argument("--bot-iot-raw-manifest", type=Path, default=DEFAULT_BOTIOT_RAW_MANIFEST)
    parser.add_argument("--extracted-manifest", type=Path, default=DEFAULT_EXTRACTED_MANIFEST)
    return parser


def _resolve_root(argument: Path | None, environment_name: str) -> Path:
    environment_value = os.environ.get(environment_name)
    raw = argument or (Path(environment_value) if environment_value else None)
    if raw is None:
        option_name = environment_name.lower().replace("_", "-")
        raise ValueError(f"Configure --{option_name} or {environment_name}.")
    root = raw.expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Configured root does not exist: {root}")
    return root


def main() -> int:
    args = build_parser().parse_args()
    n_baiot_root = _resolve_root(args.n_baiot_root, "IOTGUARD_NBAIOT_ROOT")
    bot_iot_root = _resolve_root(args.bot_iot_root, "IOTGUARD_BOTIOT_ROOT")
    if args.n_baiot_extracted_root is not None:
        extracted_root = args.n_baiot_extracted_root.expanduser().resolve()
    elif os.environ.get("IOTGUARD_DATASET_WORK_ROOT"):
        extracted_root = (
            Path(os.environ["IOTGUARD_DATASET_WORK_ROOT"]).expanduser().resolve()
            / "n_baiot_extracted"
        )
    else:
        raise ValueError(
            "Configure --n-baiot-extracted-root or IOTGUARD_DATASET_WORK_ROOT."
        )
    if not extracted_root.is_dir():
        raise FileNotFoundError(f"Extracted N-BaIoT root does not exist: {extracted_root}")

    n_inputs = build_n_baiot_inputs(
        n_baiot_root,
        extracted_root,
        args.n_baiot_raw_manifest.resolve(),
        args.extracted_manifest.resolve(),
    )
    b_inputs = build_bot_iot_inputs(bot_iot_root, args.bot_iot_raw_manifest.resolve())
    print("Auditing N-BaIoT CSV structures", flush=True)
    n_rows = audit_inputs(n_inputs)
    print("Auditing Bot-IoT CSV structures", flush=True)
    b_rows = audit_inputs(b_inputs)

    _write_csv(n_rows, STRUCTURE_FIELDS, DEFAULT_NBAIOT_STRUCTURE)
    _write_csv(b_rows, STRUCTURE_FIELDS, DEFAULT_BOTIOT_STRUCTURE)

    reference_structure = n_baiot_root / "demonstrate_structure.csv"
    reference_row = scan_csv(
        reference_structure,
        {
            "logical_id": "n_baiot:documentation:demonstrate_structure.csv",
            "dataset": "n_baiot",
            "representation": "documentation_reference",
            "source_kind": "documentation_reference",
        },
    )
    n_schemas = group_schemas(n_rows)
    n_parse_failures = sum(row["parse_status"] != "ok" for row in n_rows)
    n_schema = {
        "audit_batch": "A2.1",
        "dataset": "n_baiot",
        "schemas": n_schemas,
        "schema_count": len(n_schemas),
        "canonical_schema_consistent": len(n_schemas) == 1 and n_parse_failures == 0,
        "observed_column_counts": sorted({int(row["column_count"]) for row in n_rows}),
        "attack_member_filenames": {
            family: sorted(
                {
                    Path(str(row["extracted_relative_path"])).name
                    for row in n_rows
                    if row["archive_family_hint"] == family
                }
            )
            for family in ("gafgyt_attacks", "mirai_attacks")
        },
        "row_accounting_by_device_and_source": source_family_subtotals(n_rows),
        "documentation_cross_check": {
            "description_file": "N_BaIoT_dataset_description_v1.txt",
            "description_file_sha256": sha256_file(
                n_baiot_root / "N_BaIoT_dataset_description_v1.txt"
            ),
            "documented_independent_feature_count": 115,
            "documented_label_method": "Class label is to be derived from the respective filename.",
            "documented_instance_count": "Varies for every device and attack.",
            "numeric_documented_instance_total_available": False,
            "demonstrate_structure_column_count": reference_row["column_count"],
            "demonstrate_structure_schema_signature": reference_row["schema_signature"],
            "observed_schema_matches_demonstrate_structure": (
                len(n_schemas) == 1
                and n_schemas[0]["schema_signature"] == reference_row["schema_signature"]
            ),
            "observed_column_count_matches_documented_115": (
                {int(row["column_count"]) for row in n_rows} == {115}
            ),
        },
        "structural_discrepancies": [],
        "parse_failures": n_parse_failures,
    }
    if not n_schema["documentation_cross_check"][
        "observed_schema_matches_demonstrate_structure"
    ]:
        n_schema["structural_discrepancies"].append(
            "Observed CSV schema does not match demonstrate_structure.csv."
        )
    _write_json(n_schema, DEFAULT_NBAIOT_SCHEMA)

    b_schemas = group_schemas(b_rows)
    b_parse_failures = sum(row["parse_status"] != "ok" for row in b_rows)
    all_features_rows = [
        row for row in b_rows if row["representation"] == "all_features_5pct_shards"
    ]
    all_features_header = json.loads(str(all_features_rows[0]["header_columns"]))
    feature_workbook = (
        bot_iot_root / "Dataset" / "Features_Explanation" / "Total Feature Description.xlsx"
    )
    documented_features = read_xlsx_feature_names(feature_workbook)
    exact_missing = [column for column in documented_features if column not in all_features_header]
    exact_unexpected = [
        column for column in all_features_header if column not in documented_features
    ]
    naming_differences = _case_naming_differences(documented_features, all_features_header)
    documented_casefold = {column.casefold() for column in documented_features}
    observed_casefold = {column.casefold() for column in all_features_header}
    casefold_order_differences = _casefold_order_differences(
        documented_features, all_features_header
    )
    full_row = next(row for row in b_rows if row["representation"] == "ten_best_full")
    train_row = next(
        row for row in b_rows if row["representation"] == "ten_best_predefined_train"
    )
    test_row = next(
        row for row in b_rows if row["representation"] == "ten_best_predefined_test"
    )
    full_header = json.loads(str(full_row["header_columns"]))
    train_header = json.loads(str(train_row["header_columns"]))
    test_header = json.loads(str(test_row["header_columns"]))
    ten_best_overlap = [
        column for column in full_header if column and column in all_features_header
    ]
    comparison_rows = build_representation_comparison(b_rows)
    _write_csv(comparison_rows, COMPARISON_FIELDS, DEFAULT_BOTIOT_COMPARISON)
    b_schema = {
        "audit_batch": "A2.1",
        "dataset": "bot_iot",
        "schemas": b_schemas,
        "schema_count": len(b_schemas),
        "representation_groups": {
            row["representation"]: row for row in comparison_rows
        },
        "all_features_ordered_schema_consistent": (
            len({row["schema_signature"] for row in all_features_rows}) == 1
        ),
        "ten_best": {
            "full_ordered_columns": full_header,
            "predefined_train_ordered_columns": train_header,
            "predefined_test_ordered_columns": test_header,
            "train_test_ordered_schemas_identical": (
                train_row["schema_signature"] == test_row["schema_signature"]
            ),
            "full_train_test_schemas_structurally_identical": (
                full_row["schema_signature"]
                == train_row["schema_signature"]
                == test_row["schema_signature"]
            ),
            "full_schema_without_unnamed_leading_column_matches_split": (
                full_header[1:] == train_header == test_header
            ),
            "full_columns_overlapping_all_features": ten_best_overlap,
            "full_overlap_count": len(ten_best_overlap),
            "full_has_unnamed_leading_column": bool(full_header and full_header[0] == ""),
        },
        "documentation_cross_check": {
            "feature_workbook": "Dataset/Features_Explanation/Total Feature Description.xlsx",
            "feature_workbook_sha256": sha256_file(feature_workbook),
            "documented_feature_names": documented_features,
            "observed_all_features_names": all_features_header,
            "missing_documented_columns_exact_match": exact_missing,
            "unexpected_observed_columns_exact_match": exact_unexpected,
            "case_only_naming_differences": naming_differences,
            "missing_documented_columns_case_insensitive": sorted(
                documented_casefold - observed_casefold
            ),
            "unexpected_observed_columns_case_insensitive": sorted(
                observed_casefold - documented_casefold
            ),
            "case_insensitive_order_matches": (
                [column.casefold() for column in documented_features]
                == [column.casefold() for column in all_features_header]
            ),
            "case_insensitive_order_differences": casefold_order_differences,
            "documented_and_observed_feature_count_match": (
                len(documented_features) == len(all_features_header)
            ),
            "read_me_pdf": {
                "sha256": sha256_file(bot_iot_root / "Read_Me.pdf"),
                "observed_documentation_fact": (
                    "The documented Dataset/5% directory contains separate 10-best and "
                    "All features representations."
                ),
            },
            "dataset_pdf": {
                "sha256": sha256_file(bot_iot_root / "The Bot-IoT Dataset.pdf"),
                "observed_documentation_fact": (
                    "The documented 5% subset comprises four files, approximately 1.07 GB "
                    "and about 3 million records."
                ),
                "documented_approximate_5pct_rows": 3000000,
                "observed_5pct_all_features_rows": sum(
                    int(row["row_count"]) for row in all_features_rows
                ),
                "difference_from_approximate_3_million": (
                    sum(int(row["row_count"]) for row in all_features_rows) - 3000000
                ),
                "documented_row_count_is_approximate": True,
                "documented_approximate_total_size_gb": 1.07,
                "observed_total_size_bytes": sum(
                    int(row["size_bytes"]) for row in all_features_rows
                ),
            },
        },
        "structural_discrepancies": [
            (
                "The 10-best full file is semicolon-delimited and has an unnamed leading "
                "column; the predefined train/test files are comma-delimited without it."
            ),
            (
                "The feature workbook uses capitalization such as Stime/Flgs/Proto while "
                "the all-features CSV headers use stime/flgs/proto."
            ),
            (
                "The feature workbook orders N_IN_Conn_P_SrcIP before N_IN_Conn_P_DstIP; "
                "the observed all-features CSV header orders destination before source."
            ),
        ],
        "lineage_limits": (
            "Row-count agreement alone does not establish record-level identity between the "
            "unsplit and predefined train/test 10-best representations."
        ),
        "parse_failures": b_parse_failures,
    }
    _write_json(b_schema, DEFAULT_BOTIOT_SCHEMA)

    all_features_total = sum(int(row["row_count"]) for row in all_features_rows)
    train_test_sum = int(train_row["row_count"]) + int(test_row["row_count"])
    n_total_rows = sum(int(row["row_count"]) for row in n_rows)
    artifacts = [
        DEFAULT_NBAIOT_STRUCTURE,
        DEFAULT_BOTIOT_STRUCTURE,
        DEFAULT_NBAIOT_SCHEMA,
        DEFAULT_BOTIOT_SCHEMA,
        DEFAULT_BOTIOT_COMPARISON,
    ]
    summary = {
        "audit_batch": "A2",
        "generated_at_utc": datetime.now(tz=UTC).isoformat(),
        "n_baiot": {
            "source_benign_csv_count": 9,
            "attack_archive_count": 16,
            "attack_member_csv_count": 80,
            "logical_csv_count": len(n_rows),
            "schema_count": len(n_schemas),
            "canonical_schema_consistent": n_schema["canonical_schema_consistent"],
            "observed_column_count": sorted({int(row["column_count"]) for row in n_rows}),
            "total_data_rows": n_total_rows,
            "parse_failures": n_parse_failures,
        },
        "bot_iot": {
            "all_features_file_count": len(all_features_rows),
            "all_features_rows": all_features_total,
            "all_features_shard_rows": {
                str(row["source_relative_path"]): int(row["row_count"])
                for row in sorted(
                    all_features_rows, key=lambda item: str(item["source_relative_path"])
                )
            },
            "all_features_schema_count": len(
                {row["schema_signature"] for row in all_features_rows}
            ),
            "ten_best_full_rows": int(full_row["row_count"]),
            "ten_best_train_rows": int(train_row["row_count"]),
            "ten_best_test_rows": int(test_row["row_count"]),
            "ten_best_train_test_sum": train_test_sum,
            "ten_best_unsplit_vs_split_row_count_match": (
                int(full_row["row_count"]) == train_test_sum
            ),
            "representation_schema_count": len(b_schemas),
            "parse_failures": b_parse_failures,
        },
        "artifact_sha256": {
            artifact.relative_to(PROJECT_ROOT).as_posix(): sha256_file(artifact)
            for artifact in artifacts
        },
        "overall_status": "PASS" if not n_parse_failures and not b_parse_failures else "FAIL",
    }
    _write_json(summary, DEFAULT_SUMMARY)
    print(f"N-BaIoT total rows: {n_total_rows}")
    print(f"Bot-IoT all-features rows: {all_features_total}")
    print(f"Bot-IoT 10-best full rows: {full_row['row_count']}")
    print(f"Bot-IoT 10-best split rows: {train_test_sum}")
    print(f"Overall status: {summary['overall_status']}")
    return 0 if summary["overall_status"] == "PASS" else 1


if __name__ == "__main__":
    try:
        csv.field_size_limit(sys.maxsize)
    except OverflowError:
        csv.field_size_limit(2**31 - 1)
    try:
        raise SystemExit(main())
    except (OSError, ValueError, csv.Error, zipfile.BadZipFile) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
