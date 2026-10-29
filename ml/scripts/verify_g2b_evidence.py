"""Independently verify G2B contracts, bounded smoke evidence, and safety boundaries."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import struct
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from iotguard.data.bot_iot import BotIoTParseError, parse_bot_iot_port
from iotguard.data.n_baiot import (
    NBaiotParseError,
    map_n_baiot_provenance,
    parse_n_baiot_record,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_DIR = PROJECT_ROOT / "artifacts" / "contracts"
AUDIT_DIR = PROJECT_ROOT / "artifacts" / "audit"
MANIFEST_DIR = PROJECT_ROOT / "artifacts" / "manifests"
OUTPUT = AUDIT_DIR / "g2b_evidence_verification.json"
EXPECTED_G2A_MANIFEST_SHA256 = (
    "8c387493caaddd10ceab1f95ca0b9cb40318e23b6a9d68c3a1f3b6242fb5548e"
)
EXPECTED_N_SCHEMA = "sha256:84a9391e57a872b4b73f50e4b7f552cb208ab10e177e5bb93cb7062bebe25607"
EXPECTED_BOT_SCHEMA = "sha256:3d1d5f0c993e51d34d81660ea9d81d438d966ecf5c0c397479c795c987910048"
EXPECTED_SYNTHETIC_GROUP = (
    "sha256:76479386ed7f8818f10e629436b483ec51243e52f8287b0f767295395f718ddd"
)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return payload


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def ordered_schema_signature(names: list[str]) -> str:
    serialized = json.dumps(names, ensure_ascii=False, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(serialized.encode('utf-8')).hexdigest()}"


def independent_group_id(raw_lexemes: list[str]) -> str:
    digest = hashlib.sha256()
    for lexeme in raw_lexemes:
        encoded = lexeme.encode("utf-8")
        digest.update(struct.pack(">I", len(encoded)))
        digest.update(encoded)
    return f"sha256:{digest.hexdigest()}"


def independent_port_parse(raw: str) -> tuple[str, int | None]:
    if raw == "-1":
        return "unresolved_sentinel", None
    if re.fullmatch(r"[0-9]+", raw):
        value, kind = int(raw, 10), "decimal"
    elif re.fullmatch(r"0[xX][0-9a-fA-F]+", raw):
        value, kind = int(raw, 16), "hex"
    else:
        raise ValueError(raw)
    if not 0 <= value <= 65535:
        raise ValueError(raw)
    return kind, value


def manifest_metadata_matches(root: Path, manifest: Path) -> bool:
    with manifest.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    expected_paths = {row["relative_path"] for row in rows}
    actual_paths = {
        path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()
    }
    if expected_paths != actual_paths:
        return False
    return all(
        (root / Path(row["relative_path"])).stat().st_size == int(row["size_bytes"])
        for row in rows
    )


def extracted_metadata_matches(root: Path, manifest: Path) -> bool:
    with manifest.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    expected = {
        row["extracted_relative_path"]: int(row["size_bytes"])
        for row in rows
        if row.get("extraction_status") == "ok"
    }
    actual = {
        path.relative_to(root).as_posix(): path.stat().st_size
        for path in root.rglob("*")
        if path.is_file()
    }
    return expected == actual


def source_tree_metadata(root: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    file_count = 0
    total_size = 0
    for path in sorted((item for item in root.rglob("*") if item.is_file()), key=str):
        stat = path.stat()
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(stat.st_size.to_bytes(8, "big"))
        digest.update(stat.st_mtime_ns.to_bytes(8, "big", signed=True))
        file_count += 1
        total_size += stat.st_size
    return {
        "file_count": file_count,
        "total_size_bytes": total_size,
        "metadata_digest_sha256": digest.hexdigest(),
    }


def no_forbidden_outputs() -> bool:
    prohibited_suffixes = {
        ".joblib",
        ".pkl",
        ".pickle",
        ".onnx",
        ".tflite",
        ".pt",
        ".pth",
        ".npz",
        ".parquet",
    }
    roots = [PROJECT_ROOT / "artifacts", PROJECT_ROOT / "data" / "processed"]
    files = [path for root in roots if root.exists() for path in root.rglob("*") if path.is_file()]
    if any(path.suffix.lower() in prohibited_suffixes for path in files):
        return False
    forbidden_name_tokens = (
        "train_split",
        "validation_split",
        "test_split",
        "fitted_scaler",
        "fitted_selector",
        "resampled_dataset",
    )
    return not any(
        any(token in path.name.lower() for token in forbidden_name_tokens) for path in files
    )


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_name(f"{path.name}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def verify() -> dict[str, Any]:
    contract_manifest_path = CONTRACT_DIR / "g2a_contract_manifest.json"
    contract_manifest = load_json(contract_manifest_path)
    feature_contract = load_json(CONTRACT_DIR / "n_baiot_feature_contract_v1.json")
    bot_contract = load_json(CONTRACT_DIR / "bot_iot_secondary_source_contract_v1.json")
    smoke = load_json(AUDIT_DIR / "g2b_smoke_verification.json")

    artifact_hashes_match = all(
        sha256_file(PROJECT_ROOT / relative_path) == expected
        for relative_path, expected in contract_manifest["artifact_sha256"].items()
    )
    evidence_hashes_match = all(
        sha256_file(PROJECT_ROOT / relative_path) == expected
        for relative_path, expected in contract_manifest["source_evidence_sha256"].items()
    )
    n_names = feature_contract["ordered_feature_names"]
    bot_columns = bot_contract["ordered_source_columns"]

    synthetic = ["1"] * 115
    independent_group = independent_group_id(synthetic)
    parsed_group = parse_n_baiot_record(
        synthetic,
        "n_baiot:source:Danmini_Doorbell/benign_traffic.csv",
    ).duplicate_group_id

    provenance_examples = {
        "n_baiot:source:Danmini_Doorbell/benign_traffic.csv": (
            "benign",
            "benign",
            "benign",
        ),
        "n_baiot:extracted:Danmini_Doorbell/gafgyt_attacks/combo.csv": (
            "malicious",
            "gafgyt",
            "gafgyt_combo",
        ),
        "n_baiot:extracted:Danmini_Doorbell/mirai_attacks/udpplain.csv": (
            "malicious",
            "mirai",
            "mirai_udpplain",
        ),
    }
    provenance_matches = all(
        (
            (mapped := map_n_baiot_provenance(logical_id)).target_binary,
            mapped.label_family,
            mapped.label_fine,
        )
        == expected
        for logical_id, expected in provenance_examples.items()
    )
    try:
        map_n_baiot_provenance(
            "n_baiot:extracted:Danmini_Doorbell/gafgyt_attacks/ack.csv"
        )
        invalid_provenance_rejected = False
    except NBaiotParseError:
        invalid_provenance_rejected = True

    independent_ports = {
        raw: independent_port_parse(raw) for raw in ("443", "0x0303", "-1")
    }
    parser_ports = {
        raw: (parse_bot_iot_port(raw).kind, parse_bot_iot_port(raw).value)
        for raw in independent_ports
    }
    try:
        parse_bot_iot_port("80.0")
        invalid_port_rejected = False
    except BotIoTParseError:
        invalid_port_rejected = True

    roots = load_json(AUDIT_DIR / "a4_evidence_verification.json")["source_safety"]
    a5_source_safety = load_json(AUDIT_DIR / "a5_audit_summary.json")["source_safety"]
    source_metadata = {
        "bot_iot_raw": manifest_metadata_matches(
            Path(roots["bot_iot_raw"]["root"]),
            MANIFEST_DIR / "bot_iot_raw_manifest.csv",
        ),
        "n_baiot_raw": manifest_metadata_matches(
            Path(roots["n_baiot_raw"]["root"]),
            MANIFEST_DIR / "n_baiot_raw_manifest.csv",
        ),
        "n_baiot_extracted": extracted_metadata_matches(
            Path(roots["n_baiot_extracted"]["root"]),
            MANIFEST_DIR / "n_baiot_extracted_manifest.csv",
        ),
    }
    current_source_snapshots = {
        name: source_tree_metadata(Path(details["root"])) for name, details in roots.items()
    }
    source_snapshot_digests_match = all(
        current_source_snapshots[name]
        == {
            key: a5_source_safety[name]["after"][key]
            for key in ("file_count", "total_size_bytes", "metadata_digest_sha256")
        }
        for name in current_source_snapshots
    )

    smoke_n_rows = [row for source in smoke["n_baiot"] for row in source["rows"]]
    smoke_bot_rows = [row for source in smoke["bot_iot"] for row in source["rows"]]
    checks = {
        "g2a_manifest_hash_unchanged": sha256_file(contract_manifest_path)
        == EXPECTED_G2A_MANIFEST_SHA256,
        "g2a_artifact_hashes_match": artifact_hashes_match,
        "g2a_source_evidence_hashes_match": evidence_hashes_match,
        "n_baiot_has_115_ordered_fields": len(n_names) == 115,
        "n_baiot_schema_signature_matches": ordered_schema_signature(n_names)
        == EXPECTED_N_SCHEMA,
        "synthetic_group_matches_independent_sha256": independent_group
        == EXPECTED_SYNTHETIC_GROUP
        == parsed_group,
        "known_provenance_examples_match": provenance_matches,
        "invalid_provenance_is_rejected": invalid_provenance_rejected,
        "smoke_n_baiot_records_are_115_width": len(smoke_n_rows) == 9
        and all(row["feature_count"] == 115 for row in smoke_n_rows),
        "bot_iot_has_46_ordered_fields": len(bot_columns) == 46,
        "bot_iot_schema_signature_matches": ordered_schema_signature(bot_columns)
        == EXPECTED_BOT_SCHEMA,
        "port_parser_matches_independent_examples": parser_ports == independent_ports,
        "invalid_port_is_rejected": invalid_port_rejected,
        "smoke_bot_records_are_46_width": len(smoke_bot_rows) == 6
        and all(row["observed_column_count"] == 46 for row in smoke_bot_rows),
        "smoke_status_is_pass": smoke.get("overall_status") == "PASS",
        "smoke_is_deterministic": (
            smoke["determinism"]["n_baiot_first_records_identical_on_repeat"]
            and smoke["determinism"]["bot_iot_first_records_identical_on_repeat"]
            and not smoke["determinism"]["timestamp_or_randomness_in_canonical_records"]
        ),
        "smoke_source_metadata_unchanged": smoke["source_safety"][
            "selected_file_metadata_unchanged"
        ],
        "all_source_metadata_matches_manifests": all(source_metadata.values()),
        "source_tree_metadata_digests_unchanged_from_a5": source_snapshot_digests_match,
        "no_fitted_model_preprocessor_or_split_outputs": no_forbidden_outputs(),
        "no_forbidden_execution_in_smoke": all(
            count == 0 for count in smoke["execution_counts"].values()
        ),
    }
    return {
        "audit_batch": "G2B independent deterministic preprocessing verification",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "verification_independence": (
            "The verifier recomputes G2A hashes and schema signatures, exact-vector bytes, "
            "port semantics, manifest/source metadata, smoke widths, and forbidden-output "
            "boundaries independently; parser calls are compared with independent expectations."
        ),
        "checks": checks,
        "recomputed": {
            "n_baiot_feature_count": len(n_names),
            "n_baiot_schema_signature": ordered_schema_signature(n_names),
            "synthetic_group_id": independent_group,
            "bot_iot_column_count": len(bot_columns),
            "bot_iot_schema_signature": ordered_schema_signature(bot_columns),
            "source_metadata_matches": source_metadata,
            "source_tree_metadata": current_source_snapshots,
        },
        "overall_status": "PASS" if all(checks.values()) else "FAIL",
    }


def main() -> int:
    payload = verify()
    write_json_atomic(OUTPUT, payload)
    print(f"Wrote: {OUTPUT}")
    print(f"Overall status: {payload['overall_status']}")
    return 0 if payload["overall_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
