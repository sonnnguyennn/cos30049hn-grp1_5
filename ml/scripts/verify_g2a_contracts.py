"""Independently verify G2A contracts against compact A2-A7 evidence."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = PROJECT_ROOT / "artifacts" / "audit"
CONTRACT_DIR = PROJECT_ROOT / "artifacts" / "contracts"
DOCS_DIR = PROJECT_ROOT / "docs" / "contracts"
FORBIDDEN_KEYS = {"final_split", "final_predictors", "model", "scaler"}
EXPECTED_BINARY = ["benign", "malicious"]
EXPECTED_FAMILY = ["benign", "gafgyt", "mirai"]
EXPECTED_FINE = [
    "benign",
    "gafgyt_combo",
    "gafgyt_junk",
    "gafgyt_scan",
    "gafgyt_tcp",
    "gafgyt_udp",
    "mirai_ack",
    "mirai_scan",
    "mirai_syn",
    "mirai_udp",
    "mirai_udpplain",
]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    temporary.replace(path)


def ordered_schema_signature(names: Sequence[str]) -> str:
    serialized = json.dumps(list(names), ensure_ascii=False, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(serialized.encode('utf-8')).hexdigest()}"


def recursive_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            keys.add(str(key).lower())
            keys.update(recursive_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(recursive_keys(child))
    return keys


def independent_group_id(values: Sequence[str]) -> str:
    serialized = bytearray()
    for value in values:
        encoded = value.encode("utf-8")
        serialized.extend(len(encoded).to_bytes(4, "big"))
        serialized.extend(encoded)
    return f"sha256:{hashlib.sha256(bytes(serialized)).hexdigest()}"


def independent_port_parse(token: str) -> tuple[str, int | None]:
    if token == "-1":
        return "unresolved_sentinel", None
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", token):
        value = int(token, 16)
        kind = "hexadecimal_integer"
    elif re.fullmatch(r"\d+", token):
        value = int(token, 10)
        kind = "decimal_integer"
    else:
        raise ValueError(token)
    if not 0 <= value <= 65535:
        raise ValueError(token)
    return kind, value


def find_schema(schema: Mapping[str, Any], count: int) -> Mapping[str, Any]:
    matches = [item for item in schema["schemas"] if item["column_count"] == count]
    if len(matches) != 1:
        raise ValueError(f"expected one {count}-column schema")
    return matches[0]


def main() -> int:
    contract_names = (
        "n_baiot_feature_contract_v1.json",
        "n_baiot_label_contract_v1.json",
        "n_baiot_record_contract_v1.json",
        "bot_iot_secondary_source_contract_v1.json",
        "bot_iot_field_role_contract_v1.json",
        "g2a_contract_manifest.json",
    )
    required = [CONTRACT_DIR / name for name in contract_names] + [
        DOCS_DIR / "primary_data_contract.md",
        DOCS_DIR / "secondary_data_contract.md",
        AUDIT_DIR / "n_baiot_schema.json",
        AUDIT_DIR / "bot_iot_schema.json",
        AUDIT_DIR / "label_audit_summary.json",
        AUDIT_DIR / "a7_dataset_role_decision.json",
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"missing G2A verification inputs: {missing}")

    feature = load_json(CONTRACT_DIR / contract_names[0])
    label = load_json(CONTRACT_DIR / contract_names[1])
    record = load_json(CONTRACT_DIR / contract_names[2])
    bot_source = load_json(CONTRACT_DIR / contract_names[3])
    bot_fields = load_json(CONTRACT_DIR / contract_names[4])
    manifest = load_json(CONTRACT_DIR / contract_names[5])
    n_schema = load_json(AUDIT_DIR / "n_baiot_schema.json")
    bot_schema = load_json(AUDIT_DIR / "bot_iot_schema.json")
    labels = load_json(AUDIT_DIR / "label_audit_summary.json")
    a7 = load_json(AUDIT_DIR / "a7_dataset_role_decision.json")

    n_a2 = n_schema["schemas"][0]
    bot_a2 = find_schema(bot_schema, 46)
    ordered_names = feature["ordered_feature_names"]
    record_fields = {item["name"]: item for item in record["fields"]}
    field_roles = {item["field_name"]: item for item in bot_fields["field_roles"]}
    expected_bot_files = [
        logical.removeprefix("bot_iot:all_features_5pct_shards:")
        for logical in bot_a2["logical_files"]
    ]
    contract_payloads = [feature, label, record, bot_source, bot_fields, manifest]

    labels_from_a3 = labels["n_baiot"]
    taxonomy_matches = (
        label["levels"]["binary"] == list(labels_from_a3["binary_distribution"])
        == EXPECTED_BINARY
        and label["levels"]["family"] == list(labels_from_a3["family_distribution"])
        == EXPECTED_FAMILY
        and label["levels"]["fine"] == list(labels_from_a3["fine_class_distribution"])
        == EXPECTED_FINE
    )

    artifact_hashes_match = all(
        (PROJECT_ROOT / relative).is_file()
        and sha256_file(PROJECT_ROOT / relative) == expected
        for relative, expected in manifest["artifact_sha256"].items()
    )
    source_hashes_match = all(
        (PROJECT_ROOT / relative).is_file()
        and sha256_file(PROJECT_ROOT / relative) == expected
        for relative, expected in manifest["source_evidence_sha256"].items()
    )

    base_vector = [str(index) for index in range(115)]
    changed_vector = list(base_vector)
    changed_vector[57] = "57.0"
    group_id_a = independent_group_id(base_vector)
    group_id_b = independent_group_id(list(base_vector))
    group_id_changed = independent_group_id(changed_vector)

    execution = manifest["execution_counts"]
    target_and_identifier_roles = (
        all(
            field_roles[name]["ordinary_predictor_eligibility"] == "prohibited"
            for name in ("attack", "category", "subcategory", "pkSeqID")
        )
        and bot_fields["reference_only_physical_index"][
            "ordinary_predictor_eligibility"
        ]
        == "prohibited"
    )

    checks = {
        "primary_role_matches_a7": (
            a7["primary_dataset"] == "N-BaIoT"
            and feature["dataset"] == "N-BaIoT"
            and feature["role"] == "primary"
        ),
        "n_baiot_exactly_115_ordered_fields": (
            feature["feature_count"] == 115
            and len(ordered_names) == 115
            and ordered_names == n_a2["ordered_columns"]
        ),
        "n_baiot_schema_signature_matches_a2": (
            ordered_schema_signature(ordered_names)
            == feature["ordered_feature_schema_sha256"]
            == n_a2["schema_signature"]
        ),
        "n_baiot_taxonomy_matches_a3": taxonomy_matches,
        "binary_target_is_benign_malicious": (
            label["core_supervised_target"]["values"] == EXPECTED_BINARY
        ),
        "labels_and_provenance_not_predictors": all(
            record_fields[name].get("predictor_eligible") is False
            for name in (
                "target_binary",
                "label_family",
                "label_fine",
                "device",
                "source_logical_id",
                "archive_or_source_family",
                "source_member_filename",
                "duplicate_group_id",
            )
        ),
        "duplicate_group_id_is_split_audit_metadata": (
            record_fields["duplicate_group_id"]["role"] == "split_audit_metadata"
            and feature["duplicate_group_definition"]["predictor_eligible"] is False
        ),
        "exact_group_id_is_deterministic_and_sensitive": (
            group_id_a == group_id_b and group_id_a != group_id_changed
        ),
        "no_global_deduplication_decision": (
            feature["policy_boundaries"]["global_deduplication"] == "not adopted"
        ),
        "no_downstream_contract_keys": not any(
            recursive_keys(payload) & FORBIDDEN_KEYS for payload in contract_payloads
        ),
        "no_transform_split_resampling_execution": all(value == 0 for value in execution.values()),
        "bot_secondary_role_matches_a7": (
            a7["secondary_dataset"] == "Bot-IoT"
            and bot_source["role"] == "secondary"
        ),
        "bot_canonical_source_is_four_all_feature_shards": (
            bot_source["canonical_representation"] == "all_features_5pct_shards"
            and bot_source["canonical_source_files"] == expected_bot_files
            and len(expected_bot_files) == 4
        ),
        "bot_source_schema_is_46_columns": (
            bot_source["observed_column_count"] == 46
            and bot_source["ordered_source_columns"] == bot_a2["ordered_columns"]
            and bot_source["ordered_schema_sha256"] == bot_a2["schema_signature"]
        ),
        "bot_target_and_identifier_fields_prohibited": target_and_identifier_roles,
        "ten_best_is_derived_reference_not_canonical": (
            bot_source["representation_policy"]["ten_best_full"]
            == "DERIVED_REFERENCE_REPRESENTATION"
            and bot_source["representation_policy"]["supplied_ten_best_train_test"]
            == "DERIVED_REFERENCE_SPLIT"
            and bot_source["representation_policy"]["supplied_split_adopted"] is False
        ),
        "bot_port_contract_preserves_unresolved_sentinel": (
            bot_fields["port_lexical_contract"]["preserve_raw_lexeme"] is True
            and bot_fields["port_lexical_contract"]["unresolved_sentinel"] == "-1"
            and independent_port_parse("80") == ("decimal_integer", 80)
            and independent_port_parse("0x1F90") == ("hexadecimal_integer", 8080)
            and independent_port_parse("-1") == ("unresolved_sentinel", None)
        ),
        "cross_dataset_direct_merge_prohibited": (
            bot_source["cross_dataset_policy"]["direct_matrix_merge"]
            == "prohibited in the core pipeline"
            and bot_source["cross_dataset_policy"]["exact_named_feature_overlap_count"] == 0
            and bot_source["cross_dataset_policy"]["input_spaces_interchangeable"] is False
            and bot_source["cross_dataset_policy"]["direct_cross_dataset_evaluation"]
            == "NOT_CURRENTLY_DEFENSIBLE"
        ),
        "contract_artifact_hashes_match_manifest": artifact_hashes_match,
        "source_evidence_hashes_match_manifest": source_hashes_match,
        "contract_versions_are_v1_semver": all(
            payload.get("contract_version") == "1.0.0"
            for payload in (feature, label, record, bot_source, bot_fields)
        ),
    }
    overall = all(checks.values())
    result = {
        "audit_batch": "G2A independent contract verification",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "overall_status": "PASS" if overall else "FAIL",
        "checks": checks,
        "recomputed": {
            "n_baiot_feature_count": len(ordered_names),
            "n_baiot_ordered_schema_sha256": ordered_schema_signature(ordered_names),
            "bot_iot_column_count": bot_source["observed_column_count"],
            "bot_iot_canonical_shard_count": len(bot_source["canonical_source_files"]),
            "synthetic_group_id": group_id_a,
        },
        "contract_manifest_sha256": sha256_file(
            CONTRACT_DIR / "g2a_contract_manifest.json"
        ),
        "verification_independence": (
            "This verifier does not import scripts/generate_g2a_contracts.py. It independently "
            "recomputes schema signatures, taxonomy equality, synthetic exact-vector IDs, port "
            "parsing examples, artifact hashes, and scope boundaries from compact evidence."
        ),
    }
    output = AUDIT_DIR / "g2a_evidence_verification.json"
    write_json_atomic(output, result)
    print(f"Wrote: {output}")
    print(f"Overall status: {result['overall_status']}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
