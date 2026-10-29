"""Generate compact G2A canonical data and feature contracts from A2-A7 evidence."""

# ruff: noqa: E501

from __future__ import annotations

import csv
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = PROJECT_ROOT / "artifacts" / "audit"
MANIFEST_DIR = PROJECT_ROOT / "artifacts" / "manifests"
CONTRACT_DIR = PROJECT_ROOT / "artifacts" / "contracts"
DOCS_DIR = PROJECT_ROOT / "docs" / "contracts"
A7_COMMIT_SHA = "3219aae72391115cc24bcd7da930f32c1f118438"
CONTRACT_VERSION = "1.0.0"
TARGET_FIELDS = ("attack", "category", "subcategory")
TEMPORAL_FIELDS = ("stime", "ltime", "seq")
ENTITY_CONTEXT_FIELDS = ("saddr", "sport", "daddr", "dport")
FORBIDDEN_CONTRACT_KEYS = {"final_split", "final_predictors", "model", "scaler"}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


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


def write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8", newline="\n")
    temporary.replace(path)


def ordered_schema_signature(names: Sequence[str]) -> str:
    serialized = json.dumps(list(names), ensure_ascii=False, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(serialized.encode('utf-8')).hexdigest()}"


def validate_contract_version(version: str) -> str:
    if not re.fullmatch(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)", version):
        raise ValueError("contract version must be an explicit semantic version")
    return version


def encode_exact_vector_tokens(values: Sequence[str], *, expected_count: int = 115) -> bytes:
    if len(values) != expected_count:
        raise ValueError(f"expected {expected_count} exact source tokens, received {len(values)}")
    serialized = bytearray()
    for value in values:
        if not isinstance(value, str):
            raise TypeError("exact-vector hashing requires original source lexical strings")
        encoded = value.encode("utf-8")
        serialized.extend(len(encoded).to_bytes(4, "big"))
        serialized.extend(encoded)
    return bytes(serialized)


def exact_vector_group_id(values: Sequence[str], *, expected_count: int = 115) -> str:
    raw = encode_exact_vector_tokens(values, expected_count=expected_count)
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def parse_bot_iot_port_token(token: str) -> dict[str, Any]:
    if token != token.strip() or not token:
        raise ValueError("port token must be a non-empty unpadded source lexeme")
    if token == "-1":
        return {"raw": token, "kind": "unresolved_sentinel", "value": None}
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", token):
        value = int(token, 16)
        kind = "hexadecimal_integer"
    elif re.fullmatch(r"\d+", token):
        value = int(token, 10)
        kind = "decimal_integer"
    else:
        raise ValueError(f"unsupported port token: {token!r}")
    if not 0 <= value <= 65535:
        raise ValueError(f"port value outside 0..65535: {token!r}")
    return {"raw": token, "kind": kind, "value": value}


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


def ensure_g2a_scope(payload: Mapping[str, Any]) -> None:
    forbidden = recursive_keys(payload) & FORBIDDEN_CONTRACT_KEYS
    if forbidden:
        raise ValueError(f"G2A contract contains forbidden downstream keys: {sorted(forbidden)}")


def ensure_predictor_boundary(
    candidate_predictors: Sequence[str], labels: Sequence[str], provenance: Sequence[str]
) -> None:
    overlap = set(candidate_predictors) & (set(labels) | set(provenance))
    if overlap:
        raise ValueError(f"labels/provenance cannot enter candidate predictors: {sorted(overlap)}")


def find_schema(schema: Mapping[str, Any], column_count: int) -> dict[str, Any]:
    matches = [item for item in schema["schemas"] if item["column_count"] == column_count]
    if len(matches) != 1:
        raise ValueError(f"expected one {column_count}-column schema, found {len(matches)}")
    return dict(matches[0])


def source_hashes() -> dict[str, str]:
    paths = (
        "artifacts/audit/n_baiot_schema.json",
        "artifacts/audit/bot_iot_schema.json",
        "artifacts/audit/label_audit_summary.json",
        "artifacts/audit/a4_audit_summary.json",
        "artifacts/audit/bot_iot_field_risk_profile.csv",
        "artifacts/audit/bot_iot_port_encoding_summary.json",
        "artifacts/audit/a7_dataset_role_decision.json",
        "artifacts/manifests/n_baiot_raw_manifest.csv",
        "artifacts/manifests/n_baiot_extracted_manifest.csv",
        "artifacts/manifests/bot_iot_raw_manifest.csv",
        "docs/decisions/ADR-001-dataset-role-selection.md",
    )
    return {path: sha256_file(PROJECT_ROOT / path) for path in paths}


def build_primary_feature_contract(
    n_schema: Mapping[str, Any], hashes: Mapping[str, str]
) -> dict[str, Any]:
    schema = dict(n_schema["schemas"][0])
    names = list(schema["ordered_columns"])
    signature = ordered_schema_signature(names)
    if len(names) != 115 or signature != schema["schema_signature"]:
        raise ValueError("A2 N-BaIoT schema cannot be reconciled with the G2A contract")
    labels = ("target_binary", "label_family", "label_fine")
    provenance = (
        "device",
        "source_logical_id",
        "archive_or_source_family",
        "source_member_filename",
        "duplicate_group_id",
    )
    ensure_predictor_boundary(names, labels, provenance)
    contract = {
        "contract_name": "n_baiot_feature_contract",
        "contract_version": validate_contract_version(CONTRACT_VERSION),
        "dataset": "N-BaIoT",
        "role": "primary",
        "feature_count": len(names),
        "ordered_feature_names": names,
        "ordered_feature_schema_sha256": signature,
        "source_schema_artifact": "artifacts/audit/n_baiot_schema.json",
        "source_schema_artifact_sha256": hashes["artifacts/audit/n_baiot_schema.json"],
        "raw_manifest_sha256": hashes["artifacts/manifests/n_baiot_raw_manifest.csv"],
        "extracted_manifest_sha256": hashes[
            "artifacts/manifests/n_baiot_extracted_manifest.csv"
        ],
        "candidate_feature_set_status": (
            "all 115 audited source fields; no learned or target-dependent selection performed"
        ),
        "numeric_parse_contract": {
            "source_lexeme": "strict numeric parse from the source CSV field",
            "required_value_count": 115,
            "negative_values": "allowed; covariance and PCC fields legitimately contain negatives",
            "hard_min_max_bounds": "none; observed extrema are not validation limits",
            "source_audit_precision": "source lexical token retained for exact-equality metadata",
            "future_model_dtype": "deferred",
        },
        "finite_value_requirement": True,
        "label_source": "verified logical-file provenance; labels are not predictor columns",
        "label_taxonomy_version": "n_baiot_label_contract_v1@1.0.0",
        "duplicate_group_definition": {
            "metadata_field": "duplicate_group_id",
            "predictor_eligible": False,
            "equality_basis": "exact ordered source lexical tuple across all 115 fields",
            "serialization": (
                "for each UTF-8 source token in source order, append a four-byte unsigned "
                "big-endian byte length followed by the exact bytes"
            ),
            "hash_algorithm": "SHA-256",
            "identifier_format": "sha256:<lowercase hexadecimal digest>",
            "lossy_numeric_reformatting": "prohibited",
            "collision_policy": (
                "a digest is a candidate group identifier; exact serialized bytes remain the "
                "equality authority when collision confirmation is required"
            ),
            "source_method": "A4/A5 encode_exact_row semantics",
        },
        "source_provenance_requirements": [
            "preserve device",
            "preserve source logical identity",
            "preserve archive/source family and member filename",
            "preserve manifest and schema artifact hashes",
            "keep raw and extracted sources read-only",
        ],
        "policy_boundaries": {
            "global_deduplication": "not adopted",
            "naive_row_random_evaluation": "prohibited without duplicate-boundary control",
            "exact_vector_boundary_check": "required for every future split",
            "duplicate_weighting": "deferred",
            "data_dependent_transforms": "fit on training data only after G3 locks the split",
            "data_dependent_transform_examples": [
                "StandardScaler",
                "MinMaxScaler",
                "PCA",
                "learned imputation",
                "target-dependent feature selection",
            ],
            "resampling_before_split": "prohibited",
            "imbalance_treatment": "deferred; training partition only if later selected",
            "validation_test_distribution": "preserve the audited natural distribution",
            "evaluation_support_counts": "required",
        },
        "prohibited_operations_in_g2a": [
            "feature selection",
            "scaler fitting",
            "resampling",
            "source deduplication",
            "split materialization",
            "model training",
        ],
    }
    ensure_g2a_scope(contract)
    return contract


def build_primary_label_contract(
    labels: Mapping[str, Any], hashes: Mapping[str, str]
) -> dict[str, Any]:
    n_labels = labels["n_baiot"]
    contract = {
        "contract_name": "n_baiot_label_contract",
        "contract_version": CONTRACT_VERSION,
        "dataset": "N-BaIoT",
        "role": "primary",
        "label_source": "verified file and archive-member provenance",
        "source_artifact": "artifacts/audit/label_audit_summary.json",
        "source_artifact_sha256": hashes["artifacts/audit/label_audit_summary.json"],
        "levels": {
            "binary": list(n_labels["binary_distribution"]),
            "family": list(n_labels["family_distribution"]),
            "fine": list(n_labels["fine_class_distribution"]),
        },
        "core_supervised_target": {
            "level": "binary",
            "values": ["benign", "malicious"],
        },
        "preserved_analysis_labels": ["family", "fine"],
        "predictor_eligible": False,
        "mapping_mutability": "immutable within v1; changes require a new contract version",
    }
    validate_contract_version(contract["contract_version"])
    ensure_g2a_scope(contract)
    return contract


def build_primary_record_contract() -> dict[str, Any]:
    contract = {
        "contract_name": "n_baiot_record_contract",
        "contract_version": CONTRACT_VERSION,
        "dataset": "N-BaIoT",
        "role": "primary",
        "contract_scope": "internal data/ML logical record; not the FastAPI payload",
        "fields": [
            {
                "name": "features",
                "role": "canonical_candidate_features",
                "type": "ordered finite numeric vector",
                "cardinality": 115,
                "contract_ref": "n_baiot_feature_contract_v1.json",
            },
            {"name": "target_binary", "role": "target_metadata", "predictor_eligible": False},
            {"name": "label_family", "role": "analysis_label", "predictor_eligible": False},
            {"name": "label_fine", "role": "analysis_label", "predictor_eligible": False},
            {"name": "device", "role": "provenance_split_metadata", "predictor_eligible": False},
            {
                "name": "source_logical_id",
                "role": "provenance_split_metadata",
                "predictor_eligible": False,
            },
            {
                "name": "archive_or_source_family",
                "role": "provenance_split_metadata",
                "predictor_eligible": False,
            },
            {
                "name": "source_member_filename",
                "role": "provenance_split_metadata",
                "predictor_eligible": False,
            },
            {
                "name": "duplicate_group_id",
                "role": "split_audit_metadata",
                "predictor_eligible": False,
            },
        ],
        "predictor_boundary": (
            "only the ordered features vector is the canonical candidate set; labels and "
            "provenance/split metadata are never predictors"
        ),
        "api_payload_status": "deferred; this internal record is not an inference API design",
    }
    validate_contract_version(contract["contract_version"])
    ensure_g2a_scope(contract)
    return contract


def build_bot_source_contract(
    bot_schema: Mapping[str, Any],
    hashes: Mapping[str, str],
    a7_cross_policy: Mapping[str, Any],
) -> dict[str, Any]:
    schema = find_schema(bot_schema, 46)
    logical_prefix = "bot_iot:all_features_5pct_shards:"
    files = [
        value.removeprefix(logical_prefix)
        for value in schema["logical_files"]
        if value.startswith(logical_prefix)
    ]
    if len(files) != 4:
        raise ValueError("Bot-IoT canonical representation must contain exactly four shards")
    contract = {
        "contract_name": "bot_iot_secondary_source_contract",
        "contract_version": CONTRACT_VERSION,
        "dataset": "Bot-IoT",
        "role": "secondary",
        "canonical_representation": "all_features_5pct_shards",
        "canonical_source_files": files,
        "observed_column_count": schema["column_count"],
        "ordered_source_columns": list(schema["ordered_columns"]),
        "ordered_schema_sha256": schema["schema_signature"],
        "source_schema_artifact": "artifacts/audit/bot_iot_schema.json",
        "source_schema_artifact_sha256": hashes["artifacts/audit/bot_iot_schema.json"],
        "raw_manifest_sha256": hashes["artifacts/manifests/bot_iot_raw_manifest.csv"],
        "representation_policy": {
            "ten_best_full": "DERIVED_REFERENCE_REPRESENTATION",
            "supplied_ten_best_train_test": "DERIVED_REFERENCE_SPLIT",
            "supplied_split_adopted": False,
            "mix_representations_silently": False,
        },
        "cross_dataset_policy": {
            "direct_matrix_merge": "prohibited in the core pipeline",
            "exact_named_feature_overlap_count": a7_cross_policy[
                "exact_named_feature_overlap_count"
            ],
            "input_spaces_interchangeable": False,
            "direct_cross_dataset_evaluation": a7_cross_policy[
                "direct_cross_dataset_model_evaluation"
            ],
        },
    }
    validate_contract_version(contract["contract_version"])
    ensure_g2a_scope(contract)
    return contract


def build_bot_field_role_contract(
    source_contract: Mapping[str, Any],
    risk_rows: Sequence[Mapping[str, str]],
    port_summary: Mapping[str, Any],
    hashes: Mapping[str, str],
) -> dict[str, Any]:
    columns = list(source_contract["ordered_source_columns"])
    risk_by_name = {row["field_name"]: row for row in risk_rows if row["observed_in"] == "all_features"}
    if set(columns) != set(risk_by_name):
        raise ValueError("A5 Bot-IoT risk profile does not cover the canonical 46-column schema")
    roles = []
    for name in columns:
        if name in TARGET_FIELDS:
            role = "target_metadata"
            eligibility = "prohibited"
        elif name == "pkSeqID":
            role = "identifier_lineage_metadata"
            eligibility = "prohibited"
        elif name in TEMPORAL_FIELDS:
            role = "temporal_order_sensitive"
            eligibility = "deferred"
        elif name in ENTITY_CONTEXT_FIELDS:
            role = "entity_context_sensitive"
            eligibility = "deferred"
        else:
            role = "behavioral_statistical_candidate"
            eligibility = "candidate_not_selected"
        roles.append(
            {
                "field_name": name,
                "contract_role": role,
                "ordinary_predictor_eligibility": eligibility,
                "a5_audit_role": risk_by_name[name]["audit_role"],
                "a5_risk_terminology": risk_by_name[name]["risk_terminology"],
            }
        )
    contract = {
        "contract_name": "bot_iot_field_role_contract",
        "contract_version": CONTRACT_VERSION,
        "dataset": "Bot-IoT",
        "role": "secondary",
        "canonical_representation": source_contract["canonical_representation"],
        "field_roles": roles,
        "target_metadata": list(TARGET_FIELDS),
        "identifier_lineage_metadata": ["pkSeqID"],
        "reference_only_physical_index": {
            "field": "<unnamed_leading_index>",
            "representation": "ten_best_full",
            "ordinary_predictor_eligibility": "prohibited",
        },
        "temporal_order_sensitive": list(TEMPORAL_FIELDS),
        "entity_context_sensitive": list(ENTITY_CONTEXT_FIELDS),
        "context_field_decision": "deferred to secondary experiment design",
        "port_lexical_contract": {
            "fields": ["sport", "dport"],
            "preserve_raw_lexeme": True,
            "decimal": "ASCII digits parsed in base 10",
            "hexadecimal": "0x/0X-prefixed hexadecimal digits parsed in base 16",
            "unresolved_sentinel": "-1",
            "sentinel_semantics": "UNKNOWN; do not treat as an ordinary port or impute in G2A",
            "verified_hex_lossless": (
                port_summary["sport"]["hexadecimal_parses_losslessly_as_base16"]
                and port_summary["dport"]["hexadecimal_parses_losslessly_as_base16"]
            ),
            "implementation_status": "specified and unit-tested; no full dataset transformation",
        },
        "source_artifacts": {
            "risk_profile": "artifacts/audit/bot_iot_field_risk_profile.csv",
            "risk_profile_sha256": hashes[
                "artifacts/audit/bot_iot_field_risk_profile.csv"
            ],
            "port_summary": "artifacts/audit/bot_iot_port_encoding_summary.json",
            "port_summary_sha256": hashes[
                "artifacts/audit/bot_iot_port_encoding_summary.json"
            ],
        },
    }
    validate_contract_version(contract["contract_version"])
    ensure_g2a_scope(contract)
    return contract


def render_primary_doc(
    feature: Mapping[str, Any], label: Mapping[str, Any], record: Mapping[str, Any]
) -> str:
    return "\n".join(
        [
            "# Primary N-BaIoT data contract v1",
            "",
            "> G2A specification only. No split, fitted transform, resampling, or model exists.",
            "",
            "## Canonical representation",
            "",
            f"The primary universe contains 89 logical CSVs and uses {feature['feature_count']} source fields in the exact A2 order. The schema signature is `{feature['ordered_feature_schema_sha256']}`. Source feature names are not renamed or sorted.",
            "",
            "Every record must contain exactly 115 finite numeric values. Negative values are allowed. Observed extrema are descriptive, not hard validation bounds, and deployment dtype remains deferred.",
            "",
            "## Labels and predictor boundary",
            "",
            f"The core target is `{label['core_supervised_target']['level']}` with values `benign` and `malicious`. Family and fine labels remain analysis metadata. Labels, device, logical source identity, filenames, and `duplicate_group_id` are not predictors. All 115 source fields are only the canonical candidate set; no learned feature selection has run.",
            "",
            "## Exact-vector group metadata",
            "",
            "`duplicate_group_id` is SHA-256 over the A4/A5 length-prefixed UTF-8 serialization of the exact 115 source lexemes in source order. Lossy float formatting is prohibited. The identifier is split/audit metadata and does not deduplicate the corpus.",
            "",
            "## Downstream boundaries",
            "",
            "- No blind global deduplication.",
            "- No naive row-random evaluation without duplicate-boundary control.",
            "- Data-dependent transforms fit on training data only after G3 locks the split.",
            "- Resampling or class weighting, if later selected, operates on training data only.",
            "- Validation and test retain their audited natural distribution and support counts.",
            "- The logical record contract is internal and is not the final FastAPI payload.",
            "",
            "## Logical record",
            "",
            "The internal record contains `features`, `target_binary`, `label_family`, `label_fine`, `device`, `source_logical_id`, archive/source family, source/member filename, and `duplicate_group_id`. Only `features` is the candidate predictor container.",
            "",
            f"Record contract version: `{record['contract_version']}`.",
        ]
    ) + "\n"


def render_secondary_doc(
    source: Mapping[str, Any], fields: Mapping[str, Any]
) -> str:
    files = "\n".join(f"- `{path}`" for path in source["canonical_source_files"])
    return "\n".join(
        [
            "# Secondary Bot-IoT data contract v1",
            "",
            "> G2A specification only. No secondary experiment, split, transform, or model is selected.",
            "",
            "## Canonical source representation",
            "",
            "The canonical secondary representation is the audited four-shard All-features 5% source with one ordered 46-column schema:",
            "",
            files,
            "",
            "The 10-best full file is a derived reference representation. Supplied 10-best train/test files are a derived reference split and are not an adopted evaluation split. Representations must not be mixed silently.",
            "",
            "## Field boundaries",
            "",
            "- `attack`, `category`, and `subcategory`: target metadata; prohibited as ordinary predictors.",
            "- `pkSeqID`: identifier/lineage metadata; prohibited as an ordinary predictor.",
            "- The unnamed 10-best physical index: reference-only identifier metadata.",
            "- `stime`, `ltime`, and `seq`: temporal/order-sensitive; eligibility deferred.",
            "- Addresses and ports: entity/context-sensitive; eligibility deferred.",
            "- Remaining traffic-derived fields: behavioral/statistical candidates, not a selected predictor set.",
            "",
            "## Port lexical contract",
            "",
            f"Raw `sport` and `dport` lexemes are preserved. Decimal strings use base 10; `0x`-prefixed strings use base 16. `{fields['port_lexical_contract']['unresolved_sentinel']}` remains an unresolved sentinel and is neither an ordinary port nor imputed in G2A.",
            "",
            "## Cross-dataset boundary",
            "",
            "Direct feature-matrix merging is prohibited in the core pipeline. N-BaIoT and Bot-IoT input spaces are not interchangeable, and direct cross-dataset evaluation remains `NOT_CURRENTLY_DEFENSIBLE`.",
        ]
    ) + "\n"


def main() -> int:
    required = (
        AUDIT_DIR / "n_baiot_schema.json",
        AUDIT_DIR / "bot_iot_schema.json",
        AUDIT_DIR / "label_audit_summary.json",
        AUDIT_DIR / "a4_audit_summary.json",
        AUDIT_DIR / "bot_iot_field_risk_profile.csv",
        AUDIT_DIR / "bot_iot_port_encoding_summary.json",
        AUDIT_DIR / "a7_dataset_role_decision.json",
        MANIFEST_DIR / "n_baiot_raw_manifest.csv",
        MANIFEST_DIR / "n_baiot_extracted_manifest.csv",
        MANIFEST_DIR / "bot_iot_raw_manifest.csv",
        PROJECT_ROOT / "docs" / "decisions" / "ADR-001-dataset-role-selection.md",
    )
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"missing compact G2A source evidence: {missing}")

    hashes = source_hashes()
    n_schema = load_json(AUDIT_DIR / "n_baiot_schema.json")
    bot_schema = load_json(AUDIT_DIR / "bot_iot_schema.json")
    labels = load_json(AUDIT_DIR / "label_audit_summary.json")
    risk_rows = load_csv(AUDIT_DIR / "bot_iot_field_risk_profile.csv")
    port_summary = load_json(AUDIT_DIR / "bot_iot_port_encoding_summary.json")
    a7 = load_json(AUDIT_DIR / "a7_dataset_role_decision.json")
    if (
        a7.get("primary_dataset") != "N-BaIoT"
        or a7.get("secondary_dataset") != "Bot-IoT"
        or a7.get("decision_status") != "ACCEPTED"
    ):
        raise ValueError("accepted A7 roles are not available")

    feature = build_primary_feature_contract(n_schema, hashes)
    label = build_primary_label_contract(labels, hashes)
    record = build_primary_record_contract()
    bot_source = build_bot_source_contract(bot_schema, hashes, a7["cross_dataset_policy"])
    bot_fields = build_bot_field_role_contract(
        bot_source, risk_rows, port_summary, hashes
    )

    outputs = {
        CONTRACT_DIR / "n_baiot_feature_contract_v1.json": feature,
        CONTRACT_DIR / "n_baiot_label_contract_v1.json": label,
        CONTRACT_DIR / "n_baiot_record_contract_v1.json": record,
        CONTRACT_DIR / "bot_iot_secondary_source_contract_v1.json": bot_source,
        CONTRACT_DIR / "bot_iot_field_role_contract_v1.json": bot_fields,
    }
    for path, payload in outputs.items():
        write_json_atomic(path, payload)

    primary_doc = DOCS_DIR / "primary_data_contract.md"
    secondary_doc = DOCS_DIR / "secondary_data_contract.md"
    write_text_atomic(primary_doc, render_primary_doc(feature, label, record))
    write_text_atomic(secondary_doc, render_secondary_doc(bot_source, bot_fields))

    hashed_outputs = [*outputs, primary_doc, secondary_doc]
    manifest = {
        "contract_set": "IoTGuard G2A canonical data contracts",
        "contract_set_version": CONTRACT_VERSION,
        "gate": "G2A",
        "status": "SPECIFIED",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "a7_checkpoint_commit": A7_COMMIT_SHA,
        "artifact_sha256": {
            path.relative_to(PROJECT_ROOT).as_posix(): sha256_file(path)
            for path in hashed_outputs
        },
        "source_evidence_sha256": hashes,
        "versioning_policy": {
            "scheme": "semantic versioning",
            "version_change_required_for": [
                "ordered predictor candidate fields",
                "feature semantics",
                "label mapping",
                "numeric parsing semantics",
                "canonical secondary representation",
                "duplicate-group equality semantics",
            ],
            "compatibility_breaking_change": "increment the major version",
            "immutability": "published v1 artifacts are never silently altered",
        },
        "execution_counts": {
            "source_rows_read": 0,
            "rows_transformed": 0,
            "training_runs": 0,
            "clustering_runs": 0,
            "split_files_written": 0,
            "resampling_runs": 0,
        },
        "deferred": [
            "evaluation split",
            "fitted transforms and feature selectors",
            "duplicate weighting",
            "imbalance policy",
            "processed Assignment-2 submission data",
            "inference API payload",
            "Raspberry Pi benchmark",
        ],
    }
    ensure_g2a_scope(manifest)
    write_json_atomic(CONTRACT_DIR / "g2a_contract_manifest.json", manifest)
    print(f"Wrote G2A contracts to: {CONTRACT_DIR}")
    print(f"Wrote G2A documentation to: {DOCS_DIR}")
    print(f"N-BaIoT schema: {feature['ordered_feature_schema_sha256']}")
    print("Rows read: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
