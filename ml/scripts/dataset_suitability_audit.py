"""Build the A6 cross-dataset suitability comparison from compact A0-A5 evidence.

A6 is synthesis only. It does not read raw datasets, train models, adopt a split,
select predictors, or assign primary/secondary dataset roles.
"""

# ruff: noqa: E501

from __future__ import annotations

import csv
import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = PROJECT_ROOT / "artifacts" / "audit"
DOC_PATH = PROJECT_ROOT / "docs" / "analysis" / "dataset_suitability_comparison.md"
A5_COMMIT_SHA = "483c8ace60ad91f75f724e53159b1b57ffc4a1f9"

SUITABILITY_STATUSES = {"FAVORABLE", "MIXED", "ADVERSE", "UNKNOWN / NOT YET MEASURED"}
REQUIREMENT_STATUSES = {"SUPPORTED", "PARTIALLY_SUPPORTED", "NOT_SUPPORTED", "UNKNOWN"}
CROSS_DATASET_STATUSES = {"FEASIBLE", "CONDITIONALLY_FEASIBLE", "NOT_CURRENTLY_DEFENSIBLE"}

SOURCE_FILES = (
    "source_inventory_summary.json",
    "structural_audit_summary.json",
    "n_baiot_schema.json",
    "bot_iot_schema.json",
    "label_audit_summary.json",
    "a4_audit_summary.json",
    "n_baiot_quality_summary.csv",
    "bot_iot_quality_summary.csv",
    "n_baiot_duplicate_summary.json",
    "bot_iot_duplicate_summary.json",
    "a5_audit_summary.json",
    "a5_evidence_verification.json",
    "n_baiot_effective_imbalance.csv",
    "n_baiot_split_leakage_summary.json",
    "n_baiot_device_holdout_matrix.csv",
    "bot_iot_effective_imbalance.csv",
    "bot_iot_field_risk_profile.csv",
    "bot_iot_entity_overlap_summary.json",
    "bot_iot_identity_free_duplicate_summary.json",
    "bot_iot_port_encoding_summary.json",
    "bot_iot_numeric_lineage_analysis.json",
    "bot_iot_split_feasibility.json",
    "candidate_split_comparison.csv",
)

EXPECTED_BOT_CLASSES = {
    "binary": ("benign", "malicious"),
    "category": ("ddos", "dos", "normal", "reconnaissance", "theft"),
    "subcategory": (
        "data_exfiltration",
        "http",
        "keylogging",
        "normal",
        "os_fingerprint",
        "service_scan",
        "tcp",
        "udp",
    ),
}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    temporary.replace(path)


def write_csv_atomic(
    path: Path, fieldnames: Sequence[str], rows: Iterable[Mapping[str, Any]]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="raise")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    temporary.replace(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def percentage(numerator: int | float, denominator: int | float) -> float:
    return 0.0 if denominator == 0 else 100.0 * float(numerator) / float(denominator)


def validate_status(value: str, allowed: set[str]) -> str:
    if value not in allowed:
        raise ValueError(f"unsupported status {value!r}; expected one of {sorted(allowed)}")
    return value


def missing_classes(expected: Sequence[str], observed: Mapping[str, Any]) -> list[str]:
    return sorted(set(expected) - set(observed))


def coverage_first(
    candidate: str,
    distributions: Mapping[str, Mapping[str, int]],
    expected: Mapping[str, Sequence[str]],
) -> dict[str, Any]:
    coverage: dict[str, Any] = {"candidate": candidate, "levels": {}}
    for level, expected_classes in expected.items():
        observed = distributions.get(level, {})
        missing = missing_classes(expected_classes, observed)
        coverage["levels"][level] = {
            "total_classes_expected": len(expected_classes),
            "classes_present_in_test": len(observed),
            "present_classes": sorted(observed),
            "missing_classes": missing,
            "minimum_support_among_represented_classes": min(observed.values(), default=0),
            "coverage_complete": not missing,
        }
    return coverage


def baseline_adjusted_purity(
    global_counts: Mapping[str, int], observed_purity_fraction: float
) -> dict[str, float]:
    total = sum(global_counts.values())
    baseline = max(global_counts.values(), default=0) / total if total else 0.0
    return {
        "global_majority_baseline_percent": 100.0 * baseline,
        "observed_weighted_purity_percent": 100.0 * observed_purity_fraction,
        "increase_over_baseline_percentage_points": 100.0
        * (observed_purity_fraction - baseline),
    }


def ordered_schema(schema: Mapping[str, Any], dataset: str) -> list[str]:
    if dataset == "n_baiot":
        return list(schema["schemas"][0]["ordered_columns"])
    return list(schema["documentation_cross_check"]["observed_all_features_names"])


def feature_overlap(
    n_schema: Mapping[str, Any], bot_schema: Mapping[str, Any]
) -> dict[str, Any]:
    n_fields = ordered_schema(n_schema, "n_baiot")
    bot_fields = ordered_schema(bot_schema, "bot_iot")
    exact = sorted(set(n_fields) & set(bot_fields))
    semantic = [
        {
            "concept": "summary location/dispersion statistics",
            "n_baiot_examples": ["MI_dir_L5_mean", "HH_L5_std", "MI_dir_L5_variance"],
            "bot_iot_examples": ["mean", "stddev", "min", "max"],
            "compatibility": (
                "conceptual only; entity/window conditioning and source definitions differ"
            ),
        },
        {
            "concept": "traffic activity/rate summaries",
            "n_baiot_examples": ["MI_dir_L5_weight", "HH_jit_L5_mean"],
            "bot_iot_examples": ["pkts", "bytes", "rate", "srate", "drate"],
            "compatibility": "conceptual only; audited artifacts do not establish equivalence",
        },
    ]
    return {
        "n_baiot_feature_count": len(n_fields),
        "bot_iot_all_features_observed_column_count": len(bot_fields),
        "exact_named_feature_overlap": exact,
        "exact_named_feature_overlap_count": len(exact),
        "meaningful_semantic_overlap": semantic,
    }


def binary_counts(distribution: Mapping[str, int]) -> dict[str, int]:
    benign = int(distribution.get("benign", 0))
    malicious = sum(int(value) for key, value in distribution.items() if key != "benign")
    return {"benign": benign, "malicious": malicious}


def build_protocols(
    n_split: Mapping[str, Any],
    device_rows: list[dict[str, str]],
    bot_split: Mapping[str, Any],
) -> dict[str, Any]:
    n2 = n_split["exact_feature_group_aware"]
    n2_coverage = coverage_first(
        "N2 exact-feature-group-aware",
        {"fine_class": n2["test_fine_distribution"]},
        {"fine_class": tuple(n_split["raw_fine_class_counts"])},
    )
    n3_rows = []
    n4_rows = []
    for row in device_rows:
        present = tuple(item for item in row["fine_coverage"].split("|") if item)
        coverage = {
            "total_classes_expected": len(n_split["raw_fine_class_counts"]),
            "classes_present_in_test": len(present),
            "present_classes": sorted(present),
            "missing_classes": sorted(set(n_split["raw_fine_class_counts"]) - set(present)),
            "coverage_complete": len(present) == len(n_split["raw_fine_class_counts"]),
        }
        n3_rows.append(
            {
                "device": row["device"],
                "generalization_claim": (
                    "held-out device identity, but not unseen exact feature vectors"
                ),
                "test_rows": int(row["test_rows"]),
                "test_rows_with_exact_train_vector_percent": float(
                    row["test_rows_with_exact_train_vector_percent"]
                ),
                "fine_class_coverage": coverage,
            }
        )
        n4_rows.append(
            {
                "device": row["device"],
                "generalization_claim": "held-out device plus exact-vector novelty",
                "test_rows": int(row["test_rows"]),
                "exact_feature_overlap_percent": 0.0,
                "training_rows_excluded": int(row["isolation_train_rows_affected"]),
                "training_rows_excluded_percent": float(
                    row["isolation_train_rows_affected_percent"]
                ),
                "fine_class_coverage": coverage,
            }
        )

    bot_candidates = {
        "B1 supplied train/test": bot_split["candidate_B1_supplied"]["class_distributions"][
            "test"
        ],
        "B2 random stratified record": bot_split["candidate_B2_random_stratified"][
            "test_distributions"
        ],
        "B3 chronological numeric-order": bot_split["candidate_B3_temporal"][
            "test_distributions"
        ],
        "B4 entity grouped by saddr": bot_split["candidate_B4_entity_grouped"]["saddr"][
            "test_distributions"
        ],
        "B4 entity grouped by saddr+daddr": bot_split["candidate_B4_entity_grouped"][
            "saddr+daddr"
        ]["test_distributions"],
    }
    bot_coverage = [
        coverage_first(name, distributions, EXPECTED_BOT_CLASSES)
        for name, distributions in bot_candidates.items()
    ]
    for item in bot_coverage:
        item["test_binary_counts"] = dict(bot_candidates[item["candidate"]]["binary"])

    return {
        "n_baiot": {
            "N2": {
                "generalization_claim": (
                    "unseen exact 115-feature vectors, not unseen devices or contexts"
                ),
                "train_rows": n2["train_rows"],
                "test_rows": n2["test_rows"],
                "exact_feature_overlap_rows": n2["exact_feature_overlap_rows"],
                "maximum_distribution_drift_percentage_points": max(
                    abs(value) for value in n2["distribution_drift_percentage_points"].values()
                ),
                "coverage": n2_coverage["levels"]["fine_class"],
                "minimum_test_fine_class_support": min(n2["test_fine_distribution"].values()),
            },
            "N3": n3_rows,
            "N4": n4_rows,
        },
        "bot_iot": bot_coverage,
    }


def suitability_rows(context: Mapping[str, Any]) -> list[dict[str, str]]:
    n_raw = context["n_raw_binary"]
    n_unique = context["n_unique_binary"]
    bot_raw = context["bot_raw_binary"]
    n2 = context["protocols"]["n_baiot"]["N2"]
    sources = {
        "a1": "artifacts/audit/source_inventory_summary.json",
        "a2": "artifacts/audit/structural_audit_summary.json; artifacts/audit/n_baiot_schema.json; artifacts/audit/bot_iot_schema.json",
        "a3": "artifacts/audit/label_audit_summary.json",
        "a4": "artifacts/audit/a4_audit_summary.json; artifacts/audit/n_baiot_duplicate_summary.json; artifacts/audit/bot_iot_duplicate_summary.json",
        "a5n": "artifacts/audit/n_baiot_effective_imbalance.csv; artifacts/audit/n_baiot_split_leakage_summary.json; artifacts/audit/n_baiot_device_holdout_matrix.csv",
        "a5b": "artifacts/audit/bot_iot_effective_imbalance.csv; artifacts/audit/bot_iot_split_feasibility.json; artifacts/audit/bot_iot_entity_overlap_summary.json",
        "a5bp": "artifacts/audit/bot_iot_field_risk_profile.csv; artifacts/audit/bot_iot_port_encoding_summary.json; artifacts/audit/bot_iot_numeric_lineage_analysis.json",
    }

    def row(
        dimension: str,
        ns: str,
        ne: str,
        nl: str,
        bs: str,
        be: str,
        bl: str,
        source: str,
    ) -> dict[str, str]:
        validate_status(ns, SUITABILITY_STATUSES)
        validate_status(bs, SUITABILITY_STATUSES)
        return {
            "dimension": dimension,
            "n_baiot_status": ns,
            "n_baiot_evidence": ne,
            "n_baiot_limitation": nl,
            "bot_iot_status": bs,
            "bot_iot_evidence": be,
            "bot_iot_limitation": bl,
            "evidence_source": source,
        }

    return [
        row(
            "1. Provenance and integrity",
            "FAVORABLE",
            "27 raw files hashed; manifest and later source-metadata checks passed.",
            "Sixteen attack archives required the documented extraction workspace.",
            "FAVORABLE",
            "10 local files hashed; manifest and later source-metadata checks passed.",
            "Evidence applies to the local 5% representations, not raw PCAP capture.",
            f"{sources['a1']}; artifacts/audit/a5_audit_summary.json",
        ),
        row(
            "2. Local structural completeness",
            "FAVORABLE",
            "89 logical CSVs and 7,062,606 rows were parsed without structural failures.",
            "Completeness is relative to the audited local source tree.",
            "FAVORABLE",
            "All-features and 10-best universes each contain 3,668,522 rows; split sums match.",
            "The local corpus contains derived 5% representations rather than a capture pipeline.",
            sources["a2"],
        ),
        row(
            "3. Schema consistency",
            "FAVORABLE",
            "One stable ordered 115-column numeric schema is observed across all 89 CSVs.",
            "A downstream contract must preserve the exact order.",
            "MIXED",
            "Each representation is internally stable.",
            "Three schemas, two delimiters, an unnamed index, case differences, and column-order differences exist.",
            sources["a2"],
        ),
        row(
            "4. Label/taxonomy clarity",
            "FAVORABLE",
            "Audited mappings provide 2 binary, 3 family, and 11 fine classes.",
            "Two devices lack observed Mirai coverage.",
            "MIXED",
            "Audited mappings provide 2 binary, 5 category, and 8 subcategory labels with no semantic conflict rows.",
            "HTTP/TCP/UDP occur under multiple categories and rare classes have very small support.",
            sources["a3"],
        ),
        row(
            "5. Core benign-vs-malicious suitability",
            "FAVORABLE",
            f"Raw support is {n_raw['benign']:,} benign and {n_raw['malicious']:,} malicious; unique-vector support remains {n_unique['benign']:,} and {n_unique['malicious']:,}.",
            "The task remains imbalanced and duplicate weighting materially changes prevalence.",
            "ADVERSE",
            f"Both labels exist, but only {bot_raw['benign']:,} of {sum(bot_raw.values()):,} rows are benign.",
            "Audited test candidates contain only 0-107 benign rows, limiting benign-error resolution.",
            f"{sources['a3']}; {sources['a5n']}; {sources['a5b']}",
        ),
        row(
            "6. Fine/multiclass support",
            "FAVORABLE",
            f"N2 retains 11/11 fine classes; minimum test support is {n2['minimum_test_fine_class_support']:,}.",
            "Device holdouts for Ennio and Samsung contain only 6/11 fine classes.",
            "ADVERSE",
            "Five categories and eight subcategories exist in the full corpus.",
            "Data exfiltration has 6 rows, keylogging 73, theft 79; some candidate tests omit classes.",
            f"{sources['a3']}; {sources['a5n']}; {sources['a5b']}",
        ),
        row(
            "7. Missing/invalid-data burden",
            "FAVORABLE",
            "A4 reports no empty/null/NaN/Inf/numeric-parse/read failures across the 115 numeric fields.",
            "Scaling and distribution treatment remain future preprocessing decisions.",
            "MIXED",
            "A4 reports no empty/null/NaN/Inf/read failures.",
            "Ports include 9,052 hexadecimal rows and 213 '-1' rows; the latter semantics remain unknown.",
            f"{sources['a4']}; artifacts/audit/n_baiot_quality_summary.csv; artifacts/audit/bot_iot_quality_summary.csv; {sources['a5bp']}",
        ),
        row(
            "8. Duplicate/effective-sample burden",
            "ADVERSE",
            f"7,062,606 rows collapse to 2,482,676 exact vectors; binary proportions shift from {percentage(n_raw['benign'], sum(n_raw.values())):.4f}% to {percentage(n_unique['benign'], sum(n_unique.values())):.4f}% benign.",
            "Blind global deduplication would change the training distribution.",
            "FAVORABLE",
            "Identity-free all-feature views have zero exact duplicates; the narrow 10-best view without seq has 185 excess rows.",
            "This does not remove entity/context or representation risks.",
            f"{sources['a4']}; {sources['a5n']}; artifacts/audit/bot_iot_identity_free_duplicate_summary.json",
        ),
        row(
            "9. Leakage-controlled split feasibility",
            "FAVORABLE",
            "N2 retains both binary labels and 11/11 fine classes with zero exact-vector boundary overlap.",
            "N2 does not test unseen devices or contexts and is not adopted.",
            "MIXED",
            "B4 saddr grouping removes saddr overlap and retains both binary labels plus 8/8 subcategories.",
            "Its test has 107 benign rows and only 5 data-exfiltration rows; no candidate is adopted.",
            f"{sources['a5n']}; {sources['a5b']}",
        ),
        row(
            "10. Generalization/stress-test feasibility",
            "MIXED",
            "N3 audits held-out-device identity; N4 additionally enforces exact-vector novelty.",
            "N3 retains 83.85-97.35% exact-vector overlap; N4 excludes 36.36-54.78% of training rows.",
            "MIXED",
            "Entity-grouped candidates test selected unseen entity boundaries.",
            "B3 loses benign coverage; B4 pair loses data exfiltration; context choices define the claim.",
            f"{sources['a5n']}; {sources['a5b']}",
        ),
        row(
            "11. Preprocessing complexity",
            "FAVORABLE",
            "All 115 inputs are finite numeric fields in one ordered schema.",
            "Scaling, weighting, and duplicate handling are still unresolved.",
            "ADVERSE",
            "A deterministic pipeline is possible from audited representations.",
            "Numeric, categorical, entity, lexical-port, ID, order, and representation choices must be separated and locked.",
            f"{sources['a2']}; {sources['a5bp']}",
        ),
        row(
            "12. Representation/provenance ambiguity",
            "FAVORABLE",
            "One observed feature representation and one stable schema are audited.",
            "Feature-generation provenance is not a live-capture contract.",
            "ADVERSE",
            "Record-ID universe relationships across all-features, 10-best full, and supplied split are established.",
            "Six numeric fields differ at serialization scale; the representation must be explicitly selected and documented.",
            f"{sources['a2']}; artifacts/audit/bot_iot_numeric_lineage_analysis.json",
        ),
        row(
            "13. Classification readiness",
            "FAVORABLE",
            "Targets, stable numeric schema, meaningful support, and a zero-exact-overlap candidate are evidenced.",
            "No final split, predictor set, balancing policy, or model is selected.",
            "MIXED",
            "Targets and multiple candidate protocols are evidenced.",
            "Extreme benign scarcity, rare classes, context overlap, and representation locking constrain evaluation.",
            f"{sources['a3']}; {sources['a5n']}; {sources['a5b']}",
        ),
        row(
            "14. Clustering readiness",
            "MIXED",
            "A deterministic all-numeric matrix can be formed directly.",
            "Scale, duplicate weighting, sample strategy, and cluster-evaluation protocol are unresolved.",
            "MIXED",
            "Behavioral numeric fields can form a deterministic matrix after explicit processing.",
            "Categorical encoding, lexical ports, ID/order/context exclusions, scaling, and representation must be fixed first.",
            f"{sources['a2']}; {sources['a5n']}; {sources['a5bp']}",
        ),
        row(
            "15. Structured inference-contract complexity",
            "MIXED",
            "The contract is a stable ordered vector of 115 finite numeric values.",
            "The high-dimensional order and feature extraction assumptions must be versioned.",
            "ADVERSE",
            "Observed schemas and field roles provide a basis for a contract.",
            "Heterogeneous types, port parsing, risky fields, and representation choice make the contract more conditional.",
            f"{sources['a2']}; {sources['a5bp']}",
        ),
        row(
            "16. Raspberry-Pi structural deployability",
            "MIXED",
            "Inference would consume an already-extracted fixed numeric vector.",
            "No model-size, latency, memory, or feature-extraction benchmark exists.",
            "MIXED",
            "Inference can consume structured pre-extracted fields after a representation is locked.",
            "Encoding and validation add complexity; no Pi benchmark exists.",
            f"{sources['a2']}; {sources['a5bp']}",
        ),
        row(
            "17. FastAPI/web input-contract practicality",
            "MIXED",
            "A versioned upload or pre-extracted-vector payload can preserve the 115-field order.",
            "Manual entry of 115 fields would be impractical.",
            "MIXED",
            "A structured payload can represent the selected fields.",
            "Lexical ports, categorical values, entity fields, and representation version require stricter validation.",
            f"{sources['a2']}; {sources['a5bp']}",
        ),
        row(
            "18. Assignment-2 packaging/reproducibility",
            "MIXED",
            "A0-A5 provide manifests, schema, labels, quality, duplicates, and deterministic split evidence.",
            "The processed grader-facing package has not yet been materialized.",
            "MIXED",
            "A0-A5 provide the same audit chain and deterministic candidate definitions.",
            "A representation, safe field contract, imbalance policy, and processed package remain unresolved.",
            "artifacts/audit/source_inventory_summary.json; artifacts/audit/structural_audit_summary.json; artifacts/audit/label_audit_summary.json; artifacts/audit/a4_audit_summary.json; artifacts/audit/a5_audit_summary.json",
        ),
        row(
            "19. Value as a secondary/additional dataset",
            "FAVORABLE",
            "Supports bounded group-aware classification, clustering sensitivity, device stress tests, and leakage experiments.",
            "A secondary use must still be an executed ML experiment, not EDA-only description.",
            "FAVORABLE",
            "Supports bounded entity-grouped classification, representation sensitivity, clustering, and imbalance studies.",
            "Claims must be limited by benign and rare-class support.",
            f"{sources['a5n']}; {sources['a5b']}",
        ),
        row(
            "20. Cross-dataset compatibility",
            "ADVERSE",
            "The audited N-BaIoT and Bot-IoT schemas have zero exact named feature overlap.",
            "Conceptually similar statistics have different scopes and definitions.",
            "ADVERSE",
            "The binary target concept overlaps, but the observed input schema does not.",
            "Direct cross-dataset model evaluation lacks a verified common feature space.",
            sources["a2"],
        ),
    ]


def primary_requirement_rows(context: Mapping[str, Any]) -> list[dict[str, str]]:
    rows = [
        (
            "P1",
            "Core binary support",
            "SUPPORTED",
            "555,932 benign and 6,506,674 malicious rows; unique-vector support is 513,497 and 1,969,179.",
            "Duplicate weighting changes prevalence.",
            "PARTIALLY_SUPPORTED",
            "Both classes exist: 477 benign and 3,668,045 malicious.",
            "Benign support is too sparse for stable core evaluation across audited candidates.",
        ),
        (
            "P2",
            "Leakage-controlled evaluation candidate",
            "SUPPORTED",
            "N2 has zero exact-vector boundary overlap, both binary classes, and 11/11 fine classes.",
            "It does not test unseen devices/context and is not adopted.",
            "SUPPORTED",
            "B4 grouped by saddr has zero saddr overlap, both binary classes, 5/5 categories, and 8/8 subcategories.",
            "Only 107 benign and 5 data-exfiltration test rows remain.",
        ),
        (
            "P3",
            "Reasonable evaluation resolution",
            "SUPPORTED",
            "N2 test has 111,186 benign rows and 1,301,403 malicious rows; minimum fine support is 51,596.",
            "Metric resolution does not remove distribution-shift concerns.",
            "NOT_SUPPORTED",
            "Audited candidate tests contain 0-107 benign rows; one benign error changes the rate by about 0.93-1.79 percentage points when benign is present.",
            "This is inadequate for high-resolution benign/FPR estimation.",
        ),
        (
            "P4",
            "Deterministic inference contract",
            "SUPPORTED",
            "One ordered 115-field finite numeric schema can be versioned deterministically.",
            "Scaling and payload versioning are not implemented.",
            "PARTIALLY_SUPPORTED",
            "Audited schemas and field roles can define a deterministic contract.",
            "Representation, categorical encoding, port parsing, and sentinel semantics are not locked.",
        ),
        (
            "P5",
            "Classification without direct target/record identifiers",
            "SUPPORTED",
            "The 115 feature columns are separate from labels and N2 operates on exact feature groups.",
            "No final predictor set has been adopted.",
            "PARTIALLY_SUPPORTED",
            "Identity-free exact views exist after excluding pkSeqID and the unnamed index.",
            "Order and entity/context fields still require explicit eligibility decisions.",
        ),
        (
            "P6",
            "Practical clustering path",
            "PARTIALLY_SUPPORTED",
            "A finite all-numeric matrix can be formed deterministically.",
            "Scaling, duplicate weighting, sampling, and clustering protocol remain undefined.",
            "PARTIALLY_SUPPORTED",
            "Behavioral numeric fields can form a matrix after deterministic encoding/exclusion.",
            "Mixed types and risky ID/order/context fields increase unresolved preprocessing work.",
        ),
        (
            "P7",
            "Reproducible processed Assignment-2 package",
            "PARTIALLY_SUPPORTED",
            "A0-A5 provide source hashes, schema, labels, quality, and deterministic split evidence.",
            "No grader-facing processed package has been generated.",
            "PARTIALLY_SUPPORTED",
            "A0-A5 provide the same reproducibility chain for local representations.",
            "No representation-specific processed package has been generated.",
        ),
        (
            "P8",
            "Structural Pi/FastAPI plausibility",
            "PARTIALLY_SUPPORTED",
            "An already-extracted fixed 115-number vector is structurally serializable.",
            "No finalized API contract or Pi benchmark exists.",
            "PARTIALLY_SUPPORTED",
            "A locked subset of structured pre-extracted fields is serializable.",
            "Encoding/validation contract and Pi cost are not measured.",
        ),
    ]
    result = []
    for requirement, capability, ns, ne, nl, bs, be, bl in rows:
        validate_status(ns, REQUIREMENT_STATUSES)
        validate_status(bs, REQUIREMENT_STATUSES)
        result.append(
            {
                "requirement": requirement,
                "capability": capability,
                "n_baiot_status": ns,
                "n_baiot_evidence": ne,
                "n_baiot_limitation": nl,
                "bot_iot_status": bs,
                "bot_iot_evidence": be,
                "bot_iot_limitation": bl,
                "evidence_source": (
                    "artifacts/audit/structural_audit_summary.json; "
                    "artifacts/audit/label_audit_summary.json; "
                    "artifacts/audit/a5_audit_summary.json; "
                    "artifacts/audit/n_baiot_split_leakage_summary.json; "
                    "artifacts/audit/bot_iot_split_feasibility.json"
                ),
            }
        )
    return result


def secondary_rows() -> list[dict[str, str]]:
    rows = [
        ("n_baiot", "Supplementary group-aware binary classification", "ML experiment", "Use an audited zero-exact-overlap candidate to compare classification behavior.", "Does not establish unseen-device generalization; split remains unselected.", "artifacts/audit/n_baiot_split_leakage_summary.json"),
        ("n_baiot", "Device generalization sensitivity", "ML experiment", "Run bounded N3/N4 comparisons to separate held-out-device identity from exact-vector novelty.", "N3 has 83.85-97.35% exact overlap; N4 removes 36.36-54.78% of training rows.", "artifacts/audit/n_baiot_device_holdout_matrix.csv"),
        ("n_baiot", "Duplicate-weighting clustering sensitivity", "ML experiment", "Compare clustering under documented raw-row weighting and group-aware/sample-weight alternatives.", "Blind deduplication is not justified because class proportions change.", "artifacts/audit/n_baiot_effective_imbalance.csv"),
        ("n_baiot", "Leakage protocol case study", "ML experiment", "Measure model sensitivity between naive row-random and exact-group-aware boundaries.", "Must be framed as protocol sensitivity, not a final split decision.", "artifacts/audit/candidate_split_comparison.csv"),
        ("bot_iot", "Entity-grouped binary classification", "ML experiment", "Use bounded B4 saddr grouping to measure sensitivity to an unseen source-address boundary.", "Only 107 benign and 5 data-exfiltration test rows; claims must stay narrow.", "artifacts/audit/bot_iot_split_feasibility.json"),
        ("bot_iot", "Representation sensitivity classification", "ML experiment", "Compare explicitly locked all-features and 10-best contracts on the proven common record-ID universe.", "Six numeric fields have serialization-scale differences and risky fields require consistent exclusion.", "artifacts/audit/bot_iot_numeric_lineage_analysis.json"),
        ("bot_iot", "Behavioral-feature clustering", "ML experiment", "Cluster a deterministic matrix after excluding direct targets/IDs and documenting context-field treatment.", "Categorical encoding, ports, scaling, and imbalance/rare groups need explicit controls.", "artifacts/audit/bot_iot_field_risk_profile.csv; artifacts/audit/bot_iot_port_encoding_summary.json"),
        ("bot_iot", "Imbalance and context-memorization sensitivity", "ML experiment", "Evaluate bounded reweighting/resampling and entity-boundary sensitivity without treating binary purity as evidence beyond its baseline.", "Results cannot repair the source's 477-row benign support or prove causality.", "artifacts/audit/bot_iot_effective_imbalance.csv; artifacts/audit/bot_iot_entity_overlap_summary.json"),
    ]
    return [
        {
            "dataset_if_secondary": dataset,
            "use_case": use_case,
            "use_type": use_type,
            "technically_defensible_scope": scope,
            "limitation": limitation,
            "evidence_source": source,
            "role_selection_status": "candidate use only; A6 assigns no dataset role",
        }
        for dataset, use_case, use_type, scope, limitation, source in rows
    ]


def render_markdown(
    suitability: list[dict[str, str]],
    requirements: list[dict[str, str]],
    summary: Mapping[str, Any],
) -> str:
    lines = [
        "# A6 dataset suitability comparison",
        "",
        "> Internal evidence synthesis only. A6 does not select primary/secondary roles, a final split, predictors, or a model.",
        "",
        "## Scope and method",
        "",
        "This comparison uses only compact, independently checked A0-A5 artifacts. No raw dataset was reread and no model, clustering job, processed split, or deployment benchmark was run. Statuses are categorical and there is no numeric score or winner.",
        "",
        "## Suitability matrix",
        "",
        "| Dimension | N-BaIoT | Bot-IoT |",
        "|---|---|---|",
    ]
    for item in suitability:
        lines.append(
            f"| {item['dimension']} | **{item['n_baiot_status']}** — {item['n_baiot_evidence']} Limitation: {item['n_baiot_limitation']} | **{item['bot_iot_status']}** — {item['bot_iot_evidence']} Limitation: {item['bot_iot_limitation']} |"
        )
    lines.extend(
        [
            "",
            "## Mandatory primary-capability evidence",
            "",
            "These statuses evaluate present evidence only; they do not assign a role.",
            "",
            "| Requirement | N-BaIoT | Bot-IoT |",
            "|---|---|---|",
        ]
    )
    for item in requirements:
        lines.append(
            f"| {item['requirement']} — {item['capability']} | **{item['n_baiot_status']}** — {item['n_baiot_evidence']} | **{item['bot_iot_status']}** — {item['bot_iot_evidence']} |"
        )
    n2 = summary["evaluation_protocols"]["n_baiot"]["N2"]
    baseline = summary["bot_entity_purity_baseline_adjustment"]
    lines.extend(
        [
            "",
            "## Evaluation-protocol claims",
            "",
            f"- N2 supports an unseen-exact-vector claim: {n2['test_rows']:,} test rows, zero exact-vector overlap, 11/11 fine classes, minimum fine support {n2['minimum_test_fine_class_support']:,}. It does not test unseen devices or contexts.",
            "- N3 supports a held-out-device-identity claim, but 83.85-97.35% of held-out rows still have an exact vector in training.",
            "- N4 supports held-out-device plus exact-vector novelty, but excludes 36.36-54.78% of candidate training rows and two device tests contain only 6/11 fine classes.",
            "- Bot B1 has all binary/category labels but misses data exfiltration in test and retains near-total entity overlap.",
            "- Bot B2 has full audited label coverage but only one data-exfiltration test row and near-total entity overlap.",
            "- Bot B3 has 1/2 binary, 2/5 category, and 4/8 subcategory classes in test; it cannot support complete-task evaluation.",
            "- Bot B4-saddr has 2/2, 5/5, and 8/8 coverage with zero saddr overlap, but only 107 benign and 5 data-exfiltration rows in test. B4-pair misses data exfiltration.",
            "",
            "## Effective samples and baseline-aware interpretation",
            "",
            "N-BaIoT has 7,062,606 rows but 2,482,676 unique exact vectors. Benign prevalence changes from 7.8715% raw to 20.6832% by unique vector, so blind deduplication would alter the learning distribution; group-aware splitting can prevent boundary leakage without deleting observations.",
            "Bot-IoT has 477 benign rows total. Audited candidate tests contain 107 (B1), 95 (B2), 0 (B3), 107 (B4-saddr), or 56 (B4-pair), so a single benign error changes a candidate error rate by roughly 0.93%, 1.05%, undefined, 0.93%, or 1.79%, respectively.",
            f"Bot binary majority baseline is {baseline['binary']['global_majority_baseline_percent']:.6f}%; saddr+daddr binary purity is {baseline['binary']['observed_weighted_purity_percent']:.6f}% (only {baseline['binary']['increase_over_baseline_percentage_points']:.6f} percentage points higher). Category majority baseline is {baseline['category']['global_majority_baseline_percent']:.4f}%; pair purity is {baseline['category']['observed_weighted_purity_percent']:.4f}% ({baseline['category']['increase_over_baseline_percentage_points']:.4f} points higher). Category concentration and entity overlap are therefore more informative than the near-baseline binary purity.",
            "",
            "## Classification, clustering, and integration",
            "",
            "N-BaIoT has stronger present evidence for stable numeric preprocessing, target support, and an exact-group-controlled evaluation candidate, while duplicate weighting and device claims remain material limitations. Bot-IoT has clear labels and candidate protocols, but extreme benign/rare-class scarcity, entity/context overlap, and representation choices constrain classification claims.",
            "",
            "Both datasets can support a deterministic clustering matrix in principle. N-BaIoT still needs scaling, duplicate weighting, sampling, and cluster evaluation defined. Bot-IoT additionally needs categorical/port handling plus explicit exclusion or treatment of target, ID, order, and entity/context fields. No clustering algorithm is selected here.",
            "",
            "For Pi/FastAPI/web integration, N-BaIoT is structurally a stable 115-number vector; an upload or pre-extracted-vector API is more practical than manual entry. Bot-IoT requires a locked representation and stricter heterogeneous-field validation. These are structural observations only; no Pi latency, memory, or throughput claim is made.",
            "",
            "## Secondary-use value and cross-dataset limits",
            "",
            "Each dataset has bounded ML uses if treated as secondary: N-BaIoT supports group-aware classification, device stress tests, and duplicate-weighting clustering sensitivity; Bot-IoT supports entity-grouped classification, representation sensitivity, behavioral clustering, and imbalance/context sensitivity. These must be executed ML experiments rather than EDA-only descriptions.",
            "",
            "The schemas have zero exact named feature overlap. Similar statistical words do not establish compatible semantics because N-BaIoT fields are entity/window conditioned and Bot-IoT fields use different flow/context definitions. A shared binary label concept exists, but direct cross-dataset model evaluation is **NOT_CURRENTLY_DEFENSIBLE** without a separately verified common feature space.",
            "",
            "## Assignment and project fit",
            "",
            "A0-A6 provide traceable evidence for later construction of a processed Assignment-2 package, classification and clustering protocols, meaningful additional-dataset experiments, and reproducible evaluation. A7 must still decide roles and later phases must materialize the processed package. Deployment remains based on already-extracted structured features; raw PCAP/live capture is outside the core scope, and the web application must remain runnable without Raspberry Pi hardware.",
            "",
            "## A7 unresolved decisions",
            "",
            "- Assign primary and secondary dataset roles using the A6 matrices.",
            "- Select and justify one final evaluation protocol without overstating its generalization claim.",
            "- Lock the representation, predictor eligibility, preprocessing, imbalance treatment, and clustering protocol.",
            "- Define the processed Assignment-2 package and versioned API/inference contract.",
            "- Defer Pi performance claims until an actual benchmark exists.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    missing = [name for name in SOURCE_FILES if not (AUDIT_DIR / name).is_file()]
    if missing:
        raise FileNotFoundError(f"missing compact A0-A5 evidence: {missing}")

    inventory = load_json(AUDIT_DIR / "source_inventory_summary.json")
    structural = load_json(AUDIT_DIR / "structural_audit_summary.json")
    labels = load_json(AUDIT_DIR / "label_audit_summary.json")
    a4 = load_json(AUDIT_DIR / "a4_audit_summary.json")
    a5 = load_json(AUDIT_DIR / "a5_audit_summary.json")
    a5_verify = load_json(AUDIT_DIR / "a5_evidence_verification.json")
    checkpoints = (inventory, structural, labels, a4, a5, a5_verify)
    if any(item.get("overall_status") != "PASS" for item in checkpoints):
        raise ValueError("A0-A5 compact checkpoint is not PASS")

    n_schema = load_json(AUDIT_DIR / "n_baiot_schema.json")
    bot_schema = load_json(AUDIT_DIR / "bot_iot_schema.json")
    n_split = load_json(AUDIT_DIR / "n_baiot_split_leakage_summary.json")
    device_rows = load_csv(AUDIT_DIR / "n_baiot_device_holdout_matrix.csv")
    bot_split = load_json(AUDIT_DIR / "bot_iot_split_feasibility.json")
    entity = load_json(AUDIT_DIR / "bot_iot_entity_overlap_summary.json")
    n_imbalance = load_csv(AUDIT_DIR / "n_baiot_effective_imbalance.csv")
    bot_imbalance = load_csv(AUDIT_DIR / "bot_iot_effective_imbalance.csv")

    n_binary = [row for row in n_imbalance if row["label_level"] == "binary"]
    n_raw_binary = {row["label"]: int(row["raw_row_count"]) for row in n_binary}
    n_unique_binary = {row["label"]: int(row["unique_vector_count"]) for row in n_binary}
    bot_binary_rows = [
        row
        for row in bot_imbalance
        if row["representation"] == "all_features_5pct_shards"
        and row["view"] == "raw_rows"
        and row["label_level"] == "binary"
    ]
    bot_raw_binary = {row["label"]: int(row["count"]) for row in bot_binary_rows}
    bot_category_counts = labels["bot_iot"]["all_features_raw_distributions"]["category"]
    bot_binary_counts = labels["bot_iot"]["all_features_raw_distributions"]["attack"]
    pair_purity = entity["all_features_label_purity"]["saddr+daddr"]
    purity = {
        "binary": baseline_adjusted_purity(
            {"benign": bot_binary_counts["0"], "malicious": bot_binary_counts["1"]},
            pair_purity["weighted_binary_purity"],
        ),
        "category": baseline_adjusted_purity(
            bot_category_counts, pair_purity["weighted_category_purity"]
        ),
        "interpretation": (
            "Binary purity is nearly explained by the global malicious majority; category purity "
            "and near-total supplied-split entity overlap are more informative context-risk evidence."
        ),
    }
    protocols = build_protocols(n_split, device_rows, bot_split)
    overlap = feature_overlap(n_schema, bot_schema)
    compatibility = {
        "audit_batch": "A6 cross-dataset compatibility",
        **overlap,
        "shared_target_semantics": {
            "binary_benign_malicious_concept": True,
            "taxonomy_directly_interchangeable": False,
            "explanation": (
                "Both can be mapped to benign/malicious, but N-BaIoT family/fine labels and "
                "Bot-IoT category/subcategory labels describe different taxonomies."
            ),
        },
        "defensible_direct_model_input_space": False,
        "direct_cross_dataset_model_evaluation": validate_status(
            "NOT_CURRENTLY_DEFENSIBLE", CROSS_DATASET_STATUSES
        ),
        "reason": (
            "There is no exact named input overlap, and conceptual statistical overlaps have "
            "different entity/window/flow definitions. A6 does not engineer a common space."
        ),
        "role_selection": "not performed",
    }
    context = {
        "n_raw_binary": n_raw_binary,
        "n_unique_binary": n_unique_binary,
        "bot_raw_binary": bot_raw_binary,
        "protocols": protocols,
    }
    suitability = suitability_rows(context)
    requirements = primary_requirement_rows(context)
    secondary = secondary_rows()

    write_csv_atomic(
        AUDIT_DIR / "a6_dataset_suitability_matrix.csv",
        (
            "dimension",
            "n_baiot_status",
            "n_baiot_evidence",
            "n_baiot_limitation",
            "bot_iot_status",
            "bot_iot_evidence",
            "bot_iot_limitation",
            "evidence_source",
        ),
        suitability,
    )
    write_csv_atomic(
        AUDIT_DIR / "a6_primary_requirement_matrix.csv",
        (
            "requirement",
            "capability",
            "n_baiot_status",
            "n_baiot_evidence",
            "n_baiot_limitation",
            "bot_iot_status",
            "bot_iot_evidence",
            "bot_iot_limitation",
            "evidence_source",
        ),
        requirements,
    )
    write_csv_atomic(
        AUDIT_DIR / "a6_secondary_use_case_matrix.csv",
        (
            "dataset_if_secondary",
            "use_case",
            "use_type",
            "technically_defensible_scope",
            "limitation",
            "evidence_source",
            "role_selection_status",
        ),
        secondary,
    )
    write_json_atomic(AUDIT_DIR / "a6_cross_dataset_compatibility.json", compatibility)

    source_hashes = {name: sha256_file(AUDIT_DIR / name) for name in SOURCE_FILES}
    summary: dict[str, Any] = {
        "audit_batch": "A6 cross-dataset suitability synthesis",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "a5_checkpoint_commit": A5_COMMIT_SHA,
        "overall_status": "PASS",
        "pass_semantics": (
            "The synthesis is complete and internally consistent; PASS does not assign roles, "
            "adopt a split, select predictors, or assert either dataset is universally suitable."
        ),
        "method": {
            "raw_dataset_reads": 0,
            "models_trained": 0,
            "clustering_runs": 0,
            "processed_splits_written": 0,
            "numeric_total_score": False,
            "winner_selected": False,
            "primary_dataset_selected": False,
            "secondary_dataset_selected": False,
        },
        "source_artifact_sha256": source_hashes,
        "project_requirements_held_fixed": [
            "core supervised benign-vs-malicious IoT traffic classification",
            "classification and clustering branches",
            "leakage-controlled reproducible evaluation",
            "processed Assignment-2 package independent of raw multi-GB sources",
            "structured-feature Raspberry Pi and FastAPI/React integration",
            "web application runnable without Raspberry Pi",
        ],
        "framework": {
            "suitability_dimensions": [row["dimension"] for row in suitability],
            "allowed_suitability_statuses": sorted(SUITABILITY_STATUSES),
            "allowed_primary_requirement_statuses": sorted(REQUIREMENT_STATUSES),
            "numeric_scoring": "prohibited",
        },
        "primary_requirements": {
            row["requirement"]: {
                "capability": row["capability"],
                "n_baiot_status": row["n_baiot_status"],
                "bot_iot_status": row["bot_iot_status"],
            }
            for row in requirements
        },
        "evaluation_protocols": protocols,
        "effective_sample_interpretation": {
            "n_baiot": {
                "raw_rows": sum(n_raw_binary.values()),
                "unique_exact_vectors": sum(n_unique_binary.values()),
                "raw_binary_counts": n_raw_binary,
                "unique_vector_binary_counts": n_unique_binary,
                "raw_benign_percent": percentage(
                    n_raw_binary["benign"], sum(n_raw_binary.values())
                ),
                "unique_vector_benign_percent": percentage(
                    n_unique_binary["benign"], sum(n_unique_binary.values())
                ),
                "interpretation": (
                    "Blind deduplication changes the observed distribution; group-aware boundaries "
                    "can prevent exact-vector leakage without deleting rows."
                ),
            },
            "bot_iot": {
                "full_binary_counts": bot_raw_binary,
                "candidate_test_benign_counts": {
                    item["candidate"]: item["test_binary_counts"].get("benign", 0)
                    for item in protocols["bot_iot"]
                },
                "one_benign_error_granularity_percent": {
                    item["candidate"]: (
                        None
                        if item["test_binary_counts"].get("benign", 0) == 0
                        else 100.0 / item["test_binary_counts"]["benign"]
                    )
                    for item in protocols["bot_iot"]
                },
                "interpretation": (
                    "Total rows do not compensate for sparse benign and rare-label support."
                ),
            },
        },
        "bot_entity_purity_baseline_adjustment": purity,
        "classification_readiness": {
            "n_baiot": "FAVORABLE with unresolved split/predictor/weighting decisions",
            "bot_iot": "MIXED because benign/rare support and context/representation risks constrain claims",
        },
        "clustering_readiness": {
            "n_baiot": "MIXED; deterministic numeric matrix, unresolved scaling/weighting/sampling",
            "bot_iot": "MIXED; deterministic path requires encoding and risky-field treatment",
            "algorithm_selected": False,
        },
        "integration_scope": {
            "pi_benchmark_performed": False,
            "n_baiot": "stable 115-number pre-extracted vector; high-dimensional contract",
            "bot_iot": "heterogeneous pre-extracted schema requiring representation and parser lock",
            "web_without_pi_required": True,
        },
        "secondary_use_case_count": {
            "n_baiot": sum(row["dataset_if_secondary"] == "n_baiot" for row in secondary),
            "bot_iot": sum(row["dataset_if_secondary"] == "bot_iot" for row in secondary),
        },
        "cross_dataset_compatibility": compatibility,
        "a7_unresolved": [
            "primary and secondary dataset role assignment",
            "final evaluation protocol",
            "final representation and predictor eligibility",
            "preprocessing and imbalance policy",
            "clustering protocol",
            "processed Assignment-2 package",
            "versioned API/inference contract",
            "Raspberry Pi performance benchmark",
        ],
        "role_selection": "not performed",
    }
    write_text_atomic(DOC_PATH, render_markdown(suitability, requirements, summary))

    output_paths = (
        AUDIT_DIR / "a6_dataset_suitability_matrix.csv",
        AUDIT_DIR / "a6_primary_requirement_matrix.csv",
        AUDIT_DIR / "a6_secondary_use_case_matrix.csv",
        AUDIT_DIR / "a6_cross_dataset_compatibility.json",
        DOC_PATH,
    )
    summary["artifact_sha256"] = {
        path.relative_to(PROJECT_ROOT).as_posix(): sha256_file(path) for path in output_paths
    }
    write_json_atomic(AUDIT_DIR / "a6_evidence_summary.json", summary)
    print(f"Wrote A6 evidence to: {AUDIT_DIR}")
    print(f"Wrote A6 analysis to: {DOC_PATH}")
    print("Overall status: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
