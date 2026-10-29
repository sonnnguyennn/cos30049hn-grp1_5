"""Independently verify the compact A6 evidence synthesis."""

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
DOC_PATH = PROJECT_ROOT / "docs" / "analysis" / "dataset_suitability_comparison.md"

SUITABILITY_STATUSES = {"FAVORABLE", "MIXED", "ADVERSE", "UNKNOWN / NOT YET MEASURED"}
REQUIREMENT_STATUSES = {"SUPPORTED", "PARTIALLY_SUPPORTED", "NOT_SUPPORTED", "UNKNOWN"}
EXPECTED_BOT_CLASSES = {
    "binary": {"benign", "malicious"},
    "category": {"ddos", "dos", "normal", "reconnaissance", "theft"},
    "subcategory": {
        "data_exfiltration",
        "http",
        "keylogging",
        "normal",
        "os_fingerprint",
        "service_scan",
        "tcp",
        "udp",
    },
}
EXPECTED_SUITABILITY = {
    "1. Provenance and integrity": ("FAVORABLE", "FAVORABLE"),
    "2. Local structural completeness": ("FAVORABLE", "FAVORABLE"),
    "3. Schema consistency": ("FAVORABLE", "MIXED"),
    "4. Label/taxonomy clarity": ("FAVORABLE", "MIXED"),
    "5. Core benign-vs-malicious suitability": ("FAVORABLE", "ADVERSE"),
    "6. Fine/multiclass support": ("FAVORABLE", "ADVERSE"),
    "7. Missing/invalid-data burden": ("FAVORABLE", "MIXED"),
    "8. Duplicate/effective-sample burden": ("ADVERSE", "FAVORABLE"),
    "9. Leakage-controlled split feasibility": ("FAVORABLE", "MIXED"),
    "10. Generalization/stress-test feasibility": ("MIXED", "MIXED"),
    "11. Preprocessing complexity": ("FAVORABLE", "ADVERSE"),
    "12. Representation/provenance ambiguity": ("FAVORABLE", "ADVERSE"),
    "13. Classification readiness": ("FAVORABLE", "MIXED"),
    "14. Clustering readiness": ("MIXED", "MIXED"),
    "15. Structured inference-contract complexity": ("MIXED", "ADVERSE"),
    "16. Raspberry-Pi structural deployability": ("MIXED", "MIXED"),
    "17. FastAPI/web input-contract practicality": ("MIXED", "MIXED"),
    "18. Assignment-2 packaging/reproducibility": ("MIXED", "MIXED"),
    "19. Value as a secondary/additional dataset": ("FAVORABLE", "FAVORABLE"),
    "20. Cross-dataset compatibility": ("ADVERSE", "ADVERSE"),
}
EXPECTED_REQUIREMENTS = {
    "P1": ("SUPPORTED", "PARTIALLY_SUPPORTED"),
    "P2": ("SUPPORTED", "SUPPORTED"),
    "P3": ("SUPPORTED", "NOT_SUPPORTED"),
    "P4": ("SUPPORTED", "PARTIALLY_SUPPORTED"),
    "P5": ("SUPPORTED", "PARTIALLY_SUPPORTED"),
    "P6": ("PARTIALLY_SUPPORTED", "PARTIALLY_SUPPORTED"),
    "P7": ("PARTIALLY_SUPPORTED", "PARTIALLY_SUPPORTED"),
    "P8": ("PARTIALLY_SUPPORTED", "PARTIALLY_SUPPORTED"),
}


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


def coverage_record(
    distributions: Mapping[str, Mapping[str, int]],
    expected: Mapping[str, set[str]],
) -> dict[str, dict[str, Any]]:
    result = {}
    for level, expected_classes in expected.items():
        observed = distributions.get(level, {})
        missing = sorted(expected_classes - set(observed))
        result[level] = {
            "total_classes_expected": len(expected_classes),
            "classes_present_in_test": len(observed),
            "present_classes": sorted(observed),
            "missing_classes": missing,
            "minimum_support_among_represented_classes": min(observed.values(), default=0),
            "coverage_complete": not missing,
        }
    return result


def baseline_adjusted_purity(
    counts: Mapping[str, int], observed_purity: float
) -> dict[str, float]:
    total = sum(counts.values())
    baseline = max(counts.values(), default=0) / total if total else 0.0
    return {
        "global_majority_baseline_percent": baseline * 100.0,
        "observed_weighted_purity_percent": observed_purity * 100.0,
        "increase_over_baseline_percentage_points": (observed_purity - baseline) * 100.0,
    }


def exact_feature_overlap(n_schema: Mapping[str, Any], bot_schema: Mapping[str, Any]) -> list[str]:
    n_fields = set(n_schema["schemas"][0]["ordered_columns"])
    bot_fields = set(bot_schema["documentation_cross_check"]["observed_all_features_names"])
    return sorted(n_fields & bot_fields)


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


def no_score_or_ranking(payloads: Sequence[Any], csv_rows: Sequence[list[dict[str, str]]]) -> bool:
    forbidden = {"overall_score", "weighted_score", "ranking", "rank", "winner"}
    if any(recursive_keys(payload) & forbidden for payload in payloads):
        return False
    for rows in csv_rows:
        if rows and set(rows[0]) & forbidden:
            return False
    return True


def no_role_assignment(
    summary: Mapping[str, Any], compatibility: Mapping[str, Any], text: str
) -> bool:
    method = summary.get("method", {})
    flags_ok = (
        method.get("primary_dataset_selected") is False
        and method.get("secondary_dataset_selected") is False
        and method.get("winner_selected") is False
    )
    fields_ok = (
        summary.get("role_selection") == "not performed"
        and compatibility.get("role_selection") == "not performed"
    )
    assignment = re.compile(
        r"(?:N-BaIoT|Bot-IoT)\s+(?:is|was|becomes|selected as|chosen as)\s+"
        r"(?:the\s+)?(?:primary|secondary)\b",
        re.IGNORECASE,
    )
    return flags_ok and fields_ok and assignment.search(text) is None


def close_dict(observed: Mapping[str, float], expected: Mapping[str, float]) -> bool:
    return observed.keys() == expected.keys() and all(
        abs(float(observed[key]) - float(expected[key])) <= 1e-10 for key in expected
    )


def verify_coverage(
    summary: Mapping[str, Any], n_split: Mapping[str, Any], bot: Mapping[str, Any]
) -> dict[str, Any]:
    n_expected = {"fine_class": set(n_split["raw_fine_class_counts"])}
    n2_expected = coverage_record(
        {"fine_class": n_split["exact_feature_group_aware"]["test_fine_distribution"]},
        n_expected,
    )["fine_class"]
    n2_observed = summary["evaluation_protocols"]["n_baiot"]["N2"]["coverage"]
    n2_match = n2_observed == n2_expected

    bot_distributions = {
        "B1 supplied train/test": bot["candidate_B1_supplied"]["class_distributions"]["test"],
        "B2 random stratified record": bot["candidate_B2_random_stratified"][
            "test_distributions"
        ],
        "B3 chronological numeric-order": bot["candidate_B3_temporal"][
            "test_distributions"
        ],
        "B4 entity grouped by saddr": bot["candidate_B4_entity_grouped"]["saddr"][
            "test_distributions"
        ],
        "B4 entity grouped by saddr+daddr": bot["candidate_B4_entity_grouped"][
            "saddr+daddr"
        ]["test_distributions"],
    }
    observed_by_name = {
        item["candidate"]: item for item in summary["evaluation_protocols"]["bot_iot"]
    }
    bot_matches = {}
    missing_candidates_not_complete = True
    for name, distributions in bot_distributions.items():
        expected = coverage_record(distributions, EXPECTED_BOT_CLASSES)
        observed = observed_by_name[name]["levels"]
        bot_matches[name] = observed == expected
        for level, details in observed.items():
            if details["missing_classes"] and details["coverage_complete"]:
                missing_candidates_not_complete = False
    return {
        "n2_coverage_matches": n2_match,
        "bot_coverage_matches": bot_matches,
        "all_bot_coverage_matches": all(bot_matches.values()),
        "missing_class_candidates_not_described_as_complete": missing_candidates_not_complete,
    }


def verify_statuses(
    suitability: list[dict[str, str]], requirements: list[dict[str, str]]
) -> dict[str, Any]:
    suitability_allowed = all(
        row["n_baiot_status"] in SUITABILITY_STATUSES
        and row["bot_iot_status"] in SUITABILITY_STATUSES
        for row in suitability
    )
    suitability_observed = {
        row["dimension"]: (row["n_baiot_status"], row["bot_iot_status"])
        for row in suitability
    }
    requirements_allowed = all(
        row["n_baiot_status"] in REQUIREMENT_STATUSES
        and row["bot_iot_status"] in REQUIREMENT_STATUSES
        for row in requirements
    )
    requirements_observed = {
        row["requirement"]: (row["n_baiot_status"], row["bot_iot_status"])
        for row in requirements
    }
    return {
        "suitability_allowed_values": suitability_allowed,
        "suitability_has_fixed_20_dimensions": suitability_observed == EXPECTED_SUITABILITY,
        "primary_requirements_allowed_values": requirements_allowed,
        "primary_requirements_P1_P8_complete": requirements_observed == EXPECTED_REQUIREMENTS,
        "every_suitability_row_has_evidence_limitation_source": all(
            row["n_baiot_evidence"]
            and row["n_baiot_limitation"]
            and row["bot_iot_evidence"]
            and row["bot_iot_limitation"]
            and row["evidence_source"]
            for row in suitability
        ),
    }


def main() -> int:
    required = (
        "a6_dataset_suitability_matrix.csv",
        "a6_primary_requirement_matrix.csv",
        "a6_secondary_use_case_matrix.csv",
        "a6_cross_dataset_compatibility.json",
        "a6_evidence_summary.json",
    )
    missing = [name for name in required if not (AUDIT_DIR / name).is_file()]
    if missing or not DOC_PATH.is_file():
        raise FileNotFoundError(f"missing A6 outputs: {missing}")

    summary = load_json(AUDIT_DIR / "a6_evidence_summary.json")
    compatibility = load_json(AUDIT_DIR / "a6_cross_dataset_compatibility.json")
    suitability = load_csv(AUDIT_DIR / "a6_dataset_suitability_matrix.csv")
    requirements = load_csv(AUDIT_DIR / "a6_primary_requirement_matrix.csv")
    secondary = load_csv(AUDIT_DIR / "a6_secondary_use_case_matrix.csv")
    n_split = load_json(AUDIT_DIR / "n_baiot_split_leakage_summary.json")
    bot_split = load_json(AUDIT_DIR / "bot_iot_split_feasibility.json")
    labels = load_json(AUDIT_DIR / "label_audit_summary.json")
    entity = load_json(AUDIT_DIR / "bot_iot_entity_overlap_summary.json")
    n_schema = load_json(AUDIT_DIR / "n_baiot_schema.json")
    bot_schema = load_json(AUDIT_DIR / "bot_iot_schema.json")

    observed_hashes = {
        path: sha256_file(PROJECT_ROOT / path) for path in summary["artifact_sha256"]
    }
    artifact_hashes_match = observed_hashes == summary["artifact_sha256"]
    observed_source_hashes = {
        name: sha256_file(AUDIT_DIR / name) for name in summary["source_artifact_sha256"]
    }
    source_artifact_hashes_match = observed_source_hashes == summary["source_artifact_sha256"]

    statuses = verify_statuses(suitability, requirements)
    coverage = verify_coverage(summary, n_split, bot_split)

    pair = entity["all_features_label_purity"]["saddr+daddr"]
    attack = labels["bot_iot"]["all_features_raw_distributions"]["attack"]
    categories = labels["bot_iot"]["all_features_raw_distributions"]["category"]
    expected_binary = baseline_adjusted_purity(
        {"benign": attack["0"], "malicious": attack["1"]}, pair["weighted_binary_purity"]
    )
    expected_category = baseline_adjusted_purity(categories, pair["weighted_category_purity"])
    purity_observed = summary["bot_entity_purity_baseline_adjustment"]
    purity_matches = close_dict(purity_observed["binary"], expected_binary) and close_dict(
        purity_observed["category"], expected_category
    )

    exact_overlap = exact_feature_overlap(n_schema, bot_schema)
    cross_compatibility_matches = (
        compatibility["exact_named_feature_overlap"] == exact_overlap
        and compatibility["exact_named_feature_overlap_count"] == len(exact_overlap)
        and compatibility["direct_cross_dataset_model_evaluation"]
        == "NOT_CURRENTLY_DEFENSIBLE"
        and compatibility["defensible_direct_model_input_space"] is False
    )

    n_effective = summary["effective_sample_interpretation"]["n_baiot"]
    n_counts_match = (
        n_effective["raw_rows"] == sum(n_split["raw_fine_class_counts"].values())
        and n_effective["unique_exact_vectors"]
        == sum(n_split["unique_vector_fine_class_counts"].values())
    )
    bot_granularity = summary["effective_sample_interpretation"]["bot_iot"][
        "one_benign_error_granularity_percent"
    ]
    bot_granularity_matches = all(
        value is None if count == 0 else abs(value - 100.0 / count) <= 1e-12
        for (name, count), value in zip(
            summary["effective_sample_interpretation"]["bot_iot"][
                "candidate_test_benign_counts"
            ].items(),
            bot_granularity.values(),
            strict=True,
        )
    ) and list(bot_granularity) == list(
        summary["effective_sample_interpretation"]["bot_iot"][
            "candidate_test_benign_counts"
        ]
    )

    doc_text = DOC_PATH.read_text(encoding="utf-8")
    role_guard = no_role_assignment(summary, compatibility, doc_text)
    score_guard = no_score_or_ranking(
        [summary, compatibility], [suitability, requirements, secondary]
    )
    secondary_is_ml = (
        {row["dataset_if_secondary"] for row in secondary} == {"n_baiot", "bot_iot"}
        and all(row["use_type"] == "ML experiment" for row in secondary)
    )

    checks = {
        "artifact_hashes_match": artifact_hashes_match,
        "source_artifact_hashes_match": source_artifact_hashes_match,
        **statuses,
        **coverage,
        "bot_entity_purity_compared_to_global_baselines": purity_matches,
        "cross_dataset_overlap_and_classification_match": cross_compatibility_matches,
        "n_baiot_raw_and_unique_totals_match_sources": n_counts_match,
        "bot_candidate_benign_error_granularity_matches": bot_granularity_matches,
        "secondary_use_cases_are_ml_for_both_datasets": secondary_is_ml,
        "no_numeric_score_or_ranking": score_guard,
        "no_primary_or_secondary_role_assignment": role_guard,
        "no_raw_dataset_reads_declared": summary["method"]["raw_dataset_reads"] == 0,
        "no_model_or_clustering_execution_declared": (
            summary["method"]["models_trained"] == 0
            and summary["method"]["clustering_runs"] == 0
        ),
    }
    overall = all(
        value if isinstance(value, bool) else all(value.values())
        for value in checks.values()
    )
    result = {
        "audit_batch": "A6 independent verification",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "source_a6_summary_sha256": sha256_file(AUDIT_DIR / "a6_evidence_summary.json"),
        "checks": checks,
        "recomputed": {
            "bot_binary_purity_baseline_adjustment": expected_binary,
            "bot_category_purity_baseline_adjustment": expected_category,
            "exact_named_feature_overlap": exact_overlap,
            "n_baiot_raw_rows": sum(n_split["raw_fine_class_counts"].values()),
            "n_baiot_unique_exact_vectors": sum(
                n_split["unique_vector_fine_class_counts"].values()
            ),
        },
        "verification_independence": (
            "This verifier does not import scripts/dataset_suitability_audit.py. It parses A0-A5 "
            "sources directly and independently checks hashes, ratios, coverage, statuses, "
            "baseline-adjusted purity, feature overlap, and A6 decision guards."
        ),
        "overall_status": "PASS" if overall else "FAIL",
    }
    output = AUDIT_DIR / "a6_evidence_verification.json"
    write_json_atomic(output, result)
    print(f"Wrote: {output}")
    print(f"Overall status: {result['overall_status']}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
