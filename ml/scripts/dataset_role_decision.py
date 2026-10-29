"""Create the A7 dataset-role decision and G1 closure evidence.

A7 consumes only compact A0-A6 artifacts. It assigns project-specific dataset
roles but does not adopt a split, predictor list, preprocessing implementation,
clustering algorithm, or model.
"""

# ruff: noqa: E501

from __future__ import annotations

import csv
import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

PROJECT_ROOT = Path(__file__).resolve().parents[1]
AUDIT_DIR = PROJECT_ROOT / "artifacts" / "audit"
ADR_PATH = PROJECT_ROOT / "docs" / "decisions" / "ADR-001-dataset-role-selection.md"

A6_COMMIT_SHA = "98b392d954327e5557298a7d6baca206da03514c"
ALLOWED_DATASETS = {"N-BaIoT", "Bot-IoT"}
EXPECTED_PRIMARY_GATE = {
    "N-BaIoT": {"P1": "SUPPORTED", "P2": "SUPPORTED", "P3": "SUPPORTED"},
    "Bot-IoT": {
        "P1": "PARTIALLY_SUPPORTED",
        "P2": "SUPPORTED",
        "P3": "NOT_SUPPORTED",
    },
}
MANDATORY_CLOSURE_ITEMS = (
    "raw_source_inventory_and_hashes_completed",
    "structural_schema_audit_completed",
    "taxonomy_audit_completed",
    "missing_invalid_audit_completed",
    "duplicate_audit_completed",
    "imbalance_audit_completed",
    "leakage_split_feasibility_audit_completed",
    "cross_dataset_suitability_synthesis_completed",
    "dataset_roles_formally_assigned",
    "source_datasets_remained_immutable",
    "g2_g3_constraints_handed_off",
)
FORBIDDEN_SCORE_KEYS = {"overall_score", "weighted_score", "ranking", "rank", "winner"}
LOCAL_TIMEZONE = ZoneInfo("Asia/Ho_Chi_Minh")

TRACE_SOURCES: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "A0": (
        "source/protocol freeze",
        "fa50dc1e05a395ca9837275007c020b0f652ea68",
        ("artifacts/audit/source_inventory_summary.json",),
    ),
    "A1": (
        "source inventory and hashes",
        "fa50dc1e05a395ca9837275007c020b0f652ea68",
        (
            "artifacts/audit/source_inventory_summary.json",
            "artifacts/manifests/n_baiot_raw_manifest.csv",
            "artifacts/manifests/n_baiot_extracted_manifest.csv",
            "artifacts/manifests/bot_iot_raw_manifest.csv",
        ),
    ),
    "A2": (
        "archive access, structure, and schema",
        "fa50dc1e05a395ca9837275007c020b0f652ea68",
        (
            "artifacts/audit/structural_audit_summary.json",
            "artifacts/audit/a2_evidence_verification.json",
        ),
    ),
    "A3": (
        "label taxonomy",
        "ba0e642308907671c0a2ffc2cdf80562fa332bb5",
        (
            "artifacts/audit/label_audit_summary.json",
            "artifacts/audit/a3_evidence_verification.json",
        ),
    ),
    "A4": (
        "missing, invalid, duplicate, and lineage audit",
        "6bf4505fc01000a99f31ed7de3b41c56f058def4",
        (
            "artifacts/audit/a4_audit_summary.json",
            "artifacts/audit/a4_evidence_verification.json",
        ),
    ),
    "A5": (
        "imbalance, leakage, and split feasibility",
        "483c8ace60ad91f75f724e53159b1b57ffc4a1f9",
        (
            "artifacts/audit/a5_audit_summary.json",
            "artifacts/audit/a5_evidence_verification.json",
        ),
    ),
    "A6": (
        "cross-dataset suitability synthesis",
        A6_COMMIT_SHA,
        (
            "artifacts/audit/a6_evidence_summary.json",
            "artifacts/audit/a6_evidence_verification.json",
            "artifacts/audit/a6_primary_requirement_matrix.csv",
            "artifacts/audit/a6_cross_dataset_compatibility.json",
        ),
    ),
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


def write_csv_atomic(
    path: Path, fieldnames: Sequence[str], rows: Sequence[Mapping[str, Any]]
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


def validate_roles(primary: str, secondary: str) -> None:
    if primary not in ALLOWED_DATASETS or secondary not in ALLOWED_DATASETS:
        raise ValueError("dataset role uses an unsupported dataset value")
    if primary == secondary:
        raise ValueError("primary and secondary datasets must differ")


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


def contains_forbidden_score(value: Any) -> bool:
    return bool(recursive_keys(value) & FORBIDDEN_SCORE_KEYS)


def requirement_statuses(rows: Sequence[Mapping[str, str]]) -> dict[str, dict[str, str]]:
    return {
        "N-BaIoT": {row["requirement"]: row["n_baiot_status"] for row in rows},
        "Bot-IoT": {row["requirement"]: row["bot_iot_status"] for row in rows},
    }


def validate_primary_gate(statuses: Mapping[str, Mapping[str, str]]) -> None:
    observed = {
        dataset: {gate: statuses[dataset][gate] for gate in ("P1", "P2", "P3")}
        for dataset in ALLOWED_DATASETS
    }
    if observed != EXPECTED_PRIMARY_GATE:
        raise ValueError(f"A6 P1-P3 evidence contradicts the expected role decision: {observed}")


def trace_rows() -> list[dict[str, str]]:
    rows = []
    for checkpoint, (scope, commit, paths) in TRACE_SOURCES.items():
        missing = [path for path in paths if not (PROJECT_ROOT / path).is_file()]
        if missing:
            raise FileNotFoundError(f"missing {checkpoint} trace evidence: {missing}")
        hashes = [sha256_file(PROJECT_ROOT / path) for path in paths]
        rows.append(
            {
                "checkpoint": checkpoint,
                "scope": scope,
                "checkpoint_commit": commit,
                "evidence_paths": "; ".join(paths),
                "evidence_sha256": "; ".join(hashes),
                "status": "PASS",
                "decision_use": (
                    "establishes the auditable evidence chain used by the role-specific gate"
                ),
            }
        )
    return rows


def build_closure_checklist(
    checkpoint_statuses: Mapping[str, bool],
    *,
    roles_assigned: bool,
    sources_immutable: bool,
    constraints_handed_off: bool,
) -> dict[str, Any]:
    checks = {
        "raw_source_inventory_and_hashes_completed": checkpoint_statuses.get("A1", False),
        "structural_schema_audit_completed": checkpoint_statuses.get("A2", False),
        "taxonomy_audit_completed": checkpoint_statuses.get("A3", False),
        "missing_invalid_audit_completed": checkpoint_statuses.get("A4", False),
        "duplicate_audit_completed": checkpoint_statuses.get("A4", False),
        "imbalance_audit_completed": checkpoint_statuses.get("A5", False),
        "leakage_split_feasibility_audit_completed": checkpoint_statuses.get("A5", False),
        "cross_dataset_suitability_synthesis_completed": checkpoint_statuses.get("A6", False),
        "dataset_roles_formally_assigned": roles_assigned,
        "source_datasets_remained_immutable": sources_immutable,
        "g2_g3_constraints_handed_off": constraints_handed_off,
    }
    complete = set(checks) == set(MANDATORY_CLOSURE_ITEMS) and all(checks.values())
    return {
        "gate": "G1",
        "closure_status": "COMPLETE" if complete else "OPEN",
        "checks": checks,
        "all_mandatory_checks_pass": complete,
    }


def source_safety_is_accepted(a5: Mapping[str, Any]) -> bool:
    safety = a5.get("source_safety", {})
    expected = {"n_baiot_raw", "n_baiot_extracted", "bot_iot_raw"}
    return set(safety) == expected and all(
        item.get("metadata_unchanged") is True
        and item.get("before") == item.get("after")
        for item in safety.values()
    )


def bot_candidate_benign_counts(bot_split: Mapping[str, Any]) -> dict[str, int]:
    return {
        "B1 supplied train/test": bot_split["candidate_B1_supplied"]["class_distributions"][
            "test"
        ]["binary"].get("benign", 0),
        "B2 random stratified record": bot_split["candidate_B2_random_stratified"][
            "test_distributions"
        ]["binary"].get("benign", 0),
        "B3 chronological numeric-order": bot_split["candidate_B3_temporal"][
            "test_distributions"
        ]["binary"].get("benign", 0),
        "B4 entity grouped by saddr": bot_split["candidate_B4_entity_grouped"]["saddr"][
            "test_distributions"
        ]["binary"].get("benign", 0),
        "B4 entity grouped by saddr+daddr": bot_split["candidate_B4_entity_grouped"][
            "saddr+daddr"
        ]["test_distributions"]["binary"].get("benign", 0),
    }


def build_decision(context: Mapping[str, Any]) -> dict[str, Any]:
    primary = "N-BaIoT"
    secondary = "Bot-IoT"
    validate_roles(primary, secondary)

    statuses = context["requirement_statuses"]
    validate_primary_gate(statuses)
    n2 = context["n2"]
    bot_counts = context["bot_candidate_benign_counts"]
    compatibility = context["compatibility"]
    n_facts = context["n_facts"]
    bot_facts = context["bot_facts"]

    decision: dict[str, Any] = {
        "gate": "G1",
        "decision_status": "ACCEPTED",
        "primary_dataset": primary,
        "secondary_dataset": secondary,
        "role_scope": (
            "IoTGuard's core benign-vs-malicious classification, Assignment-2 pipeline, "
            "and later structured-feature deployment"
        ),
        "decision_rule": {
            "type": "requirements_gate_without_numeric_scoring",
            "mandatory_primary_gates": {
                "P1": "core binary support must be SUPPORTED",
                "P2": "a leakage-controlled evaluation candidate must be SUPPORTED",
                "P3": "reasonable core-class evaluation resolution must be SUPPORTED",
            },
            "enabling_requirements": (
                "P4-P8 must provide a defensible path, with unresolved implementation choices "
                "explicitly deferred"
            ),
            "limitation_policy": (
                "Prefer controllable limitations with verified mitigation paths over intrinsic "
                "source-distribution limits that prevent reliable primary evaluation."
            ),
        },
        "primary_requirement_statuses": statuses[primary],
        "secondary_requirement_statuses": statuses[secondary],
        "decision_basis": [
            "N-BaIoT passes P1, P2, and P3; Bot-IoT does not pass P1 or P3 at the required level.",
            "N-BaIoT has a stable ordered numeric schema and a verified zero-exact-vector-overlap feasibility path.",
            "Bot-IoT's 477 benign rows are an intrinsic limitation of the audited local 5% source and cannot be repaired for evaluation by resampling.",
            "Both datasets retain meaningful project value when assigned different roles.",
        ],
        "primary_evidence": {
            "raw_rows": n_facts["raw_rows"],
            "benign_rows": n_facts["benign_rows"],
            "malicious_rows": n_facts["malicious_rows"],
            "logical_csvs": n_facts["logical_csvs"],
            "ordered_numeric_features": n_facts["ordered_numeric_features"],
            "fine_classes": n_facts["fine_classes"],
            "unique_exact_vectors": n_facts["unique_exact_vectors"],
            "naive_test_exact_overlap_percent_approx": n_facts[
                "naive_test_exact_overlap_percent"
            ],
            "quality_failure_totals": n_facts["quality_failure_totals"],
            "n2_feasibility": {
                "status": "leading audited candidate / feasibility reference; not final split",
                "train_rows": n2["train_rows"],
                "test_rows": n2["test_rows"],
                "exact_feature_overlap_rows": n2["exact_feature_overlap_rows"],
                "fine_class_coverage": len(n2["test_fine_distribution"]),
                "minimum_fine_class_test_support": min(n2["test_fine_distribution"].values()),
                "maximum_distribution_drift_percentage_points": max(
                    abs(value) for value in n2["distribution_drift_percentage_points"].values()
                ),
            },
        },
        "secondary_evidence": {
            "all_features_records": bot_facts["all_features_records"],
            "benign_rows": bot_facts["benign_rows"],
            "malicious_rows": bot_facts["malicious_rows"],
            "category_count": bot_facts["category_count"],
            "subcategory_count": bot_facts["subcategory_count"],
            "rare_label_counts": bot_facts["rare_label_counts"],
            "candidate_test_benign_counts": bot_counts,
            "candidate_test_benign_range": [min(bot_counts.values()), max(bot_counts.values())],
        },
        "limitation_classification": {
            "N-BaIoT": {
                "mitigable": [
                    "exact-vector boundary leakage can be controlled by group-aware assignment",
                    "scaling, feature selection, sampling, and duplicate weighting remain design choices",
                ],
                "intrinsic_or_source_bound": [
                    "the audited corpus contains a large exact-duplicate/effective-sample burden",
                    "device coverage differs for two devices",
                ],
            },
            "Bot-IoT": {
                "mitigable": [
                    "representation, risky-field eligibility, and lexical port parsing can be locked deterministically",
                    "entity-grouped candidates can control a specified entity boundary",
                ],
                "intrinsic_or_source_bound": [
                    "only 477 benign observations exist in the audited local 5% source",
                    "data exfiltration, keylogging, and theft labels have 6, 73, and 79 observations",
                ],
            },
        },
        "rejected_alternative": {
            "primary_dataset": secondary,
            "secondary_dataset": primary,
            "reason": (
                "For this project's primary role, Bot-IoT fails the present P3 evaluation-resolution "
                "gate and only partially supports P1. Entity grouping cannot create additional "
                "independent benign or rare-class observations. This is role-specific and does not "
                "make Bot-IoT unusable or universally inferior."
            ),
        },
        "primary_constraints": [
            "The core supervised objective remains benign versus malicious.",
            "Family and fine labels remain preserved as metadata and analysis labels.",
            "Naive row-random evaluation is prohibited without duplicate-boundary control.",
            "Blind global deduplication is not adopted.",
            "Every future split must check exact-vector boundary leakage or prove an equivalent control.",
            "The 115-column order and feature-generation provenance must be versioned.",
            "N2 is a leading audited candidate and feasibility reference, not the final split.",
            "Device holdout remains a possible stress-test family, not automatically the main protocol.",
        ],
        "secondary_constraints": [
            "attack, category, and subcategory are target metadata and not ordinary predictors.",
            "pkSeqID and the unnamed physical index are lineage/identifier metadata and excluded from ordinary predictors unless a future ADR explicitly overturns this.",
            "Treatment of stime, ltime, seq, addresses, ports, and other context fields remains deferred.",
            "Hexadecimal ports require deterministic lexical-aware parsing if retained.",
            "The semantics of the -1 port token remain unresolved.",
            "A representation must be explicitly locked before any official experiment.",
            "The supplied split is not considered proven leakage-free.",
        ],
        "authorized_secondary_ml_candidates": [
            "entity-grouped binary classification sensitivity",
            "representation-sensitivity classification",
            "behavioral-feature clustering after deterministic field treatment",
            "imbalance and context-memorization sensitivity",
        ],
        "secondary_ml_requirement": (
            "G2/G3 must select and execute at least one technically defensible Bot-IoT ML experiment; "
            "the secondary dataset may not be used only for EDA."
        ),
        "cross_dataset_policy": {
            "direct_matrix_merge_in_core_pipeline": False,
            "exact_named_feature_overlap_count": compatibility["exact_named_feature_overlap_count"],
            "shared_binary_target_concept": True,
            "input_spaces_interchangeable": False,
            "direct_cross_dataset_model_evaluation": "NOT_CURRENTLY_DEFENSIBLE",
            "future_exception": (
                "Only a separately justified and verified common representation may revisit this policy."
            ),
        },
        "adopted_final_split": None,
        "adopted_final_predictors": None,
        "preprocessing_implemented": False,
        "clustering_algorithm_selected": False,
        "model_selected": False,
        "deferred_to_g2": [
            "lock the primary 115-field representation, order, and provenance contract",
            "decide predictor eligibility and feature selection",
            "select scaling or normalization",
            "select duplicate weighting without blind global deduplication",
            "select imbalance and resampling policy",
            "lock the Bot-IoT representation and field treatment, including ports and unresolved sentinels",
            "materialize the reproducible processed Assignment-2 package and versioned feature contract",
        ],
        "deferred_to_g3": [
            "adopt the final train, validation, and test protocol; N2 is only the leading audited reference",
            "decide whether device holdout is used as a stress test",
            "select and evaluate classifiers and the final model",
            "select the clustering algorithm, sampling, and evaluation protocol",
            "select and execute at least one bounded Bot-IoT secondary ML experiment",
            "finalize the inference payload after the feature contract and defer Pi claims until benchmarking",
        ],
        "a6_checkpoint_commit": A6_COMMIT_SHA,
        "a7_commit": None,
    }
    if contains_forbidden_score(decision):
        raise ValueError("A7 decision contains a prohibited score or ranking key")
    return decision


def jira_handoff() -> dict[str, dict[str, str]]:
    return {
        "IOTG-42": {"scope": "Audit N-BaIoT", "status": "TECHNICALLY_COMPLETE", "evidence": "A1-A5 N-BaIoT compact artifacts"},
        "IOTG-43": {"scope": "Audit Bot-IoT", "status": "TECHNICALLY_COMPLETE", "evidence": "A1-A5 Bot-IoT compact artifacts"},
        "IOTG-44": {"scope": "Compare dataset schemas", "status": "TECHNICALLY_COMPLETE", "evidence": "n_baiot_schema.json; bot_iot_schema.json; a6_cross_dataset_compatibility.json"},
        "IOTG-45": {"scope": "Inspect labels and attack classes", "status": "TECHNICALLY_COMPLETE", "evidence": "label_audit_summary.json; A3 verification"},
        "IOTG-46": {"scope": "Inspect missing/invalid values", "status": "TECHNICALLY_COMPLETE", "evidence": "A4 quality artifacts and verification"},
        "IOTG-47": {"scope": "Inspect duplicate records", "status": "TECHNICALLY_COMPLETE", "evidence": "A4 duplicate artifacts and verification"},
        "IOTG-48": {"scope": "Assess class imbalance", "status": "TECHNICALLY_COMPLETE", "evidence": "A5 effective-imbalance artifacts"},
        "IOTG-49": {"scope": "Assess leakage risks", "status": "TECHNICALLY_COMPLETE", "evidence": "A5 leakage and split-feasibility artifacts"},
        "IOTG-50": {"scope": "Decide primary vs secondary dataset", "status": "TECHNICALLY_COMPLETE", "evidence": "ADR-001; a7_dataset_role_decision.json"},
    }


def render_adr(decision: Mapping[str, Any], source_hashes: Mapping[str, str]) -> str:
    n2 = decision["primary_evidence"]["n2_feasibility"]
    bot = decision["secondary_evidence"]
    jira = jira_handoff()
    lines = [
        "# ADR-001: Dataset Role Selection for IoTGuard",
        "",
        "- **ADR ID:** ADR-001",
        f"- **Date:** {datetime.now(LOCAL_TIMEZONE).date().isoformat()}",
        "- **Status:** Accepted",
        "",
        "## Context",
        "",
        "IoTGuard requires one primary dataset for the core benign-versus-malicious pipeline and one secondary dataset for a meaningful additional ML experiment. A0-A6 established source provenance, structure, taxonomy, quality, duplicates, imbalance, leakage surfaces, split feasibility, and role-specific suitability without selecting roles.",
        "",
        "## Decision drivers",
        "",
        "The primary dataset must pass the non-numeric P1-P3 gate: core binary support, a leakage-controlled evaluation path, and meaningful evaluation resolution for both binary classes. P4-P8 must provide a defensible future path, while implementation choices remain deferred. Controllable limitations with verified mitigations are preferred over intrinsic source-distribution limits that prevent reliable primary evaluation.",
        "",
        "## Decision",
        "",
        "- **Primary = N-BaIoT**",
        "- **Secondary = Bot-IoT**",
        "",
        "This is a role-specific decision for IoTGuard, not a claim that N-BaIoT is universally better.",
        "",
        "## Evidence used",
        "",
        "The decision traces A0-A6 through `artifacts/audit/a7_decision_trace.csv`. Key source hashes are preserved in `artifacts/audit/a7_dataset_role_decision.json`.",
        "",
        f"- A6 summary SHA-256: `{source_hashes['artifacts/audit/a6_evidence_summary.json']}`",
        f"- A6 primary-requirement matrix SHA-256: `{source_hashes['artifacts/audit/a6_primary_requirement_matrix.csv']}`",
        f"- N-BaIoT leakage summary SHA-256: `{source_hashes['artifacts/audit/n_baiot_split_leakage_summary.json']}`",
        f"- Bot-IoT split-feasibility SHA-256: `{source_hashes['artifacts/audit/bot_iot_split_feasibility.json']}`",
        "",
        "## Why N-BaIoT is primary",
        "",
        "N-BaIoT passes P1, P2, and P3. It contains 7,062,606 rows (555,932 benign and 6,506,674 malicious), 89 logical CSVs, one stable ordered 115-numeric-field schema, and 11 fine classes. A4 found no missing, NaN, infinity, numeric-parse, or read failures in those fields.",
        "",
        "Its severe duplicate burden is material: 7,062,606 rows collapse to 2,482,676 exact vectors, naive row-random splitting leaves about 84.7% of test rows with an exact training vector, and device holdout alone does not remove that overlap. The limitation has a verified control path: N2 assigns exact-vector groups across boundaries, retaining 11/11 fine classes with zero exact-vector overlap, "
        f"{n2['train_rows']:,} train rows, {n2['test_rows']:,} test rows, and minimum fine-class test support {n2['minimum_fine_class_test_support']:,}. N2 demonstrates feasibility; it is not adopted as the final split.",
        "",
        "Blind global deduplication is not adopted because duplicate weighting materially changes class proportions. G2/G3 must explicitly prevent exact-vector boundary leakage or demonstrate an equivalent control.",
        "",
        "## Why Bot-IoT is secondary",
        "",
        f"Bot-IoT contains {bot['all_features_records']:,} all-feature records but only {bot['benign_rows']} benign observations versus {bot['malicious_rows']:,} malicious observations. Data exfiltration, keylogging, and theft have 6, 73, and 79 rows. Audited candidate tests contain {bot['candidate_test_benign_range'][0]}-{bot['candidate_test_benign_range'][1]} benign rows. The supplied split has near-total familiar-entity overlap; the chronological candidate loses benign coverage; entity grouping controls selected boundaries but cannot create independent benign or rare-class observations.",
        "",
        "Bot-IoT remains useful because it provides a different flow/context schema, attack taxonomy, imbalance regime, representation structure, and entity/context leakage surface. It is authorized for a bounded future ML experiment rather than EDA-only use.",
        "",
        "## Rejected alternative",
        "",
        "Bot-IoT as primary and N-BaIoT as secondary was rejected for this project role. Bot-IoT only partially supports P1 and does not support P3 at the required level; resampling cannot improve independent evaluation resolution. This does not describe Bot-IoT as bad or unusable.",
        "",
        "## Cross-dataset policy",
        "",
        "Direct merging of the two feature matrices is outside the core pipeline. Exact named feature overlap is zero and the input definitions are not interchangeable. Direct cross-dataset model evaluation is **NOT_CURRENTLY_DEFENSIBLE** unless a future ADR justifies and verifies a common representation.",
        "",
        "## Consequences",
        "",
        "### Positive",
        "",
        "- The core pipeline receives a dataset with supported binary evaluation resolution and a verified leakage-control path.",
        "- Bot-IoT adds a meaningfully different secondary ML setting without constraining the deployment pipeline.",
        "- G1 closes with explicit traceability and without selecting downstream implementation details.",
        "",
        "### Negative",
        "",
        "- N-BaIoT's duplicate burden requires split-boundary checks and an explicit weighting policy.",
        "- The primary input contract is high-dimensional and depends on preserving 115-field order and provenance.",
        "- Bot-IoT secondary claims remain bounded by benign and rare-label scarcity.",
        "",
        "### Constraints",
        "",
        *[f"- {item}" for item in decision["primary_constraints"]],
        *[f"- Bot-IoT: {item}" for item in decision["secondary_constraints"]],
        "",
        "## What this decision does not decide",
        "",
        "A7 does not adopt a final split, predictor list, feature selection, scaler, duplicate-weighting policy, imbalance policy, clustering protocol, processed dataset, API payload, Raspberry Pi model, classifier, or final model. It performs no preprocessing, training, or clustering.",
        "",
        "## G2/G3 follow-up",
        "",
        "### Deferred to G2",
        "",
        *[f"- {item}" for item in decision["deferred_to_g2"]],
        "",
        "### Deferred to G3",
        "",
        *[f"- {item}" for item in decision["deferred_to_g3"]],
        "",
        "## Jira handoff record",
        "",
        "No external Jira mutation was performed.",
        "",
        "| Task | Scope | G1 evidence outcome |",
        "|---|---|---|",
        *[
            f"| {task} | {details['scope']} | {details['status']}: {details['evidence']} |"
            for task, details in jira.items()
        ],
        "",
        "## Traceability",
        "",
        "A0-A6 evidence paths, checkpoint commits, and SHA-256 values are recorded in `artifacts/audit/a7_decision_trace.csv`. The machine-readable decision and G1 checklist are independently checked by `scripts/verify_a7_evidence.py`.",
        "",
        "## Revisit trigger",
        "",
        "Revisit only if the audited source representation changes, new independent benign support becomes available, a verified common feature representation is created, or later G2/G3 evidence invalidates a mandatory gate."
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    required = {
        path for _, _, paths in TRACE_SOURCES.values() for path in paths
    } | {
        "artifacts/audit/n_baiot_split_leakage_summary.json",
        "artifacts/audit/bot_iot_split_feasibility.json",
        "artifacts/audit/label_audit_summary.json",
        "artifacts/audit/a5_audit_summary.json",
        "artifacts/audit/a6_primary_requirement_matrix.csv",
        "artifacts/audit/a6_cross_dataset_compatibility.json",
    }
    missing = sorted(path for path in required if not (PROJECT_ROOT / path).is_file())
    if missing:
        raise FileNotFoundError(f"missing compact A0-A6 evidence: {missing}")

    checkpoint_statuses: dict[str, bool] = {}
    for checkpoint, (_, _, paths) in TRACE_SOURCES.items():
        json_paths = [path for path in paths if path.endswith(".json")]
        payloads = [load_json(PROJECT_ROOT / path) for path in json_paths]
        statuses = [payload["overall_status"] for payload in payloads if "overall_status" in payload]
        checkpoint_statuses[checkpoint] = bool(statuses) and all(
            status == "PASS" for status in statuses
        )
    if not all(checkpoint_statuses.values()):
        raise ValueError(f"G1 checkpoint chain is incomplete: {checkpoint_statuses}")

    requirement_rows = load_csv(AUDIT_DIR / "a6_primary_requirement_matrix.csv")
    n_split = load_json(AUDIT_DIR / "n_baiot_split_leakage_summary.json")
    bot_split = load_json(AUDIT_DIR / "bot_iot_split_feasibility.json")
    compatibility = load_json(AUDIT_DIR / "a6_cross_dataset_compatibility.json")
    a5 = load_json(AUDIT_DIR / "a5_audit_summary.json")
    structural = load_json(AUDIT_DIR / "structural_audit_summary.json")
    labels = load_json(AUDIT_DIR / "label_audit_summary.json")
    a4 = load_json(AUDIT_DIR / "a4_audit_summary.json")

    n_labels = labels["n_baiot"]
    bot_distributions = labels["bot_iot"]["all_features_raw_distributions"]
    n_quality = a4["quality_findings"]["n_baiot"]
    n_facts = {
        "raw_rows": structural["n_baiot"]["total_data_rows"],
        "benign_rows": n_labels["binary_distribution"]["benign"],
        "malicious_rows": n_labels["binary_distribution"]["malicious"],
        "logical_csvs": structural["n_baiot"]["logical_csv_count"],
        "ordered_numeric_features": structural["n_baiot"]["observed_column_count"][0],
        "fine_classes": n_labels["fine_class_count"],
        "unique_exact_vectors": sum(n_split["unique_vector_fine_class_counts"].values()),
        "naive_test_exact_overlap_percent": n_split["naive_stratified_row_random"][
            "overlap_percent_mean"
        ],
        "quality_failure_totals": {
            "missing_rows": n_quality["missing_any_rows"],
            "nan": n_quality["nan_total"],
            "positive_inf": n_quality["positive_inf_total"],
            "negative_inf": n_quality["negative_inf_total"],
            "numeric_parse": n_quality["numeric_parse_failure_total"],
        },
    }
    bot_facts = {
        "all_features_records": structural["bot_iot"]["all_features_rows"],
        "benign_rows": bot_distributions["attack"]["0"],
        "malicious_rows": bot_distributions["attack"]["1"],
        "category_count": len(bot_distributions["category"]),
        "subcategory_count": len(bot_distributions["subcategory"]),
        "rare_label_counts": {
            "Data Exfiltration": bot_distributions["subcategory"]["Data_Exfiltration"],
            "Keylogging": bot_distributions["subcategory"]["Keylogging"],
            "Theft": bot_distributions["category"]["Theft"],
        },
    }

    context = {
        "requirement_statuses": requirement_statuses(requirement_rows),
        "n2": n_split["exact_feature_group_aware"],
        "bot_candidate_benign_counts": bot_candidate_benign_counts(bot_split),
        "compatibility": compatibility,
        "n_facts": n_facts,
        "bot_facts": bot_facts,
    }
    decision = build_decision(context)

    source_paths = sorted(required)
    source_hashes = {path: sha256_file(PROJECT_ROOT / path) for path in source_paths}
    decision["source_evidence"] = source_hashes
    decision["jira_handoff"] = jira_handoff()
    decision["generated_at_utc"] = datetime.now(UTC).isoformat()

    trace = trace_rows()
    closure = build_closure_checklist(
        checkpoint_statuses,
        roles_assigned=(
            decision["decision_status"] == "ACCEPTED"
            and decision["primary_dataset"] != decision["secondary_dataset"]
        ),
        sources_immutable=source_safety_is_accepted(a5),
        constraints_handed_off=bool(decision["deferred_to_g2"] and decision["deferred_to_g3"]),
    )
    closure["evidence_basis"] = {
        "checkpoint_trace": "artifacts/audit/a7_decision_trace.csv",
        "role_decision": "artifacts/audit/a7_dataset_role_decision.json",
        "source_immutability": "artifacts/audit/a5_audit_summary.json#source_safety",
        "current_metadata_recheck": (
            "required by A7 Phase 0 and recorded in the review report; no raw content read"
        ),
    }
    if closure["closure_status"] != "COMPLETE":
        raise ValueError(f"G1 cannot close: {closure}")

    decision_path = AUDIT_DIR / "a7_dataset_role_decision.json"
    trace_path = AUDIT_DIR / "a7_decision_trace.csv"
    closure_path = AUDIT_DIR / "a7_g1_closure_checklist.json"
    write_json_atomic(decision_path, decision)
    write_csv_atomic(
        trace_path,
        (
            "checkpoint",
            "scope",
            "checkpoint_commit",
            "evidence_paths",
            "evidence_sha256",
            "status",
            "decision_use",
        ),
        trace,
    )
    write_json_atomic(closure_path, closure)
    write_text_atomic(ADR_PATH, render_adr(decision, source_hashes))

    print(f"Wrote A7 decision: {decision_path}")
    print(f"Wrote G1 closure checklist: {closure_path}")
    print(f"Wrote ADR: {ADR_PATH}")
    print("Primary: N-BaIoT")
    print("Secondary: Bot-IoT")
    print("G1 closure status: COMPLETE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
