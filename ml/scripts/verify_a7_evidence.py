"""Independently verify the A7 dataset-role decision and G1 closure."""

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
ADR_PATH = PROJECT_ROOT / "docs" / "decisions" / "ADR-001-dataset-role-selection.md"

EXPECTED_CHECKPOINTS = {f"A{index}" for index in range(7)}
EXPECTED_CLOSURE_CHECKS = {
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
}
EXPECTED_JIRA_TASKS = {f"IOTG-{number}" for number in range(42, 51)}
FORBIDDEN_SCORE_KEYS = {"overall_score", "weighted_score", "ranking", "rank", "winner"}


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


def no_numeric_score_or_ranking(decision: Mapping[str, Any], adr_text: str) -> bool:
    forbidden_text = re.compile(r"\b(?:overall|weighted)\s+score\b|\brank(?:ing)?\b", re.I)
    return not (recursive_keys(decision) & FORBIDDEN_SCORE_KEYS) and not forbidden_text.search(
        adr_text
    )


def trace_is_complete(rows: Sequence[Mapping[str, str]]) -> bool:
    return (
        {row.get("checkpoint") for row in rows} == EXPECTED_CHECKPOINTS
        and all(row.get("status") == "PASS" for row in rows)
    )


def trace_hashes_match(rows: Sequence[Mapping[str, str]]) -> bool:
    for row in rows:
        paths = row["evidence_paths"].split("; ")
        hashes = row["evidence_sha256"].split("; ")
        if len(paths) != len(hashes):
            return False
        for relative, expected in zip(paths, hashes, strict=True):
            path = PROJECT_ROOT / relative
            if not path.is_file() or sha256_file(path) != expected:
                return False
    return True


def source_hashes_match(decision: Mapping[str, Any]) -> bool:
    sources = decision.get("source_evidence", {})
    return bool(sources) and all(
        (PROJECT_ROOT / relative).is_file()
        and sha256_file(PROJECT_ROOT / relative) == expected
        for relative, expected in sources.items()
    )


def requirement_gate(requirements: Sequence[Mapping[str, str]]) -> dict[str, Any]:
    rows = {row["requirement"]: row for row in requirements}
    expected = {"P1", "P2", "P3"}
    if not expected.issubset(rows):
        return {"matches": False, "observed": {}}
    observed = {
        "N-BaIoT": {gate: rows[gate]["n_baiot_status"] for gate in sorted(expected)},
        "Bot-IoT": {gate: rows[gate]["bot_iot_status"] for gate in sorted(expected)},
    }
    wanted = {
        "N-BaIoT": {"P1": "SUPPORTED", "P2": "SUPPORTED", "P3": "SUPPORTED"},
        "Bot-IoT": {
            "P1": "PARTIALLY_SUPPORTED",
            "P2": "SUPPORTED",
            "P3": "NOT_SUPPORTED",
        },
    }
    return {"matches": observed == wanted, "observed": observed}


def bot_candidate_benign_counts(bot: Mapping[str, Any]) -> dict[str, int]:
    return {
        "B1": bot["candidate_B1_supplied"]["class_distributions"]["test"]["binary"].get(
            "benign", 0
        ),
        "B2": bot["candidate_B2_random_stratified"]["test_distributions"]["binary"].get(
            "benign", 0
        ),
        "B3": bot["candidate_B3_temporal"]["test_distributions"]["binary"].get(
            "benign", 0
        ),
        "B4-saddr": bot["candidate_B4_entity_grouped"]["saddr"]["test_distributions"][
            "binary"
        ].get("benign", 0),
        "B4-pair": bot["candidate_B4_entity_grouped"]["saddr+daddr"][
            "test_distributions"
        ]["binary"].get("benign", 0),
    }


def main() -> int:
    required = {
        "a7_dataset_role_decision.json",
        "a7_decision_trace.csv",
        "a7_g1_closure_checklist.json",
        "a6_primary_requirement_matrix.csv",
        "a6_cross_dataset_compatibility.json",
        "n_baiot_split_leakage_summary.json",
        "bot_iot_split_feasibility.json",
        "label_audit_summary.json",
    }
    missing = sorted(name for name in required if not (AUDIT_DIR / name).is_file())
    if missing or not ADR_PATH.is_file():
        raise FileNotFoundError(f"missing A7 inputs: {missing}")

    decision = load_json(AUDIT_DIR / "a7_dataset_role_decision.json")
    trace = load_csv(AUDIT_DIR / "a7_decision_trace.csv")
    closure = load_json(AUDIT_DIR / "a7_g1_closure_checklist.json")
    requirements = load_csv(AUDIT_DIR / "a6_primary_requirement_matrix.csv")
    compatibility = load_json(AUDIT_DIR / "a6_cross_dataset_compatibility.json")
    n_split = load_json(AUDIT_DIR / "n_baiot_split_leakage_summary.json")
    bot_split = load_json(AUDIT_DIR / "bot_iot_split_feasibility.json")
    labels = load_json(AUDIT_DIR / "label_audit_summary.json")
    adr_text = ADR_PATH.read_text(encoding="utf-8")

    gate = requirement_gate(requirements)
    n2 = n_split["exact_feature_group_aware"]
    bot_benign = labels["bot_iot"]["all_features_raw_distributions"]["attack"]["0"]
    candidate_counts = bot_candidate_benign_counts(bot_split)

    source_facts = {
        "n_baiot_p1_p2_p3": gate["observed"].get("N-BaIoT"),
        "bot_iot_p1_p2_p3": gate["observed"].get("Bot-IoT"),
        "n2_exact_feature_overlap_rows": n2["exact_feature_overlap_rows"],
        "n2_fine_class_coverage": len(n2["test_fine_distribution"]),
        "bot_iot_benign_rows": bot_benign,
        "bot_candidate_test_benign_min": min(candidate_counts.values()),
        "bot_candidate_test_benign_max": max(candidate_counts.values()),
        "cross_dataset_exact_named_feature_overlap_count": compatibility[
            "exact_named_feature_overlap_count"
        ],
    }

    adr_decision_matches = (
        "**Primary = N-BaIoT**" in adr_text
        and "**Secondary = Bot-IoT**" in adr_text
        and decision.get("primary_dataset") == "N-BaIoT"
        and decision.get("secondary_dataset") == "Bot-IoT"
        and decision.get("decision_status") == "ACCEPTED"
    )
    closure_checks = closure.get("checks", {})
    closure_complete = (
        set(closure_checks) == EXPECTED_CLOSURE_CHECKS
        and all(closure_checks.values())
        and closure.get("closure_status") == "COMPLETE"
        and closure.get("all_mandatory_checks_pass") is True
    )
    jira = decision.get("jira_handoff", {})

    checks = {
        "a6_primary_gate_statuses_match_sources": gate["matches"],
        "role_assignment_follows_primary_gate": (
            gate["matches"]
            and decision.get("primary_dataset") == "N-BaIoT"
            and decision.get("secondary_dataset") == "Bot-IoT"
        ),
        "n2_zero_exact_vector_overlap_and_11_class_coverage": (
            n2["exact_feature_overlap_rows"] == 0
            and len(n2["test_fine_distribution"]) == 11
        ),
        "bot_benign_support_is_477": bot_benign == 477,
        "bot_candidate_test_benign_range_is_0_to_107": (
            min(candidate_counts.values()) == 0 and max(candidate_counts.values()) == 107
        ),
        "cross_dataset_exact_feature_overlap_is_zero": (
            compatibility["exact_named_feature_overlap_count"] == 0
        ),
        "no_direct_cross_dataset_input_space_claim": (
            compatibility["defensible_direct_model_input_space"] is False
            and decision["cross_dataset_policy"]["input_spaces_interchangeable"] is False
            and decision["cross_dataset_policy"]["direct_cross_dataset_model_evaluation"]
            == "NOT_CURRENTLY_DEFENSIBLE"
        ),
        "adr_matches_machine_decision": adr_decision_matches,
        "no_numeric_score_or_ranking": no_numeric_score_or_ranking(decision, adr_text),
        "no_final_split_adopted": (
            decision.get("adopted_final_split") is None
            and "does not adopt a final split" in adr_text.lower()
        ),
        "no_final_predictors_adopted": (
            decision.get("adopted_final_predictors") is None
            and "predictor list" in adr_text.lower()
        ),
        "no_preprocessing_implementation": decision.get("preprocessing_implemented") is False,
        "no_clustering_algorithm_selected": (
            decision.get("clustering_algorithm_selected") is False
        ),
        "g2_g3_deferrals_present": bool(
            decision.get("deferred_to_g2") and decision.get("deferred_to_g3")
        ),
        "rejected_alternative_present": (
            decision.get("rejected_alternative", {}).get("primary_dataset") == "Bot-IoT"
            and decision.get("rejected_alternative", {}).get("secondary_dataset") == "N-BaIoT"
        ),
        "decision_trace_contains_a0_through_a6": trace_is_complete(trace),
        "decision_trace_hashes_match": trace_hashes_match(trace),
        "decision_source_hashes_match": source_hashes_match(decision),
        "g1_checklist_complete": closure_complete,
        "jira_handoff_covers_iotg_42_through_50": (
            set(jira) == EXPECTED_JIRA_TASKS
            and all(item.get("status") == "TECHNICALLY_COMPLETE" for item in jira.values())
        ),
        "secondary_ml_use_is_required": (
            bool(decision.get("authorized_secondary_ml_candidates"))
            and "must select and execute" in decision.get("secondary_ml_requirement", "")
        ),
    }
    overall = all(checks.values())
    output_paths = (
        AUDIT_DIR / "a7_dataset_role_decision.json",
        AUDIT_DIR / "a7_decision_trace.csv",
        AUDIT_DIR / "a7_g1_closure_checklist.json",
        ADR_PATH,
    )
    result = {
        "audit_batch": "A7 independent verification",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "checks": checks,
        "recomputed_from_a0_a6": source_facts,
        "verified_output_sha256": {
            path.relative_to(PROJECT_ROOT).as_posix(): sha256_file(path) for path in output_paths
        },
        "verification_independence": (
            "This verifier does not import scripts/dataset_role_decision.py. It reads A0-A6 "
            "compact evidence directly, recomputes the role gate and key support facts, and "
            "cross-checks the ADR, decision, trace, and G1 closure artifacts."
        ),
        "overall_status": "PASS" if overall else "FAIL",
    }
    output = AUDIT_DIR / "a7_evidence_verification.json"
    write_json_atomic(output, result)
    print(f"Wrote: {output}")
    print(f"Overall status: {result['overall_status']}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
