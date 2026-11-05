"""Accepted full-population comparison using the unchanged shared selector."""

import csv
from copy import deepcopy
from pathlib import Path

from iotguard.data.primary_package import sha256_file
from iotguard.evaluation.primary import select_validation
from iotguard.evaluation.primary_runtime import check_file, file_identity, read_json, write_json


def load_runs(directories):
    runs, seen = [], set()
    for directory in directories:
        for path in sorted(Path(directory).glob("*/result.json")):
            result = read_json(path)
            if result["run_id"] in seen:
                raise ValueError(f"Duplicate run ID: {result['run_id']}")
            seen.add(result["run_id"])
            receipt_path = path.with_name("acceptance.json")
            runs.append(
                {
                    "result": result,
                    "path": path,
                    "receipt_path": receipt_path,
                    "receipt": read_json(receipt_path) if receipt_path.exists() else None,
                }
            )
    return runs


def accepted_result(run):
    original, receipt = run["result"], run["receipt"]
    if receipt is None:
        raise ValueError("No independent acceptance receipt; full population is unproven")
    if (
        receipt.get("schema_version") != "primary_acceptance_v1"
        or receipt.get("status") != "PASS"
        or receipt.get("run_id") != original["run_id"]
        or receipt.get("result_sha256") != sha256_file(run["path"])
        or receipt.get("metrics") != original["metrics"]
        or receipt.get("TEST_opened") is not False
        or receipt.get("classifiers_fitted") is not False
    ):
        raise ValueError("Acceptance/result identity or status mismatch")
    for key in ("package_manifest_sha256", "protocol_revision", "validation_population_sha256"):
        if receipt.get(key) != original.get(key):
            raise ValueError(f"Acceptance/result mismatch: {key}")
    required = {"result.json", "probabilities.npy", "predictions.npy", "labels.npy", "metadata.npy"}
    if not required.issubset(receipt["payloads"]):
        raise ValueError("Incomplete accepted inference payloads")
    for name, identity in receipt["payloads"].items():
        if check_file(identity) != (run["path"].parent / name).resolve():
            raise ValueError("Receipt payload points outside the accepted run")
    check_file(receipt["model"])
    population = receipt["population"]
    if receipt.get("eligible_for_full_comparison") is not True or population["kind"] != "full":
        raise ValueError(
            f"Subset/diagnostic TRAIN: {population['rows']} / {population['rows_in_train']} rows"
        )
    if (
        population["rows"] != population["rows_in_train"]
        or population["train_population_sha256"] != population["parent_train_population_sha256"]
    ):
        raise ValueError("Full TRAIN declaration contradicts actual membership")
    if receipt["replay"]["reload_parity"] != "PASS" or receipt["validation_rows"] != sum(
        original["metrics"][k] for k in ("TN", "FP", "FN", "TP")
    ):
        raise ValueError("Incomplete validation/reload evidence")
    if original.get("diagnostic_only") or original.get("eligible_for_official_comparison") is False:
        raise ValueError("Original workflow declared diagnostic/ineligible")
    if original["resolved_configuration"]["input_view"] == "scaled":
        if original.get("runtime", {}).get("converged") is not True:
            raise ValueError("LR convergence gate failed")
    if (
        original["metrics"].get("threshold") != 0.5
        or original["resolved_configuration"].get("threshold") != 0.5
    ):
        raise ValueError("Threshold differs from protocol")
    result = deepcopy(original)
    result["train_population_sha256"] = population["train_population_sha256"]
    select_validation([result])
    return result


def choose_pool(runs):
    pool, excluded = [], []
    for run in runs:
        try:
            run["accepted_result"] = accepted_result(run)
            pool.append(run)
        except (ValueError, KeyError, OSError) as error:
            excluded.append({"run_id": run["result"]["run_id"], "reason": str(error)})
    if not pool:
        raise ValueError(f"No accepted full candidates: {excluded}")
    # Fail on every eligible identity conflict. Never select a majority group.
    select_validation([r["accepted_result"] for r in pool])
    return pool, excluded


def describe(run):
    result, receipt = run["result"], run["receipt"]
    m, config = result["metrics"], result["resolved_configuration"]
    population = receipt["population"] if receipt else {}
    row = {
        "run_id": result["run_id"],
        "algorithm": receipt["replay"]["input_contract"]["family"] if receipt else "unverified",
        "train_population_kind": population.get("kind", "unproven"),
        "actual_train_rows": population.get("rows"),
        "validation_rows": receipt.get("validation_rows") if receipt else None,
        **{k: m[k] for k in ("TN", "FP", "FN", "TP", "accuracy", "macro_f1", "fpr")},
        "threshold": m["threshold"],
        "input_view": config["input_view"],
        "training_source_revision": result["code_revision"],
        "training_dirty_worktree": result["dirty_worktree"],
        "package_manifest_sha256": result["package_manifest_sha256"],
        "train_population_sha256": population.get("train_population_sha256"),
        "validation_population_sha256": result["validation_population_sha256"],
        "model_sha256": receipt["model"]["sha256"] if receipt else None,
        "acceptance_sha256": sha256_file(run["receipt_path"]) if receipt else None,
    }
    for label in ("benign", "malicious"):
        for metric in ("precision", "recall", "f1", "support"):
            row[f"{label}_{metric}"] = m["per_class"][label][metric]
    return row


def compare(runs, output):
    pool, excluded = choose_pool(runs)
    remaining = sorted(pool, key=lambda r: r["result"]["run_id"])
    ranking = []
    while remaining:
        winner = select_validation([r["accepted_result"] for r in remaining])
        chosen = next(r for r in remaining if r["accepted_result"] is winner)
        ranking.append(chosen)
        remaining.remove(chosen)
    winner = ranking[0]["accepted_result"]
    wm = winner["metrics"]
    maximum = max(r["accepted_result"]["metrics"]["macro_f1"] for r in pool)
    ties = [
        r["result"]["run_id"]
        for r in ranking[1:]
        if maximum - r["result"]["metrics"]["macro_f1"] <= 1e-6
        and r["result"]["metrics"]["fpr"] == wm["fpr"]
        and r["result"]["metrics"]["per_class"]["malicious"]["recall"]
        == wm["per_class"]["malicious"]["recall"]
    ]
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    rank = {r["result"]["run_id"]: i + 1 for i, r in enumerate(ranking)}
    reason = {r["run_id"]: r["reason"] for r in excluded}
    rows = [
        {
            "rank": rank.get(r["result"]["run_id"]),
            **describe(r),
            "excluded_reason": reason.get(r["result"]["run_id"], ""),
        }
        for r in runs
    ]
    rows.sort(key=lambda r: (r["rank"] or 1_000_000, r["run_id"]))
    with (output / "comparison.csv").open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    selection = {
        "schema_version": "primary_selection_v1",
        "status": "VALIDATION_ONLY_SELECTED",
        "rule": "shared select_validation: max macro-F1, within 1e-6 lower FPR then higher "
        "malicious recall; remaining exact ties preserve sorted run_id order",
        "winner": winner["run_id"],
        "exact_ties_with_winner": ties,
        "ranking": [r["result"]["run_id"] for r in ranking],
        "excluded": excluded,
        "comparison": file_identity(output / "comparison.csv"),
        "accepted_candidates": {
            r["result"]["run_id"]: {
                "result": file_identity(r["path"]),
                "acceptance": file_identity(r["receipt_path"]),
            }
            for r in pool
        },
        "selected_result": winner,
        "TEST_used": False,
    }
    write_json(output / "selection.json", selection)
    return selection
