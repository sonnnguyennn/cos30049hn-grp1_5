"""Freeze-gated, inference-only final evaluation. Selection never receives TEST."""

import time
import traceback
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import psutil
from threadpoolctl import threadpool_limits

from iotguard.data.primary_package import sha256_file
from iotguard.evaluation.comparison import accepted_result
from iotguard.evaluation.primary import _binary_metrics_core, select_validation
from iotguard.evaluation.primary_acceptance import check_result_package
from iotguard.evaluation.primary_runtime import (
    EXPECTED_MANIFEST,
    check_file,
    environment,
    evaluation_identity,
    file_identity,
    input_contract,
    payload_identities,
    predict_partition,
    read_json,
    verified_package,
    write_json,
)


def utc_now():
    return datetime.now(UTC).isoformat()


def checked_selection(path):
    selection = read_json(path)
    if (
        selection.get("schema_version") != "primary_selection_v1"
        or selection.get("status") != "VALIDATION_ONLY_SELECTED"
        or selection.get("TEST_used") is not False
    ):
        raise ValueError("Require a validation-only accepted selection")
    check_file(selection["comparison"])
    candidates, receipts = [], {}
    for run_id, files in selection["accepted_candidates"].items():
        result_path = check_file(files["result"])
        acceptance_path = check_file(files["acceptance"])
        receipt = read_json(acceptance_path)
        result = accepted_result(
            {
                "path": result_path,
                "result": read_json(result_path),
                "receipt": receipt,
                "receipt_path": acceptance_path,
            }
        )
        if result["run_id"] != run_id:
            raise ValueError("Candidate run ID differs")
        candidates.append(result)
        receipts[run_id] = receipt
    candidates.sort(key=lambda r: r["run_id"])
    winner = select_validation(candidates)
    if winner != selection["selected_result"] or winner["run_id"] != selection["winner"]:
        raise ValueError("Selection decision does not follow the shared validation selector")
    return selection, winner, receipts[winner["run_id"]]


def freeze_model(selection_path, package_root, output):
    """Persist the exact decision before any final TEST array is opened."""
    selection, result, acceptance = checked_selection(selection_path)
    package, package_receipt = verified_package(package_root)
    check_result_package(result, package)
    evaluation = evaluation_identity()
    if evaluation["dirty_worktree"]:
        raise ValueError("Commit the tested evaluation implementation before freezing")
    record = {
        "schema_version": "primary_model_freeze_v1",
        "status": "FROZEN_VALIDATION_ONLY",
        "created_utc": utc_now(),
        "selected_run_id": result["run_id"],
        "training_source_revision": result["code_revision"],
        "training_dirty_worktree": result["dirty_worktree"],
        "evaluation_source": evaluation,
        "model": acceptance["model"],
        "selected_result": result,
        "selection": file_identity(selection_path),
        "comparison": selection["comparison"],
        "selected_acceptance": selection["accepted_candidates"][result["run_id"]]["acceptance"],
        "validation_payloads": acceptance["payloads"],
        "package": {
            "root": str(package.root),
            "manifest": file_identity(package.root / "manifest.json"),
            "version": package.manifest["package_version"],
            "counts": package.manifest["counts"],
            "partition_payloads": {
                p: {
                    name: package.manifest["files"][f"{p}_{name}.npy"]
                    for name in ("X", "y", "metadata")
                }
                for p in ("TRAIN", "VALIDATION", "TEST")
            },
        },
        "input_contract": input_contract(package, result),
        "reported_training_environment": acceptance["reported_training_environment"],
        "accepted_validation_environment": acceptance["evaluation_environment"],
        "final_evaluation_environment": environment(),
        "package_pretest_verification": package_receipt,
        "decision_basis": "Accepted full TRAIN and full VALIDATION only; shared selector unchanged",
        "TEST_opened": False,
        "TEST_metrics_seen": False,
        "no_refit": True,
        "threshold_locked": 0.5,
        "original_experiment_owner": acceptance["original_experiment_owner"],
        "selection_and_final_evaluation_owner": "Phan Nguyen Son",
    }
    write_json(output, record)
    return record


def validate_freeze(path, package_root):
    """All checks in this function complete before TEST arrays are accessed."""
    freeze = read_json(path)
    if (
        freeze.get("schema_version") != "primary_model_freeze_v1"
        or freeze.get("status") != "FROZEN_VALIDATION_ONLY"
        or freeze.get("TEST_opened") is not False
        or freeze.get("TEST_metrics_seen") is not False
        or freeze.get("no_refit") is not True
        or freeze.get("threshold_locked") != 0.5
    ):
        raise ValueError("Invalid final evaluation freeze gate")
    check_file(freeze["model"])
    check_file(freeze["selection"])
    check_file(freeze["comparison"])
    check_file(freeze["selected_acceptance"])
    for identity in freeze["validation_payloads"].values():
        check_file(identity)
    for identity in freeze["evaluation_source"]["implementation"].values():
        check_file(identity)
    package, receipt = verified_package(package_root)
    check_result_package(freeze["selected_result"], package)
    manifest_identity = file_identity(package.root / "manifest.json")
    if (
        manifest_identity["sha256"] != EXPECTED_MANIFEST
        or manifest_identity != freeze["package"]["manifest"]
    ):
        raise ValueError("Frozen package manifest differs")
    if input_contract(package, freeze["selected_result"]) != freeze["input_contract"]:
        raise ValueError("Frozen preprocessing/input contract differs")
    for partition, parts in freeze["package"]["partition_payloads"].items():
        for name, identity in parts.items():
            if package.manifest["files"][f"{partition}_{name}.npy"] != identity:
                raise ValueError("Frozen partition identity differs")
    if environment() != freeze["final_evaluation_environment"]:
        raise ValueError("Final runtime differs from frozen runtime")
    _, winner, acceptance = checked_selection(freeze["selection"]["path"])
    if (
        winner != freeze["selected_result"]
        or winner["run_id"] != freeze["selected_run_id"]
        or acceptance["model"] != freeze["model"]
    ):
        raise ValueError("Frozen model and selection decision differ")
    return freeze, package, receipt


def final_metrics(y_true, probabilities, *, validated_freeze):
    """Only the final workflow uses this entry point; training binary_metrics stays sealed."""
    if (
        validated_freeze.get("status") != "FROZEN_VALIDATION_ONLY"
        or validated_freeze.get("no_refit") is not True
        or validated_freeze.get("threshold_locked") != 0.5
    ):
        raise PermissionError("A validated freeze is required for final reporting")
    metrics = _binary_metrics_core(y_true, probabilities, partition="TEST", threshold=0.5)
    metrics["schema_version"] = "primary_final_metrics_v1"
    return metrics


def final_evaluate(freeze_path, package_root, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    start = time.perf_counter()
    test_opened = False
    log = output / "execution.jsonl"

    def event(name, **details):
        with log.open("a", encoding="utf-8") as stream:
            import json

            stream.write(json.dumps({"utc": utc_now(), "event": name, **details}) + "\n")

    try:
        event("STARTED", freeze=file_identity(freeze_path))
        freeze, package, pretest_package = validate_freeze(freeze_path, package_root)
        event("FREEZE_VALIDATED", TEST_opened=False)
        validation_dir = output / "pretest_validation_replay"
        validation_dir.mkdir()
        with threadpool_limits(limits=2):
            _, validation_probabilities, parity = predict_partition(
                package,
                freeze["selected_result"],
                freeze["model"]["path"],
                "VALIDATION",
                validation_dir,
            )
        original = np.load(
            freeze["validation_payloads"]["probabilities.npy"]["path"],
            allow_pickle=False,
            mmap_mode="r",
        )
        if not np.allclose(
            validation_probabilities, original, rtol=1e-12, atol=1e-12
        ) or not np.array_equal(validation_probabilities >= 0.5, original >= 0.5):
            raise ValueError("Selected model fails accepted VALIDATION prediction parity")
        gate = {
            "status": "PASS",
            "utc": utc_now(),
            "freeze": file_identity(freeze_path),
            "model": freeze["model"],
            "TEST_opened": False,
            "validation_parity": parity,
            "package": pretest_package,
        }
        write_json(output / "pretest_gate.json", gate)
        event("PRETEST_GATE_PASS", TEST_opened=False)
        # Only now verify and open the sealed TEST payloads of the frozen package.
        test_opened = True
        event(
            "TEST_ACCESS_STARTED",
            frozen_population=freeze["package"]["partition_payloads"]["TEST"]["metadata"]["sha256"],
        )
        for name in ("X", "y", "metadata"):
            path = package.root / f"TEST_{name}.npy"
            if sha256_file(path) != freeze["package"]["partition_payloads"]["TEST"][name]["sha256"]:
                raise ValueError(f"Frozen TEST payload checksum mismatch: {name}")
        test_start = time.perf_counter()
        with threadpool_limits(limits=2):
            labels, probabilities, replay = predict_partition(
                package,
                freeze["selected_result"],
                freeze["model"]["path"],
                "TEST",
                output,
                allow_test=True,
            )
        metrics = final_metrics(labels, probabilities, validated_freeze=freeze)
        write_json(output / "metrics.json", metrics)
        write_json(output / "environment.json", environment())
        event(
            "FINAL_TEST_COMPLETE",
            rows=len(labels),
            inference_seconds=time.perf_counter() - test_start,
        )
        receipt = {
            "schema_version": "primary_final_evaluation_v1",
            "status": "FINAL_TEST_COMPLETE",
            "created_utc": utc_now(),
            "freeze": file_identity(freeze_path),
            "selected_run_id": freeze["selected_run_id"],
            "model": freeze["model"],
            "training_source_revision": freeze["training_source_revision"],
            "evaluation_source": freeze["evaluation_source"],
            "package_manifest_sha256": freeze["package"]["manifest"]["sha256"],
            "TEST_population_sha256": freeze["package"]["partition_payloads"]["TEST"]["metadata"][
                "sha256"
            ],
            "metrics": metrics,
            "inference": replay,
            "elapsed_seconds": time.perf_counter() - start,
            "peak_process_rss_bytes": getattr(
                psutil.Process().memory_info(), "peak_wset", psutil.Process().memory_info().rss
            ),
            "payloads": payload_identities(output),
            "pretest_validation_payloads": payload_identities(validation_dir),
            "classifiers_fitted": False,
            "threshold_changed": False,
            "post_TEST_reselection_allowed": False,
        }
        check_file(freeze["model"])
        write_json(output / "receipt.json", receipt)
        return receipt
    except Exception as error:
        event("FAILED", error=repr(error), TEST_access_started=test_opened)
        write_json(
            output / "failure.json",
            {
                "status": "FAILED",
                "error": repr(error),
                "traceback": traceback.format_exc(),
                "TEST_access_started": test_opened,
                "freeze": file_identity(freeze_path),
                "environment": environment(),
                "elapsed_seconds": time.perf_counter() - start,
                "classifiers_fitted": False,
            },
        )
        raise
