"""Independent post-run verification without executing models or training code."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from iotguard.evaluation.primary_runtime import check_file, file_identity, read_json, write_json


def verify(review, freeze_path, output):
    inventory = read_json(review / "inventory.json")
    for relative, identity in inventory["files"].items():
        path = Path(inventory["received_root"]) / relative
        if file_identity(path)["sha256"] != identity["sha256"]:
            raise ValueError(f"Original received evidence changed: {relative}")
    check_file(inventory["lr_archive"])
    freeze = read_json(freeze_path)
    final_dir = review / "final_test_01"
    receipt = read_json(final_dir / "receipt.json")
    if (
        receipt["status"] != "FINAL_TEST_COMPLETE"
        or receipt["freeze"]["sha256"] != file_identity(freeze_path)["sha256"]
        or receipt["model"] != freeze["model"]
    ):
        raise ValueError("Final receipt/freeze identity mismatch")
    check_file(freeze["model"])
    check_file(freeze["selection"])
    check_file(freeze["comparison"])
    for identity in freeze["evaluation_source"]["implementation"].values():
        check_file(identity)
    for collection in (receipt["payloads"], receipt["pretest_validation_payloads"]):
        for identity in collection.values():
            check_file(identity)
    y = np.load(final_dir / "labels.npy", allow_pickle=False)
    p = np.load(final_dir / "probabilities.npy", allow_pickle=False)
    pred = np.load(final_dir / "predictions.npy", allow_pickle=False)
    if (
        p.shape != y.shape
        or not np.isfinite(p).all()
        or np.any((p < 0) | (p > 1))
        or not np.isin(y, [0, 1]).all()
        or not np.array_equal(pred, p >= 0.5)
    ):
        raise ValueError("Invalid or misaligned final predictions")
    tn, fp, fn, tp = map(int, confusion_matrix(y, pred, labels=[0, 1]).ravel())
    precision, recall, f1, support = precision_recall_fscore_support(y, pred, labels=[0, 1])
    independent = {
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "TP": tp,
        "accuracy": float((pred == y).mean()),
        "macro_f1": float(f1.mean()),
        "fpr": fp / (tn + fp),
        "per_class": {
            label: {
                "precision": float(precision[i]),
                "recall": float(recall[i]),
                "f1": float(f1[i]),
                "support": int(support[i]),
            }
            for i, label in enumerate(("benign", "malicious"))
        },
    }
    metrics = receipt["metrics"]
    for key in ("TN", "FP", "FN", "TP", "accuracy", "macro_f1", "fpr"):
        if not np.isclose(independent[key], metrics[key], atol=1e-15, rtol=0):
            raise ValueError(f"Independent metric mismatch: {key}")
    for label in ("benign", "malicious"):
        for key, value in independent["per_class"][label].items():
            if not np.isclose(value, metrics["per_class"][label][key], atol=1e-15, rtol=0):
                raise ValueError(f"Independent per-class metric mismatch: {label}/{key}")
    events = [json.loads(line) for line in (final_dir / "execution.jsonl").read_text().splitlines()]
    names = [e["event"] for e in events]
    if (
        names
        != [
            "STARTED",
            "FREEZE_VALIDATED",
            "PRETEST_GATE_PASS",
            "TEST_ACCESS_STARTED",
            "FINAL_TEST_COMPLETE",
        ]
        or not read_json(final_dir / "pretest_gate.json")["status"] == "PASS"
    ):
        raise ValueError("Final gate execution order differs")
    package_root = Path(freeze["package"]["root"])
    manifest = read_json(check_file(freeze["package"]["manifest"]))
    for name, identity in manifest["files"].items():
        actual = file_identity(package_root / name)
        if actual["sha256"] != identity["sha256"] or actual["bytes"] != identity["bytes"]:
            raise ValueError(f"Original package changed: {name}")
    for output_name, package_name in (
        ("labels.npy", "TEST_y.npy"),
        ("metadata.npy", "TEST_metadata.npy"),
    ):
        if (
            file_identity(final_dir / output_name)["sha256"]
            != manifest["files"][package_name]["sha256"]
        ):
            raise ValueError("Final labels/row identities differ from frozen TEST")
    acceptances = {}
    for path in sorted((review / "accepted_01").glob("*/acceptance.json")):
        data = read_json(path)
        check_file(data["model"])
        for identity in data["payloads"].values():
            check_file(identity)
        acceptances[data["run_id"]] = {
            "receipt": file_identity(path),
            "status": data["status"],
            "model": data["model"],
            "population": data["population"],
            "metrics": data["metrics"],
            "original_result": data["original_result"],
            "evaluation_source_revision": data["evaluation_source"]["revision"],
            "evaluation_dirty_worktree": data["evaluation_source"]["dirty_worktree"],
            "reported_training_environment": data["reported_training_environment"],
            "evaluation_environment": data["evaluation_environment"],
            "reload_parity": data["replay"]["reload_parity"],
            "original_error_row_parity": data["replay"]["original_error_row_parity"],
        }
    selection = read_json(freeze["selection"]["path"])
    # Git may normalize checkout CRLF; retain both identities rather than rewriting evidence.
    repo = Path(__file__).resolve().parents[2]
    git_freeze = subprocess.check_output(
        ["git", "show", "HEAD:ml/artifacts/manifests/primary_model_freeze_20261105.json"], cwd=repo
    )
    result = {
        "schema_version": "primary_final_independent_verification_v1",
        "status": "PASS",
        "inventory": file_identity(review / "inventory.json"),
        "original_received_files_unchanged": len(inventory["files"]),
        "original_package_payloads_unchanged": len(manifest["files"]),
        "original_lr_archive_unchanged": True,
        "accepted_runs": acceptances,
        "full_ranking": selection["ranking"],
        "excluded_subsets": selection["excluded"],
        "comparison": freeze["comparison"],
        "selection": freeze["selection"],
        "freeze": file_identity(freeze_path),
        "freeze_git_blob_sha256": hashlib.sha256(git_freeze).hexdigest(),
        "freeze_git_values_match": json.loads(git_freeze) == freeze,
        "final_receipt": file_identity(final_dir / "receipt.json"),
        "final_metrics": metrics,
        "independent_sklearn_metrics": independent,
        "gate_event_order": names,
        "metric_agreement_absolute_tolerance": 1e-15,
        "model_deserialized_by_this_verifier": False,
        "classifiers_fitted": False,
        "new_TEST_inference_by_this_verifier": False,
    }
    if not result["freeze_git_values_match"]:
        raise ValueError("Committed freeze values differ from executed freeze")
    write_json(output, result)
    print(f"PASS: {len(acceptances)} accepted models, final TEST independently recomputed")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review", required=True, type=Path)
    parser.add_argument("--freeze", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    verify(args.review, args.freeze, args.output)
