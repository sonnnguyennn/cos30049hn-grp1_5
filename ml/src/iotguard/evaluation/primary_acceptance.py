"""Read-only evidence acceptance; never fits a classifier or opens TEST."""

import csv
import hashlib
import shutil
import time

import numpy as np
import psutil
from threadpoolctl import threadpool_limits

from iotguard.data.primary_package import sha256_file
from iotguard.evaluation.population import selected_population
from iotguard.evaluation.primary import binary_metrics, select_validation
from iotguard.evaluation.primary_runtime import (
    check_file,
    environment,
    evaluation_identity,
    file_identity,
    input_contract,
    payload_identities,
    predict_partition,
    read_json,
    write_json,
)


def check_result_package(result, package):
    m = package.manifest
    expected = {
        "package_version": m["package_version"],
        "package_manifest_sha256": sha256_file(package.root / "manifest.json"),
        "validation_population_sha256": m["files"]["VALIDATION_metadata.npy"]["sha256"],
        "protocol_revision": "primary_experiments_v1",
    }
    for key, value in expected.items():
        if result.get(key) != value:
            raise ValueError(f"Run/package identity mismatch: {key}")
    select_validation([result])
    config, metrics = result["resolved_configuration"], result["metrics"]
    if (
        config.get("threshold") != 0.5
        or metrics.get("threshold") != 0.5
        or metrics.get("positive_class") != "malicious"
        or metrics.get("confusion_order") != ["benign", "malicious"]
        or config.get("seeds") != {"python": 42, "numpy": 42, "scikit_learn": 42}
    ):
        raise ValueError("Run violates primary threshold, labels or seed policy")
    if result.get("diagnostic_only") or result.get("eligible_for_official_comparison") is False:
        raise ValueError("Run explicitly diagnostic/ineligible")


def checked_sampling(result, package, source, inventory):
    _, labels, metadata = package.load("TRAIN")
    sampling = result["resolved_configuration"]["parameters"].get("train_sampling")
    parent = package.manifest["files"]["TRAIN_metadata.npy"]["sha256"]
    if sampling is None:
        status = read_json(source / "run_status.json")
        if (
            result.get("run_mode") != "full"
            or result.get("diagnostic_only") is not False
            or result.get("eligible_for_official_comparison") is not True
            or status.get("status") != "BASELINES_COMPLETE"
            or status.get("training_location") != "Kaggle"
            or status.get("TEST_evaluated") is not False
            or status.get("train_rows") != len(labels)
            or status.get("validation_rows") != package.manifest["counts"]["VALIDATION"]
            or status.get("package_manifest_sha256") != result["package_manifest_sha256"]
            or status.get("bundle_manifest_sha256")
            != result["code_provenance"]["training_extension_bundle_sha256"]
        ):
            raise ValueError("Missing authenticated LR full-population workflow evidence")
        for name in ("run_status.json", "source/bundle_manifest.json", "scaler.json"):
            if sha256_file(source / name) != inventory["lr_archive"]["payload_checksums"][name]:
                raise ValueError(f"LR workflow binding failed: {name}")
        if (
            sha256_file(source / "scaler.json")
            != package.manifest["files"]["scaler.json"]["sha256"]
        ):
            raise ValueError("LR scaler differs from TRAIN package state")
        if result.get("runtime", {}).get("converged") is not True:
            raise ValueError("LR convergence is not established")
        idx = np.arange(len(labels), dtype="<i8")
        basis = "checksummed original Kaggle full workflow plus archive/source/count binding"
    else:
        idx_path = source / "train_sample_indices.npy"
        entry = inventory["files"][f"{source.name}/train_sample_indices.npy"]
        if sha256_file(idx_path) != entry["sha256"]:
            raise ValueError("Received sampling indices changed")
        idx = np.load(idx_path, allow_pickle=False)
        if idx.dtype != np.dtype("<i8"):
            raise ValueError("Unexpected sampling index representation")
        if hashlib.sha256(idx.tobytes()).hexdigest() != sampling["indices_sha256"]:
            raise ValueError("Saved indices disagree with historical result")
        if sampling["rows_in_train"] != len(labels) or sampling["rows"] != len(idx):
            raise ValueError("Sampling row counts disagree")
        fraction = sampling["fraction"]
        if not 0 < fraction <= 1:
            raise ValueError("Invalid sampling fraction")
        if sampling["method"] == "none: all TRAIN rows":
            if fraction != 1 or sampling["seed"] is not None:
                raise ValueError("Inconsistent full sampling policy")
        elif sampling["method"] == (
            "random sample inside TRAIN, same fraction per class, seeded, TRAIN only"
        ):
            if sampling["seed"] != 42:
                raise ValueError("Unexpected sampling seed")
            rng = np.random.default_rng(sampling["seed"])
            expected = []
            for label in (0, 1):
                rows = np.flatnonzero(labels == label)
                expected.append(
                    rng.choice(rows, size=max(1, round(len(rows) * fraction)), replace=False)
                )
            if not np.array_equal(idx, np.sort(np.concatenate(expected))):
                raise ValueError("Indices do not match the reported deterministic sampling")
        else:
            raise ValueError("Unrecognized historical sampling workflow")
        basis = "exact saved indices plus independent deterministic sampling reconstruction"
    identity = selected_population(metadata, idx)
    if (identity["kind"] == "full") != (sampling is None or sampling["fraction"] == 1):
        raise ValueError("Full/subset declaration contradicts actual membership")
    counts = np.bincount(labels[idx], minlength=2)
    identity["class_counts"] = {"benign": int(counts[0]), "malicious": int(counts[1])}
    if sampling and identity["class_counts"] != sampling["class_counts"]:
        raise ValueError("Saved indices disagree with reported class counts")
    if identity["kind"] == "full" and identity["train_population_sha256"] != parent:
        raise ValueError("Full TRAIN membership differs from package")
    if result["train_population_sha256"] not in {parent, identity["train_population_sha256"]}:
        raise ValueError("Unexplained historical TRAIN fingerprint")
    identity.update(
        {
            "parent_train_population_sha256": parent,
            "historical_train_population_sha256": result["train_population_sha256"],
            "historical_parent_as_subset": identity["kind"] == "subset"
            and result["train_population_sha256"] == parent,
            "basis": basis,
        }
    )
    return identity


def check_historical_errors(source, package, probabilities, labels):
    path = source / "misclassified_rows.csv"
    if not path.exists():
        return "not available; independent full replay supplies new row-aligned evidence"
    analysis = read_json(source / "error_analysis.json")
    if analysis.get("detail_truncated") is not False:
        raise ValueError("Historical error rows are truncated")
    _, _, meta = package.load("VALIDATION")
    actual = set()
    for i in np.flatnonzero((probabilities >= 0.5) != labels):
        record = meta[i]
        source_name = package.manifest["sources"][int(record["source"])]["source_relative_path"]
        actual.add((source_name, int(record["row"])))
    with path.open(newline="", encoding="utf-8") as stream:
        historical = list(csv.DictReader(stream))
    expected = {(r["source_file"], int(r["source_row"])) for r in historical}
    if expected != actual or len(historical) != len(actual):
        raise ValueError("Replayed error row identities differ from original error analysis")
    return "PASS: exact source file and 1-based row match on every original error"


def accept_run(package, source, result_name, inventory, output):
    """Produce an additive acceptance sidecar and aligned inference evidence."""
    output.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter()
    model_path = None
    try:
        result_path = source / result_name
        result = read_json(result_path)
        if result_name == "result.json":
            for name in ("result.json", "run_notes.json"):
                expected = inventory["files"][f"{source.name}/{name}"]
                if sha256_file(source / name) != expected["sha256"]:
                    raise ValueError(f"Historical received file changed: {name}")
            notes = read_json(source / "run_notes.json")
            if notes.get("test_partition_used") is not False:
                raise ValueError("Historical run does not establish TEST non-use")
            provenance = next(r for r in inventory["runs"] if r["run_id"] == result["run_id"])
            if provenance["training_source_revision"] != result["code_revision"]:
                raise ValueError("Inventory/source revision mismatch")
        else:
            if (
                sha256_file(result_path)
                != inventory["lr_archive"]["payload_checksums"][result_name]
            ):
                raise ValueError("LR original result changed")
            notes = read_json(source / "environment.json")
            provenance = result["code_provenance"]
        check_result_package(result, package)
        population = checked_sampling(result, package, source, inventory)
        contract = input_contract(package, result)
        model_name = {
            "RF": "model.joblib",
            "XGB": "model.json",
            "LR": "lr_model.joblib",
            "Dummy": "dummy_model.joblib",
        }[contract["family"]]
        model_path = source / model_name
        expected_model = (
            inventory["files"][f"{source.name}/{model_name}"]["sha256"]
            if result_name == "result.json"
            else inventory["lr_archive"]["payload_checksums"][model_name]
        )
        if sha256_file(model_path) != expected_model:
            raise ValueError("Original model checksum differs")
        model_identity = file_identity(model_path)
        with threadpool_limits(limits=2):
            labels, probabilities, replay = predict_partition(
                package, result, model_path, "VALIDATION", output
            )
        metrics = binary_metrics(labels, probabilities)
        if metrics != result["metrics"]:
            raise ValueError(f"Full VALIDATION replay metrics differ: {metrics}")
        if result_name != "result.json":
            prefix = "lr" if contract["family"] == "LR" else "dummy"
            original = np.load(source / f"{prefix}_validation_probabilities.npy", mmap_mode="r")
            original_predictions = np.load(
                source / f"{prefix}_validation_predictions.npy", mmap_mode="r"
            )
            if not np.allclose(
                probabilities, original, rtol=1e-12, atol=1e-12
            ) or not np.array_equal(probabilities >= 0.5, original_predictions):
                raise ValueError("Original LR/Dummy validation probabilities do not replay")
            replay["original_probability_max_delta"] = float(
                np.max(np.abs(probabilities - original))
            )
        replay["original_error_row_parity"] = check_historical_errors(
            source, package, probabilities, labels
        )
        check_file(model_identity)
        shutil.copyfile(result_path, output / "result.json")
        receipt = {
            "schema_version": "primary_acceptance_v1",
            "status": "PASS",
            "run_id": result["run_id"],
            "result_sha256": sha256_file(result_path),
            "original_result": file_identity(result_path),
            "model": model_identity,
            "population": population,
            "metrics": metrics,
            "validation_rows": len(labels),
            "validation_population_sha256": result["validation_population_sha256"],
            "package_manifest_sha256": result["package_manifest_sha256"],
            "protocol_revision": result["protocol_revision"],
            "eligible_for_full_comparison": population["kind"] == "full",
            "replay": replay,
            "training_provenance": provenance,
            "reported_training_environment": notes.get("environment", notes),
            "evaluation_environment": environment(),
            "evaluation_source": evaluation_identity(),
            "inventory_identity": inventory["inventory_identity"],
            "payloads": payload_identities(output),
            "elapsed_seconds": time.perf_counter() - started,
            "peak_process_rss_bytes": getattr(
                psutil.Process().memory_info(), "peak_wset", psutil.Process().memory_info().rss
            ),
            "TEST_opened": False,
            "classifiers_fitted": False,
            "original_experiment_owner": "Le Minh Hieu"
            if result_name == "result.json"
            else ("Phan Nguyen Son"),
            "acceptance_owner": "Phan Nguyen Son",
        }
        write_json(output / "acceptance.json", receipt)
        print(
            f"PASS {result['run_id']}: {population['kind']}, macro-F1={metrics['macro_f1']:.12f}",
            flush=True,
        )
        return receipt
    except Exception as error:
        write_json(
            output / "failure.json",
            {
                "status": "FAILED",
                "error": repr(error),
                "source": str(source),
                "result_name": result_name,
                "model": str(model_path),
                "elapsed_seconds": time.perf_counter() - started,
                "TEST_opened": False,
                "classifiers_fitted": False,
                "environment": environment(),
            },
        )
        raise
