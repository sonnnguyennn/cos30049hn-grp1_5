"""Standalone Kaggle-only Bot-IoT secondary baselines; no preprocessing fitting."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
import warnings
import zipfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PACKAGE_SHA = "dd4fdc2551df68f294968f38ca3ecced0c27ac8bc2d1e1ae22239b7d676bae7c"
PREPROCESSOR_SHA = "6714eefbc631f46d5dfe948b6de2d0b0194ac377439f656570980fdcb71074da"
ANCHOR = "413952c7fb9dc5b9ed4e85b5bd90fcf56ad147a666dacec19fd8ada49a90b844"
PROTOCOL = "bot_iot_secondary_kaggle_baseline_v1"
BUNDLE_ID = "iotguard_bot_iot_secondary_v2_kaggle_v1"
sys.dont_write_bytecode = True


def sha_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def write_json(path, value):
    with Path(path).open("xb") as handle:
        handle.write(json_bytes(value))


def configuration():
    return {
        "protocol": PROTOCOL,
        "threshold": 0.5,
        "threads": 4,
        "chunk_size": 8192,
        "dummy": {"strategy": "most_frequent", "random_state": 1729},
        "lr": {
            "solver": "lbfgs",
            "penalty": "l2",
            "C": 1.0,
            "tol": 1e-4,
            "max_iter": 1000,
            "class_weight": None,
            "fit_intercept": True,
            "random_state": 1729,
        },
        "smoke": {
            "group_limit": 8192,
            "seed": 1729,
            "anchor": ANCHOR,
            "ordering": "sha256(ASCII bot-iot-v2-smoke:1729: + group_hex),tie group_hex",
            "TRAIN": "first8192 hash-ranked groups union fixed mixed-label anchor; "
            "retain every row, no duplication or label balancing",
            "VALIDATION": "entire fixed VALIDATION",
        },
    }


def assert_kaggle():
    if (
        platform.system() != "Linux"
        or not Path("/kaggle/input").is_dir()
        or not Path("/kaggle/working").is_dir()
    ):
        raise RuntimeError("Classifier fitting is restricted to Kaggle; local execution forbidden")


def check_bundle():
    manifest = json.loads((ROOT / "bundle_manifest.json").read_bytes())
    if (
        manifest["bundle_id"] != BUNDLE_ID
        or manifest["expected_package_manifest"] != PACKAGE_SHA
        or len(manifest["source_git_revision"]) != 40
        or type(manifest["source_dirty_worktree"]) is not bool
    ):
        raise ValueError("Bundle source identity invalid")
    required = {
        "kaggle_secondary_runner.py",
        "vendor/bot_iot_package_v2.py",
        "protocols/bot_iot_secondary_kaggle_baseline_v1.md",
        "README.md",
        "requirements.txt",
        "contracts/bot_iot_secondary_ml_v2.json",
    }
    if not required.issubset(manifest["files"]):
        raise ValueError("Bundle missing required runtime payload")
    actual = {
        str(p.relative_to(ROOT)).replace("\\", "/")
        for p in ROOT.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    }
    if actual != set(manifest["files"]) | {"bundle_manifest.json"}:
        raise ValueError("Bundle checksum coverage mismatch")
    for name, expected in manifest["files"].items():
        path = (ROOT / name).resolve()
        if not path.is_relative_to(ROOT) or sha_file(path) != expected:
            raise ValueError(f"Bundle payload mismatch:{name}")
    if manifest["configuration"] != configuration():
        raise ValueError("Configuration differs from frozen bundle")
    return manifest, sha_file(ROOT / "bundle_manifest.json")


def environment():
    names = ("numpy", "scikit-learn", "joblib", "psutil", "threadpoolctl")
    versions = {name: importlib.metadata.version(name) for name in names}
    numpy_version = tuple(int(n) for n in versions["numpy"].split(".")[:2])
    sklearn_version = tuple(int(n) for n in versions["scikit-learn"].split(".")[:2])
    if not (1, 26) <= numpy_version < (3, 0) or not (1, 6) <= sklearn_version < (2, 0):
        raise RuntimeError("Unsupported runtime; review requirements then run a new smoke")
    return {
        "python": sys.version,
        "platform": platform.platform(),
        "packages": versions,
        "KAGGLE_KERNEL_RUN_TYPE": os.environ.get("KAGGLE_KERNEL_RUN_TYPE"),
    }


def find_package(explicit=None):
    candidates = (
        [Path(explicit) / "manifest.json"]
        if explicit
        else Path("/kaggle/input").rglob("manifest.json")
    )
    found = [p for p in candidates if p.is_file() and sha_file(p) == PACKAGE_SHA]
    if len(found) != 1 or not found[0].resolve().is_relative_to(Path("/kaggle/input")):
        raise ValueError("Attach exactly one pinned Bot-IoT package under /kaggle/input")
    return found[0].parent.resolve()


def preflight_package(root, run_directory):
    """Only this separate standalone subprocess may perform mechanical TEST checks."""
    manifest = json.loads((root / "manifest.json").read_bytes())
    if sha_file(root / "manifest.json") != PACKAGE_SHA:
        raise ValueError("Package manifest differs from pinned release")
    for name in ("verify_package.py", "bot_iot_package_v2.py"):
        if sha_file(root / name) != manifest["files"][name]["sha256"]:
            raise ValueError("Untrusted standalone verification implementation")
    receipt = run_directory / "package_verification.json"
    temporary = run_directory / "mechanical_verifier_temp"
    temporary.mkdir(exist_ok=False)
    verifier_environment = {**os.environ, "TMPDIR": str(temporary)}
    started = time.perf_counter()
    with (run_directory / "package_verification.log").open("x", encoding="utf-8") as log:
        subprocess.run(
            [
                sys.executable,
                "-I",
                str(root / "verify_package.py"),
                str(root),
                "--expected-manifest",
                PACKAGE_SHA,
                "--output",
                str(receipt),
            ],
            cwd=run_directory,
            env=verifier_environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=True,
        )
    result = json.loads(receipt.read_bytes())
    if (
        result["status"] != "PASS_STANDALONE_FULL_VERIFICATION"
        or result["manifest_sha256"] != PACKAGE_SHA
        or result["performance_metrics_computed"]
        or result["encoded_features"] != 36
    ):
        raise ValueError("Standalone package preflight failed")
    return {
        "sha256": sha_file(receipt),
        "elapsed_seconds": time.perf_counter() - started,
        "mechanical_TEST_check": "standalone subprocess only",
        "result": result["status"],
    }


def selected_groups(records, limit=8192, anchor=ANCHOR):
    """Pure deterministic group selection; label counts never affect ordering."""
    records = list(records)
    ordered = sorted(
        records,
        key=lambda r: (
            hashlib.sha256(("bot-iot-v2-smoke:1729:" + r[0]).encode("ascii")).hexdigest(),
            r[0],
        ),
    )
    chosen = {r[0] for r in ordered[:limit]} | {anchor}
    selected = [r for r in records if r[0] in chosen]
    if anchor not in {r[0] for r in selected}:
        raise ValueError("Fixed mixed-label smoke anchor missing")
    if not all(sum(r[y + 1] for r in selected) > 0 for y in (0, 1)):
        raise ValueError("Smoke requires both classes; never reroll or rebalance")
    return sorted(selected)


def smoke_plan(package, directory):
    db = sqlite3.connect((package.root / "groups.sqlite").as_uri() + "?mode=ro", uri=True)
    # Only existing TRAIN groups are inspected; no TEST groups or populations loaded.
    records = db.execute("SELECT sha,n0,n1 FROM groups WHERE partition=0").fetchall()
    db.close()
    selected = selected_groups(records, configuration()["smoke"]["group_limit"])
    group_path = directory / "smoke_selected_groups.jsonl"
    with group_path.open("xb") as out:
        for record in selected:
            out.write(json.dumps(record, separators=(",", ":")).encode() + b"\n")
    keys = {r[0] for r in selected}
    member_path = directory / "smoke_TRAIN_membership.jsonl"
    digest = hashlib.sha256()
    counts = [0, 0]
    with (
        (package.root / "TRAIN_membership.jsonl").open("rb") as source,
        member_path.open("xb") as out,
    ):
        for raw in source:
            record = json.loads(raw)
            if record[4] in keys:
                digest.update(raw)
                out.write(raw)
                counts[int(record[3])] += 1
    if counts != [sum(r[y + 1] for r in selected) for y in (0, 1)]:
        raise ValueError("Smoke whole-group membership/count reconciliation failed")
    return {
        "groups": len(selected),
        "rows": sum(counts),
        "binary_rows": counts,
        "membership_sha256": digest.hexdigest(),
        "groups_sha256": sha_file(group_path),
    }, keys


def resources(train_rows, available_ram, free_disk):
    cache_bytes = train_rows * 36 * 8
    ram = max(3 * 1024**3, cache_bytes * 6 + 2 * 1024**3)
    disk = cache_bytes + 2 * 1024**3  # memberships, model outputs, archive and headroom
    return {
        "status": "PASS" if available_ram >= ram and free_disk >= disk else "BLOCKED",
        "available_ram_bytes": available_ram,
        "required_ram_bytes": ram,
        "free_disk_bytes": free_disk,
        "required_disk_bytes": disk,
        "float64_encoded_cache_bytes": cache_bytes,
        "policy": "conservative estimate; no fallback sampling/precision/solver change",
    }


def accept_smoke(receipt, expected_identity, expected_plan):
    if (
        receipt.get("status") != "SMOKE_PASS"
        or receipt.get("mode") != "smoke"
        or receipt.get("identity") != expected_identity
        or receipt.get("smoke_plan") != expected_plan
        or receipt.get("train_population_sha256") != expected_plan["membership_sha256"]
        or receipt.get("training_rows") != expected_plan["rows"]
        or receipt.get("validation_rows") != 733704
        or receipt.get("validation_population_sha256")
        != "161376d656b8fe967f6a12549e92f4642c302f9cae46d07980910d16cd6aca1f"
        or receipt.get("eligible_for_full_population_comparison") is not False
        or receipt.get("resource_preflight", {}).get("status") != "PASS"
        or receipt.get("package_verification", {}).get("result")
        != "PASS_STANDALONE_FULL_VERIFICATION"
        or receipt.get("training_runner_TEST_opened") is not False
        or receipt.get("TEST_performance_evaluated") is not False
        or not receipt.get("models")
        or set(receipt["models"]) != {"dummy", "lr"}
        or not all(
            m.get("converged") is True and m.get("reload_parity") == "PASS"
            for m in receipt["models"].values()
        )
    ):
        raise ValueError(
            "Full requires matching successful smoke; rerun smoke on any identity change"
        )


def metric_tables(labels, probabilities, group_sizes):
    """Global sufficient statistics, no chunk-F1 averaging and no classifier operations."""
    import numpy as np

    y = np.asarray(labels)
    scores = np.asarray(probabilities)
    sizes = np.asarray(group_sizes)
    if (
        y.ndim != 1
        or scores.shape != y.shape
        or sizes.shape != y.shape
        or not np.isin(y, [0, 1]).all()
        or not np.isfinite(scores).all()
        or (scores < 0).any()
        or (scores > 1).any()
        or not np.isfinite(sizes).all()
        or (sizes < 1).any()
        or (sizes != np.floor(sizes)).any()
    ):
        raise ValueError("Invalid probabilities, labels or original group sizes")
    predicted = scores >= 0.5

    def report(weighted):
        totals = np.zeros(4, dtype=np.float64)
        for start in range(0, len(y), 32768):
            yy, pp = y[start : start + 32768], predicted[start : start + 32768]
            weights = 1 / sizes[start : start + 32768] if weighted else np.ones(len(yy))
            masks = ((yy == 0) & ~pp, (yy == 0) & pp, (yy == 1) & ~pp, (yy == 1) & pp)
            totals += [weights[m].sum() for m in masks]
        tn, fp, fn, tp = totals

        def ratio(a, b):
            return float(a / b) if b else None

        benign_f1 = ratio(2 * tn, 2 * tn + fp + fn)
        malicious_f1 = ratio(2 * tp, 2 * tp + fp + fn)
        return {
            "weighting": "1/n_g original exact-X group" if weighted else "1 per observation",
            "confusion_kind": "weighted masses" if weighted else "integer counts",
            "confusion": dict(
                zip(
                    ("TN", "FP", "FN", "TP"),
                    totals.tolist() if weighted else totals.astype(int).tolist(),
                )
            ),
            "class_supports": {
                "benign": float(tn + fp) if weighted else int(tn + fp),
                "malicious": float(fn + tp) if weighted else int(fn + tp),
            },
            "benign_recall": ratio(tn, tn + fp),
            "malicious_recall": ratio(tp, tp + fn),
            "malicious_precision": ratio(tp, tp + fp),
            "FPR": ratio(fp, fp + tn),
            "macro_f1": (benign_f1 + malicious_f1) / 2
            if benign_f1 is not None and malicious_f1 is not None
            else None,
            "accuracy_supplementary": ratio(tn + tp, totals.sum()),
            "undefined": "null",
        }

    return {"row_primary": report(False), "group_sensitivity": report(True)}


class MemoryMonitor:
    def __enter__(self):
        import psutil

        self.process = psutil.Process()
        self.peak = self.process.memory_info().rss
        self.stop = threading.Event()

        def watch():
            while not self.stop.wait(0.05):
                self.peak = max(self.peak, self.process.memory_info().rss)

        self.thread = threading.Thread(target=watch, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.peak = max(self.peak, self.process.memory_info().rss)
        self.stop.set()
        self.thread.join()


def validate_encoded(block):
    import numpy as np

    if block.ndim != 2 or block.shape[1] != 36 or block.dtype != np.float64:
        raise ValueError("Expected 36-column float64 encoded features")
    if not np.isfinite(block).all():
        raise ValueError("Nonfinite encoded features")


def validate_population(package, partition):
    import numpy as np

    if partition not in {"TRAIN", "VALIDATION"}:
        raise ValueError("Training runner permits TRAIN/VALIDATION only")
    expected = package.manifest["expected_partitions"][partition]
    if sha_file(package.root / f"{partition}_membership.jsonl") != expected["membership_sha256"]:
        raise ValueError("Population fingerprint mismatch")
    counts = np.zeros(2, dtype=np.int64)
    checked = 0
    group_mass = 0.0
    for block, labels, metadata in package.chunks(partition, chunk_size=8192):
        validate_encoded(block)
        if not np.isin(labels, [0, 1]).all():
            raise ValueError("Invalid labels")
        counts += np.bincount(labels, minlength=2)
        sizes = metadata["group_size"]
        if (sizes < 1).any():
            raise ValueError("Invalid original group size")
        group_mass += float((1 / sizes).sum())
        checked += len(labels)
    if checked != expected["rows"] or counts.tolist() != [
        expected["binary_rows"][f] for f in ("benign", "malicious")
    ]:
        raise ValueError("Population counts/support changed")
    if not np.isclose(group_mass, expected["distinct_X_groups"], rtol=1e-10, atol=1e-8):
        raise ValueError("Original group-weight mass does not reconcile")


def create_train_cache(package, mode, keys, plan, cache_directory, run_directory):
    import numpy as np

    expected = package.manifest["expected_partitions"]["TRAIN"]
    n = plan["rows"] if mode == "smoke" else expected["rows"]
    x = np.lib.format.open_memmap(
        cache_directory / "TRAIN_encoded.npy", mode="w+", dtype="<f8", shape=(n, 36)
    )
    y = np.lib.format.open_memmap(
        cache_directory / "TRAIN_y.npy", mode="w+", dtype="u1", shape=(n,)
    )
    indices = (
        np.lib.format.open_memmap(
            run_directory / "TRAIN_selected_indices.npy", mode="w+", dtype="<i8", shape=(n,)
        )
        if mode == "smoke"
        else None
    )
    selected_bytes = {k.encode("ascii") for k in keys}
    offset, source_offset = 0, 0
    counts = np.zeros(2, dtype=np.int64)
    for block, labels, metadata in package.chunks("TRAIN", chunk_size=8192):
        validate_encoded(block)
        mask = (
            np.fromiter(
                (g in selected_bytes for g in metadata["group"]), dtype=bool, count=len(labels)
            )
            if mode == "smoke"
            else np.ones(len(labels), bool)
        )
        stop = offset + int(mask.sum())
        x[offset:stop] = block[mask]
        y[offset:stop] = labels[mask]
        if indices is not None:
            indices[offset:stop] = np.flatnonzero(mask) + source_offset
        counts += np.bincount(labels[mask], minlength=2)
        offset = stop
        source_offset += len(labels)
    expected_counts = (
        plan["binary_rows"]
        if mode == "smoke"
        else [expected["binary_rows"][f] for f in ("benign", "malicious")]
    )
    if offset != n or counts.tolist() != expected_counts:
        raise ValueError("Actual TRAIN subset/full counts differ from fingerprinted population")
    x.flush()
    y.flush()
    if indices is not None:
        indices.flush()
    return x, y


def fit_and_evaluate(package, train_x, train_y, run_directory):
    assert_kaggle()  # Also guard the only helper containing classifier .fit calls.
    import joblib
    import numpy as np
    from sklearn.dummy import DummyClassifier
    from sklearn.linear_model import LogisticRegression
    from threadpoolctl import threadpool_limits

    results = {}
    _, _, validation_y, validation_metadata = package.load("VALIDATION")
    np.save(run_directory / "VALIDATION_y.npy", validation_y, allow_pickle=False)
    np.save(run_directory / "VALIDATION_metadata.npy", validation_metadata, allow_pickle=False)
    estimators = {
        "dummy": DummyClassifier(**configuration()["dummy"]),
        "lr": LogisticRegression(**configuration()["lr"]),
    }
    with threadpool_limits(limits=configuration()["threads"]):
        for name, model in estimators.items():
            started = time.perf_counter()
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                model.fit(train_x, train_y)
            fit_seconds = time.perf_counter() - started
            messages = [
                {"category": w.category.__name__, "message": str(w.message)} for w in caught
            ]
            iterations = getattr(model, "n_iter_", None)
            converged = not any(m["category"] == "ConvergenceWarning" for m in messages)
            if name == "lr" and int(np.max(iterations)) >= configuration()["lr"]["max_iter"]:
                converged = False
            if model.classes_.tolist() != [0, 1]:
                raise ValueError("Binary class order changed")
            model_path = run_directory / f"{name}_model.joblib"
            joblib.dump(model, model_path)
            restored = joblib.load(model_path)
            n = len(validation_y)
            probs = np.lib.format.open_memmap(
                run_directory / f"{name}_VALIDATION_probabilities.npy",
                mode="w+",
                dtype="<f8",
                shape=(n,),
            )
            predictions = np.lib.format.open_memmap(
                run_directory / f"{name}_VALIDATION_predictions.npy",
                mode="w+",
                dtype="u1",
                shape=(n,),
            )
            offset, largest_delta = 0, 0.0
            for block, labels, _ in package.chunks("VALIDATION", chunk_size=8192):
                validate_encoded(block)
                current = model.predict_proba(block)[:, 1]
                reloaded = restored.predict_proba(block)[:, 1]
                np.testing.assert_allclose(current, reloaded, rtol=0, atol=1e-12)
                np.testing.assert_array_equal(current >= 0.5, reloaded >= 0.5)
                largest_delta = max(largest_delta, float(np.max(np.abs(current - reloaded))))
                probs[offset : offset + len(labels)] = current
                predictions[offset : offset + len(labels)] = current >= 0.5
                offset += len(labels)
            if offset != n:
                raise ValueError("VALIDATION prediction row identity/count mismatch")
            probs.flush()
            predictions.flush()
            results[name] = {
                "converged": converged,
                "warnings": messages,
                "fit_seconds": fit_seconds,
                "iterations": iterations.tolist() if iterations is not None else None,
                "reload_parity": "PASS",
                "reload_max_probability_delta": largest_delta,
                "metrics": metric_tables(validation_y, probs, validation_metadata["group_size"]),
            }
    return results


def checksums_and_archive(directory):
    write_json(
        directory / "output_checksums.json",
        {
            str(p.relative_to(directory)).replace("\\", "/"): sha_file(p)
            for p in sorted(directory.rglob("*"))
            if p.is_file()
        },
    )
    output = directory.with_suffix(".zip")
    with output.open("xb") as handle, zipfile.ZipFile(handle, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                archive.write(path, str(path.relative_to(directory)))
    return output


def run(mode, *, package_directory=None, smoke_receipt=None):
    assert_kaggle()
    if mode not in {"smoke", "full"}:
        raise ValueError("Choose smoke or full")
    bundle, bundle_sha = check_bundle()
    runtime = environment()
    package_root = find_package(package_directory)
    run_id = "bot_iot_secondary_" + mode + "_" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    directory = Path("/kaggle/working") / run_id
    directory.mkdir(exist_ok=False)
    cache = Path("/kaggle/working") / (run_id + "_scratch")
    cache.mkdir(exist_ok=False)
    started = time.perf_counter()
    try:
        preflight = preflight_package(package_root, directory)
        sys.path.insert(0, str(ROOT / "vendor"))
        from bot_iot_package_v2 import SecondaryPackage

        # Hash verification was performed by the separate standalone verifier. Do not
        # reopen TEST payloads here; loader verify=False only stats/schema on init.
        package = SecondaryPackage(package_root, verify=False)
        if (
            package.manifest["preprocessor_sha256"] != PREPROCESSOR_SHA
            or sha_file(ROOT / "vendor/bot_iot_package_v2.py")
            != package.manifest["files"]["bot_iot_package_v2.py"]["sha256"]
        ):
            raise ValueError("Package preprocessing/portable loader identity changed")
        feature_order = package.manifest["encoded_features"]
        if (
            len(feature_order) != 36
            or feature_order != package.preprocessor.state["encoded_features"]
        ):
            raise ValueError("Encoded feature order changed")
        plan, keys = smoke_plan(package, directory)
        identity = {
            "package_manifest_sha256": PACKAGE_SHA,
            "bundle_manifest_sha256": bundle_sha,
            "bundle_id": BUNDLE_ID,
            "source_git_revision": bundle["source_git_revision"],
            "source_dirty_worktree": bundle["source_dirty_worktree"],
            "preprocessor_sha256": PREPROCESSOR_SHA,
            "data_contract_sha256": package.manifest["contract_sha256"],
            "data_protocol_sha256": package.manifest["protocol_sha256"],
            "experiment_protocol_sha256": bundle["files"][
                "protocols/bot_iot_secondary_kaggle_baseline_v1.md"
            ],
            "feature_order_sha256": hashlib.sha256(json_bytes(feature_order)).hexdigest(),
            "configuration": configuration(),
            "runtime_packages": runtime["packages"],
        }
        accepted = None
        if mode == "full":
            if not smoke_receipt:
                raise ValueError("Full requires explicit Smoke run_status.json path")
            receipt_path = Path(smoke_receipt).resolve()
            if not any(receipt_path.is_relative_to(base) for base in
                       (Path("/kaggle/input"), Path("/kaggle/working"))):
                raise ValueError("Smoke receipt must be a Kaggle input or working artifact")
            accepted = json.loads(receipt_path.read_bytes())
            accept_smoke(accepted, identity, plan)
            shutil.copyfile(receipt_path, directory / "accepted_smoke_receipt.json")
        import psutil

        n_train = plan["rows"] if mode == "smoke" else 2201114
        resource = resources(
            n_train, psutil.virtual_memory().available, shutil.disk_usage(directory).free
        )
        write_json(directory / "resource_preflight.json", resource)
        if resource["status"] != "PASS":
            raise RuntimeError(
                "Resource preflight BLOCKED; do not sample/fallback; review capacity"
            )
        write_json(directory / "resolved_configuration.json", identity)
        write_json(directory / "environment.json", runtime)
        write_json(directory / "smoke_plan.json", plan)
        shutil.copytree(ROOT, directory / "source", ignore=shutil.ignore_patterns("__pycache__"))
        validate_population(package, "TRAIN")
        validate_population(package, "VALIDATION")
        train_population = (
            plan["membership_sha256"]
            if mode == "smoke"
            else package.manifest["expected_partitions"]["TRAIN"]["membership_sha256"]
        )
        validation_population = package.manifest["expected_partitions"]["VALIDATION"][
            "membership_sha256"
        ]
        if mode == "full":
            shutil.copyfile(
                package_root / "TRAIN_membership.jsonl", directory / "TRAIN_membership.jsonl"
            )
        else:
            shutil.copyfile(
                directory / "smoke_TRAIN_membership.jsonl", directory / "TRAIN_membership.jsonl"
            )
        shutil.copyfile(
            package_root / "VALIDATION_membership.jsonl", directory / "VALIDATION_membership.jsonl"
        )
        if sha_file(directory / "TRAIN_membership.jsonl") != train_population:
            raise ValueError("Actual training membership hash mismatch")
        with MemoryMonitor() as memory:
            train_x, train_y = create_train_cache(package, mode, keys, plan, cache, directory)
            models = fit_and_evaluate(package, train_x, train_y, directory)
        all_pass = all(m["converged"] and m["reload_parity"] == "PASS" for m in models.values())
        status = (
            ("SMOKE_PASS" if mode == "smoke" else "BASELINES_COMPLETE")
            if all_pass
            else ("NONCONVERGED_DIAGNOSTIC")
        )
        for name, result in models.items():
            write_json(
                directory / f"{name}_result.json",
                {
                    "run_id": run_id,
                    "model": name,
                    "mode": mode,
                    "identity": identity,
                    "train_population_sha256": train_population,
                    "validation_population_sha256": validation_population,
                    "eligible_for_full_population_comparison": mode == "full" and all_pass,
                    "diagnostic_only": mode == "smoke" or not all_pass,
                    **result,
                },
            )
        write_json(
            directory / "run_status.json",
            {
                "status": status,
                "run_id": run_id,
                "mode": mode,
                "identity": identity,
                "smoke_plan": plan,
                "resource_preflight": resource,
                "models": models,
                "training_rows": n_train,
                "validation_rows": 733704,
                "train_population_sha256": train_population,
                "validation_population_sha256": validation_population,
                "accepted_smoke_receipt_sha256": sha_file(directory / "accepted_smoke_receipt.json")
                if accepted
                else None,
                "package_verification": preflight,
                "peak_runner_rss_bytes_after_package_verification": memory.peak,
                "elapsed_seconds_including_package_verification": time.perf_counter() - started,
                "training_runner_TEST_opened": False,
                "TEST_performance_evaluated": False,
                "package_manifest_status_unchanged": "PREPARED_PENDING_REVIEW",
                "eligible_for_full_population_comparison": mode == "full" and all_pass,
                "cache_directory_not_archived": str(cache),
            },
        )
    except Exception as error:
        write_json(
            directory / "failure.json",
            {
                "status": "FAILED",
                "error": str(error),
                "traceback": traceback.format_exc(),
                "TEST_performance_evaluated": False,
            },
        )
        checksums_and_archive(directory)
        raise
    archive = checksums_and_archive(directory)
    return {
        "run_directory": str(directory),
        "archive": str(archive),
        "archive_sha256": sha_file(archive),
        "status": status,
    }
