"""Kaggle-only primary LR + Dummy experiments; never fit on a local machine."""

from __future__ import annotations

import csv
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import sys
import threading
import time
import traceback
import warnings
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FOUNDATION_COMMIT = "e478e8e7ff0d374d9fd6f53e411bd4f414ce1c14"
EXPECTED_MANIFEST = "6ab99e86397242e219bfa1f8490d8e03b169ec87a092af80cb3e7aef1e61147b"
COUNTS = {"TRAIN": 4944968, "VALIDATION": 1056372}
SUPPORT = {"TRAIN": [388965, 4556003], "VALIDATION": [83435, 972937]}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path, payload):
    path = Path(path)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(payload, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    temp.replace(path)


def assert_kaggle():
    if not Path("/kaggle/input").is_dir() or not Path("/kaggle/working").is_dir():
        raise RuntimeError("Training is restricted to Kaggle. Import this notebook into Kaggle.")


def check_bundle():
    manifest = json.loads((ROOT / "bundle_manifest.json").read_text())
    if (
        manifest.get("bundle_id") != "iotguard_primary_lr_kaggle_v2"
        or not isinstance(manifest.get("source_git_revision"), str)
        or len(manifest["source_git_revision"]) not in {40, 64}
        or any(c not in "0123456789abcdef" for c in manifest["source_git_revision"])
        or type(manifest.get("source_dirty_worktree")) is not bool
        or manifest.get("expected_data_manifest_sha256") != EXPECTED_MANIFEST
    ):
        raise ValueError("Missing or incompatible bundle source identity")
    required = {
        "kaggle_lr_runner.py",
        "vendor/iotguard/data/primary_package.py",
        "vendor/iotguard/evaluation/primary.py",
        "config/seeds.yaml",
        "protocols/primary_result_v1.schema.json",
        "README.md",
        "requirements.txt",
    }
    if not required.issubset(manifest.get("files", {})):
        raise ValueError("Bundle is missing checksummed runtime payloads")
    for relative, expected in manifest["files"].items():
        candidate = (ROOT / relative).resolve()
        if not candidate.is_relative_to(ROOT) or sha256(candidate) != expected:
            raise ValueError(f"Bundle integrity mismatch: {relative}")
    return manifest, sha256(ROOT / "bundle_manifest.json")


def environment():
    packages = [
        "numpy",
        "scikit-learn",
        "PyYAML",
        "joblib",
        "psutil",
        "threadpoolctl",
        "jsonschema",
    ]
    versions, missing = {}, []
    for package in packages:
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            missing.append(package)
    if missing:
        raise RuntimeError(
            "Missing Kaggle packages: "
            + ", ".join(missing)
            + ". Install requirements.txt in the Kaggle notebook, then restart."
        )
    import numpy as np
    import sklearn

    if not (1, 26) <= tuple(int(x) for x in np.__version__.split(".")[:2]) < (3, 0):
        raise RuntimeError("Require NumPy >=1.26,<3; do not silently change runtime.")
    if not (1, 3) <= tuple(int(x) for x in sklearn.__version__.split(".")[:2]) < (2, 0):
        raise RuntimeError("Require scikit-learn >=1.3,<2.")
    return {
        "python": sys.version,
        "platform": platform.platform(),
        "packages": versions,
        "KAGGLE_KERNEL_RUN_TYPE": os.environ.get("KAGGLE_KERNEL_RUN_TYPE"),
    }


def find_package(explicit=None):
    assert_kaggle()
    candidates = (
        [Path(explicit) / "manifest.json"]
        if explicit
        else list(Path("/kaggle/input").rglob("manifest.json"))
    )
    matches = [p for p in candidates if p.is_file() and sha256(p) == EXPECTED_MANIFEST]
    if len(matches) != 1:
        raise RuntimeError(
            f"Expected exactly one G3B manifest {EXPECTED_MANIFEST}; found "
            f"{len(matches)}. Add the original processed package as Kaggle Input "
            "or set PACKAGE_DIRECTORY explicitly. Do not edit its manifest."
        )
    return matches[0].parent


def validate_package(package):
    import numpy as np

    if sha256(package.root / "manifest.json") != EXPECTED_MANIFEST:
        raise ValueError("Unexpected original data package manifest")
    if package.manifest["status"] != "FULL":
        raise ValueError("A full G3B package is required even for a diagnostic smoke run")
    for partition in COUNTS:
        x, y, _ = package.load(partition)
        if x.shape != (COUNTS[partition], 115):
            raise ValueError(f"Wrong {partition} population")
        counts = np.zeros(2, dtype=np.int64)
        for start in range(0, len(y), 65536):
            block = y[start : start + 65536]
            if not np.isin(block, [0, 1]).all():
                raise ValueError("Invalid binary target")
            counts += np.bincount(block, minlength=2)
        if counts.tolist() != SUPPORT[partition]:
            raise ValueError(f"Unexpected {partition} label support")
    try:
        package.load("TEST")
    except PermissionError:
        pass
    else:
        raise ValueError("Default TEST access must remain blocked")


def diagnostic_indices(y, size, seed):
    """Reproducible stratified row subset, not a new evaluation split."""
    import numpy as np

    if not isinstance(size, int) or not 2 <= size < len(y):
        raise ValueError("Smoke size must be between 2 and partition length minus 1")
    rng = np.random.default_rng(seed)
    supports = np.bincount(y, minlength=2)
    benign_count = max(1, min(size - 1, round(size * int(supports[0]) / len(y))))
    selected = []
    for label, count in ((0, benign_count), (1, size - benign_count)):
        positions = np.flatnonzero(y == label)
        selected.append(rng.choice(positions, size=count, replace=False))
    return np.sort(np.concatenate(selected)).astype("<i8")


class MemoryMonitor:
    def __init__(self):
        import psutil

        self.process = psutil.Process()
        self.peak_rss = self.process.memory_info().rss
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._watch, daemon=True)

    def _watch(self):
        while not self.stop.wait(0.2):
            self.peak_rss = max(self.peak_rss, self.process.memory_info().rss)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.peak_rss = max(self.peak_rss, self.process.memory_info().rss)
        self.stop.set()
        self.thread.join()


def scaled_cache(package, indices, directory, mode, chunk_size):
    import numpy as np

    raw, labels, _ = package.load("TRAIN")
    n = len(labels) if indices is None else len(indices)
    directory.mkdir(parents=True, exist_ok=False)
    marker = directory / "INCOMPLETE.json"
    write_json(marker, {"status": "BUILDING", "rows": n, "mode": mode})
    target = directory / "X_scaled.npy"
    arr = np.lib.format.open_memmap(target, mode="w+", dtype="float64", shape=(n, 115))
    for start in range(0, n, chunk_size):
        stop = min(start + chunk_size, n)
        block = raw[start:stop] if indices is None else raw[indices[start:stop]]
        transformed = (block - package.mean) / package.scale
        if not np.isfinite(transformed).all():
            raise ValueError("Non-finite scaled TRAIN features")
        arr[start:stop] = transformed
        if start % (chunk_size * 256) == 0:
            arr.flush()
            print(f"Scaled TRAIN cache: {stop:,}/{n:,}", flush=True)
    arr.flush()
    del arr
    marker.unlink()
    write_json(
        directory / "cache_identity.json",
        {
            "package_manifest_sha256": EXPECTED_MANIFEST,
            "mode": mode,
            "rows": n,
            "scaler_sha256": sha256(package.root / "scaler.json"),
            "dtype": "float64",
            "sampling": "none" if indices is None else "diagnostic indices saved with run",
        },
    )
    return np.load(target, mmap_mode="r", allow_pickle=False)


def predict_validation(model, package, indices, scaled, target, chunk_size):
    import numpy as np

    raw, labels, _ = package.load("VALIDATION")
    n = len(labels) if indices is None else len(indices)
    probabilities = np.lib.format.open_memmap(target, mode="w+", dtype="float64", shape=(n,))
    positive = list(model.classes_).index(1)
    for start in range(0, n, chunk_size):
        stop = min(start + chunk_size, n)
        if scaled:
            block = raw[start:stop] if indices is None else raw[indices[start:stop]]
            features = (block - package.mean) / package.scale
        else:
            # DummyClassifier ignores all feature values; no large feature copy is needed.
            features = np.zeros((stop - start, 1), dtype=np.uint8)
        if not np.isfinite(features).all():
            raise ValueError("Non-finite validation features")
        probabilities[start:stop] = model.predict_proba(features)[:, positive]
    probabilities.flush()
    del probabilities
    return np.load(target, mmap_mode="r", allow_pickle=False)


def make_result(name, probabilities, targets, package, settings, bundle_hash, indices, mode):
    import numpy as np

    from iotguard.evaluation.primary import binary_metrics, experiment_result, resolve_configuration

    configuration = resolve_configuration(
        input_view=settings["input_view"], parameters=settings["parameters"]
    )
    configuration["training_environment"] = "Kaggle CPU"
    population = {
        part: package.manifest["files"][f"{part}_metadata.npy"]["sha256"] for part in COUNTS
    }
    if mode == "smoke":
        for part in COUNTS:
            framing = (
                bytes.fromhex(population[part]) + np.asarray(indices[part], dtype="<i8").tobytes()
            )
            population[part] = hashlib.sha256(framing).hexdigest()
    source_identity, actual_bundle_hash = check_bundle()
    if actual_bundle_hash != bundle_hash:
        raise ValueError("Code bundle changed during the run")
    result = experiment_result(
        name,
        binary_metrics(targets, probabilities),
        configuration=configuration,
        code_revision=source_identity["source_git_revision"],
        dirty_worktree=source_identity["source_dirty_worktree"],
        package_version=package.manifest["package_version"],
        package_manifest_sha256=EXPECTED_MANIFEST,
        train_population_sha256=population["TRAIN"],
        validation_population_sha256=population["VALIDATION"],
    )
    result["run_mode"] = mode
    result["diagnostic_only"] = mode != "full"
    result["code_provenance"] = {
        "foundation_commit": FOUNDATION_COMMIT,
        "source_git_revision": source_identity["source_git_revision"],
        "source_dirty_worktree": source_identity["source_dirty_worktree"],
        "training_extension_bundle_sha256": bundle_hash,
        "dirty_worktree_basis": "Actual source checkout state recorded by the bundle exporter; "
        "the exact exported source is retained and checksummed.",
    }
    import jsonschema

    schema = json.loads((ROOT / "protocols/primary_result_v1.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(result)
    return result


def write_comparison(directory, results):
    with (directory / "comparison.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "model",
                "macro_f1",
                "accuracy",
                "precision",
                "recall",
                "malicious_f1",
                "benign_recall",
                "fpr",
                "TN",
                "FP",
                "FN",
                "TP",
            ],
        )
        writer.writeheader()
        for name, result in results.items():
            m = result["metrics"]
            writer.writerow(
                {
                    "model": name,
                    "macro_f1": m["macro_f1"],
                    "accuracy": m["accuracy"],
                    "precision": m["per_class"]["malicious"]["precision"],
                    "recall": m["per_class"]["malicious"]["recall"],
                    "malicious_f1": m["per_class"]["malicious"]["f1"],
                    "benign_recall": m["per_class"]["benign"]["recall"],
                    "fpr": m["fpr"],
                    **{k: m[k] for k in ("TN", "FP", "FN", "TP")},
                }
            )


def baseline_configuration(
    *, max_iter=1000, threads=4, chunk_size=8192, smoke_train=50000, smoke_validation=10000
):
    values = (max_iter, threads, chunk_size, smoke_train, smoke_validation)
    if any(type(value) is not int or value < 1 for value in values):
        raise ValueError("Positive integer run settings required")
    if max_iter != 1000 or smoke_train != 50000 or smoke_validation != 10000:
        raise ValueError("Baseline settings are locked; create a protocol/bundle revision")
    return {
        "max_iter": max_iter,
        "threads": threads,
        "chunk_size": chunk_size,
        "smoke_train": smoke_train,
        "smoke_validation": smoke_validation,
    }


def run(
    *,
    mode,
    package_directory=None,
    smoke_train=50000,
    smoke_validation=10000,
    max_iter=1000,
    threads=4,
    chunk_size=8192,
):
    """All fitting is inside this Kaggle-guarded function, never during import."""
    assert_kaggle()
    if mode not in {"smoke", "full"}:
        raise ValueError("Choose smoke or full")
    run_configuration = baseline_configuration(
        max_iter=max_iter,
        threads=threads,
        chunk_size=chunk_size,
        smoke_train=smoke_train,
        smoke_validation=smoke_validation,
    )
    sys.path.insert(0, str(ROOT / "vendor"))
    from iotguard.data.primary_package import PrimaryPackage
    from iotguard.evaluation import primary as metrics_module

    if (
        Path(sys.modules[PrimaryPackage.__module__].__file__).resolve()
        != (ROOT / "vendor/iotguard/data/primary_package.py").resolve()
        or Path(metrics_module.__file__).resolve()
        != (ROOT / "vendor/iotguard/evaluation/primary.py").resolve()
    ):
        raise RuntimeError(
            "Shared modules from another source are cached. Restart the Kaggle session."
        )
    import joblib
    import numpy as np
    import psutil
    from sklearn.dummy import DummyClassifier
    from sklearn.exceptions import ConvergenceWarning
    from sklearn.linear_model import LogisticRegression
    from threadpoolctl import threadpool_limits

    _, bundle_hash = check_bundle()
    if metrics_module.resolve_configuration(input_view="raw", parameters={})["seeds"] != {
        "python": 42,
        "numpy": 42,
        "scikit_learn": 42,
    }:
        raise ValueError("Baseline seed policy changed; create a protocol/bundle revision")
    runtime = environment()
    package = PrimaryPackage(find_package(package_directory), verify=True)
    validate_package(package)
    if mode == "full":
        prerequisite = smoke_receipt(run_configuration)
    else:
        prerequisite = None
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    directory = Path("/kaggle/working") / f"iotguard_lr_{mode}_{stamp}"
    if directory.resolve().is_relative_to(ROOT):
        raise ValueError("Run output must be separate from the code-bundle directory")
    directory.mkdir()
    cache = Path("/kaggle/working") / f"_lr_cache_{stamp}"
    status = {
        "status": "RUNNING",
        "mode": mode,
        "output_directory": str(directory),
        "package_manifest_sha256": EXPECTED_MANIFEST,
        "bundle_manifest_sha256": bundle_hash,
        "smoke_receipt": prerequisite,
        "training_location": "Kaggle",
        "TEST_evaluated": False,
        "run_configuration": run_configuration,
    }
    write_json(directory / "run_status.json", status)
    shutil.copyfile(package.root / "manifest.json", directory / "data_manifest.json")
    shutil.copyfile(package.root / "scaler.json", directory / "scaler.json")
    shutil.copyfile(
        package.root / "n_baiot_feature_contract_v1.json", directory / "feature_contract.json"
    )
    shutil.copytree(
        ROOT, directory / "source", ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
    )
    write_json(directory / "environment.json", runtime)
    (directory / "requirements_exact.txt").write_text(
        "\n".join(f"{k}=={v}" for k, v in runtime["packages"].items()) + "\n"
    )
    monitor = MemoryMonitor()
    start_run = time.perf_counter()
    train_x = None
    try:
        with monitor, threadpool_limits(limits=threads):
            train_raw, train_y_all, _ = package.load("TRAIN")
            validation_raw, validation_y_all, _ = package.load("VALIDATION")
            indices = {"TRAIN": None, "VALIDATION": None}
            if mode == "smoke":
                indices = {
                    "TRAIN": diagnostic_indices(train_y_all, smoke_train, 42),
                    "VALIDATION": diagnostic_indices(validation_y_all, smoke_validation, 43),
                }
                for part, values in indices.items():
                    np.save(directory / f"{part}_diagnostic_indices.npy", values)
            train_y = train_y_all if indices["TRAIN"] is None else train_y_all[indices["TRAIN"]]
            targets = (
                validation_y_all
                if indices["VALIDATION"] is None
                else validation_y_all[indices["VALIDATION"]]
            )
            estimated_cache = len(train_y) * 115 * 8
            available = psutil.virtual_memory().available
            free_disk = shutil.disk_usage("/kaggle/working").free
            # Conservative guard: allow room for estimator copies, OS, and output files.
            estimated_working_set = estimated_cache * 2 + 1024**3
            resource = {
                "available_ram_bytes": available,
                "disk_free_bytes": free_disk,
                "scaled_cache_bytes": estimated_cache,
                "conservative_ram_requirement_bytes": estimated_working_set,
                "train_rows": len(train_y),
                "validation_rows": len(targets),
                "threads": threads,
                "cpu_count": os.cpu_count(),
            }
            write_json(directory / "resources_preflight.json", resource)
            print(json.dumps(resource, indent=2))
            if free_disk < estimated_cache + 1024**3 or available < estimated_working_set:
                raise MemoryError(
                    "BLOCKED_RESOURCE: insufficient conservative RAM/disk budget. "
                    "Do not silently reduce the official population."
                )
            train_x = scaled_cache(package, indices["TRAIN"], cache, mode, chunk_size)
            dummy = DummyClassifier(strategy="most_frequent", random_state=42)
            params = {
                "C": 1.0,
                "solver": "lbfgs",
                "tol": 1e-4,
                "max_iter": max_iter,
                "class_weight": None,
                "random_state": 42,
            }
            lr = LogisticRegression(**params)
            # lbfgs + finite C uses L2 in supported sklearn versions; record effective defaults.
            settings = {
                "dummy": {"input_view": "raw", "parameters": dummy.get_params()},
                "lr": {"input_view": "scaled", "parameters": lr.get_params()},
            }
            write_json(directory / "resolved_parameters.json", settings)
            records = {}
            convergence = {}
            for name, model in (("dummy", dummy), ("lr", lr)):
                assert_kaggle()
                start = time.perf_counter()
                with warnings.catch_warnings(record=True) as captured:
                    warnings.simplefilter("always")
                    model.fit(train_x[:, :1] if name == "dummy" else train_x, train_y)
                notes = [
                    {"category": w.category.__name__, "message": str(w.message)} for w in captured
                ]
                converged = not any(issubclass(w.category, ConvergenceWarning) for w in captured)
                if name == "lr" and int(np.max(model.n_iter_)) >= max_iter:
                    converged = False
                convergence[name] = {
                    "fit_seconds": time.perf_counter() - start,
                    "warnings": notes,
                    "converged": converged,
                    "n_iter": model.n_iter_.tolist() if name == "lr" else None,
                }
                print(name, convergence[name], flush=True)
                joblib.dump(model, directory / f"{name}_model.joblib")
                reloaded = joblib.load(directory / f"{name}_model.joblib")
                fixture = validation_raw[:32]
                transformed = (
                    (fixture - package.mean) / package.scale
                    if name == "lr"
                    else np.zeros((len(fixture), 1), dtype=np.uint8)
                )
                np.testing.assert_allclose(
                    model.predict_proba(transformed),
                    reloaded.predict_proba(transformed),
                    rtol=1e-12,
                    atol=1e-12,
                )
                probability = predict_validation(
                    model,
                    package,
                    indices["VALIDATION"],
                    name == "lr",
                    directory / f"{name}_validation_probabilities.npy",
                    chunk_size,
                )
                np.save(
                    directory / f"{name}_validation_predictions.npy",
                    (probability >= 0.5).astype("uint8"),
                )
                result = make_result(
                    f"{name}_{mode}_{stamp}",
                    probability,
                    targets,
                    package,
                    settings[name],
                    bundle_hash,
                    indices,
                    mode,
                )
                result["runtime"] = convergence[name]
                result["reload_parity"] = "PASS"
                if not converged:
                    result["diagnostic_only"] = True
                    result["eligible_for_official_comparison"] = False
                    write_json(directory / f"{name}_NONCONVERGED_diagnostic.json", result)
                else:
                    result["eligible_for_official_comparison"] = mode == "full"
                    write_json(directory / f"{name}_result.json", result)
                    records[name] = result
            write_json(directory / "convergence.json", convergence)
            write_comparison(directory, records)
            success = len(records) == 2
            status["status"] = (
                ("SMOKE_PASS" if mode == "smoke" else "BASELINES_COMPLETE")
                if success
                else "LR_NOT_CONVERGED"
            )
            status["eligible_for_official_comparison"] = success and mode == "full"
            status["fit_seconds"] = {k: v["fit_seconds"] for k, v in convergence.items()}
            status["train_rows"] = len(train_y)
            status["validation_rows"] = len(targets)
    except Exception as error:
        status["status"] = "BLOCKED_RESOURCE" if isinstance(error, MemoryError) else "FAILED"
        status["error"] = repr(error)
        (directory / "traceback.txt").write_text(traceback.format_exc(), encoding="utf-8")
        print(status["error"], flush=True)
    finally:
        if train_x is not None:
            del train_x
        if cache.exists():
            if cache.resolve().parent != Path("/kaggle/working").resolve():
                raise ValueError("Refusing cleanup outside Kaggle working directory")
            shutil.rmtree(cache)
        status["elapsed_seconds"] = time.perf_counter() - start_run
        status["peak_process_rss_bytes"] = monitor.peak_rss
        write_json(directory / "run_status.json", status)
        hashes = {
            str(p.relative_to(directory)): sha256(p)
            for p in sorted(directory.rglob("*"))
            if p.is_file()
        }
        write_json(directory / "output_checksums.json", hashes)
        archive = shutil.make_archive(str(directory), "zip", directory)
        print("Run status:", json.dumps(status, indent=2))
        print("Download result archive:", archive)
    return status


def smoke_receipt_matches(receipt, bundle_hash, expected_configuration):
    return (
        receipt.get("status") == "SMOKE_PASS"
        and receipt.get("mode") == "smoke"
        and receipt.get("package_manifest_sha256") == EXPECTED_MANIFEST
        and receipt.get("bundle_manifest_sha256") == bundle_hash
        and receipt.get("run_configuration") == expected_configuration
    )


def smoke_receipt(expected_configuration=None):
    """Require a previous successful smoke output attached to the full notebook."""
    candidates = list(Path("/kaggle/input").rglob("run_status.json")) + list(
        Path("/kaggle/working").glob("iotguard_lr_smoke_*/run_status.json")
    )
    _, current_bundle_hash = check_bundle()
    if expected_configuration is None:
        expected_configuration = baseline_configuration()
    matches = []
    for path in candidates:
        try:
            receipt = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if smoke_receipt_matches(receipt, current_bundle_hash, expected_configuration):
            matches.append((path, receipt))
    if not matches:
        raise RuntimeError(
            "No matching SMOKE_PASS receipt. Run notebook 01, save its output, "
            "and attach that output as Input to notebook 02. Do not bypass the gate."
        )
    path, receipt = sorted(matches, key=lambda item: str(item[0]))[-1]
    return {
        "receipt_path": str(path),
        "receipt_sha256": sha256(path),
        "smoke_fit_seconds": receipt.get("fit_seconds"),
        "smoke_peak_process_rss_bytes": receipt.get("peak_process_rss_bytes"),
    }
