"""Small I/O helpers. Training and evaluation remain visible in the notebooks."""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

import numpy as np


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False,
                                    allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def read_config(path="experiment_config.json"):
    cfg = json.loads(Path(path).read_text(encoding="utf-8"))
    cfg["package_dir"] = str(Path(cfg["package_dir"]).expanduser().resolve())
    cfg["output_root"] = str(Path(cfg["output_root"]).expanduser().resolve())
    if cfg["stage"] not in {"pilot", "full"}:
        raise ValueError("stage must be pilot or full")
    if cfg["scalings"] != ["g3b_standard", "raw"]:
        raise ValueError("This protocol requires the primary scaling and raw ablation")
    if not all(2 <= k <= 32767 for k in cfg["k_values"]):
        raise ValueError("K must be >=2 and fit in int16 prediction files")
    return cfg


def package_identity(cfg, package):
    root = Path(cfg["package_dir"])
    expected = cfg["expected_manifest_sha256"]
    # The PDF does not give the manifest filename. Match its exact supplied hash,
    # rather than guessing an undocumented JSON schema or filename.
    candidates = [p for p in root.rglob("*.json")
                  if not any(part.startswith(".") or part in {"site-packages", "node_modules"}
                             for part in p.relative_to(root).parts)]
    matches = [p for p in candidates if p.stat().st_size < 50_000_000
               and sha256_file(p) == expected]
    if not matches:
        raise ValueError("No JSON matches the handoff manifest SHA-256. Confirm the package version.")
    manifest = sorted(matches)[0]
    identity = {"manifest_relative_path": str(manifest.relative_to(root)),
                "manifest_sha256": expected, "partitions": {}}
    for split in ("TRAIN", "VALIDATION"):
        X, _unused_y, metadata = package.load(split)
        if list(X.shape) != cfg["expected_shapes"][split]:
            raise ValueError(f"Unexpected {split} shape: {X.shape}")
        # A file-backed view is important: avoid silently loading 4+ GiB into RAM.
        if not getattr(X, "filename", None):
            raise TypeError("Expected a NumPy memmap from PrimaryPackage.load; inspect your loader.")
        metadata_path = getattr(metadata, "filename", None)
        if not metadata_path:
            raise TypeError("Expected file-backed metadata for population fingerprinting")
        metadata_path = Path(metadata_path).resolve()
        identity["partitions"][split] = {
            "shape": list(X.shape), "dtype": str(X.dtype),
            "metadata_relative_path": str(metadata_path.relative_to(root)),
            "metadata_sha256": sha256_file(metadata_path),
        }
    return identity


def open_package(cfg):
    root = Path(cfg["package_dir"])
    loader = root / "primary_package.py"
    if not loader.is_file():
        raise FileNotFoundError(f"Copy the COMPLETE G3B directory here first: {root}")
    # Only use the documented, supplied loader; never allow TEST.
    sys.path.insert(0, str(root))
    importlib.invalidate_caches()
    if "primary_package" in sys.modules:
        loaded = Path(sys.modules["primary_package"].__file__).resolve()
        if loaded != loader.resolve():
            raise RuntimeError("A different primary_package is imported. Restart the kernel.")
    module = importlib.import_module("primary_package")
    package = module.PrimaryPackage(str(root), verify=True)
    return package, package_identity(cfg, package)


def feature_chunks(package, split, scaling, chunk_size):
    if split not in {"TRAIN", "VALIDATION"}:
        raise ValueError("This workflow never opens TEST")
    if scaling not in {"g3b_standard", "raw"}:
        raise ValueError("Unknown scaling")
    position = 0
    for X_chunk, _unused_y in package.chunks(
            split, scaled=(scaling == "g3b_standard"), chunk_size=chunk_size):
        X_chunk = np.asarray(X_chunk, dtype=np.float64, order="C")
        if X_chunk.ndim != 2 or not np.isfinite(X_chunk).all():
            raise ValueError("Non-finite or malformed G3B features; do not silently impute or drop rows")
        end = position + len(X_chunk)
        yield position, end, X_chunk
        position = end


def collect_rows(package, split, scaling, indices, chunk_size):
    """One sequential scan, only selected feature rows kept in memory."""
    indices = np.asarray(indices, dtype=np.int64)
    if len(indices) == 0 or np.any(np.diff(indices) <= 0):
        raise ValueError("Sample indices must be nonempty, sorted and unique")
    result = None
    copied = 0
    for start, end, X in feature_chunks(package, split, scaling, chunk_size):
        left, right = np.searchsorted(indices, [start, end])
        if result is None:
            result = np.empty((len(indices), X.shape[1]), dtype=np.float64)
        if right > left:
            result[left:right] = X[indices[left:right] - start]
            copied += right - left
        if copied == len(indices):
            break
    if copied != len(indices):
        raise ValueError("Sample points outside the stream")
    return result


def prepare_cache(package, cfg, identity, experiment_dir):
    cache = Path(experiment_dir) / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    policy = {k: cfg[k] for k in ("pilot_train_rows", "validation_eval_rows",
                                 "silhouette_rows", "silhouette_repeats", "sample_seed")}
    expected = {"identity": identity, "sampling_policy": policy}
    marker = cache / "cache_identity.json"
    if marker.exists():
        if json.loads(marker.read_text()) != expected:
            raise ValueError("Cache population/policy changed; use a NEW experiment_id")
        return cache
    if any(cache.iterdir()):
        raise RuntimeError("Incomplete cache exists; use a NEW experiment_id")
    n_train = identity["partitions"]["TRAIN"]["shape"][0]
    n_val = identity["partitions"]["VALIDATION"]["shape"][0]
    rng = np.random.default_rng(cfg["sample_seed"])
    for split, population, requested in (("TRAIN", n_train, cfg["pilot_train_rows"]),
                                          ("VALIDATION", n_val, cfg["validation_eval_rows"])):
        indices = np.sort(rng.choice(population, size=min(population, requested), replace=False))
        np.save(cache / f"{split}_indices.npy", indices)
        for scaling in cfg["scalings"]:
            X = collect_rows(package, split, scaling, indices, cfg["batch_size"])
            np.save(cache / f"{split}_{scaling}.npy", X)
            del X
    n_eval = min(n_val, cfg["validation_eval_rows"])
    for repeat in range(cfg["silhouette_repeats"]):
        positions = np.sort(rng.choice(n_eval, min(n_eval, cfg["silhouette_rows"]), replace=False))
        np.save(cache / f"silhouette_positions_{repeat}.npy", positions)
    write_json(marker, expected)
    return cache


def shuffled_batches(package, scaling, batch_size, buffer_batches, seed):
    """Bounded local shuffle. This is explicitly NOT a global row permutation."""
    rng = np.random.default_rng(seed)
    parts = []
    for _start, _end, X in feature_chunks(package, "TRAIN", scaling, batch_size):
        parts.append(np.array(X, copy=True, order="C"))
        if len(parts) == buffer_batches:
            block = np.concatenate(parts, axis=0)
            parts.clear()
            rng.shuffle(block, axis=0)
            for offset in range(0, len(block), batch_size):
                yield block[offset:offset + batch_size]
    if parts:
        block = np.concatenate(parts, axis=0)
        parts.clear()
        rng.shuffle(block, axis=0)
        for offset in range(0, len(block), batch_size):
            yield block[offset:offset + batch_size]


def save_predictions(package, estimator, scaling, split, n_rows, output_path, chunk_size):
    """Save FINAL-center predictions, never intermediate partial_fit labels_."""
    output_path = Path(output_path)
    predictions = np.lib.format.open_memmap(output_path, mode="w+", dtype=np.int16, shape=(n_rows,))
    counts = np.zeros(estimator.n_clusters, dtype=np.int64)
    sse = 0.0
    seen = 0
    for start, end, X in feature_chunks(package, split, scaling, chunk_size):
        labels = estimator.predict(X)
        predictions[start:end] = labels
        counts += np.bincount(labels, minlength=estimator.n_clusters)
        difference = X - estimator.cluster_centers_[labels]
        sse += float(np.einsum("ij,ij->", difference, difference))
        seen = end
    predictions.flush()
    del predictions
    if seen != n_rows or not np.isfinite(sse):
        raise ValueError("Prediction coverage or distance failed")
    return {"rows": seen, "cluster_counts": counts.tolist(), "sse": sse,
            "mean_squared_distance": sse / n_rows,
            "labels_sha256": sha256_file(output_path)}


def record_environment(output_dir):
    import joblib
    import matplotlib
    import pandas
    import sklearn
    output_dir = Path(output_dir)
    write_json(output_dir / "environment.json", {
        "python": sys.version, "platform": platform.platform(),
        "numpy": np.__version__, "scikit_learn": sklearn.__version__,
        "pandas": pandas.__version__, "matplotlib": matplotlib.__version__,
        "joblib": joblib.__version__,
        "threads": {key: os.environ.get(key) for key in
                    ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS")},
    })
    completed = subprocess.run([sys.executable, "-m", "pip", "freeze"],
                               text=True, capture_output=True, check=False)
    if completed.returncode:
        raise RuntimeError("Could not capture pip freeze for reproducibility")
    (output_dir / "requirements-lock.txt").write_text(completed.stdout, encoding="utf-8")


def comparison_policy(cfg):
    # Stage and machine paths can change without changing the experiment policy.
    return {k: v for k, v in cfg.items()
            if k not in {"stage", "package_dir", "output_root", "experiment_id"}}

