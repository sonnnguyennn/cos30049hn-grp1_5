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
    cfg.pop("drive_url", None)  # The delivery link is separate from the archived fit settings.
    cfg["package_dir"] = str(Path(cfg["package_dir"]).expanduser().resolve())
    cfg["output_root"] = str(Path(cfg["output_root"]).expanduser().resolve())
    if cfg["stage"] not in {"pilot", "full"}:
        raise ValueError("stage must be pilot or full")
    if cfg["scalings"] != ["g3b_standard", "raw"]:
        raise ValueError("This protocol requires the primary scaling and raw ablation")
    if not all(2 <= k <= 32767 for k in cfg["k_values"]):
        raise ValueError("K must be >=2 and fit in int16 prediction files")
    return cfg


def matching_manifest(root, expected):
    # The PDF does not give the manifest filename. Match its exact supplied hash,
    # rather than guessing an undocumented JSON schema or filename.
    candidates = [p for p in root.rglob("*.json")
                  if not any(part.startswith(".") or part in {"site-packages", "node_modules"}
                             for part in p.relative_to(root).parts)]
    matches = [p for p in candidates if p.stat().st_size < 50_000_000
               and sha256_file(p) == expected]
    if not matches:
        raise ValueError("No JSON matches the handoff manifest SHA-256. Confirm the package version.")
    return sorted(matches)[0]


def package_identity(cfg, package, manifest):
    root = Path(cfg["package_dir"])
    expected = cfg["expected_manifest_sha256"]
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
    manifest = matching_manifest(root, cfg["expected_manifest_sha256"])
    # Only use the documented, supplied loader; never allow TEST.
    sys.path.insert(0, str(root))
    importlib.invalidate_caches()
    if "primary_package" in sys.modules:
        loaded = Path(sys.modules["primary_package"].__file__).resolve()
        if loaded != loader.resolve():
            raise RuntimeError("A different primary_package is imported. Restart the kernel.")
    module = importlib.import_module("primary_package")
    package = module.PrimaryPackage(str(root), verify=True)
    return package, package_identity(cfg, package, manifest)


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



def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def completed_runs(stage_dir, cfg, identity, specs=None):
    """Return a checked run index, or None when this stage has yet to start."""
    if not stage_dir.exists():
        return None
    index_path = stage_dir / "run_index.json"
    if not index_path.is_file():
        raise RuntimeError(f"Incomplete stage at {stage_dir}. Use a new experiment_id.")
    if (comparison_policy(read_json(stage_dir / "configuration.json")) != comparison_policy(cfg)
            or read_json(stage_dir / "package_identity.json") != identity):
        raise ValueError("Saved configuration or package differs. Use a new experiment_id.")
    index = read_json(index_path)
    if not index or any(item["stage"] != stage_dir.name for item in index):
        raise ValueError(f"Invalid run index for {stage_dir.name}")
    if specs is not None:
        archived_specs = [{key: item[key] for key in ("scaling", "k", "seed")} for item in index]
        if archived_specs != specs:
            raise ValueError("Saved runs differ from the planned runs. Use a new experiment_id.")
    for item in index:
        model_file = stage_dir / item["run_id"] / "model.joblib"
        if sha256_file(model_file) != item["model_sha256"]:
            raise ValueError(f"Saved model changed: {model_file}")
    return index


def start_stage(stage_dir, cfg, identity):
    import shutil

    stage_dir.mkdir(parents=True, exist_ok=False)
    write_json(stage_dir / "configuration.json", cfg)
    write_json(stage_dir / "package_identity.json", identity)
    record_environment(stage_dir)
    source = Path(cfg["package_dir"]) / identity["manifest_relative_path"]
    shutil.copy2(source, stage_dir / "source_manifest.json")


def train_and_save(stage_dir, cfg, identity, package, cache, spec, fit):
    """Run a notebook's fit function, then write its artifacts and verify a reload."""
    import time
    from datetime import datetime, timezone

    import joblib

    stage = stage_dir.name
    scaling, k, seed = spec["scaling"], spec["k"], spec["seed"]
    run_id = f"{scaling}_k{k}_seed{seed}"
    run_dir = stage_dir / run_id
    run_dir.mkdir(exist_ok=False)
    started = time.perf_counter()
    with (run_dir / "training.jsonl").open("w", encoding="utf-8", buffering=1) as log:
        def log_event(event, **values):
            record = {"time_utc": datetime.now(timezone.utc).isoformat(), "event": event, **values}
            log.write(json.dumps(record, allow_nan=False) + "\n")

        try:
            X_pilot = np.load(cache / f"TRAIN_{scaling}.npy", mmap_mode="r")
            model, fit_rows = fit(spec, X_pilot, log_event)
            fit_seconds = time.perf_counter() - started
            model_path = run_dir / "model.joblib"
            bundle = {
                "estimator": model, "scaling": scaling, "identity": identity,
                "feature_policy": "all 115 canonical G3B predictors, original order, float64",
                "transform": f"PrimaryPackage.chunks(scaled={scaling == 'g3b_standard'})",
                "config": cfg, "spec": spec,
            }
            joblib.dump(bundle, model_path)
            write_json(run_dir / "configuration.json", {
                **spec, "stage": stage, "unique_fit_rows": fit_rows, "fit_seconds": fit_seconds,
                "full_epochs": cfg["full_epochs"] if stage == "full" else None,
                "estimator_parameters": {key: value for key, value in model.get_params().items()
                                         if key != "init"},
                "initialization": "k-means++ on sample",
            })
            np.save(run_dir / "cluster_centers.npy", model.cluster_centers_)
            X_val = np.load(cache / f"VALIDATION_{scaling}.npy", mmap_mode="r")
            val_labels = model.predict(X_val).astype(np.int16)
            np.save(run_dir / "VALIDATION_sample_clusters.npy", val_labels)

            coverage = {}
            if stage == "pilot":
                np.save(run_dir / "TRAIN_sample_clusters.npy", model.predict(X_pilot).astype(np.int16))
            else:
                for split in ("TRAIN", "VALIDATION"):
                    n_rows = identity["partitions"][split]["shape"][0]
                    coverage[split] = save_predictions(
                        package, model, scaling, split, n_rows,
                        run_dir / f"{split}_clusters.npy", cfg["batch_size"])
                full_val = np.load(run_dir / "VALIDATION_clusters.npy", mmap_mode="r")
                positions = np.load(cache / "VALIDATION_indices.npy", mmap_mode="r")
                np.testing.assert_array_equal(full_val[positions], val_labels)
                write_json(run_dir / "prediction_coverage.json", coverage)

            reloaded = joblib.load(model_path)["estimator"]
            np.testing.assert_array_equal(model.predict(X_val[:64]), reloaded.predict(X_val[:64]))
            log_event("saved_and_reload_verified", fit_seconds=fit_seconds,
                      total_seconds=time.perf_counter() - started, coverage=coverage)
            print(f"Saved {run_id} ({fit_seconds:.2f} seconds to fit)", flush=True)
        except Exception as error:
            write_json(run_dir / "failure.json", {"type": type(error).__name__, "message": str(error)})
            raise

    return {"run_id": run_id, **spec, "stage": stage, "unique_fit_rows": fit_rows,
            "fit_seconds": fit_seconds, "model_sha256": sha256_file(model_path)}


def load_validation_sample(cache, stage_dir, item):
    import joblib

    run_dir = stage_dir / item["run_id"]
    model = joblib.load(run_dir / "model.joblib")["estimator"]
    X = np.load(cache / f"VALIDATION_{item['scaling']}.npy", mmap_mode="r")
    clusters = np.load(run_dir / "VALIDATION_sample_clusters.npy", mmap_mode="r")
    np.testing.assert_array_equal(model.predict(X), clusters)
    return model, X, clusters


def geometry_record(cfg, stage_dir, item, X, clusters, repeat_details, dbi, ch, mean_distance):
    """Summarize score repetitions and format the comparison record."""
    usable = [detail["score"] for detail in repeat_details if detail["score"] is not None]
    eligible = len(usable) == cfg["silhouette_repeats"]
    counts = np.bincount(clusters, minlength=item["k"])
    row = {
        "run_id": item["run_id"], "stage": stage_dir.name, "scaling": item["scaling"],
        "requested_k": item["k"], "seed": item["seed"], "unique_fit_rows": item["unique_fit_rows"],
        "fit_seconds": item["fit_seconds"], "geometry_eval_rows": len(X),
        "observed_clusters_in_eval_sample": int(np.count_nonzero(counts)),
        "smallest_cluster_in_eval_sample": int(counts.min()),
        "silhouette_rows_per_repeat": min(len(X), cfg["silhouette_rows"]),
        "silhouette_valid_repeats": len(usable),
        "silhouette_mean": float(np.mean(usable)) if eligible else None,
        "silhouette_sample_std": float(np.std(usable, ddof=1)) if len(usable) > 1 else None,
        "davies_bouldin": dbi, "calinski_harabasz": ch,
        "sample_mean_squared_distance": mean_distance,
        "selection_eligible": eligible, "geometry_scope": "fixed uniform VALIDATION sample",
    }
    if stage_dir.name == "full":
        coverage = read_json(stage_dir / item["run_id"] / "prediction_coverage.json")["VALIDATION"]
        row["full_validation_mean_squared_distance"] = coverage["mean_squared_distance"]
        row["observed_clusters_full_validation"] = sum(count > 0 for count in coverage["cluster_counts"])
    return row


def save_geometry(stage_dir, rows, details):
    import pandas as pd

    write_json(stage_dir / "internal_metrics.json", rows)
    write_json(stage_dir / "silhouette_sampling_details.json", details)
    frame = pd.DataFrame(rows)
    frame.to_csv(stage_dir / "internal_comparison.csv", index=False)
    return frame


def plot_silhouette(stage_dir, frame, scalings):
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 2, figsize=(11, 4), constrained_layout=True)
    for axis, scaling in zip(axes, scalings):
        group = frame[frame["scaling"] == scaling]
        for seed, seeded in group.groupby("seed"):
            seeded = seeded.sort_values("requested_k")
            axis.errorbar(seeded["requested_k"], seeded["silhouette_mean"],
                          yerr=seeded["silhouette_sample_std"].fillna(0), marker="o", label=f"seed {seed}")
        axis.set(title=f"{stage_dir.name} · {scaling}", xlabel="Requested K", ylabel="Sampled silhouette")
        axis.legend()
    fig.savefig(stage_dir / "silhouette_by_k.png", dpi=160)
    plt.show()


def best_within_scaling(frame, scaling):
    eligible = frame[(frame["scaling"] == scaling) & frame["selection_eligible"]].copy()
    if eligible.empty:
        raise ValueError(f"No eligible candidate for {scaling}. Inspect collapsed clusters and sample coverage.")
    eligible["silhouette_for_tie"] = eligible["silhouette_mean"].round(6)
    return eligible.sort_values(["silhouette_for_tie", "requested_k", "seed"],
                                ascending=[False, True, True]).iloc[0]


def freeze_json(path, record):
    if path.exists():
        if read_json(path) != record:
            raise ValueError("A frozen selection would change. Use a new experiment_id.")
    else:
        write_json(path, record)


def load_validation_predictions(run_dir, n_rows):
    path = run_dir / "VALIDATION_clusters.npy"
    expected = read_json(run_dir / "prediction_coverage.json")["VALIDATION"]["labels_sha256"]
    if sha256_file(path) != expected:
        raise ValueError(f"Saved cluster assignments changed: {path}")
    clusters = np.load(path, mmap_mode="r")
    if clusters.shape != (n_rows,):
        raise ValueError("Cluster labels and ground truth must cover the same VALIDATION rows")
    return clusters


def save_composition(run_dir, counts, prevalence):
    import pandas as pd

    composition = pd.DataFrame(counts, columns=["benign_count", "malicious_count"])
    composition.index.name = "cluster_id"
    composition["total"] = composition.sum(axis=1)
    denominator = composition["total"].replace(0, np.nan)
    composition["malicious_fraction"] = composition["malicious_count"] / denominator
    composition["benign_fraction"] = composition["benign_count"] / denominator
    composition["malicious_lift_vs_validation"] = composition["malicious_fraction"] / prevalence
    composition.to_csv(run_dir / "cluster_composition_validation.csv")
    return composition


def save_profiles(STAGE_DIR, primary_id):
    import matplotlib.pyplot as plt
    import pandas as pd

    primary_dir = STAGE_DIR / primary_id
    composition = pd.read_csv(primary_dir / "cluster_composition_validation.csv", index_col="cluster_id")
    centers = np.load(primary_dir / "cluster_centers.npy")
    np.testing.assert_equal(centers.shape[1], 115)
    spread = np.std(centers, axis=0)
    top_positions = np.argsort(spread)[-8:][::-1]
    profiles = pd.DataFrame(centers, columns=[f"feature_position_{j:03d}" for j in range(centers.shape[1])])
    profiles.index.name = "cluster_id"
    profiles.to_csv(primary_dir / "centroid_profiles_standardized.csv")
    pd.DataFrame({"zero_based_feature_position": np.arange(115), "between_center_std": spread}).to_csv(
        primary_dir / "centroid_spread_by_feature_position.csv", index=False)
    fig, axes = plt.subplots(1, 2, figsize=(12, 4), constrained_layout=True)
    composition[["benign_fraction", "malicious_fraction"]].plot.bar(
        stacked=True, ax=axes[0], color=["#2d9d78", "#cc695c"], rot=0)
    axes[0].set(title="Entire VALIDATION: within-cluster composition", ylabel="Fraction", ylim=(0, 1))
    image = axes[1].imshow(centers[:, top_positions], aspect="auto", cmap="coolwarm")
    axes[1].set_xticks(range(len(top_positions)), [str(j) for j in top_positions])
    axes[1].set(title="Primary centroids: largest between-center spread", xlabel="Zero-based feature position",
                ylabel="Cluster ID", yticks=range(len(centers)))
    fig.colorbar(image, ax=axes[1], label="G3B standardized coordinate")
    fig.savefig(STAGE_DIR / "cluster_interpretation.png", dpi=160)
    plt.show()

    return composition


def save_analysis(STAGE_DIR, CFG, selection, comparison, composition):
    primary = comparison.loc[comparison["run_id"] == selection["selected_run_id"]].iloc[0]
    raw = comparison.loc[comparison["scaling"] == "raw"].iloc[0]
    valid_composition = composition[composition["total"] > 0]
    small_clusters = int((valid_composition["total"] < 0.01 * valid_composition["total"].sum()).sum())
    text = f"""# Clustering experiment: measured validation analysis

Primary run: {primary['run_id']}. Protocol: {CFG['protocol_id']}.
All 115 ordered G3B numeric predictors were used. Labels, source identity and device strings
were excluded from fitting. The complete TRAIN population ({int(primary['unique_fit_rows']):,} rows)
was processed for {CFG['full_epochs']} epochs with batch size {CFG['batch_size']}.
Standardization reused G3B's TRAIN-only scaler. TEST was not opened.

## Experiment design and selection
The pilot compared K={CFG['k_values']} for both G3B standardization and raw features, using the
same {CFG['pilot_train_rows']:,}-row uniform TRAIN sample and seed(s) {CFG['seeds']}.
It shortlisted one K per scaling using internal VALIDATION silhouette only. Each finalist was then
trained on all TRAIN rows. Standardized geometry was the primary analysis by prior policy.
The selection was saved before any ground-truth validation labels were inspected.
This is a separate unsupervised protocol proposal, not a classifier macro-F1 result schema.

## Internal geometry
The primary model's silhouette mean was {primary['silhouette_mean']:.6f}, with sample standard
deviation {primary['silhouette_sample_std']:.6f}, over {CFG['silhouette_repeats']} fixed uniform
subsets of {int(primary['silhouette_rows_per_repeat']):,} validation observations.
DBI was {primary['davies_bouldin']:.6f}; CH was {primary['calinski_harabasz']:.6f}, on the same
{int(primary['geometry_eval_rows']):,}-row validation evaluation population used by every run.
Requested K={int(primary['requested_k'])}; full VALIDATION represented
{int(primary['observed_clusters_full_validation'])} clusters.
The raw finalist used K={int(raw['requested_k'])} with silhouette {raw['silhouette_mean']:.6f}.
These geometries differ; this does not establish scale-free superiority of either scaling.
Use pilot/internal_comparison.csv and silhouette_by_k.png for measured K sensitivity.
Pilot and full scores have different fit populations and must not be presented as identical training.

## Post-selection relation to security labels
On all {int(primary['external_eval_rows']):,} VALIDATION records, ARI={primary['ari']:.6f}
and NMI={primary['nmi']:.6f}. These compare cluster partitions with binary labels;
they are not classification accuracy and do not assign benign/malicious names to cluster IDs.
Overall malicious prevalence was {primary['overall_malicious_fraction']:.2%}.
Among nonempty clusters, malicious fractions ranged from
{valid_composition['malicious_fraction'].min():.2%} to {valid_composition['malicious_fraction'].max():.2%}.
There were {small_clusters} nonempty clusters with <1% of validation rows.
Inspect exact counts, enrichment, and centroid profiles before describing separation.

## Limits and interpretation still required
K-Means favors compact Euclidean groups, always assigns a cluster, and does not supply a calibrated
malicious probability. Scaling, outliers, related predictors and device/source effects can dominate.
The full stream used local buffer shuffling rather than a global permutation; order effects remain.
Two epochs are a budget, not evidence of full convergence. Default seed 42 provides no seed stability claim.
Uniform evaluation samples can miss rare groups; sample variation is not a confidence interval.
Binary-label agreement does not establish separation of attack types, unseen devices or future traffic.
G3B preserves duplicates and original splits; this evaluation does not remove leakage/source risks.
The supplied handoff's verification does not by itself prove this receiving machine is TEAM_VERIFIED.

Before submission, map the largest-spread centroid feature positions to canonical feature names,
describe the observed direction and support of at least two clusters, and state whether mixed
clusters suggest device/traffic structure rather than a useful benign/malicious partition.
Do not revise model selection after this post-selection inspection without a new protocol version.
"""
    (STAGE_DIR / "analysis.md").write_text(text, encoding="utf-8")
    write_json(STAGE_DIR / "evaluation_receipt.json", {
        "status": "validation_evaluated", "test_opened": False,
        "primary_run_id": selection["selected_run_id"],
        "internal_feature_rows": int(primary["geometry_eval_rows"]),
        "silhouette_rows_per_repeat": int(primary["silhouette_rows_per_repeat"]),
        "silhouette_repeats": CFG["silhouette_repeats"],
        "external_label_rows": int(primary["external_eval_rows"]),
        "ground_truth_used_for_fit_or_selection": False,
    })
    return text
