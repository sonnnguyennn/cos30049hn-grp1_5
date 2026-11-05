import argparse
import hashlib
import json
import platform
import random
import re
import subprocess
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from iotguard.evaluation.population import selected_population
from iotguard.evaluation.primary import binary_metrics, experiment_result, resolve_configuration
from iotguard.evaluation.primary_runtime import verified_package
from iotguard.experiments.kaggle_lr import assert_kaggle


def stratified_indices(y, fraction, seed):
    rng = np.random.default_rng(seed)
    parts = []

    for cls in (0, 1):
        idx = np.flatnonzero(y == cls)
        n = max(1, round(len(idx) * fraction))
        parts.append(rng.choice(idx, size=n, replace=False))

    return np.sort(np.concatenate(parts))


def gather_float32(x, idx, block=50000):
    out = np.empty((len(idx), x.shape[1]), dtype=np.float32)

    for start in range(0, len(idx), block):
        out[start : start + block] = x[idx[start : start + block]]

    return out


def predict_validation(model, package, chunk_size):
    ys, ps = [], []

    for block, y in package.chunks("VALIDATION", scaled=False, chunk_size=chunk_size):
        ps.append(model.predict_proba(block.astype(np.float32))[:, 1])
        ys.append(np.asarray(y))

    return np.concatenate(ys), np.concatenate(ps)


def git_output(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def peak_memory_mb():
    try:
        import psutil

        info = psutil.Process().memory_info()

        def to_mb(b):
            return round(b / 2**20, 1)

        return {
            "peak_working_set_mb": to_mb(getattr(info, "peak_wset", info.rss)),
            "peak_private_mb": to_mb(info.peak_pagefile)
            if hasattr(info, "peak_pagefile")
            else None,
        }

    except Exception:
        return None


def parse_max_features(text):
    if text in ("sqrt", "log2"):
        return text
    try:
        count = int(text)
    except ValueError:
        pass
    else:
        if count < 1:
            raise argparse.ArgumentTypeError("a count must be at least 1")
        return count
    try:
        fraction = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "use sqrt, log2, a fraction like 0.3, or a whole number like 20"
        ) from None
    if not 0 < fraction <= 1:
        raise argparse.ArgumentTypeError("a fraction must be in (0, 1]")
    return fraction


def main():
    assert_kaggle()
    # ----- 1. Read command-line arguments -----
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--package", required=True, type=Path)
    ap.add_argument("--fraction", type=float, default=0.05)
    ap.add_argument(
        "--seeds",
        required=True,
        type=Path,
        help="path to seeds.yaml (random_seeds: python/numpy/scikit_learn)",
    )
    ap.add_argument("--trees", type=int, default=100)
    ap.add_argument(
        "--max-depth", type=int, default=None, help="maximum tree depth (default: no limit)"
    )
    ap.add_argument(
        "--min-samples-leaf", type=int, default=1, help="minimum rows in a leaf (default 1)"
    )
    ap.add_argument(
        "--max-features",
        type=parse_max_features,
        default="sqrt",
        help="features tried per split: sqrt, log2, fraction, or count (default sqrt)",
    )
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--chunk-size", type=int, default=50000)
    ap.add_argument(
        "--out", required=True, type=Path, help="results folder; keep it OUTSIDE the git repo"
    )
    ap.add_argument(
        "--tag",
        default="",
        help="short label added to the run name, e.g. leaf5 (letters, digits, . _ -)",
    )
    ap.add_argument(
        "--overwrite",
        action="store_true",
        help="allow replacing a finished run that has the same name",
    )
    args = ap.parse_args()
    if not 0 < args.fraction <= 1:
        sys.exit("--fraction must be in (0, 1]")
    if args.tag and not re.fullmatch(r"[A-Za-z0-9._-]+", args.tag):
        sys.exit("--tag may contain only letters, digits, dot, dash and underscore")
    if args.max_depth is not None and args.max_depth < 1:
        sys.exit("--max-depth must be at least 1")
    if args.min_samples_leaf < 1:
        sys.exit("--min-samples-leaf must be at least 1")

    try:
        code_revision = git_output("rev-parse", "HEAD").strip()
        changed = git_output("status", "--porcelain").splitlines()
        repo_top = Path(git_output("rev-parse", "--show-toplevel").strip()).resolve()
    except (subprocess.CalledProcessError, FileNotFoundError):
        sys.exit("git failed: run this script from inside the training git checkout.")

    dirty_worktree = bool(changed)
    print(f"code revision: {code_revision[:12]}   dirty_worktree: {dirty_worktree}")
    if dirty_worktree:
        print("  uncommitted changes (commit the script before the run you report):")
        for line in changed[:10]:
            print("   ", line)
    out_resolved = args.out.resolve()
    if out_resolved == repo_top or repo_top in out_resolved.parents:
        print(
            "WARNING: --out is inside the repo. New result files will make later runs 'dirty' "
            "unless that folder is listed in .gitignore."
        )

    seeds = resolve_configuration(input_view="raw", parameters={}, seed_file=args.seeds)["seeds"]
    random.seed(seeds["python"])
    np.random.seed(seeds["numpy"])
    seed_sample = seeds["numpy"]
    seed_model = seeds["scikit_learn"]

    run_id = f"rf_frac{args.fraction:g}_seed{seed_model}" + (f"_{args.tag}" if args.tag else "")
    run_dir = args.out / run_id
    if (run_dir / "result.json").exists() and not args.overwrite:
        sys.exit(
            f"{run_dir} already holds a finished run.\n"
            "  Give this run its own name with --tag, or add --overwrite to replace it."
        )
    print("1. Read args complete")

    # ----- 2. Open the package -----
    sys.path.insert(0, str(args.package.resolve()))
    from primary_package import sha256_file

    package, package_verification = verified_package(args.package)
    manifest = package.manifest
    x_train, y_train, train_metadata = package.load("TRAIN")
    print("2. Open package complete")

    # ----- 3. Build training sample -----
    t0 = time.perf_counter()
    full_train = args.fraction == 1
    if full_train:
        idx = np.arange(len(y_train), dtype=np.int64)
    else:
        idx = stratified_indices(np.asarray(y_train), args.fraction, seed_sample)
    actual_population = selected_population(train_metadata, idx)
    X = gather_float32(x_train, idx)
    y = np.asarray(y_train)[idx]
    t_load = time.perf_counter() - t0
    idx_hash = hashlib.sha256(idx.tobytes()).hexdigest()
    print("3. Build sample complete")

    # ----- 4. Train Random Forest -----
    model = RandomForestClassifier(
        n_estimators=args.trees,
        n_jobs=args.jobs,
        random_state=seed_model,
        max_depth=args.max_depth,
        min_samples_leaf=args.min_samples_leaf,
        max_features=args.max_features,
    )
    t0 = time.perf_counter()
    model.fit(X, y)
    t_fit = time.perf_counter() - t0
    assert list(model.classes_) == [0, 1]
    print("4. RF train complete")

    # ----- 5. Evaluate on VALIDATION -----
    t0 = time.perf_counter()
    y_true, proba = predict_validation(model, package, args.chunk_size)
    metrics = binary_metrics(y_true, proba)
    t_eval = time.perf_counter() - t0
    print("5. Evaluation complete")

    # ----- 6. Build result -----
    config = resolve_configuration(
        input_view="raw",
        seed_file=args.seeds,
        parameters={
            "algorithm": "RandomForestClassifier",
            "n_estimators": args.trees,
            "class_weight": None,
            "random_state": seed_model,
            "max_depth": args.max_depth,
            "min_samples_leaf": args.min_samples_leaf,
            "max_features": args.max_features,
            "fit_dtype": "float32",
            "train_sampling": {
                "method": (
                    "none: all TRAIN rows"
                    if full_train
                    else "random sample inside TRAIN, same fraction per class, seeded, TRAIN only"
                ),
                "fraction": args.fraction,
                "seed": None if full_train else seed_sample,
                "rows": int(len(idx)),
                "rows_in_train": int(manifest["counts"]["TRAIN"]),
                "class_counts": {"benign": int((y == 0).sum()), "malicious": int((y == 1).sum())},
                "indices_sha256": idx_hash,
            },
        },
    )
    result = experiment_result(
        run_id,
        metrics,
        configuration=config,
        code_revision=code_revision,
        dirty_worktree=dirty_worktree,
        package_version=manifest["package_version"],
        package_manifest_sha256=sha256_file(package.root / "manifest.json"),
        train_population_sha256=actual_population["train_population_sha256"],
        validation_population_sha256=manifest["files"]["VALIDATION_metadata.npy"]["sha256"],
    )

    result["parent_train_population_sha256"] = manifest["files"]["TRAIN_metadata.npy"]["sha256"]
    result["actual_train_membership"] = actual_population
    # ----- 7. Save everything -----
    run_dir.mkdir(parents=True, exist_ok=True)
    np.save(run_dir / "train_sample_indices.npy", idx)
    (run_dir / "package_verification.json").write_text(json.dumps(package_verification, indent=2))
    joblib.dump(model, run_dir / "model.joblib")
    (run_dir / "result.json").write_text(json.dumps(result, indent=2))
    notes = {
        "run_id": run_id,
        "validation_rows": int(manifest["counts"]["VALIDATION"]),
        "resources": {
            "load_sample_seconds": round(t_load, 1),
            "fit_seconds": round(t_fit, 1),
            "validation_predict_seconds": round(t_eval, 1),
            "model_size_mb": round((run_dir / "model.joblib").stat().st_size / 2**20, 1),
            "peak_memory": peak_memory_mb(),
        },
        "environment": {
            "python": platform.python_version(),
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
        },
        "uncommitted_files_at_start": changed[:20],
        "test_partition_used": False,
    }
    (run_dir / "run_notes.json").write_text(json.dumps(notes, indent=2))
    mal = metrics["per_class"]["malicious"]
    print(
        json.dumps(
            {
                "rows_sampled": len(idx),
                "TN_FP_FN_TP": [metrics["TN"], metrics["FP"], metrics["FN"], metrics["TP"]],
                "macro_f1": metrics["macro_f1"],
                "fpr": metrics["fpr"],
                "malicious_recall": mal["recall"],
                "resources": notes["resources"],
            },
            indent=2,
        )
    )
    print(f"\nSaved to {run_dir}")


if __name__ == "__main__":
    main()
