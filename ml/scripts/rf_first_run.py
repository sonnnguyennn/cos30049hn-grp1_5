import argparse
import hashlib
import subprocess
import sys
import time
import random
import json
import platform
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from iotguard.evaluation.primary import binary_metrics, experiment_result, resolve_configuration

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
        out[start:start + block] = x[idx[start:start + block]]

    return out

def predict_validation(model, package, chunk_size):
    ys, ps = [], []
    
    for block, y in package.chunks('VALIDATION', scaled=False, chunk_size=chunk_size):
        ps.append(model.predict_proba(block.astype(np.float32))[:, 1])
        ys.append(np.asarray(y))

    return np.concatenate(ys), np.concatenate(ps)

def git_output(*args):
    return subprocess.run(['git', *args], capture_output=True, text=True, check=True).stdout

def peak_memory_mb():
    try:
        import psutil
        process = psutil.Process()
        return process.memory_info().rss / (1024*1024)

    except Exception:
        return None

def main():
    # ----- 1. Read command-line arguments -----
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--package", required=True, type=Path)
    ap.add_argument("--fraction", type=float, default=0.05)
    ap.add_argument("--seeds", required=True, type=Path, help='path to seeds.yaml (random_seeds: python/numpy/scikit_learn)')
    ap.add_argument("--trees", type=int, default=100)
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--chunk-size", type=int, default=50000)
    ap.add_argument("--out", required=True, type=Path, help='results folder; keep it OUTSIDE the git repo')
    args = ap.parse_args()
    if not 0 < args.fraction <= 1:
        sys.exit('--fraction must be in (0, 1]')

    try:
        code_revision = git_output('rev-parse', 'HEAD').strip()
        changed = git_output('status', '--porcelain').splitlines()
        repo_top = Path(git_output('rev-parse', '--show-toplevel').strip()).resolve()
    except (subprocess.CalledProcessError, FileNotFoundError):
        sys.exit('git failed: run this script from inside the training git checkout.')
    
    dirty_worktree = bool(changed)
    print(f"code revision: {code_revision[:12]}   dirty_worktree: {dirty_worktree}")
    if dirty_worktree:
        print("  uncommitted changes (commit the script before the run you report):")
        for line in changed[:10]:
            print("   ", line)
    out_resolved = args.out.resolve()
    if out_resolved == repo_top or repo_top in out_resolved.parents:
        print("WARNING: --out is inside the repo. New result files will make later runs 'dirty' unless that folder is listed in .gitignore.")

    seeds = resolve_configuration(input_view='raw', parameters={}, seed_file=args.seeds)['seeds']
    random.seed(seeds['python'])
    np.random.seed(seeds['numpy'])
    seed_sample = seeds['numpy']
    seed_model = seeds['scikit_learn']
    print('1. Read arg complete')

    # ----- 2. Open the package -----
    sys.path.insert(0, str(args.package.resolve()))
    from primary_package import PrimaryPackage, sha256_file
    package = PrimaryPackage(args.package, verify=False)
    manifest = package.manifest
    x_train, y_train, _ = package.load('TRAIN')
    print('2. Open package complete')

    # ----- 3. Build training sample -----
    t0 = time.perf_counter()
    idx = stratified_indices(np.asarray(y_train), args.fraction, seed_sample)
    X = gather_float32(x_train, idx)
    y = np.asarray(y_train)[idx]
    t_load = time.perf_counter() - t0
    idx_hash = hashlib.sha256(idx.tobytes()).hexdigest()
    print('3. Build sample complete')

    # ----- 4. Train Random Forest -----
    model = RandomForestClassifier(n_estimators=args.trees, n_jobs=args.jobs, random_state=seed_model)
    t0 = time.perf_counter()
    model.fit(X, y)
    t_fit = time.perf_counter() - t0
    assert list(model.classes_) == [0, 1]
    print('4. RF Train complete')

    # ----- 5. Evaluate on VALIDATION -----
    t0 = time.perf_counter()
    y_true, proba = predict_validation(model, package, args.chunk_size)
    metrics = binary_metrics(y_true, proba)
    t_eval = time.perf_counter() - t0
    print('5. Evaluation complete')

    # ----- 6. Build result -----
    run_id = f"rf_frac{args.fraction:g}_seed{seed_model}"
    config = resolve_configuration(input_view='raw', seed_file=args.seeds, parameters={
        'algorithm': 'RandomForestClassifier',
        'n_estimators': args.trees,
        'class_weight': None,
        'random_state': seed_model,
        'fit_dtype': 'float32',
        'train_sampling': {
            'method': 'random sample inside TRAIN, same fraction per class, seeded, TRAIN only',
            'fraction': args.fraction,
            'seed': seed_sample,
            'rows': int(len(idx)),
            'rows_in_train': int(manifest['counts']['TRAIN']),
            'class_counts': {"benign": int((y == 0).sum()), "malicious": int((y == 1).sum())},
            'indices_sha256': idx_hash
        }
    })
    result = experiment_result(
        run_id, metrics, configuration=config,
        code_revision=code_revision,
        dirty_worktree=dirty_worktree,
        package_version=manifest['package_version'],
        package_manifest_sha256=sha256_file(package.root / "manifest.json"),
        train_population_sha256=manifest["files"]["TRAIN_metadata.npy"]["sha256"],
        validation_population_sha256=manifest["files"]["VALIDATION_metadata.npy"]["sha256"]
    )

    # ----- 7. Save everything -----
    run_dir = args.out / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    np.save(run_dir / 'train_sample_indices.npy', idx)
    joblib.dump(model, run_dir / 'model.joblib')
    (run_dir / 'result.json').write_text(json.dumps(result, indent=2))
    notes = {
        'run_id': run_id,
        'validation_rows': int(manifest['counts']['VALIDATION']),
        'resources': {
            'load_sample_seconds': round(t_load, 1),
            'fit_seconds': round(t_fit, 1),
            'validation_predict_seconds': round(t_eval, 1),
            'model_size_mb': round((run_dir / 'model.joblib').stat().st_size() / 2**20, 1),
            'peak_memory_mb': peak_memory_mb()
        },
        'environment': {'python': platform.python_version(), 'numpy': np.__version__, 'scikit_learn': sklearn.__version__},
        'uncommitted_files_at_start': changed[:20],
        'test_partition_used': False
    }
    (run_dir / 'run_notes.json').write_text(json.dumps(notes, indent=2))
    mal = metrics['per_class']['malicious']
    print(json.dumps({
        "rows_sampled": len(idx),
        "TN_FP_FN_TP": [metrics["TN"], metrics["FP"], metrics["FN"], metrics["TP"]],
        "macro_f1": metrics["macro_f1"], "fpr": metrics["fpr"], "malicious_recall": mal["recall"],
        "resources": notes["resources"]
    }, indent=2))
    print(f"\nSaved to {run_dir}")

if __name__ == '__main__':
    main()
