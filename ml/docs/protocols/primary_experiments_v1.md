# Primary experiments protocol revision 1

Status: IMPLEMENTED for G3B data preparation and shared metrics. No classifier or clustering model has been trained. Historical G3A contracts remain unchanged.

Inputs are all 115 source features in G2A order, float64. Preserve every observation and original row weighting; no deduplication, subsampling or resampling. Assign the G3A numeric group and partition before storage or scaling. Labels, device, source identity and group IDs are metadata only. The primary target is benign=0, malicious=1; the source taxonomy strings remain in the package source table and copied contracts.

Use the same full TRAIN and VALIDATION populations for classifier comparisons. Population identity is the SHA-256 of each partition's metadata file in the package manifest, along with the manifest checksum and package version. A later change to features, sampling, scaling, or evaluation policy requires a protocol revision before comparisons run.

Raw read-only float64 memmaps support RF/XGBoost. StandardScaler is incrementally fit on TRAIN only, preserving the original observation weighting. Persist mean, variance, scale, and sample count in JSON. VALIDATION is transform-only. TEST is prepared mechanically and remains SEALED; no model evaluation or selection uses it. The loader requires an explicit partition and denies TEST by default. Scaled chunks are computed on demand to avoid a second full matrix. Full-batch training may still require more RAM than this machine has; the training team must measure their algorithm's memory needs separately.

The default probability threshold is 0.5 (malicious if p >= 0.5), without threshold tuning. Positive class: malicious. Confusion matrix order: [benign, malicious]. Report TN, FP, FN, TP, class support, accuracy, per-class precision/recall/F1, macro-F1, and FPR=FP/(FP+TN). Undefined rates are JSON null. Macro-F1 is null if a class F1 is undefined; do not silently turn undefined rates into zero.

Select the highest VALIDATION macro-F1. Candidates within 1e-6 of the maximum are tied; prefer lower FPR, then higher malicious recall. A remaining exact tie preserves caller order and should be reported. Reject candidates with undefined selection metrics or differing population fingerprints. TEST cannot be submitted to the shared G3B metrics interface.

Seeds resolve from `config/seeds.yaml` (Python, NumPy and scikit-learn: 42). Every future run must record the resolved seeds, algorithm and hyperparameters, input view, protocol revision, code revision, dirty status, package manifest checksum, and partition fingerprints. `evaluation.primary.experiment_result` creates the shared `primary_result_v1` envelope with explicit configuration; `binary_metrics` creates the `primary_metrics_v1` payload. No training run exists yet.

The machine-readable envelope and metrics schema is [primary_result_v1.schema.json](primary_result_v1.schema.json). `experiment_result` now requires `package_version`, `package_manifest_sha256`, and boolean `dirty_worktree` as explicit keyword arguments. Omission or unknown dirty status is rejected. `select_validation` refuses missing identity or different package version, exact manifest checksum, protocol revision, TRAIN fingerprint, or VALIDATION fingerprint. Each result's protocol revision must also match its resolved configuration. Dirty status is recorded per run and may differ between candidates; it is not a selection tie-breaker. Legacy results lacking identity must be reconstructed from authentic run evidence before comparison.

The experiment's `dirty_worktree` describes the actual training checkout as a boolean; do not copy the package manifest's historical build-time Git status string into that field.

Use `resolve_configuration` to read defaults. For future validation predictions (no model training is performed by this example):

```python
import subprocess
from iotguard.data.primary_package import PrimaryPackage, sha256_file
from iotguard.evaluation.primary import binary_metrics, experiment_result, resolve_configuration

def record_validation(run_id, probabilities, package_directory):
    # Run from the training checkout so Git identifies the actual training implementation.
    package = PrimaryPackage(package_directory, verify=True)
    _, targets, _ = package.load('VALIDATION')
    config = resolve_configuration(input_view='raw', parameters={})  # Record actual parameters.
    return experiment_result(
        run_id, binary_metrics(targets, probabilities), configuration=config,
        code_revision=subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode().strip(),
        dirty_worktree=bool(subprocess.check_output(['git', 'status', '--porcelain'])),
        package_version=package.manifest['package_version'],
        package_manifest_sha256=sha256_file(package.root / 'manifest.json'),
        train_population_sha256=package.manifest['files']['TRAIN_metadata.npy']['sha256'],
        validation_population_sha256=package.manifest['files']['VALIDATION_metadata.npy']['sha256'],
    )
```

Package manifest revision `primary_package_v1` records source/feature/split hashes, source lineage, counts, dtype/order, labels, duplicate policy, TRAIN-only scaling, resource preflight, actual invocation, code revision and dirty status. SHA-256 covers every payload file. Raw storage tolerance is zero; CSV export uses 17 significant digits. Scaled reload comparisons use atol=rtol=1e-12.

Source/package integrity failures stop publication. Incomplete builds retain `INCOMPLETE.json` and lack a valid final manifest. Smoke packages have status SMOKE and are rejected by the default team loader. A full package is READY_FOR_TEAM only after isolated loading without source config passes. TEAM_VERIFIED requires a real run by Hiếu or Minh Sơn on their machine.

## Self-contained build and receipt

From `ml/`, one build command produces the complete portable package, including loader, README, standalone verifier, scaler, contracts and arrays. All payload sizes/checksums are in `files`; `implementation_sha256` covers the builder/verifier, portable loader, canonical parsing/split/contract implementation, seed configuration, label mapping and README source. Runtime versions are recorded in `environment`. No manual copy or manifest-edit step is needed.

```powershell
# Use a new external output path. Do not overwrite an accepted package.
.venv/Scripts/python.exe scripts/materialize_primary.py --full --output E:/Document/iotguard_primary_packages/g3b_primary_v1_next
```

Copy the resulting directory to the recipient machine and follow its README. Install NumPy there and run `python -I -B verify_primary_package.py . --output recipient_verification.json` from that copied directory. The verifier is for FULL packages; development smoke output remains explicitly SMOKE and cannot replace the official training population. This repair was verified with a small real-source build only; the accepted `g3b_primary_v1` package was not rebuilt or modified.
