# IoTGuard Kaggle LR and Dummy baseline — integrated release v2

Training policy: all model fitting, including diagnostic smoke, runs on Kaggle only. Local work is limited to preparing source, validating notebooks, and reviewing exported results. This release covers Son's LR + Dummy phase, not Hieu's RF/XGBoost or Minh Son's clustering implementation.

## Files and workflow

For repository users, first build the external code ZIP with the command below; do not upload the full source checkout. The ZIP contains all standalone files required by the two notebooks.

1. Unzip this bundle locally only to access the two .ipynb files. Do not execute training locally.
2. Create a Kaggle Dataset containing the original complete `g3b_primary_v1` directory from `E:/Document/iotguard_primary_packages/g3b_primary_v1`. Preserve every filename and the exact manifest. Original package size: 6,575,404,266 bytes. The data is NOT included in this code bundle.
3. Create another Kaggle Dataset containing the extracted code bundle, or upload `IoTGuard_Kaggle_LR_Bundle.zip` unchanged. Use the same bundle for both notebooks. Sharing private inputs with the project members is sufficient; publishing is not required.
4. Import `01_IoTGuard_LR_Smoke.ipynb` into a Kaggle Notebook. Add the processed-data and code-bundle inputs. Use a CPU session (no accelerator required by this implementation). Existing runtime packages are checked before fit. If a dependency is missing, install this bundle's requirements in Kaggle and restart the session. No installation is performed automatically.
5. Run all cells and inspect `run_status.json`. The required outcome is `SMOKE_PASS`; this uses diagnostic subsets of existing TRAIN/VALIDATION, not a new split and not an official comparison population. Save the notebook version with outputs.
6. Import `02_IoTGuard_LR_Full.ipynb`. Add the same two inputs plus the successful smoke notebook's saved output as an input. Run all cells. The gate requires the same package and exact bundle identity as the smoke run.
7. Download the `iotguard_lr_full_*.zip` output. Success is `BASELINES_COMPLETE` with `eligible_for_official_comparison=true`. Send the ZIP to the reviewer. If status is BLOCKED_RESOURCE, FAILED or LR_NOT_CONVERGED, send its status/logs instead; do not call the run complete.

Kaggle saves outputs under `/kaggle/working` when a notebook version is saved. Use Save Version / Run All and retain the outputs. The runner deletes the large scaled cache on normal completion/failure, keeping the result directory and review ZIP. A hard session interruption can leave an incomplete cache; do not treat it as a completed run or reuse it manually.

## Locked data and baseline decisions

See `protocols/kaggle_lr_baseline_v1.md` in the exported ZIP (or `ml/docs/protocols/kaggle_lr_baseline_v1.md` in the repository). Full execution requires the same run configuration as its matching smoke receipt.

Expected original manifest SHA-256:
`6ab99e86397242e219bfa1f8490d8e03b169ec87a092af80cb3e7aef1e61147b`

Full TRAIN has 4,944,968 rows and VALIDATION has 1,056,372. Input: 115 float64 features. Metadata never enters X. The package's scaler is used unchanged; it was fitted on TRAIN. TEST is not loaded for modeling. File checksum validation may read TEST payload bytes mechanically, without evaluation.

Dummy uses most_frequent fitted on TRAIN. LR uses lbfgs, C=1.0, class_weight=None, tol=1e-4, seed 42, max_iter=1000 and threshold 0.5. Effective sklearn parameters and exact runtime versions are exported. lbfgs with finite C is the L2 baseline in the supported sklearn versions. Thread limit: 4 by default. No parameter search, rebalancing, feature selection or threshold tuning occurs.

Smoke uses 50,000 deterministic stratified TRAIN rows and 10,000 deterministic stratified VALIDATION rows (seeds 42/43). Indices and derived subset identities are saved. Smoke metrics are diagnostic only and must not be mixed with official full-population comparisons.

Full LR uses a disk-backed C-ordered float64 scaled matrix and chunked predictions. Preflight conservatively requires about two scaled-matrix sizes plus 1 GiB of available RAM, and cache size plus 1 GiB free disk. This is a guard, not proof against every estimator/runtime allocation. Record peak RSS and convergence. No automatic fallback to SGD, subset training, float32 or another solver is allowed.

Nonconverged LR is saved only as a diagnostic result, not an official `lr_result.json`. Discuss a protocol/config revision before retrying; do not silently change settings after observing validation scores.

## Source and experiment identity

The imported archive referenced foundation commit `e478e8e7ff0d374d9fd6f53e411bd4f414ce1c14`. The integrated runner now lives in `ml/src/iotguard/experiments/kaggle_lr.py`; notebooks live in `ml/notebooks/kaggle/`. Loader, metrics, seed configuration and schemas stay canonical in the repository. Vendored copies exist only in the generated external code ZIP, not as duplicate source packages in Git.

Generate a new bundle from the intended source checkpoint (from `ml/`):

```powershell
.venv/Scripts/python.exe scripts/build_kaggle_lr_bundle.py --output E:/Document/iotguard_kaggle_exports/IoTGuard_Kaggle_LR_Bundle.zip
```

Use a fresh output filename if a release already exists. The exporter records the actual checkout commit, boolean dirty status and exact source hashes in `bundle_manifest.json`. A clean export after commit records that committed implementation; exports with uncommitted edits explicitly remain dirty. Results use that source revision/status and bind the entire bundle manifest hash. Never rewrite previous run receipts to point to a later commit.

Release id is `iotguard_primary_lr_kaggle_v2`. Any modification changes bundle identity and requires a fresh matching smoke run before full. Package identity remains the original G3B manifest hash. The notebooks automatically use the same exported canonical implementation and refuse cached shared modules from another source.

Result identity uses the existing strict experiment API/schema, exact data manifest hash, package version and population fingerprints. Global VALIDATION metrics are calculated from all predictions; F1 is not averaged across chunks. Both models are serialized and reloaded for prediction parity.

## Outputs for review

- `run_status.json`, `comparison.csv`, per-model result JSON and validation probabilities/predictions.
- LR/Dummy models, fitted scaler JSON, feature contract and original data manifest.
- Resolved parameters, convergence/warnings, fit time, peak process RSS and runtime versions.
- Exact source snapshot and output checksums.

Local QA validates code, notebook JSON and policy guards only. The exporter and integration tests do not fit models or execute Kaggle runs. The two notebooks and runner must be executed on the user's Kaggle account with the original dataset attached.

References supplied in the imported bundle (not evidence of a completed run):
- https://www.kaggle.com/docs/notebooks
- https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LogisticRegression.html
