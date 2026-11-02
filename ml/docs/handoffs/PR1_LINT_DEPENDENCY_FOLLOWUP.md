# PR #1 lint/dependency follow-up and next owners

This follow-up removes inherited RF/XGB lint debt and declares the optional XGBoost
dependency. It does not make the legacy RF/XGB scripts eligible for official model
comparison. All classifier/clustering fitting, including smoke, remains Kaggle-only.

## What changed

- Sort imports, wrap long lines and replace each local to_mb lambda with an equivalent
  function in the two inherited scripts.
- Declare optional extra `xgboost>=2,<4`; install using
  `uv sync --locked --extra dev --extra kaggle --extra xgboost` or
  `python -m pip install -e ".[dev,kaggle,xgboost]"` from ml/.
- Update the lockfile without changing any of the 35 existing package/version pairs.
  New XGBoost versions/dependencies have Python/platform markers in the universal lock.
- Do not rewrite the earlier integration receipt: its 20-error result accurately
  describes its historical checkout. The new additive receipt records this fix.

Checks: locked Ruff 0.16.8 on the complete ML Python/notebook snapshot; formatting
check on both scripts; normalized AST comparison against b609fca; Python compilation;
and `uv lock --check --offline`. No classifier fit, model reload or TEST evaluation.
The earlier 375-test receipt remains historical, not a claim that those tests were
rerun for this follow-up. Dependency resolution is not XGBoost training validation.

## Hiếu: IOTG-60/61/63/65

Next checkpoint is a repaired primary RF/XGB workflow plus separate Kaggle smoke/full
notebooks and a frozen code bundle. Target: checkpoint on 02/11 and comparable outputs
on 03/11, subject to actual resource/runtime results.

1. Keep the approved primary package/feature/label/split contracts. Full uses
   4,944,968 TRAIN and 1,056,372 VALIDATION observations. TEST stays closed.
2. Correct the actual TRAIN population identity. A sampled smoke must carry its own
   selected-row membership fingerprint and counts; it must not claim the full TRAIN
   fingerprint or be eligible for the official full-population comparison.
3. Full must use all frozen TRAIN rows by default, with no automatic sampling or
   resource fallback. Freeze and record baseline settings and explicit raw/scaled
   view, dtype, seeds and package/manifest/config/source identities.
4. Verify the package before training; avoid requiring a Git checkout on Kaggle.
   Do not refit preprocessing. Pin the actual dependency runtime used in the bundle/run.
5. Persist full VALIDATION row identity, labels, malicious probabilities/predictions,
   model, metrics, timing/RAM, source snapshot and output checksums. Verify model
   reload prediction/probability parity on Kaggle.
6. Keep fresh output directories. Require matching successful smoke evidence and
   resource preflight before Full. Select hyperparameters only using TRAIN/VALIDATION.
7. Run a small justified, predeclared tuning budget only after valid baselines exist;
   report baseline versus tuning with matching populations.

Do not run the current legacy entrypoints as official results just because Ruff now
passes. Their population-identity/export/output gaps are still pending.

## Minh Sơn: IOTG-62/64/68

Publish the clustering implementation, frozen configuration and current artifacts or
a specific blocker. Clustering does not wait for final classifier selection.

- Use the fitted primary preprocessing and record actual fit/evaluation populations.
- Fix K candidates, seed, algorithm and resource limits before fitting on Kaggle.
- Ground-truth labels do not enter the fit; use them after fit for ARI/NMI.
- Record cluster sizes, bounded/resource-aware silhouette procedure and any sampling
  fingerprints, plus interpretation and limitations.
- Target clustering notes/results draft on 03/11; Technical Implementation draft 04/11.
- Prepare Conda README/package structure in parallel. Final packaging follows final
  classifier selection; independent reproduction remains a separate requirement.

## Duy: IOTG-66/171

Publish EDA scripts, source tables and figures from existing audit evidence and the
verified primary LR/Bot-IoT outputs. Do not rerun all audits or wait for every model.

Show macro-F1, supports, benign recall/FPR and confusion counts; label VALIDATION
clearly. Bot-IoT LR Full has TN=7, FP=89, FN=3, TP=733605; accuracy near 100% does not
establish useful benign performance. Use the archived source metrics, not hand-entered
guesses. EDA draft is due 03/11; evaluation figures 04-05/11.

## Sơn

Complete PR review/integration and confirm recipient access to processed packages.
Write Intro/Problem Framing (~420 words) and shared Methodology (~320 words total)
for the 03/11 draft checkpoint. Comparison/final selection remains pending RF/XGB
outputs; final TEST follows configuration freeze. Preserve actual contribution
records for data preparation, execution and scientific review.

