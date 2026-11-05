# Primary classifier acceptance and final evaluation v1

This additive protocol implements `primary_experiments_v1`; its selection policy,
115 features, labels, split, preprocessing and threshold remain unchanged. Original
results, package manifests and historical receipts remain immutable. The assignment
plan supplies context, not permission to claim unexecuted work or another owner's approval.

## Acceptance before selection

Inventory every received file and compare small original result/notes files against
Git. A repeated run ID with different content is an error. Verify the pinned G3B
manifest and TRAIN/VALIDATION payload hashes before replay. Do not read TEST arrays
during acceptance or selection. Verify source commits and preserve their historical
identities separately from the evaluation implementation revision.

Actual membership is authoritative: validate saved indices as sorted, unique,
in-range little-endian int64; reconcile their checksum, class counts and sampling
method against TRAIN. Full requires exactly `arange(TRAIN rows)`. The population
fingerprint is SHA-256 of the selected metadata serialized as an uncompressed NumPy
v1 array, in selected index order, with the original structured dtype. For full
TRAIN this must equal the package metadata file hash. Future subset results put
this actual hash in `train_population_sha256` and retain the parent identity
separately. Legacy incorrect parent-as-subset hashes are explained in new sidecars,
never edited in place. Missing sampling metadata is not evidence of full training.

The original LR/Dummy full workflow is recognized through its checksummed archive,
full/diagnostic/eligibility flags, run status, source snapshot, exact package and
counts, convergence record and saved validation probabilities. It does not require
the unrelated RF/XGB `train_sampling` field. Replay the received models on all
VALIDATION rows: LR uses persisted TRAIN scaler and float64; RF/XGB use raw input
cast to float32. Record loaded model configuration, package, model and source hashes,
runtime versions, original versus replay counts, row-aligned probabilities, labels,
predictions and metadata. Original historical probabilities, when available, must
match replay within atol=rtol=1e-12 with exact threshold decisions. Reload the same
model and check prediction parity. Compatibility differences must be disclosed.
No training or parameter repair is permitted during replay. A failed gate is
recorded before retry in a fresh directory.

Official candidates require accepted full TRAIN and full VALIDATION, threshold
0.5, malicious positive, the same package/protocol/populations and applicable
convergence/eligibility checks. Subsets are diagnostic and excluded with reasons.
Conflicting identities stop comparison; do not retain only a majority group.
Use the existing shared `select_validation` rule: highest macro-F1; within 1e-6
of maximum use lower FPR, then higher malicious recall. Report remaining ties.
Report accuracy, precision/recall/F1/support for both classes, FPR and TN/FP/FN/TP.

## Freeze and final TEST gate

Persist and checksum a freeze record before opening TEST. Bind the selected run,
original training revision, evaluation revision and implementation hashes, exact
model, full configuration, input view/dtype, ordered features, label mapping,
scaler, threshold, package manifest/version and all partition identities, runtime,
comparison/selection files, acceptance receipts and validation predictions. The
freeze attests selection used TRAIN/VALIDATION only. Validate every bound file,
selection winner and validation reload parity before explicit TEST access.

`binary_metrics` and the shared selector continue to reject TEST. The final-only
entry point validates the freeze, then uses the identical confusion-count metric
implementation under a separate `primary_final_metrics_v1` envelope. Evaluate the
locked model on the full TEST population once, without fitting on TRAIN+VALIDATION.
Use fresh output directories and save probabilities, threshold decisions, labels,
metadata, metrics/confusion/support, environment, timing, logs, payload hashes and
freeze identity. A technical failure produces a failure receipt; a retry is a new
attempt with the same frozen identities. TEST does not authorize model reselection,
threshold changes or retrospective tuning. Those belong to future research.

## Execution and attribution

All new classifier fitting, retraining and tuning must execute on Kaggle. Local
acceptance, inference, metrics and code/fixture tests are allowed. Reuse valid
historical experiments; record their reported runtime honestly, without asserting
they ran on Kaggle when original evidence does not say so. Hiếu owns the original
RF/XGB experiments; Sơn owns this integration, code fixes, independent replay,
selection and final evaluation. Independent teammate review is still a separate
activity; automated acceptance does not fabricate approval or TEAM_VERIFIED status.

Clustering, EDA, final source ZIP and report formatting stay with their owners.
Bot-IoT evidence is linked separately and is never pooled with primary metrics.
