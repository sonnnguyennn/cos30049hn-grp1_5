# Bot-IoT secondary Kaggle baseline protocol v1

Execution owner: Hiếu, after review. Preparation only; NOT_RUN on Kaggle at bundle release.
This is a new Bot-IoT experiment, not an N-BaIoT rerun. Package remains
PREPARED_PENDING_REVIEW; any later execution acceptance is an external receipt, never a
package-manifest status edit. v2 followed structural TEST diagnostics before any model fit.

Pin package manifest SHA256:
`dd4fdc2551df68f294968f38ca3ecced0c27ac8bc2d1e1ae22239b7d676bae7c`.
Package, contract, preprocessor and memberships remain unchanged. No preprocessing fitting,
PCA, SMOTE, class balancing, resampling, hyperparameter search or threshold tuning.

Fixed baselines:

- DummyClassifier(strategy=most_frequent,random_state=1729).
- LogisticRegression(solver=lbfgs,penalty=l2,C=1,tol=1e-4,max_iter=1000,
  class_weight=None,fit_intercept=True,random_state=1729).
- Threshold0.5; threads4 using threadpoolctl; chunk_size8192; float64 throughout.

Smoke selection is frozen before fitting: hash TRAIN group identifiers with ASCII
`bot-iot-v2-smoke:1729:` prefix, sort ascending digest then group identifier, take first8192
groups and union the fixed mixed-label group
`413952c7fb9dc5b9ed4e85b5bd90fcf56ad147a666dacec19fd8ada49a90b844`.
This predeclared anchor tests accepted representation ambiguity and guarantees both classes.
Retain every row of selected groups without replication or label-based weights. No seed
reroll, category-based relocation or score-based choice. Record exact selected group list,
original membership JSONL bytes, global TRAIN indices, counts and hashes. Smoke changes
training prevalence incidentally and is diagnostic only; it is not a full baseline result.
Smoke and full both use the entire original VALIDATION (733,704 rows,96 benign).

Full TRAIN is exactly2,201,114 rows (286 benign), no default sample. Full requires a
SMOKE_PASS status receipt matching package/bundle/source/contract/protocol/preprocessor,
encoded-order/configuration/runtime identities and the recomputed exact smoke plan.
Both smoke models must have converged and passed reload probability/prediction parity.
Different code/config/runtime requires a new smoke. Fresh full resource preflight must pass;
never fall back to subset, float32, SGD, different solver or balancing to fit resources.

Preflight locates exactly one pinned manifest under /kaggle/input, authenticates verifier
and loader against it, then runs the bundled standalone verifier as an isolated subprocess.
Receipt/log and temporary storage are outside the read-only package, under /kaggle/working.
Only that subprocess may inspect TEST mechanically under v2. The training runner reads
TRAIN/VALIDATION arrays/chunks only; no TEST predictions, performance metrics or model use.
It verifies package identity, persisted feature order36, float64/finite encoded values,
membership digests, binary support and original group mass before classifier fitting.

SecondaryPackage.chunks() creates an external disk-backed float64 TRAIN encoded cache;
scaler/vocabulary are never refit. Cache is outside the run archive. Resource estimates
require max(3GiB,6*encoded TRAIN bytes+2GiB) available RAM and encoded TRAIN bytes+2GiB
free working disk. These are conservative estimates, not a guarantee against runtime OOM.

Save complete VALIDATION y, source/row/pk/group/group-size metadata and original membership,
per-model malicious probabilities/predictions, serialized models and results. Threshold uses
probability>=0.5. Report global integer row confusion counts and class supports/recalls,
malicious precision,FPR,macro-F1 (accuracy supplemental). Group sensitivity uses1/n_g per
row from the original fixed X group within VALIDATION, including mixed groups if present;
each group contributes total mass1. No class-conditional weighting and no chunk-F1 averages.
Weighted confusion/supports are masses, explicitly distinct from integer counts.

Record every fitting warning, convergence flag/n_iter, fit duration, total elapsed time,
package-verification duration and runner peak RSS after standalone verification. Serialize
and reload each model, compare all VALIDATION probabilities (absolute tolerance1e-12) and
threshold predictions exactly. Nonconverged results remain diagnostic; smoke cannot PASS.
Row/group reports do not remove the uncertainty from only96 VALIDATION benign rows and
18/96 concentration in the largest benign group. No unseen-device/future-time/deployment claim.

All outputs use a new microsecond UTC run directory; files/archives cannot overwrite.
Archive includes exact bundle source snapshot and checksum coverage for every output.
Results bind package manifest, protocol/config, preprocessor, bundle/source and actual TRAIN
and VALIDATION population hashes. Full can be eligible for full-population comparison only
after convergence/parity; this does not constitute TEAM_VERIFIED or package status promotion.
Local work is code/notebook/packaging verification only; every classifier fit occurs Kaggle.
