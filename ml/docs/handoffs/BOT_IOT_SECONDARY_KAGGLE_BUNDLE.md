# Bot-IoT secondary v2 Kaggle bundle — Hiếu review/execution handoff

Prepared from clean checkpoint5808144 on branch `feat/bot-iot-secondary-kaggle-bundle`.
Only frontend/AGENTS.md exists; ML paths have no additional applicable instructions.
No package, prior protocol/receipt/audit, frontend or backend edits. No local model fits.

## Deliverable and exact identities

Use release **bot_iot_secondary_v2_20261102_02**, superseding local draft_01.

- ZIP: `E:/Document/iotguard_kaggle_exports/bot_iot_secondary_v2_20261102_02/IoTGuard_BotIoT_Secondary_v2_Kaggle_Bundle.zip`
-29,633 bytes,11 files; code/notebooks only, no bulk data/models.
- ZIP SHA256: `0fb3ade6dd8e07857cd921f6ce77353f1e40fb66c1ebfa28f303a2b1fb4f015a`.
- Bundle manifest SHA256: `06c19f532414cd28ccb977f0f957c7c0e4436990c45f23798b3963604e8a0b75`.
- Actual source revision: `84f3068386f1c11a5691d5383b2c4a46c8591b21`, dirty=false.
  Canonical source hashes match both exact snapshot bytes and Git blobs at that revision.
- Data package manifest pinned:
  `dd4fdc2551df68f294968f38ca3ecced0c27ac8bc2d1e1ae22239b7d676bae7c`.
- Preprocessor pinned: `6714eefbc631f46d5dfe948b6de2d0b0194ac377439f656570980fdcb71074da`.

[Release receipt/QA](../../artifacts/manifests/bot_iot_secondary_kaggle_bundle_release.json)
contains notebook hashes, source identity, ZIP/manifest hashes and external receipt hashes.
Original release_receipt.json and release_QA.json are beside the ZIP. Later documentation
commits do not replace the source revision actually exported. The exporter creates vendor
copies only outside Git; canonical sources are maintained once.

## Review and run instructions

Hiếu owns review and running this independent Bot-IoT experiment. Kaggle **NOT_RUN** here;
no claim of execution/convergence or model performance. Package stays PREPARED_PENDING_REVIEW;
any later acceptance is a receipt outside the data package, not a manifest edit.

Read [README/upload guide](../experiments/kaggle_bot_iot_secondary_v2.md) and
[frozen baseline protocol](../protocols/bot_iot_secondary_kaggle_baseline_v1.md).
Import these unexecuted notebooks and attach unchanged package plus code input:

1. [Smoke](../../notebooks/kaggle/bot_iot_secondary_v2/01_Bot_IoT_Secondary_Smoke.ipynb)
2. [Full](../../notebooks/kaggle/bot_iot_secondary_v2/02_Bot_IoT_Secondary_Full.ipynb)

Run Smoke first; retain/archive/download complete output and run_status.json. Attach its
output as a private input to Full, or reference the same session's working receipt. Set
Full's explicit SMOKE_RECEIPT_PATH. Notebook bootstrap tolerates byte-identical code/source
snapshots attached with smoke outputs, but refuses multiple distinct bundle versions.
Compressed code input is extracted safely to a fresh working path. No Windows/checkout
dependency in runtime. Install requirements on Kaggle if needed, restart, then run smoke.

Smoke TRAIN groups are defined before fitting: first8192 deterministic SHA-ranked TRAIN
groups union fixed mixed-label anchor, all rows retained. The anchor tests v2's accepted
11-benign/3733-malicious representation ambiguity and guarantees both classes. No repeated
rows, balancing or alternate seeds. Exact selected groups/memberships/counts/indices/hashes
are computed on Kaggle before fitting; **not executed on real data locally**. No claim of
smoke count/performance is inferred from code tests. Smoke is diagnostic, not full evidence.
Both modes use the entire733,704-row VALIDATION. Full uses every2,201,114 TRAIN row.

Full gate checks Smoke PASS, convergence/parity for both models, actual smoke populations,
package/bundle/source/data+experiment protocols/preprocessor/feature-order/configuration,
library versions and Python runtime. Fresh full resource preflight must independently pass.
Changes require another smoke. No fallback subset/float32/solver/resampling or tuning.

## Runtime behavior and evidence

Fixed LR:lbfgs/l2/C1/tol1e-4/max_iter1000/class_weight=None/random_state1729;
most-frequent Dummy/random_state1729; threshold0.5,threads4,chunk8192.
Use existing SecondaryPackage.chunks() for36-column float64 encoded X, no scaler/vocab fit.
Before fitting, validate encoded order/dtype/finiteness, exact membership/class support and
group-weight mass. Resource guard requires conservative RAM/disk capacity; estimates are
not a guarantee that Kaggle cannot hit a runtime limit.

Preflight authenticates pinned manifest/verifier, runs packaged standalone verifier in its
own isolated subprocess, writing receipt/log/temp storage under /kaggle/working. Only that
mechanical verifier can inspect TEST. Training runner loads TRAIN/VALIDATION only; package
constructor uses already verified checksums without rereading TEST payloads. No TEST
predictions, performance metrics or TEST-based model selection. Package remains read-only.

Fresh run directory/ZIP refuse overwrite. Archive contains exact source bundle snapshot,
resolved identities/environment/config, standalone verification receipt, actual TRAIN and
full VALIDATION membership, VALIDATION labels/metadata, both models/probabilities/predictions,
global row metrics and group1/n_g sensitivity, warnings/iterations/convergence/fit time,
runner peak RSS and total elapsed. Reload parity checks every VALIDATION probability and
threshold prediction. Nonconverged LR remains diagnostic and cannot produce Smoke PASS.
Checksums cover every output except output_checksums.json itself; return archive SHA256.
Disk-backed encoded TRAIN cache lives in a separate scratch directory, excluded from ZIP.

Metrics distinguish integer row confusion counts from group-weighted masses. Each original
group has total mass1, including mixed groups; no class-conditional weighting or chunk-F1
averaging. Report class supports/recalls,malicious precision,FPR,macro-F1; accuracy secondary.
Only96 benign VALIDATION observations and18/96 group concentration limit precision. No
N-BaIoT rerun/feature merging or deployment/generalisation claim.

## VERIFIED local scope and commands

-30 code/packaging tests passed (1.74s); no classifier fitting or real-data run.
-Ruff PASS including notebook cells; nbformat validation/AST compilation PASS.
-Tests cover whole-group deterministic selection/anchor, exact toy membership/cache indices,
  full receipt identity/resource/convergence/parity failures, row/group mass calculations,
  float64/finite guard, archive checksum coverage/no overwrite, duplicate code snapshots and
  mixed versions, unsafe ZIP paths, and local Kaggle guard.
-Exact11-file release checksum coverage, canonical source and Git-blob bytes PASS.
-Standalone bundle import/integrity/local-fit guard PASS in NumPy-only venv with no
  iotguard/sklearn, Python -I, neutral cwd outside checkout. This is not a Kaggle run.
-Static package manifest/vendor loader identities match; existing package untouched.

```powershell
# From repo root. Repeat export needs fresh external ZIP/receipt paths.
ml/.venv/Scripts/python.exe -m pytest ml/tests/unit/test_kaggle_secondary_v2.py ml/tests/integration/test_kaggle_secondary_bundle.py -q
ml/.venv/Scripts/python.exe -m ruff check ml/src/iotguard/experiments/kaggle_secondary_v2.py ml/scripts/build_kaggle_secondary_bundle.py ml/tests/unit/test_kaggle_secondary_v2.py ml/tests/integration/test_kaggle_secondary_bundle.py ml/notebooks/kaggle/bot_iot_secondary_v2
ml/.venv/Scripts/python.exe ml/scripts/build_kaggle_secondary_bundle.py --output E:/Document/iotguard_kaggle_exports/bot_iot_secondary_v2_20261102_02/IoTGuard_BotIoT_Secondary_v2_Kaggle_Bundle.zip --receipt E:/Document/iotguard_kaggle_exports/bot_iot_secondary_v2_20261102_02/release_receipt.json
```

Pending: Hiếu review, upload/attach inputs, actual Kaggle preflight/resources, Smoke PASS,
then Full. No runtime/model success is claimed by local QA. No TEAM_VERIFIED or
READY_FOR_TRAINING promotion; no merge or automatic account/upload actions.
