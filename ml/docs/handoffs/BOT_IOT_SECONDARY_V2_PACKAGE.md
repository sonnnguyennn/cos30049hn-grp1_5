# Bot-IoT secondary v2 package — PREPARED_PENDING_REVIEW

Checkpoint c8d1de7 was clean; work uses branch `codex/bot-iot-secondary-package-v2`
created from that exact commit. Only frontend/AGENTS.md exists and does not apply to ML.
Policy committed first at `5cbd568e249c5f8e999bc76fe4e60bb733a94fad`; implementation
committed at `b170be91f8a610e05f8d24e602e8b19958c36fc5` before the full build.
No v1 source/contract/protocol/receipt/audit or original package was edited.

## Method revision and scope

The user authorized accepting fixed13-feature representational ambiguity and generic typed
UNKNOWN slots. The same11 benign +3,733 malicious mixed group remains intact in TRAIN;
labels are not declared erroneous. Same13 predictors, seed1729, observations and exact-X
membership. Decision timing is after structural TEST diagnostics, before model fitting or
performance evaluation; no claim of a pristine design-blind TEST.

- [v2 contract](../../artifacts/contracts/bot_iot_secondary_ml_v2.json)
- [v2 protocol](../protocols/bot_iot_secondary_experiment_v2.md)
- [Decision](../decisions/BOT_IOT_V2_PREPARATION.md)

StandardScaler was partial-fit on every TRAIN observation only, in canonical membership
order, population variance ddof0. Vocabulary came only from TRAIN:9 flags,4 protocols,
10 states. Each field appends one typed reserved UNKNOWN slot; no source string can collide
with the schema object/slot. Any valid arbitrary novel string uses the generic mechanism;
invalid syntax remains rejected. No category is dropped.10+10+5+11=36 encoded features.

Package numeric/category arrays are unscaled/raw codes; encoded float64 views are generated
in bounded chunks. State includes exact TRAIN sample count, mean/var/scale, vocabulary,
encoded order, fit-membership and contract hashes. Exact group dictionary retains source
category text, including held-out values, without adding them to learned vocabularies.

## Build and identities

Package: `E:/Document/iotguard_secondary_packages/bot_iot_secondary_v2_20261102_01`

-27 files,1,436,802,269 bytes (~1.44GB,1.34GiB).
-Manifest SHA256 `dd4fdc2551df68f294968f38ca3ecced0c27ac8bc2d1e1ae22239b7d676bae7c`.
-Preprocessor SHA256 `6714eefbc631f46d5dfe948b6de2d0b0194ac377439f656570980fdcb71074da`.
-Source revision `b170be91f8a610e05f8d24e602e8b19958c36fc5`, dirty=false.
-Build135.02s; peak RSS644,632,576 bytes (~615MiB).
-Reference-vs-portable after JSON serialization parity checked on all3,668,522 observations.

Builder emitted loader, README, standalone verifier, state, group dictionary, memberships,
arrays, policy/evidence copies and checksum manifest automatically. No manual package edits.
Raw source hashes and external scan database/memberships were rechecked for reuse and again
for immutability; no full G1/G2 or parser scan was rerun. Source-code hashes also remained
unchanged during materialisation. No resampling, new seed or feature change.

| Partition | Rows | Benign | Malicious | Membership SHA256 |
| --- | ---: | ---: | ---: | --- |
| TRAIN | 2,201,114 | 286 | 2,200,828 | 60113558b7f65dba48c398bd035e538847e5417132b2a3ad514318596d541a3e |
| VALIDATION | 733,704 | 96 | 733,608 | 161376d656b8fe967f6a12549e92f4642c302f9cae46d07980910d16cd6aca1f |
| TEST | 733,704 | 95 | 733,609 | 156f75e15b95ae4a0811c43814de37c14841a653b8cc97d3d216b8438f64c5c0 |

Exact original-X overlap remains0. VALIDATION UNKNOWN count0;8 TEST observations map to
UNKNOWN for proto/state via generic policy; flags UNKNOWN0. These are mechanical preprocessing
checks, not TEST metrics. TEST is sealed by default in load/chunks; explicit allow_test is
mechanical access, not permission to select models or evaluate performance.

## Tests and reproduction

105 selected tests passed (final run5.58s); Ruff and diff checks pass. Tests cover arbitrary
novel tokens, source names resembling reserved display names, invalid input, no held-out fit
or vocabulary changes, exact TRAIN moments, JSON reload/portable parity and invalid state.
Historical parser/equivalence/mixed-group tests also pass. No classifier/clustering fits.

Actual build command from repo root:

```powershell
ml/.venv/Scripts/python.exe ml/scripts/build_bot_iot_secondary_v2.py --evidence-dir E:/Document/iotguard_secondary_candidate_reviews/20261102_full_v1 --output E:/Document/iotguard_secondary_packages/bot_iot_secondary_v2_20261102_01 --receipt E:/Document/iotguard_secondary_packages/bot_iot_secondary_v2_20261102_01_build_receipt.json
ml/.venv/Scripts/python.exe -m pytest ml/tests/unit/test_bot_iot_v2_preprocessing.py ml/tests/unit/test_bot_iot_candidate_scan.py ml/tests/unit/test_bot_iot_secondary.py ml/tests/unit/test_bot_iot_preprocessing.py -q
```

A repeat build requires fresh external output/receipt paths. Do not overwrite this package
or change the historical builder receipt's NOT_YET_RUN standalone field: a later standalone
receipt documents verification after build. No package/model/predictions bulk outputs in Git.

## Reporting and review

Row-weighted metrics are primary (each observation weight1): integer confusion counts,
class supports/recalls, malicious precision,FPR,macro-F1; accuracy supplementary.
Group-weighted sensitivity uses row weight1/n_g within each original exact-X group/partition,
including mixed groups, so total group mass1. It is not label-conditional or class-balanced;
report weighted confusion masses/supports explicitly, separate from integer counts.
Select model/hyperparameters/threshold using VALIDATION only, with group-aware uncertainty.
Only96/95 benign evaluation observations and largest benign groups18/8 (18.75%/8.42%) limit
precision. Shared capture/device/campaign context also limits generalisation.

PM/Hiếu package/protocol review and Kaggle runtime/resource/model validation remain pending.
All classifier/clustering fitting, including smoke, must run on Kaggle. No LR rerun or TEST
performance evaluation occurred. No promotion to READY_FOR_TRAINING or TEAM_VERIFIED.


## VERIFIED — relocation and independent environment

Full standalone verifier PASS on relocated copy:
`E:/Document/iotguard_secondary_relocation_checks/v2_20261102_01/relocated_bot_iot_v2`.
Run used Python3.11.15 / NumPy2.4.6 in a fresh NumPy-only venv with `-I`, neutral cwd;
find_spec confirmed no iotguard,sklearn,pandas,pytest. No raw dataset/checkout parameter
or access is required. Environment was created with --without-pip; only installed NumPy
and its libraries/metadata were copied into its isolated site-packages.

```powershell
E:/Document/iotguard_secondary_verification_envs/numpy_only_v2_20261102/Scripts/python.exe -I E:/Document/iotguard_secondary_relocation_checks/v2_20261102_01/relocated_bot_iot_v2/verify_package.py E:/Document/iotguard_secondary_relocation_checks/v2_20261102_01/relocated_bot_iot_v2 --expected-manifest dd4fdc2551df68f294968f38ca3ecced0c27ac8bc2d1e1ae22239b7d676bae7c --output <fresh-external-receipt.json>
```

Full verification took121.87s. All payload hashes/schema/identities, every membership row,
complete source-row union, original exact-X groups and class/group counts were checked.
Group-label mismatches0; cross-partition original-X overlap0. TRAIN moments recomputed
independently with NumPy; vocabulary re-derived from TRAIN groups only; generic arbitrary
novel strings map to reserved slots. Default TEST access rejects; explicit mechanical
verification confirms UNKNOWN counts0/0/8 observations, not performance metrics.

[Preparation receipt](../../artifacts/manifests/bot_iot_secondary_v2_preparation.json) stores
original immutable build receipt, later relocation/standalone receipts, all receipt hashes,
source/policy revisions, environment, counts, parity and resource usage. The builder's
NOT_YET_RUN field remains an accurate build-time snapshot; later verification is additive.
