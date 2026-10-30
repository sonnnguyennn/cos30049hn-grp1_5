# G3B primary data handoff

Date: 2026-10-30. **READY_FOR_TEAM**, not TEAM_VERIFIED. Hiếu or Minh Sơn must run the copied package on their own machine before claiming TEAM_VERIFIED.

Build/identity repair: see [G3B_BUILD_IDENTITY_FIX.md](G3B_BUILD_IDENTITY_FIX.md) and the current primary protocol before new builds or baseline comparisons. This handoff records the original package run; that accepted package remains unchanged. The repaired builder now performs the portable packaging steps automatically.

## Checkout and verified outcome

Repository: `E:\Document\iotguard-cos30049hn-grp1-5`. Started on clean `chore/import-g3a-ml-foundation` at foundation HEAD `290fbef4ae2e42d6aadd43ea8231976fd095f610`; implementation branch `feat/g3b-primary-data-package`. No reset or automatic merge occurred. The local checkpoint containing this document identifies the final implementation (`git log -1 --format=%H -- ml/docs/handoffs/G3B_PRIMARY_DATA_HANDOFF.md`). The materialisation manifest records the foundation revision and dirty implementation state; exact implementation hashes are recorded separately in the same manifest. No push/merge is part of this task.

- **VERIFIED:** one full primary build using the canonical parser and unchanged split functions; all 89 input CSV content hashes and row counts matched the canonical traversal. All 80 historical artifact files remain byte-identical to the import snapshot.
- **VERIFIED:** 215 tests passed, 0 failed, 0 skipped, 0 blocked; Ruff clean. This comprises 199 foundation tests and 16 G3B test cases. New tests cover known confusion counts, missing classes, invalid inputs, selection ties/populations, schema refusal, scaler policy, serialization and readable roundtrip.
- **VERIFIED:** real-source smoke: 890 rows over 89 sources, all split assignments/labels checked, sampled raw rows exactly matched canonical parser output, TRAIN mean verified, readable CSV roundtrip exact. Smoke population was never adopted for training.
- **VERIFIED:** full package copied into a new recipient directory and loaded in a separate Python 3.11 environment containing NumPy 2.4.6, with no installed IoTGuard or scikit-learn and no source-local configuration. The copied NumPy-only verifier checked all payload hashes, class counts, TRAIN scaler moments, and reconstructed full membership independently from stored arrays/metadata.
- **REPORTED:** historical G1-G3A completion/acceptance remains supported by its preserved evidence; those audits were not rerun solely for G3B.
- **PLANNED:** classification, clustering, threshold tuning beyond 0.5, Bot-IoT experiments and final model packaging. None was executed here.
- **BLOCKED:** no required G3B check is blocked. Training memory feasibility remains the trainer's responsibility.

## Package identity

Sender: `E:\Document\iotguard_primary_packages\g3b_primary_v1`

Independently tested relocated copy: `E:\Document\iotguard_primary_packages\recipient_check_v1`

Complete sender package: **6,575,404,266 bytes (6.124 GiB)**. Send the entire directory, including the loader, copied contracts, scaler JSON and manifest. The package contains no original raw CSV files. Both copies have the same manifest checksum.

Manifest SHA-256: `6ab99e86397242e219bfa1f8490d8e03b169ec87a092af80cb3e7aef1e61147b`

Membership SHA-256: `edfeb1d96cd2031e0b459fed16e59ef5b1203a56bd2af2306b15968331a0958c`

| Partition | Records |
| --- | ---: |
| TRAIN | 4,944,968 |
| VALIDATION | 1,056,372 |
| TEST | 1,061,266 |

Each partition has `X.npy` (115 ordered float64 predictors), `y.npy` (uint8), and `metadata.npy` (source-table index plus 1-based source row). Device, original taxonomy strings and source identity are in the manifest source table and copied label contracts. They are excluded from X. No rows were deduplicated, sampled or resampled. Raw numeric storage has zero roundtrip tolerance.

StandardScaler was incrementally fit on exactly 4,944,968 TRAIN observations. JSON stores mean, variance, scale and count. Scaled views are transform-only bounded chunks; no second full scaled matrix is required. Raw views support RF/XGBoost. TEST was prepared and checked mechanically only; default loader access is denied. No model evaluation on TEST took place.

## Reproduce or load

Build command used from `ml/`:

```powershell
.venv/Scripts/python.exe scripts/materialize_primary.py --full --output E:/Document/iotguard_primary_packages/g3b_primary_v1
```

The output must be a new external directory. Source roots resolved from the existing verified evidence because no local YAML or IOTGUARD environment overrides were present. Both benign and extracted attack files were available; alternate machines building from raw data can explicitly pass `--n-baiot-raw-root` and `--n-baiot-extracted-root`. Receiving machines only need the finished package.

On Hiếu/Minh Sơn's machine, copy the package to any directory, enter it, then:

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install numpy==2.4.6
.venv/Scripts/python.exe -I -B verify_primary_package.py . --output recipient_verification.json
```

```python
from primary_package import PrimaryPackage
p = PrimaryPackage('.', verify=True)
X_train, y_train, metadata = p.load('TRAIN')
X_validation, y_validation, _ = p.load('VALIDATION')
assert X_train.shape == (4944968, 115)
assert X_validation.shape == (1056372, 115)
for X_chunk, y_chunk in p.chunks('TRAIN', scaled=True, chunk_size=4096):
    pass  # Hand these bounded chunks to the future training routine.
# Optional readable export; output may be large.
# p.export_csv('VALIDATION', 'validation.csv')
```

Loader refuses unknown package/contract versions, wrong feature order, malformed shapes, incomplete builds, wrong scaler fit scope, and checksum failures when `verify=True`. Explicit `allow_test=True` exists only for authorized mechanical preparation/verification; it does not authorize model selection on TEST.

## Common experiment contract

Use `docs/protocols/primary_experiments_v1.md` and `primary_result_v1.schema.json`. Malicious=positive, threshold=0.5, confusion order [benign, malicious], undefined rates=null. Selection uses highest VALIDATION macro-F1, within 1e-6 prefer lower FPR, then higher malicious recall. Resolve seeds from config (42 for Python/NumPy/scikit-learn) for every run. Use each partition metadata file's manifest SHA-256 as the population fingerprint, along with package manifest identity; comparisons must preserve the same populations. Any policy change needs a revision before comparison.

## Resources, evidence and remaining work

Preflight measured 2,613,338,112 available RAM bytes and 57,807,413,248 free disk bytes; estimated array payload was 6,575,286,186 bytes. Memmaps and 4,096-row buffers avoided loading the full dataset as Python objects or full RAM matrices. RAM pressure increased during the build, so independent verification/testing waited until the builder exited. The independent verifier uses bounded numeric chunks and a three-way metadata merge.

Compact results and all payload sizes/checksums: `artifacts/audit/g3b_primary_package_verification.json`. External build/test/verifier logs, environment record and readiness receipt: `E:\Document\iotguard_primary_packages`. The original build manifest is preserved there separately. An auxiliary Git byte comparison flagged only an old scaffold .gitkeep CRLF/LF distinction; the actual 80 historical evidence files all match their source hashes and were not edited.

Remaining: Hiếu/Minh Sơn verification on their machine; resource-aware training implementations; classification and clustering runs; separate Bot-IoT design; final evaluation/selection and inference packaging. No web, Pi or Jira work was performed. This data handoff does not prove that full-batch RF/XGBoost/LR training will fit the receiving machine's RAM.

## Changed files

- `ml/README.md`
- `ml/artifacts/audit/g3b_primary_package_verification.json`
- `ml/docs/handoffs/G3B_PRIMARY_DATA_HANDOFF.md`
- `ml/docs/protocols/evaluation_protocol.md`
- `ml/docs/protocols/primary_experiments_v1.md`
- `ml/docs/protocols/primary_result_v1.schema.json`
- `ml/scripts/materialize_primary.py`
- `ml/scripts/verify_primary_package.py`
- `ml/src/iotguard/data/primary_package.py`
- `ml/src/iotguard/evaluation/primary.py`
- `ml/tests/unit/test_primary_package.py`
