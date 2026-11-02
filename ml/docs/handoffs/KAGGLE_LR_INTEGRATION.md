# Kaggle LR bundle integration

Integrated on branch `feat/kaggle-lr-integration` from main
`e478e8e7ff0d374d9fd6f53e411bd4f414ce1c14`. This document describes the
implementation in its containing commit; the exported manifest records the exact
release commit without a circular self-reference.

## Input and placement

The original `E:/Downloads/IoTGuard_Kaggle_LR_Bundle.zip` has SHA-256
`8bc4be5d8ee5935266cb6b84f0fdb0de62186b4c39c8049e1188fa39f840c7c1`.
All 14 members were inspected and extracted outside Git to
`E:/Document/iotguard_bundle_staging/8bc4be5d8ee59352`; all original manifest
payload checksums matched. Archive instructions were reviewed as reference,
not authorization to upload, publish, train, or operate external accounts.

| Supplied content | Repository destination / treatment |
| --- | --- |
| LR runner | `ml/src/iotguard/experiments/kaggle_lr.py` |
| Two notebooks | `ml/notebooks/kaggle/`, unexecuted and without outputs |
| Runtime requirements | `ml/notebooks/kaggle/requirements.txt`; optional `kaggle` dependencies in `ml/pyproject.toml` |
| README | `ml/docs/experiments/kaggle_lr.md`, updated for integrated workflow |
| Loader, metrics, seeds, common protocol/schema | Existing canonical files retained; supplied bytes matched |
| Original manifest and LOCAL_QA | `ml/artifacts/manifests/kaggle_lr_bundle_import.json`; original QA is explicitly REPORTED |
| New extension protocol | `ml/docs/protocols/kaggle_lr_baseline_v1.md` |
| Standalone export | `ml/scripts/build_kaggle_lr_bundle.py`; generated vendor files only outside Git |

No dataset, fitted model, cache, environment, original ZIP, or duplicate vendored
package was added to source control. The exporter copies shared implementations
directly from canonical repository files and includes both notebooks, protocols,
requirements, README, QA scope and payload checksums.

## Integration decisions

- Corrected source provenance: results use the actual export commit and dirty
  boolean, alongside the exact bundle checksum. The old foundation commit is
  retained as a reference, not claimed as the integrated runner's revision.
- Full execution requires a successful smoke receipt matching package, bundle,
  and complete run configuration. Fixed baseline settings cannot silently change.
- Retained full TRAIN/VALIDATION, TRAIN-only scaling, float64, threshold 0.5,
  global metrics, TEST seal, resource guards, reload parity and convergence gates.
- Smoke has its own population fingerprints and diagnostic status. Nonconverged
  LR cannot be exported as an official successful result.
- Local run guard prevents fitting. Both notebooks remain NOT_RUN on Kaggle;
  successful source integration is not a successful LR experiment.

## Verification

Commands from `E:/Document/iotguard-cos30049hn-grp1-5/ml`:

```powershell
uv lock --project .
.venv/Scripts/python.exe -m pytest -q -ra
.venv/Scripts/python.exe -m ruff check .
git diff --check
```

Final completed suite: **260 passed in 43.56s**, zero failed/skipped.
Ruff: **All checks passed**, including notebook cells. Diff whitespace check:
PASS (Git's existing LF/CRLF conversion notice is not a failure).

The 25 new cases cover sampling, fixed policy, local fitting guard, smoke
identity/configuration, actual bundle export and isolated standalone imports,
official notebook schema validation, canonical-source equality, result identity,
tampering, missing runtime checksums and output placement/overwrite protection.
The new bundle tests do not create or fit estimators; synthetic arrays validate
result formatting and identity only.

An earlier run had 259 passes and one `MemoryError` in the unchanged real-source
builder portability test while allocating a 4 MiB hash read buffer. Windows also
reported a PowerShell startup OutOfMemoryException. The final full suite was
rerun with a lightweight cmd shell and passed without changing assertions,
mocking raw data, skipping checks, or changing system settings. After a session
limit interrupted visibility of that rerun, another complete run produced the
final count above. This was a transient resource failure, not missing raw data
or an unresolved unit-test failure. The bounded real-data portability test ran
successfully; no full dataset materialisation was requested or performed.

All 80 historical artifacts were rehashed against `G3A_IMPORT_VALIDATION.json`
and matched. Original G3B manifest still hashes to
`6ab99e86397242e219bfa1f8490d8e03b169ec87a092af80cb3e7aef1e61147b`.
The original processed package was not modified or rematerialised; its full
6.57 GB payload was not redundantly rehashed during this integration.

## Receiving and running the package

From a clean committed checkout, generate to a fresh external directory:

```powershell
.venv/Scripts/python.exe scripts/build_kaggle_lr_bundle.py --output E:/Document/iotguard_kaggle_exports/<commit>/IoTGuard_Kaggle_LR_Bundle.zip
```

The exporter prints ZIP SHA-256, manifest SHA-256, source revision and dirty
status. Keep that receipt with the external ZIP. Existing outputs cannot be
overwritten. A release should have `source_dirty_worktree=false`; changes require
a new export and a matching new smoke run. The exported runtime does not require
this source checkout or its editable install.

Give the recipient that **code ZIP** and separately the unchanged original
`E:/Document/iotguard_primary_packages/g3b_primary_v1` directory
(6,575,404,266 bytes). Follow `ml/docs/experiments/kaggle_lr.md`: attach both as
Kaggle inputs, import notebook 01, obtain SMOKE_PASS, save its outputs, and attach
them with the same code/data inputs to notebook 02. Only BASELINES_COMPLETE with
accepted convergence is a successful full run. No upload or training occurred
as part of this integration.
