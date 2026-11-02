# Bot-IoT secondary runs — immutable archive and PR #1 integration

Status: VERIFIED_ARCHIVE_VALIDATION_EVIDENCE; PR remains draft/pending review.
Run source is **84f3068386f1c11a5691d5383b2c4a46c8591b21**, not the integration HEAD.
Release documentation commit8d5f76f also is not the code revision used to fit these models.

## Archive and evidence levels

Both original output ZIPs and executed notebooks were copied byte-for-byte to a fresh
external archive: `E:/Document/iotguard_run_reviews/bot_iot_20261102_pr1_archive_01`.
Originals remain unchanged at E:/Document and E:/Downloads. No ZIP, model, data or executed
notebook bulk content was added to Git. Receipt records original/archive paths, bytes,
SHA256, run IDs, exact identities/populations, metrics and notebook execution transcripts.

- [Run archive receipt](../../artifacts/manifests/bot_iot_secondary_run_archive_20261102.json)
- [Integration check receipt](../../artifacts/manifests/pr1_integration_checks_20261102.json)
- [Read-only archive verifier](../../scripts/archive_bot_iot_run_evidence.py)
- Review context: [draft PR #1](https://github.com/sonnnguyennn/cos30049hn-grp1_5/pull/1).

VERIFIED here: ZIP member/path safety; exact33-output-checksum coverage per ZIP; both
11-file source snapshots equal original code release byte-for-byte; source hashes match
Git blobs at84f3068; actual TRAIN/VALIDATION membership hashes; original VALIDATION
labels/metadata equality; all saved probabilities/predictions and independently recomputed
row/group metrics; Full accepted the exact Smoke run_status.json bytes. Executed notebook
code matches the release template semantically, allowing only the Full receipt input path;
its output references the matching run ID/status/archive hash. Notebooks were not reexecuted.

REPORTED by archived runner: fitting/convergence/peak RAM and model reload parity (delta0).
Model files were hash-checked only, not deserialized or rerun. Historical Kaggle standalone
package-verification PASS receipts were hash-checked, not rerun here. Their mechanical TEST
checks are historical; this task opened no official TEST payloads or model predictions.
Current independent work reads VALIDATION labels/metadata and saved probabilities only.

## Exact archive identities

| Mode | Run ID | ZIP bytes | ZIP SHA256 |
| --- | --- | ---: | --- |
| Smoke | bot_iot_secondary_smoke_20261102T055131920288Z | 23,244,706 | 043a12b177791d624e34c44c4b1c7a0c6c69d80bd853dbc0380f6251ae69a2d7 |
| Full | bot_iot_secondary_full_20261102T062917639798Z | 54,077,898 | dc7ca7e5cf3ce91367673622c0591ea318cabba8b0fad4d2b9d0dcea3c20f377 |

Executed notebooks are archived exactly as downloaded:

- `01-bot-iot-secondary-smoke.ipynb`,5,842 bytes;
  SHA256 `4e6ab35504d93b9ce915ac2c8e1449d1f330ce9a885485614ebcd123bd87b026`.
- `02-bot-iot-secondary-full.ipynb`,6,157 bytes;
  SHA256 `0bb4c8fd557512247c906953749b63a80414599c49c3100bd71d2797b2d155b2`.

Package SHA256 remains
`dd4fdc2551df68f294968f38ca3ecced0c27ac8bc2d1e1ae22239b7d676bae7c`.
Preprocessor SHA256 remains
`6714eefbc631f46d5dfe948b6de2d0b0194ac377439f656570980fdcb71074da`.
Bundle manifest SHA256:
`06c19f532414cd28ccb977f0f957c7c0e4436990c45f23798b3963604e8a0b75`.
Full's accepted Smoke status SHA256:
`e330753d5086e11001d046a5962957f10af2b42710767a4b6cc3f74e8739469f`.

## Actual populations and reviewed VALIDATION baseline

| Mode | TRAIN rows | TRAIN benign/malicious | TRAIN exact groups | VALIDATION rows |
| --- | ---: | --- | ---: | ---: |
| Smoke, diagnostic | 45,817 | 17 /45,800 | 8,193 | 733,704 |
| Full | 2,201,114 | 286 /2,200,828 | 396,266 | 733,704 |

Smoke TRAIN membership SHA256:
`356554ea1a075355cb27f4cbd1c09dd280ea097f0eaaa48ea8eed1d78f9f65d0`.
Full TRAIN membership SHA256:
`60113558b7f65dba48c398bd035e538847e5417132b2a3ad514318596d541a3e`.
Common full VALIDATION membership SHA256:
`161376d656b8fe967f6a12549e92f4642c302f9cae46d07980910d16cd6aca1f`.
VALIDATION has96 benign /733,608 malicious,138,060 exact groups (77 benign groups).
The original package/contract and archived full membership identity bind these supports;
no new split, labels, threshold, seed, balancing or feature set was introduced.

| Mode/model | Row TN /FP /FN /TP | Row macro-F1 | Group macro-F1 |
| --- | --- | ---: | ---: |
| Smoke Dummy | 0 /96 /0 /733,608 | 0.4999672871209395 | 0.49986052897555816 |
| Smoke LR | 0 /96 /1 /733,607 | 0.499966946339256 | 0.4998587171517378 |
| Full Dummy | 0 /96 /0 /733,608 | 0.4999672871209395 | 0.49986052897555816 |
| Full LR | 7 /89 /3 /733,605 | 0.5660063857929672 | 0.5803275395483074 |

Full LR benign recall7/96=0.07291666666666667; FPR89/96=0.9270833333333334;
malicious recall0.9999959106225669. Group-weighted benign recall7/77=0.09090909090909091;
group confusion masses TN7,FP70,FN3,TP137980 (float roundoff retained in receipt).
Weights are1/n_g per original exact-X group, never label-conditional. Accuracy is supplemental;
high malicious prevalence cannot hide poor benign recall. These are valid but limited
VALIDATION baselines, not deployment/TEST evidence or an invitation to tune against TEST.
Smoke is diagnostic only and cannot replace the full-population baseline.

Runner-reported LR iterations18 Smoke /14 Full; fit0.258315615s /5.409247761s;
elapsed including package verification121.135255607s /146.788555676s. Peak runner RSS
657,694,720 /1,144,868,864 bytes. Both report convergence and reload parity PASS; each LR
has one SciPy L-BFGS-B option deprecation warning and no ConvergenceWarning. No rerun here.

## Integration source checks, separate from run provenance

Dedicated worktree:
`C:/Users/Admin/.codex/worktrees/iotguard-pr1-integration/iotguard-cos30049hn-grp1-5`.
Original checkout was clean and remained untouched. Fetched origin before integration.
PR head8d5f76f and origin/main b91a419 had no common modified paths; `git merge --no-ff
origin/main` succeeded using ort, **zero conflicts**. Integration merge commit:
`9a850b5d3a63e1b592b8ca1e1ec3089e12fa29a2`, parents8d5f76f and b91a419.
All changed blobs from each parent were compared against the integrated tree and preserved
exactly, including backend/frontend and both primary RF/XGB scripts. No default conflict
assumption, rebase, force-push, duplicate PR, package-manifest edit or history rewrite.

Dedicated locked worktree environment (`uv sync --locked --extra dev --extra kaggle`) imports
iotguard from this worktree, not the original editable checkout. Checks on integrated source:

-375 tests passed,27.33s: all ML unit/configuration tests and both Kaggle packaging
  integrations. This is explicit scope, not a full-suite claim: real-source primary builder
  rematerialisation/portability was not rerun. Synthetic unit TEST fixtures do not open
  official sealed TEST payloads. No classifier/clustering fitted.
-Full ML Ruff: **FAIL,20 inherited errors** confined to unchanged train_rf_baseline.py and
  train_xgb_baseline.py. Ruff on remaining ML, including notebooks/new archive script: PASS.
  No lint suppression/config changes or changes to those two scripts were made.
-Frontend npm ci PASS; eslint PASS with one inherited unused `inter` warning in
  dataset-explorer/page.tsx; Next16.4.2 production build and TypeScript/static pages PASS.
-Backend compileall PASS; no backend app/model runtime started. git diff --check PASS.

Remaining blockers before merge: inherited RF/XGB lint debt and separately tracked
population-identity/dependency/Kaggle-export work; reviewer approval. Clustering checkpoint
and report figures remain independent pending work from PR context. This integration does
not validate or execute RF/XGB, nor promote the package to TEAM_VERIFIED/READY_FOR_TRAINING.

## Reproduce archive without model/TEST access

Use the new archive script with the original two ZIP/notebook paths, original code ZIP and
package root, plus **fresh** --archive-dir and --receipt paths. The command never executes
notebooks, imports run snapshot code, deserializes joblib or runs standalone verification.
It copies bulk evidence outside Git and writes only a small receipt in Git. Existing
archives/receipts are refused rather than overwritten. Preserve all old files unchanged.
