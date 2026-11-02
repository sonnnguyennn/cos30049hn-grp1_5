# LR baseline archive checkpoint — 2026-11-02

Status: **VERIFIED_ARCHIVE_AND_SOURCE_LINEAGE**. No retraining or TEST evaluation.
Machine-readable evidence: [summary](../../artifacts/manifests/lr_baseline_archive_summary.json).

## VERIFIED in this checkpoint

- Original Smoke and Full archives are present at the exact paths in the summary.
  SHA-256 respectively:
  `436b2791ab745bb6e05b9abb1a85f7ee3b5e21a486c0c8b160f613d530f4e660` and
  `cc6f7cf0ea126deac2e5a72d305d9aee8e94dd74626781e23f55f7774738d65b`.
- Exact output-checksum coverage: 36 Smoke / 34 Full files. Run IDs are
  `iotguard_lr_smoke_20261102T010830365927Z` and
  `iotguard_lr_full_20261102T011513018213Z` (model result IDs also retained in JSON).
- Both complete `source/` snapshots equal the original released bundle, byte for byte.
  Bundle ID `iotguard_primary_lr_kaggle_v2`; manifest SHA-256
  `4faf0ffc20ac1ceae960260b15b629f69888174ab641a9fcd03eb0cb56fd81f0`.
- Package manifest SHA-256
  `6ab99e86397242e219bfa1f8490d8e03b169ec87a092af80cb3e7aef1e61147b`
  matches the archived data manifest. Full's receipt hash matches Smoke's exact status bytes.
- `ea57689` is the abbreviated **Git commit**
  `ea57689eb73322e2536eb47d3bfa574b68cc6404`, also used as the release directory name.
  It is not a replacement identifier invented for this archive checkpoint.
- Canonical Kaggle v2 runner, notebooks, exporter and shared sources already exist in Git.
  Each manifest-listed source matches the current checkout's bytes. Each corresponding
  Git blob at the original revision matches either exactly or by the verified checkout
  LF-to-CRLF conversion. **Runner and README have CRLF snapshot bytes and LF Git blobs.**
  The summary records both hashes and exact reconstruction recipes. This distinction
  must survive Linux checkouts; a clean Git status alone does not prove byte equality.
- Original release ZIP remains at
  `E:/Document/iotguard_kaggle_exports/ea57689/IoTGuard_Kaggle_LR_Bundle.zip`.
  It preserves the exact generated snapshot, including manifest and LOCAL_QA. Its SHA-256
  is `a879615bc61ce0a5ecdad654605b6826e1609618a4b0f76afa9aabdde500e6c6`.
  All snapshot file hashes are archived in the new summary; no duplicate maintained
  vendor source tree, models, predictions or ZIPs are added to Git.

## Metrics and their evidence level

Result JSON equality with the historical verification report was rechecked here.
The earlier independent probability/label recomputation is **REPORTED by the original
audit**, not rerun by this checkpoint's archive script.

| Mode | TRAIN / VALIDATION | LR macro-F1 | LR TN / FP / FN / TP | Use |
| --- | --- | --- | --- | --- |
| Smoke | 50,000 / 10,000 | 0.9979407821101739 | 788 / 2 / 4 / 9,206 | diagnostic only |
| Full | 4,944,968 / 1,056,372 | 0.9984837469527315 | 83,189 / 246 / 220 / 972,717 | official full-population VALIDATION |

Full Dummy macro-F1: 0.4794425097410005; Full LR accuracy: 0.9995588675201539,
benign recall: 0.9970515970515971, malicious recall: 0.9997738805287496,
FPR: 0.0029484029484029483. These do not establish TEST or deployment performance.
Runner-reported LR convergence: 57 Smoke / 68 Full iterations. Reload prediction parity
is **REPORTED by runner**; neither this checkpoint nor original audit deserialized models.
The SciPy option deprecation warning does not require a rerun.

## Original evidence and reproduction

- `E:/Document/iotguard_run_reviews/20261102/REVIEW.md`
- `E:/Document/iotguard_run_reviews/20261102/verification.json`
- `E:/Document/iotguard_run_reviews/20261102/verify_lr_runs.py`

These historical files and receipts were not edited. Hashes of the original review and
verification are in the new summary. Do not run the historical script merely to refresh
this archive: it writes to its historical review directory. The new script reads evidence
and writes only a fresh output path:

```powershell
# From repository root; use a fresh --output path for repeat verification.
ml/.venv/Scripts/python.exe ml/scripts/archive_lr_evidence.py --review-dir E:/Document/iotguard_run_reviews/20261102 --release-zip E:/Document/iotguard_kaggle_exports/ea57689/IoTGuard_Kaggle_LR_Bundle.zip --package-manifest E:/Document/iotguard_primary_packages/g3b_primary_v1/manifest.json --output <fresh-summary.json>
```

## PLANNED / BLOCKED boundaries

Archive/source verification has no missing-file blocker. Portable retention still requires
retaining the referenced external evidence: this small Git record is not a backup of ZIPs.
Push/merge is not performed. Remote main was fetched at `b91a419`; it is not merged into
this branch. RF/XGB identity/protocol issues remain outside scope; do not compare subset
runs with Full LR. New commits must never replace the historical run's source revision.
Historical `NOT_RUN` bundle metadata describes export-time state; preserve it and use this
additive handoff for later run evidence.
