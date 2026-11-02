# Bot-IoT secondary v2 Kaggle bundle — Hiếu review/run handoff

Status at release: code prepared, Kaggle NOT_RUN. Hiếu owns review and execution.
No local classifier fitting, package edits or automatic Kaggle account/upload actions.
Read `protocols/bot_iot_secondary_kaggle_baseline_v1.md` before running.

## Upload and attach

1. Keep the original27-file package intact. Upload the complete directory as one private
   Kaggle Dataset, preserving relative filenames. Expected manifest SHA256:
   `dd4fdc2551df68f294968f38ca3ecced0c27ac8bc2d1e1ae22239b7d676bae7c`.
   Do not change its PREPARED_PENDING_REVIEW status or preprocessing state.
2. Upload this code ZIP as another private input (ZIP or extracted contents both supported).
   Compare ZIP/bundle-manifest hashes with release receipt. Bundle has only code/notebooks,
   not the1.44GB data package. Add both inputs to each notebook.
3. Import `01_Bot_IoT_Secondary_Smoke.ipynb`. Dependencies are in requirements.txt;
   install on Kaggle if needed, then restart session before running. No local model fitting.
   Notebook bootstrap finds the bundle ID under /kaggle/input; if a ZIP remains compressed,
   it safely extracts code into a fresh /kaggle/working directory. No Windows paths/checkout.

## Smoke, then full

Smoke uses a deterministic set of whole TRAIN groups plus the fixed mixed-group anchor;
all VALIDATION rows are evaluated. It records exact selected populations and is diagnostic.
Preflight runs full standalone verification; allow several minutes and working disk for
temporary verification. Only the verifier performs mechanical TEST checks. Training uses
the existing36-column preprocessing through SecondaryPackage.chunks(), without fitting state.

Download the smoke run ZIP and retain its output_checksums.json, models/results, source
snapshot, package verification and run_status.json. A passing status is SMOKE_PASS.
Upload its complete output as a private smoke-results input for Full (or use the existing
working run_status.json in the same session). Set explicit SMOKE_RECEIPT_PATH in Full.
No receipt means Full stops. Changed bundle/config/runtime/package means smoke must rerun.

Import `02_Bot_IoT_Secondary_Full.ipynb`, attach the same package/code and smoke evidence.
Full recomputes the smoke population binding, checks receipt and fresh resource capacity,
then uses all2,201,114 TRAIN and733,704 VALIDATION observations. There is no default sampling
or automatic resource fallback. Resource BLOCKED means stop and review capacity, not tune.

Fixed LR lbfgs/l2/C1/tol1e-4/max_iter1000/no class weights; most-frequent Dummy; threshold0.5.
Do not alter settings to improve scores within this baseline. Nonconverged LR is diagnostic
and cannot produce a passing smoke or eligible full comparison.

## Outputs and boundaries

Everything is written under /kaggle/working to a fresh UTC-named run directory. Original
/kaggle/input package stays read-only. Standalone verification receipt/log is outside package;
its temporary storage is in the working run. Training cache is a separate *_scratch directory
and is not archived. Keep disk-backed float64 cache; no preprocessing refit or precision change.

Run ZIP has exact bundle snapshot, source identities, resolved config, environment, actual
TRAIN membership/selection, full VALIDATION membership/y/metadata, predictions/probabilities,
models, row/group reports, warnings, timing, runner RAM and full reload parity evidence.
output_checksums.json covers every payload except itself. Save returned archive SHA256 too.
Full acceptance remains an external receipt; do not edit data manifest to rename status.

Training runner never opens TEST arrays or computes TEST performance. Structural TEST checks
are confined to standalone preflight. VALIDATION is for future model/threshold selection;
this baseline fixes threshold0.5 with no tuning. Row metrics are primary, group sensitivity
uses1/n_g original group weights; uncertainty from96 benign and group concentration remains.
No N-BaIoT baseline rerun or feature-matrix merge. Review is not TEAM_VERIFIED by automation.
