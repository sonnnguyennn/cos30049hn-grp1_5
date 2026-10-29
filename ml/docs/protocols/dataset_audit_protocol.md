# Dataset audit protocol

This protocol freezes the read-only evidence process for the N-BaIoT source package and the local Bot-IoT 5% subset package. ADR-001 closes G1 with N-BaIoT as primary and Bot-IoT as secondary; downstream implementation decisions remain open.

## Source and local configuration

The source datasets are:

- `n_baiot`: the local N-BaIoT copy;
- `bot_iot`: the downloaded Bot-IoT 5% subset plus its supplied feature/documentation files, not the full Bot-IoT dataset.

Official source pages recorded for provenance:

- N-BaIoT: <https://archive.ics.uci.edu/dataset/442/detection%2Bof%2Biot%2Bbotnet%2Battacks%2Bn%2Bbaiot>
- Bot-IoT: <https://research.unsw.edu.au/projects/bot-iot-dataset>

The local acquisition/download dates were not recorded and remain unknown. File timestamps are evidence about the local files, not assumed download dates.

Raw roots are machine-local inputs. Configure them with `IOTGUARD_NBAIOT_ROOT` and `IOTGUARD_BOTIOT_ROOT`, CLI arguments, or ignored `config/data_paths.local.yaml`. Resolution precedence is CLI, environment, then local YAML. Absolute roots are recorded in the generated summary for provenance but are not embedded in the implementation.

## Immutable-input policy

Source directories are read-only. The audit must not edit, rename, move, delete, normalize, extract into, or write generated data under either root. Raw data must not be copied into this repository or added to Git. Outputs are rejected if they resolve inside a source root.

## Audit phases

1. **A0 — source/protocol freeze:** define inputs, safety, configuration, and reproducibility rules.
2. **A1 — file inventory and integrity:** inventory regular files, stream SHA-256, and inspect supported archive metadata without extraction.
3. **A2 — structural/schema audit.**
4. **A3 — label/taxonomy audit.**
5. **A4 — data quality, duplicate/feature-collision, and representation-lineage audit.**
6. **A5 — imbalance/leakage audit.**
7. **A6 — cross-dataset comparison.**
8. **A7 — primary/secondary decision.**

A0 through A5 are implemented and independently verified. A5 was externally accepted after its
packaging-completeness check passed. A5 is diagnostic only: it does not select a representation,
approve a supplied or simulated split, decide final predictor eligibility, or select
primary/secondary roles.

## A1 reproducibility rules

- Traverse each configured root recursively and inventory regular files only.
- Do not follow directory or file symlinks; report the number skipped and all traversal errors.
- Store POSIX-style paths relative to the applicable source root and sort manifest rows by `relative_path`.
- Hash raw file bytes with SHA-256 using 4 MiB streaming reads. Never load an entire source file into memory.
- Compare size and nanosecond modification time before and after reading. A detected change invalidates that file's hash and makes the audit incomplete.
- Record byte size, UTC modification time, hash/read outcome, error text, and archive classification for every discovered regular file.
- Recognize `.zip`, `.rar`, `.7z`, `.tar`, `.tar.gz`, `.tgz`, and `.gz`. Inspect ZIP and TAR-family member metadata with the Python standard library and never extract members. Hash unsupported RAR, 7z, and standalone gzip files normally and mark member listing as unsupported; this alone does not fail the audit.
- Capture the source roots, manifest hashes, script hash, invocation, Python runtime, platform, traversal policy, and archive policy in `artifacts/audit/source_inventory_summary.json`.
- `PASS` requires no read/hash failures, supported-archive inspection failures, or traversal errors. Unsupported member listing is explicit but does not prevent `PASS`.

## Outputs and rerun

Generated evidence is written to:

- `artifacts/manifests/n_baiot_raw_manifest.csv`
- `artifacts/manifests/bot_iot_raw_manifest.csv`
- `artifacts/audit/source_inventory_summary.json`

PowerShell rerun with environment variables:

```powershell
$env:IOTGUARD_NBAIOT_ROOT = "E:\Document\N_BaIoT_Dataset"
$env:IOTGUARD_BOTIOT_ROOT = "E:\Document\Bot_IoT_Dataset"
.\.venv\Scripts\python.exe scripts\dataset_inventory.py
```

Equivalent explicit CLI arguments:

```powershell
.\.venv\Scripts\python.exe scripts\dataset_inventory.py `
  --n-baiot-root "E:\Document\N_BaIoT_Dataset" `
  --bot-iot-root "E:\Document\Bot_IoT_Dataset"
```

Missing roots, unsafe output paths, and output failures terminate with a non-zero exit. A completed but incomplete audit also returns non-zero after preserving its evidence.

## A2 controlled archive access

N-BaIoT RAR access uses the already-installed `C:\Program Files\WinRAR\UnRAR.exe` version 6.22 x64. No dependency was installed. `scripts/n_baiot_archive_access.py` first runs technical listing (`lt -c-`) for all 16 archives and records member names, types, and uncompressed sizes. Extraction is permitted only after every listing succeeds and every member path passes traversal/absolute-path checks.

The configurable work base is `IOTGUARD_DATASET_WORK_ROOT`; the extracted hierarchy is placed under its `n_baiot_extracted` child, outside both the repository and source roots. Each archive receives a separate `device/archive-family` directory. Extraction uses `x -idq -o- -y`, refuses a non-empty target, preserves member hierarchy, and never overwrites an existing file. Pre-flight requires at least 10 GiB to remain after the listed uncompressed size is deducted from current free space.

Every extracted regular file is reconciled against the archive listing, size-checked, and streamed through SHA-256. These hashes describe local derived content and are not claimed as official upstream checksums.

```powershell
.\.venv\Scripts\python.exe scripts\n_baiot_archive_access.py --mode list `
  --n-baiot-root "E:\Document\N_BaIoT_Dataset" `
  --tool "C:\Program Files\WinRAR\UnRAR.exe"

.\.venv\Scripts\python.exe scripts\n_baiot_archive_access.py --mode extract `
  --n-baiot-root "E:\Document\N_BaIoT_Dataset" `
  --work-root "E:\Document\iotguard_dataset_work" `
  --tool "C:\Program Files\WinRAR\UnRAR.exe"
```

## A2 structural/schema method

`scripts/dataset_structure_audit.py` streams every logical CSV with Python's CSV parser. It detects the local delimiter from the header, preserves ordered header names exactly, reads every record, counts data rows excluding the header, and records every width mismatch or parse failure. It does not calculate null, invalid-value, duplicate, label-distribution, imbalance, or leakage statistics.

The deterministic schema signature is SHA-256 over the compact UTF-8 JSON serialization of the ordered header vector. This preserves empty names and column order. The observed files are grouped as follows:

- N-BaIoT: 9 immutable benign CSVs plus 80 derived attack CSV members from 16 archives.
- Bot-IoT `all_features_5pct_shards`: four shards of one observed representation.
- Bot-IoT `ten_best_full`: one separate derived representation.
- Bot-IoT `ten_best_predefined_train` and `ten_best_predefined_test`: supplied split representations retained only as audit evidence and not adopted as the IoTGuard evaluation split.

Audit fact: the four All-features files form one representation group. The 10-best files are derived representation(s). These groups must not be concatenated as independent observations. A later decision may choose a representation; A2 does not.

The local 10-best full file is semicolon-delimited and contains an unnamed leading column. The comma-delimited predefined train/test files omit that column. Their row-count relationship is recorded, but record-level lineage is not inferred.

```powershell
.\.venv\Scripts\python.exe scripts\dataset_structure_audit.py `
  --n-baiot-root "E:\Document\N_BaIoT_Dataset" `
  --bot-iot-root "E:\Document\Bot_IoT_Dataset" `
  --n-baiot-extracted-root "E:\Document\iotguard_dataset_work\n_baiot_extracted"

.\.venv\Scripts\python.exe scripts\verify_a2_evidence.py `
  --n-baiot-root "E:\Document\N_BaIoT_Dataset" `
  --bot-iot-root "E:\Document\Bot_IoT_Dataset" `
  --n-baiot-extracted-root "E:\Document\iotguard_dataset_work\n_baiot_extracted"
```

A2 evidence is stored in `artifacts/audit/` and `artifacts/manifests/n_baiot_extracted_manifest.csv`. The verifier independently reconciles source path/size/timestamp metadata, uses PowerShell `Get-FileHash` for source and extracted samples, and uses binary physical-line counting/direct header splitting for row and schema samples.

## A3 label/taxonomy method

`scripts/dataset_label_audit.py` implements A3 without rereading N-BaIoT feature rows.
N-BaIoT labels are derived strictly from the verified A2 logical-file provenance and exact
row counts. The mapper preserves device, source kind, archive family hint, parent archive,
source/extracted path, member name, and logical ID. Its three canonical levels are binary,
family, and family-qualified fine class. Unexpected provenance fails the run; no `UNKNOWN`
label is assigned.

Bot-IoT is read with a streaming CSV parser restricted to the source columns `attack`,
`category`, and `subcategory`. Raw lexical strings are counted before canonicalization.
The four All-features 5% shards are the primary representation for audit evidence only.
The 10-best full, predefined train, and predefined test files are profiled independently,
then compared by total, single-field, pair, and joint label distributions. The unnamed
leading 10-best-full field is ignored through exact label-column lookup and is not changed.

The Bot-IoT source label columns are classified as label/target metadata, not candidate
predictors. The All-features files have 46 observed columns; A3 makes no claim that these
are 46 usable ML features. Canonical labels are added as one-to-one conventions while raw
labels remain authoritative.

```powershell
.\.venv\Scripts\python.exe scripts\dataset_label_audit.py `
  --bot-iot-root "E:\Document\Bot_IoT_Dataset"

.\.venv\Scripts\python.exe scripts\verify_a3_evidence.py `
  --n-baiot-root "E:\Document\N_BaIoT_Dataset" `
  --bot-iot-root "E:\Document\Bot_IoT_Dataset" `
  --n-baiot-extracted-root "E:\Document\iotguard_dataset_work\n_baiot_extracted"
```

Primary A3 evidence is stored in the compact `artifacts/audit/*label*` CSV/JSON files.
`artifacts/audit/a3_evidence_verification.json` is produced independently with a strict
second N-BaIoT mapper and pandas chunked Bot-IoT label aggregation. Matching aggregate
distributions do not establish record identity, row order, or lineage.

The detailed source-fact/project-convention boundary, exact mappings, counts, and deferred
questions are documented in `docs/protocols/dataset_label_taxonomy.md`.

## A4 quality, duplicate, and lineage method

`scripts/dataset_quality_audit.py` streams all 89 logical N-BaIoT CSVs and each Bot-IoT
representation separately with NA coercion disabled. Empty fields, exact null-like spellings,
`NaN`, positive/negative infinity, numeric parse failures, finite ranges, negative observations,
zeroes, and outer whitespace remain distinct categories. Negative values are observations, not
automatically classified as invalid.

Duplicate discovery uses deterministic pandas 64-bit hashes only to identify candidates. Every
candidate row is reread from its source and grouped by an exact length-prefixed UTF-8 field tuple;
SHA-256 identifies the confirmed exact group. The temporary SQLite database and Bot-IoT lineage
arrays live outside the repository. The accepted retry2 state remains outside the repository for
A5 reuse and independent diagnosis; the failed retry1 state was deleted after explicit approval.

Bot-IoT lineage uses unique integer `pkSeqID` values. Numeric projection fields compare as finite
numbers so harmless forms such as `1` and `1.0` compare equally; protocol, address, port, category,
and subcategory fields compare as exact source strings. Record-set identity, value identity, and
row ordering are reported separately.

Key observed results are:

- all 7,062,606 N-BaIoT rows contain no empty fields, explicit null tokens, `NaN`, infinity, or
  numeric parse failures across the 115 observed numeric-like columns;
- N-BaIoT has 2,482,676 unique feature vectors and 4,579,930 duplicate excess rows
  (64.8475930839%); the confirmed groups do not cross canonical fine label, family, or the
  benign/malicious boundary;
- the four Bot-IoT All-features shards contain no exact full-row or 43-non-label-field duplicate
  groups; `sport` and `dport` contain 18,104 numeric parse failures across 9,052 records because
  local values include nonnumeric lexical forms;
- the unnamed leading 10-best-full field is the unique zero-based physical row index from 0 to
  3,668,521;
- `pkSeqID` is complete and unique in All-features and 10-best full. Train and test IDs are
  disjoint and their union equals the full ID set;
- All-features and 10-best full have identical ID order, but 1,433,468 records differ in at least
  one compared numeric field. The predefined train/test files likewise contain numeric-field
  differences from 10-best full and do not preserve its relative row order. Therefore neither
  exact value projection nor an exact value-preserving supplied partition is claimed.

Primary and independent rerun commands:

```powershell
.\.venv\Scripts\python.exe scripts\dataset_quality_audit.py `
  --n-baiot-root "E:\Document\N_BaIoT_Dataset" `
  --bot-iot-root "E:\Document\Bot_IoT_Dataset" `
  --n-baiot-extracted-root "E:\Document\iotguard_dataset_work\n_baiot_extracted" `
  --temp-dir "E:\Document\iotguard_dataset_work\a4_fingerprints"

.\.venv\Scripts\python.exe scripts\verify_a4_evidence.py `
  --n-baiot-root "E:\Document\N_BaIoT_Dataset" `
  --bot-iot-root "E:\Document\Bot_IoT_Dataset" `
  --n-baiot-extracted-root "E:\Document\iotguard_dataset_work\n_baiot_extracted" `
  --temp-dir "E:\Document\iotguard_dataset_work\a4_fingerprints"
```

The verifier must run before removing the external temporary directory. Its persisted result is
`artifacts/audit/a4_evidence_verification.json`. A4 `PASS` means the audit and evidence
reconciliation completed; it does not assert that no quality or duplicate findings exist.

## A5 imbalance, leakage, and split-feasibility method

`scripts/dataset_leakage_audit.py` reuses the accepted A4 N-BaIoT exact groups to compare raw-row
and unique-vector class support and to simulate deterministic row-random, exact-group-aware,
leave-one-device-out, and device-plus-vector-isolation diagnostics. It does not write any
processed split.

Bot-IoT is streamed by representation. A5 separately audits target metadata, unique/index fields,
documented time/order fields, entity/context fields, and behavioral statistics. It measures class
support, supplied-split entity/time overlap, label concentration by identifier range, diagnostic
random/chronological/entity-grouped candidates, identity-free exact duplicates both with and
without `seq`, raw port token forms, and the six known numeric lineage fields. Timestamp evidence
is limited to numeric/order relationships because the local documentation does not justify a
calendar interpretation. Negative port-token semantics remain unknown where the feature
documentation is silent.

Candidate hashes are only a discovery filter. Candidate rows are confirmed using exact
length-prefixed UTF-8 tuples in an external SQLite database. External candidate hashes, temporal
maps, lineage arrays, delta arrays, and the exact database must remain available until
`verify_a5_evidence.py` passes. A5 `PASS` means the measurements reconcile; it does not mean a
dataset or split is safe.

Primary and independent rerun commands use separate external A5 state:

```powershell
.\.venv\Scripts\python.exe scripts\dataset_leakage_audit.py `
  --n-baiot-root "E:\Document\N_BaIoT_Dataset" `
  --bot-iot-root "E:\Document\Bot_IoT_Dataset" `
  --n-baiot-extracted-root "E:\Document\iotguard_dataset_work\n_baiot_extracted" `
  --a4-temp-dir "E:\Document\iotguard_dataset_work\a4_fingerprints_phase0_retry2_20260925" `
  --temp-dir "E:\Document\iotguard_dataset_work\a5_leakage_phase0_retry1_20260926"

.\.venv\Scripts\python.exe scripts\verify_a5_evidence.py `
  --bot-iot-root "E:\Document\Bot_IoT_Dataset" `
  --a4-temp-dir "E:\Document\iotguard_dataset_work\a4_fingerprints_phase0_retry2_20260925" `
  --a5-temp-dir "E:\Document\iotguard_dataset_work\a5_leakage_phase0_retry1_20260926" `
  --output "artifacts\audit\a5_evidence_verification.json"
```

The A5 source and evidence changes may be committed only after independent verification and
external review. A6 may synthesize the accepted compact evidence, but it must not select a final
split, select final predictors, or assign dataset roles.

## A6 cross-dataset suitability synthesis

`scripts/dataset_suitability_audit.py` reads only compact A0-A5 artifacts. It evaluates a fixed
20-dimension suitability framework, P1-P8 mandatory capabilities, coverage-first split evidence,
secondary ML use cases, and exact/semantic cross-dataset compatibility. Statuses are categorical;
the method prohibits a numeric total, ranking, winner, primary/secondary assignment, final split,
predictor selection, model training, clustering execution, or raw-data reread.

Bot-IoT entity purity is interpreted against the relevant global baseline. Its approximately
99.987% malicious majority makes near-100% weighted binary purity weak incremental evidence;
category purity and entity-overlap evidence carry more context-risk information. Candidate split
coverage always records expected, present, and missing classes before minimum represented-class
support.

The lightweight independent verifier parses A0-A5 sources directly, recomputes key ratios,
coverage, global-baseline adjustments, and exact schema overlap, verifies artifact hashes and
allowed statuses, and rejects numeric scoring or role assignment:

```powershell
.\.venv\Scripts\python.exe scripts\dataset_suitability_audit.py
.\.venv\Scripts\python.exe scripts\verify_a6_evidence.py
```

A6 evidence and `docs/analysis/dataset_suitability_comparison.md` were accepted after external
review and committed as `98b392d954327e5557298a7d6baca206da03514c`. The omitted comparison
document was checked locally against the SHA-256 recorded by the A6 summary before commit.

## A7 dataset-role decision and G1 closure

`scripts/dataset_role_decision.py` reads only compact A0-A6 evidence and applies a non-numeric
requirements gate. P1-P3 require supported core binary data, a leakage-controlled evaluation
path, and meaningful evaluation resolution. N-BaIoT satisfies all three; Bot-IoT is bounded by
the intrinsic 477-row benign support of the audited local 5% representation.

ADR-001 therefore assigns N-BaIoT as primary and Bot-IoT as secondary for IoTGuard. N2 is only a
leading audited feasibility reference: A7 does not adopt it as the final split. Bot-IoT remains
required for at least one technically defensible future ML experiment. Direct matrix merging and
direct cross-dataset model evaluation remain outside the core pipeline because no verified common
input space exists.

The independent verifier reads A0-A6 compact evidence directly and recomputes the P1-P3 gate,
N2 overlap and coverage, Bot-IoT benign support, candidate-test benign range, cross-dataset feature
overlap, decision trace, ADR consistency, downstream deferrals, and G1 checklist:

```powershell
.\.venv\Scripts\python.exe scripts\dataset_role_decision.py
.\.venv\Scripts\python.exe scripts\verify_a7_evidence.py
```

A7 performs no raw-data read, preprocessing, model training, clustering, processed-split creation,
or Jira mutation. Its files remain unstaged and uncommitted for external review. G2 must not start
as part of A7.
