# A2 data analysis, evaluation figures and package check (CODE 4.1-4.4)

Everything here is computed from saved, accepted results: no model is fitted, tuned or re-run,
and no TEST array is opened (TEST values come from the saved final TEST receipt).

## Status

| | |
|---|---|
| **Done** | 4.1.1 class counts; 4.1.2 TRAIN features (Bot-IoT; N-BaIoT via the local step, run on Windows); 4.1.3 duplicates; 4.2.1-4.2.5 classifier tables and figures, confusion matrices, final TEST, clustering; 4.3 Bot-IoT Dummy/LR, row vs group; 4.4.1-4.4.3 clean Conda check (PASS, run 06) |
| **Checked** | Each script re-derives its numbers from the source files and stops on any mismatch (checks in `outputs/logs/<script>.json`), e.g. every 4.2 metric recomputed from the confusion counts, TEST counts 83,531 / 1 / 11 / 977,723, all 4.3 check values from the brief. N-BaIoT TRAIN/VALIDATION counts and the cluster composition were also re-counted from the package's own label files. The clustering numbers match Tables C.2–C.3 of the report. Input ZIP SHA-256 values match the brief (`outputs/logs/input_zip_checksums.json`). Every figure passes a text-overlap and print-width check. |
| **Missing** | 4.4.4: the final group package has not been delivered yet (checklist below). |
| **Not run** | None. |

## Environment

Python 3.11 with `requirements-eda.txt` (NumPy 2.4.6, matplotlib 3.11.2); nothing else is
needed (pandas is not used). The outputs here were made with Python 3.11.18; every log records
the versions and platform. Keep this environment separate from the clean 4.4 one.

```powershell
conda create -n iotguard-eda python=3.11 -y
conda activate iotguard-eda
python -m pip install -r analysis/duy_a2/requirements-eda.txt
```

## Inputs

| Input | Location | Used by |
|---|---|---|
| Audit summaries, contracts, manifests | `ml/artifacts/audit/`, `contracts/`, `manifests/` (Git) | 4.1, 4.2 |
| Classifier comparison, selection record, final TEST receipt | `ml/artifacts/manifests/primary_classifier_comparison_20261105.csv`, `primary_classifier_selection_20261105.json`, `primary_final_test_receipt_20261105.json` | 4.2 |
| Selected run's error analysis | `ml/experiments/xgb_frac1_seed42_lr01/error_analysis.json` | 4.2 (fig42b) |
| Clustering outputs | `ml/notebooks/Clustering/results/full/` (Git) | 4.2.5 |
| `Bot_IoT_processed_package_v2.zip` (SHA-256 `06cc1208...7566`) | extracted to its own folder | 4.1, 4.3 |
| `Bot_IoT_Full_experiment_outputs.zip` (`dc7ca7e5...f377`) | extracted to its own folder | 4.3 |
| `g3b_primary_v1.zip` (no published ZIP checksum; manifest SHA-256 `6ab99e86...147b`) | read in place, not extracted | 4.1.2 N-BaIoT |
| `IoTGuard_Primary_XGBoost_Handoff.zip` (`6ff11f67...6d77`) | the 4.4 script extracts it | 4.4 |

The packages are only read, never written to; the scripts check them against their own
manifests (the Full outputs against `output_checksums.json`). The old
`xgb-rf-experiments/comparison.csv` is not used (no LR/Dummy rows). The brief cites repo commit
`3539f3f`; these files come from a branch of `main` (`56da830`), and the comparison CSV, TEST
receipt and freeze record hash-match the selection record, the handoff bundle and the A2
handoff document.

## Run (PowerShell, from `ml/`)

```powershell
$S = "analysis/duy_a2/scripts"
$P = "<extracted Bot_IoT_processed_package_v2 folder>"
$F = "<extracted Bot_IoT_Full_experiment_outputs folder>"
python $S/t41_class_distribution.py --botiot-package $P   # optional: --nbaiot-local-receipt <extract>/nbaiot_local_receipt.json
python $S/t41_botiot_train_features.py --botiot-package $P
python $S/t41_duplicates.py --botiot-package $P
python $S/t42_classifier_figures.py
python $S/t42_clustering_figures.py                        # optional: --validation-labels <extract>/VALIDATION_y.npy
python $S/t43_botiot_analysis.py --full-outputs $F --botiot-package $P
python $S/build_figure_index.py                            # run last
```

Each script prints `N checks PASS` or stops at the first failed check, and writes
`outputs/logs/<script>.json` (inputs with SHA-256, outputs, checks, versions). In the same
environment a rerun reproduces the tables and figures byte for byte.

**N-BaIoT local step (4.1.2, fig41d).** The extract script streams the 6.1 GB package straight
from the ZIP, checks the manifest SHA-256 and every member it reads, never opens TEST members,
and needs only Python 3.9+ and NumPy. From `ml/`, with `$S` as above:

```powershell
python -I $S/t41_nbaiot_extract_local.py --package "<...>\g3b_primary_v1.zip" --out "<...>\nbaiot_extract_01"
python $S/t41_nbaiot_train_features.py --extract-dir "<...>\nbaiot_extract_01"
python $S/build_figure_index.py
```

The extract (about 77 MB) stays outside Git. With it, the two optional arguments above add a
record-level cross-check of the N-BaIoT partition counts and the cluster composition (both run
for the outputs here).

**Features (4.1.2)**, chosen by meaning before looking at any distribution; all TRAIN records,
raw values, log1p axis, the same 40 bins for both classes, each class normalised by its size:

| Dataset | Features (reason) |
|---|---|
| Bot-IoT | `pkts` (packets in the flow: volume), `bytes` (data volume), `dur` (flow duration: timing); raw values from `package.load("TRAIN")`, not the 36 encoded columns |
| N-BaIoT | `MI_dir_L0.1_weight` (decayed packet count: volume), `H_L0.1_mean` (mean packet size), `HH_jit_L0.1_mean` (mean inter-packet interval: timing); one decay window (L0.1), names and positions from `n_baiot_feature_contract_v1.json` |

## Outputs (`analysis/duy_a2/outputs/`)

| Path | Content |
|---|---|
| `tables/t41_*.csv` | class counts (corpus from the audit, TRAIN/VALIDATION/TEST from the packages), Bot-IoT TRAIN histograms and quantiles, duplicates |
| `tables/t42_*.csv`, `t42_tables.md` | 9 Full runs (overview, per class), subset runs kept apart, final TEST of the selected XGBoost, clustering sizes, composition and metrics |
| `tables/t43_*.csv` | Bot-IoT Dummy/LR row vs group, brief check values, the 77 benign groups, N-BaIoT vs Bot-IoT |
| `figures/` | fig41a-e, fig42a-e, fig43a-c as PNG (300 dpi) and PDF, drawn at print size (at most 6.3 in wide, text 6-7.5 pt): insert at 100%, not stretched |
| `figure_index.csv` | per figure: files, inputs with SHA-256, dataset, run ID, scope, n, weighting, sampling/transform, caption (N/A where not applicable) |
| `captions.md` | caption and 2-4 sentence commentary per figure |
| `logs/` | per-script checks and provenance, `figure_text/` layout checks, `input_zip_checksums.json`, `t44_conda_check_windows/` (4.4 evidence) |

All outputs are small (2.2 MB in total), so nothing needs to go to Drive.

## Rules applied

* Corpus (audit) and partition counts are separate tables; label levels are never added together.
* Duplicates are described, not removed: rows in repeated groups vs excess rows; Bot-IoT on all
  43 source fields (none) and on the 13 predictors (81.7% excess rows).
* Classifier figures keep the 0-1 scale. Confusion matrices: [benign, malicious], rows = true
  class, counts with row percentages. TEST is shown only for the selected `xgb_frac1_seed42_lr01`.
* Bot-IoT group weights use the original exact-X groups in `VALIDATION_metadata.npy`; weighted
  confusion values stay weighted masses.
* Clusters are described with labels only after fitting; no cluster is called benign or malicious.

## 4.4 clean-environment check

PASS in run 06 on Windows with a new Conda environment; runs 01-05 stopped on local setup and
are kept in `failed_runs/`. Details: `outputs/logs/t44_conda_check_windows/summary.md`. To rerun:

```powershell
powershell -ExecutionPolicy Bypass -File analysis\duy_a2\scripts\t44_handoff_check.ps1 `
  -HandoffZip "<...>\IoTGuard_Primary_XGBoost_Handoff.zip" -RunId 07   # any unused ID
```

The script checks the ZIP SHA-256, extracts it into a new folder, creates
`duy-iotguard-check-<ID>` from `environment.yml`, runs the brief's two `predict_primary.py`
commands in it, compares the outputs with `example_expected.json` (labels
`[benign, malicious, benign]`; the third is the documented false negative) and saves everything
in `~\iotguard_4_4_check\evidence_<ID>\`. After a failure, keep that folder and rerun with the
next ID; never edit the manifest, model, input contract or expected outputs. Install Miniconda
to a path without spaces; if `conda.exe` is not found, add
`-CondaExe "<install folder>\Scripts\conda.exe"`; the Terms of Service fix used for run 06 is in
`summary.md`.

**4.4.4 final group package (when delivered):**

- [ ] record the version / commit / hash of the received package
- [ ] every file named in its README is present
- [ ] setup works in a new environment (new name)
- [ ] the model loads and predicts with the documented input path
- [ ] report wrong input paths and missing steps to the package owner
- [ ] note that the classifier-handoff PASS does not imply PASS for this package

## Notes

* The TEST receipt's `persisted_config` shows `learning_rate 0.3`, XGBoost's loader default (the
  model JSON does not store training parameters, as the receipt says); the training value is
  0.1 (the run's `result.json`), so quote that one.
* `xgb_frac1_seed42_d8` and `rf_frac1_seed42` have identical VALIDATION counts (1 FP, 29 FN);
  the selection rule breaks the tie by run ID order.
* The RF baseline's `result.json` records only `n_estimators` (100); its other settings are the
  scikit-learn 1.9.1 defaults (`run_notes.json`).
