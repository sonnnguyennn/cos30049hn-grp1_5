# Duy - A2 data analysis, evaluation figures and package check (CODE 4.1-4.4)

Scripts, tables, figures and evidence for Duy's part of Assignment 2. Everything is computed
from **saved, accepted evidence**: no classifier or clustering model is fitted, tuned or re-run,
and no TEST array is opened (TEST numbers come only from the saved final TEST receipt and the
package manifests).

## Status (handoff summary)

| Task | Status | Evidence |
|---|---|---|
| 4.1.1 class counts and shares | **Done** - corpus (audit) and partition tables kept separate; 55 checks | `t41_class_counts_*.csv`, fig41a, fig41b |
| 4.1.2 Bot-IoT TRAIN features (pkts, bytes, dur) | **Done** - all 2,201,114 TRAIN rows, raw values via `package.load("TRAIN")` | fig41c, `t41_botiot_train_feature_*.csv` |
| 4.1.2 N-BaIoT TRAIN features | **Pending local step** - the 1.6 GB package is on Duy's PC; run `t41_nbaiot_extract_local.py` there | fig41d (PENDING in `figure_index.csv`) |
| 4.1.3 duplicates | **Done** - both definitions for Bot-IoT (43 source fields vs 13 predictors) | `t41_duplicates_*.csv`, fig41e |
| 4.2.1-4.2.4 classifier tables, figures, CMs, final TEST | **Done** - 9 Full runs, 206 checks incl. recomputing every metric from counts | `t42_*.csv`, `t42_tables.md`, fig42a-d |
| 4.2.5 clustering | **Done from `notebooks/Clustering/results/full`** - confirm with Minh Son that these are the final outputs | `t42_clustering_*.csv`, fig42e |
| 4.3 Bot-IoT Dummy/LR, row vs group | **Done** - every brief check value matched; 71 checks | `t43_*.csv`, fig43a-c |
| 4.4.1-4.4.3 clean-env handoff check | **Ready to run on Duy's PC** (`t44_handoff_check.ps1`). Pre-check in Claude's Linux venv PASSED - this is not the Conda PASS | `outputs/logs/t44_precheck_claude_workspace/` |
| 4.4.4 final group package | **Waiting for Minh Son** | checklist below |

Not run yet: the N-BaIoT local extract, the Windows Conda check, the final group package check.

## Environment

* Python 3.11 with `requirements-eda.txt` (NumPy 2.4.6, matplotlib 3.11.2). The scripts use only
  the standard library, NumPy and matplotlib.
* All outputs in this folder were produced with Python 3.11.18 / NumPy 2.4.6 / matplotlib 3.11.2
  (versions are also written into every log). A second run with Python 3.13 / NumPy 2.5.3
  produced byte-identical tables.
* Keep this EDA environment separate from the 4.4 check environment, which must stay clean.

```powershell
conda create -n duy-eda python=3.11 -y
conda activate duy-eda
python -m pip install -r analysis/duy_a2/requirements-eda.txt
```

## Inputs

| Input | Where | Used by |
|---|---|---|
| Audit, contracts, manifests | `ml/artifacts/audit/`, `ml/artifacts/contracts/`, `ml/artifacts/manifests/` (in Git) | all |
| Official classifier comparison | `artifacts/manifests/primary_classifier_comparison_20261105.csv` (SHA-256 `0b9763d6...4d47`, matches the selection record) | 4.2 |
| Final TEST receipt | `artifacts/manifests/primary_final_test_receipt_20261105.json` | 4.2.4 |
| Clustering outputs | `notebooks/Clustering/results/full/` (in Git) | 4.2.5 |
| Bot-IoT package v2 | extracted `Bot_IoT_processed_package_v2.zip` (ZIP SHA-256 `06cc1208...7566`) | 4.1, 4.3 |
| Bot-IoT Full outputs | extracted `Bot_IoT_Full_experiment_outputs.zip` (ZIP SHA-256 `dc7ca7e5...f377`) | 4.3 |
| G3B primary package | `g3b_primary_v1.zip`, read in place (manifest SHA-256 `6ab99e86...147b`) | 4.1.2 local step |
| Classifier handoff | `IoTGuard_Primary_XGBoost_Handoff.zip` (ZIP SHA-256 `6ff11f67...6d77`) | 4.4 |

The old `xgb-rf-experiments/comparison.csv` is **not** used: it has no LR/Dummy rows.

## Commands (PowerShell, from `ml/`)

```powershell
$P = "<extracted Bot_IoT_processed_package_v2 folder>"
$F = "<extracted Bot_IoT_Full_experiment_outputs folder>"
$S = "analysis/duy_a2/scripts"
python $S/t41_class_distribution.py --botiot-package $P [--nbaiot-local-receipt <extract>/nbaiot_local_receipt.json]
python $S/t41_botiot_train_features.py --botiot-package $P
python $S/t41_duplicates.py --botiot-package $P
python $S/t42_classifier_figures.py
python $S/t42_clustering_figures.py [--validation-labels <extract>/VALIDATION_y.npy]
python $S/t43_botiot_analysis.py --full-outputs $F --botiot-package $P
python $S/build_figure_index.py      # run last
```

For a verified artifact restore, pass `--results-dir <restored-full-directory>`
to the clustering command. See the [archive guide](../../../docs/experiment-artifacts.md).

Each script stops with an error if any check fails; on success it prints `N checks PASS` and
writes `outputs/logs/<script>.json` (inputs with SHA-256, outputs, every check, versions).
Every figure is also checked for text that overlaps or touches other text, dots, bars or axis
lines, and for fitting its print width; any problem is printed as `WARNING <figure>` and
listed in `outputs/logs/figure_text/<figure>.json`, together with every drawn text and its
position (used to re-check each shown number against the sources).

### N-BaIoT local step (4.1.2) - on the PC that holds `g3b_primary_v1.zip`

The package is 6.1 GB uncompressed, so this script streams it straight from the ZIP (no
extraction). It checks the manifest SHA-256 and hashes every member it reads; TEST members are
never opened. It needs only Python 3.9+ and NumPy, and takes a few minutes.

```powershell
python -I analysis/duy_a2/scripts/t41_nbaiot_extract_local.py `
  --package "<...>\Primary Data (N-BaIoT)\g3b_primary_v1.zip" `
  --out "<...>\Primary Data (N-BaIoT)\duy_eda_extract_01"
python analysis/duy_a2/scripts/t41_nbaiot_train_features.py --extract-dir "<...>\duy_eda_extract_01"
```

The extract (about 100 MB, observation-scale) stays **outside Git**. Features, chosen by meaning
before looking at any distribution, one per behaviour at the same decay window (L0.1):
`MI_dir_L0.1_weight` (volume), `H_L0.1_mean` (packet size), `HH_jit_L0.1_mean` (timing).
Names and positions come from the package's `n_baiot_feature_contract_v1.json`.

## Outputs

| File | Content |
|---|---|
| `outputs/tables/t41_class_counts_corpus.csv` | full-corpus counts per **single** level (N-BaIoT binary/family/fine_class; Bot-IoT attack/category/subcategory, `all_features_5pct_shards` only) |
| `outputs/tables/t41_class_counts_partitions.csv` | TRAIN/VALIDATION/TEST binary counts and shares |
| `outputs/tables/t41_botiot_train_feature_*.csv` | shared-bin histograms and exact quantiles, Bot-IoT TRAIN |
| `outputs/tables/t41_duplicates_summary.csv` | rows, distinct vectors, repeated groups, rows in repeated groups, excess rows |
| `outputs/tables/t41_duplicates_by_class.csv` | the same per class (raw vs distinct shares) |
| `outputs/tables/t41_botiot_duplicates_by_partition_class.csv` | Bot-IoT TRAIN/VALIDATION group stats per class |
| `outputs/tables/t42_validation_full_runs_overview.csv` | 9 Full runs: accuracy, macro-F1, FPR, TN/FP/FN/TP, configuration |
| `outputs/tables/t42_validation_full_runs_per_class.csv` | precision/recall/F1/support per class (undefined = N/A) |
| `outputs/tables/t42_validation_subset_runs_diagnostic.csv` | the 5 subset runs, kept apart |
| `outputs/tables/t42_test_selected_xgb.csv` | final TEST metrics, selected XGBoost only |
| `outputs/tables/t42_tables.md` | the three classifier tables as Markdown, ready for the report |
| `outputs/tables/t42_clustering_*.csv` | cluster sizes/composition; metrics labelled SAMPLE or FULL PARTITION |
| `outputs/tables/t43_botiot_validation_row_vs_group.csv` | Dummy/LR, row-weighted counts and group-weighted masses |
| `outputs/tables/t43_botiot_brief_checks.csv` | brief 3.2/3.3 check values vs actual |
| `outputs/tables/t43_botiot_validation_benign_groups_lr.csv` | the 77 benign VALIDATION groups and LR's prediction |
| `outputs/tables/t43_dataset_comparison.csv` | N-BaIoT vs Bot-IoT (3.4) |
| `outputs/figures/*.png, *.pdf` | figures, PNG 300 dpi + vector PDF, drawn at print size (6.3 in full width, 3.1 in half width; text 6-7.5 pt): insert them at 100% scale, not stretched |
| `outputs/figure_index.csv` | per figure: files, input files + SHA-256, dataset, run ID, scope, n, weighting, sampling/transform, caption (N/A where not applicable) |
| `outputs/captions.md` | caption + 2-4 sentence commentary per figure |
| `outputs/logs/*.json` | per-script provenance and checks |
| `outputs/logs/figure_text/*.json` | per figure: text layout check (0 problems) and every drawn text with its position |

## Rules applied

* Corpus totals (audit) and partition counts are labelled separately; label levels are never
  added together.
* Feature plots use TRAIN only, raw values, the same bins for both classes, each class
  normalised by its own size, log1p stated on the axis; no sampling.
* Duplicates: "rows in repeated groups" vs "excess rows" are reported separately; nothing is
  deduplicated. Bot-IoT is shown for all 43 source fields (0 duplicates) and for the 13
  predictors (81.7% excess rows).
* Classifier figures use the 0-1 scale (no truncated axes); error counts show the small
  differences between tree models instead. Confusion matrices: order [benign, malicious],
  rows = true class, counts plus row percentages.
* TEST appears only for the selected `xgb_frac1_seed42_lr01`, from the saved receipt
  (83,531 / 1 / 11 / 977,723 verified).
* Bot-IoT group weights use the original exact-X group (13 raw predictors) stored in
  `VALIDATION_metadata.npy`; weighted confusion values stay weighted masses.
* Clusters are described by labels only after fitting; no cluster is named benign/malicious.

## 4.4 clean-environment check (run on Duy's Windows PC)

Prerequisite: Conda (Miniconda). The Windows user folder `C:\Users\SV STORE` contains a space,
and Conda advises against installing into a path with spaces, so install Miniconda to a path
like `C:\miniconda3`. Then, from the **Anaconda PowerShell Prompt**:

```powershell
powershell -ExecutionPolicy Bypass -File analysis\duy_a2\scripts\t44_handoff_check.ps1 `
  -HandoffZip "<...>\IoTGuard_Primary_XGBoost_Handoff.zip" -RunId 01
```

The script checks the ZIP SHA-256, extracts into a new folder, runs
`conda env create -n duy-iotguard-check-01 -f environment.yml`, runs the two README commands
inside that environment (`conda run`), compares both outputs with `example_expected.json`
(labels `[benign, malicious, benign]`; the third example is the documented false negative),
and writes everything to `~\iotguard_4_4_check\evidence_01\` (transcript, stdout/stderr per
command, `conda list`, OS, `checklist_01.md/.json`). `-ExecutionPolicy Bypass` applies to that
one PowerShell process only; it does not change any system setting.

If a step fails: keep `evidence_01`, send the failing command and full message to Minh Son, and
rerun with `-RunId 02` (new env and folders; nothing is overwritten). Do not edit the manifest,
model, input contract or expected outputs. If only a venv can be used, record it as a venv check:
Conda PASS is then not confirmed.

Manual equivalent (the brief's commands):

```powershell
conda env create -n duy-iotguard-check-01 -f environment.yml
conda activate duy-iotguard-check-01
$expectedManifest = "9fac1acde3f696bb765937c997977b3d7b1e1c2fa6cd60626e910037ea1fe132"
python -I predict_primary.py --bundle . --expected-manifest $expectedManifest --verify --output ../duy_verification_01.json
python -I predict_primary.py --bundle . --expected-manifest $expectedManifest --input example_input.json --output ../duy_predictions_01.json
```

`predict_primary.py` refuses to overwrite an existing `--output` file, so every rerun needs new
output names.

### 4.4.4 final group package (when Minh Son delivers it)

- [ ] record version / commit / hash of the received package
- [ ] every file named in its README is present
- [ ] setup instructions work in a new environment (new env name)
- [ ] model loads and predicts with the documented input path
- [ ] input paths and missing steps reported to Minh Son
- [ ] note: the classifier-handoff PASS does not imply PASS for the group package

## Notes for the team

* The brief cites repo commit `3539f3f` (`feat/a2-classifier-final-evaluation`); this work used
  the files in branch `duy` (from `main` 56da830). The comparison CSV, TEST receipt and freeze
  record hash-match the selection record, handoff bundle and A2 handoff document.
* `g3b_primary_v1.zip` has no published ZIP checksum, but its manifest SHA-256 is published
  (`6ab99e86...147b`) and the local step verifies it plus every member it reads.
* The TEST receipt's `persisted_config` shows `learning_rate 0.3`: that is XGBoost's loader
  default (model JSON does not store training parameters, as the receipt says). The training
  value 0.1 is in the run's `result.json`; quote that one.
* `xgb_frac1_seed42_d8` and `rf_frac1_seed42` have identical VALIDATION counts (1 FP, 29 FN); the
  selection rule breaks the exact tie by run ID order.
