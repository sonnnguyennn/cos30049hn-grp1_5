# Test the frozen classifier with real samples

From the repository root, run:

```bash
ml/.venv/bin/python ml/scripts/sample_prediction.py --out ml/data/samples/primary-prediction
```

This selects three benign and three malicious rows from VALIDATION, runs the
accepted `xgb_frac1_seed42_lr01` model, and prints the actual label, predicted
label, malicious probability and whether each prediction is correct. Change
the count with `--per-class 10` (1–100). Omit `--out` to print without saving.
Each export needs a new directory so previous results are preserved.

The default dataset location is `../g3b_primary_v1` beside the repository.
Override it with `--package /path/to/g3b_primary_v1`. The model defaults to
`ml/experiments/xgb_frac1_seed42_lr01/model.json`; `--model` accepts a relocated
copy with the same frozen checksum. No training or TEST inference runs.
The script checks the published package manifest, VALIDATION payload checksums,
shared package files and exact model checksum before predicting.

The output directory contains:

| File | Contents |
| --- | --- |
| `sample_input.json` | `feature_order` and numeric `rows`, compatible with the portable handoff's `--input`. |
| `sample_input.csv` | The same rows with exactly 115 ordered feature columns; no labels or metadata. |
| `predictions.json` | Probabilities, predictions, actual labels, source-row lineage, checksums and runtime versions. |

Inputs use raw values cast to float32, without scaling. Malicious probability
at least 0.5 means malicious. These are a few deliberately balanced examples;
their correctness does not estimate general model performance. The dashboard's
upload inspection endpoint does not yet classify files.

If setting up a new environment on Linux, use:

```bash
python3 -m venv ml/.venv
ml/.venv/bin/python -m pip install numpy==2.4.6 scipy==1.17.1 xgboost-cpu==3.2.0
```

On Windows use `ml\.venv\Scripts\python.exe` and `xgboost==3.2.0` instead of
`xgboost-cpu`. The CPU distribution avoids GPU dependencies on Linux. The report
records the actual runtime; the original acceptance environment used Python
3.11.15 on Windows, so a local sample run is an additional smoke check rather
than a replacement for the team's acceptance evidence.
