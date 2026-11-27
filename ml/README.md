# IoTGuard ML

Internal engineering guide for data contracts, experiments and frozen inference. N-BaIoT is the primary dataset. The [dataset decision](docs/decisions/ADR-001-dataset-role-selection.md) assigns Bot-IoT to separate supporting experiments.

## Set up

Use Python 3.11 or later. From `ml/` in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe scripts/check_environment.py
.\.venv\Scripts\python.exe scripts/check_data_paths.py
.\.venv\Scripts\python.exe -m pytest
```

If dataset paths differ, copy `config/data_paths.example.yaml` to `config/data_paths.local.yaml` and set the local paths. Keep raw data, packages and new large experiment outputs outside Git. See the [tracking policy](../docs/git-tracking.md) and [G3A import handoff](docs/handoffs/G3A_IMPORT_HANDOFF.md) for path overrides and original audit evidence.

## Use the accepted model

The frozen XGBoost model takes 115 ordered N-BaIoT features. See the [inference contract](docs/architecture/inference_contract.md), [real VALIDATION examples](docs/experiments/sample_prediction.md) and [Manual Analysis upload guide](../docs/csv-upload-api-guide.md).

## Work with experiment artifacts

- **Primary package.** The independently verified G3B package is `READY_FOR_TEAM`. `TEAM_VERIFIED` requires a recipient run. Follow the [G3B handoff](docs/handoffs/G3B_PRIMARY_DATA_HANDOFF.md) and [build identity repair](docs/handoffs/G3B_BUILD_IDENTITY_FIX.md) for checksums, raw/scaled views and provenance.
- **Classifiers.** Follow the [primary experiment protocol](docs/protocols/primary_experiments_v1.md) and [Kaggle LR and Dummy guide](docs/experiments/kaggle_lr.md). Run new classifier fits on Kaggle. A2 acceptance replays saved models. The [A2 handoff](docs/handoffs/A2_CLASSIFIER_EVALUATION.md) records the selected model, final results and portable package.
- **Dependencies.** Install the optional training extras with `python -m pip install -e ".[dev,kaggle,xgboost]"` in the ML environment or `uv sync --locked --extra dev --extra kaggle --extra xgboost`. Keep the frozen inference runtime documented separately.
- **Evaluation.** Fit on TRAIN and select on VALIDATION. Follow the [final evaluation protocol](docs/protocols/primary_final_evaluation_v1.md) for the frozen-model TEST gate. Retain original package IDs and receipts with archived results.

See the [documentation index](docs/README.md) for protocols and historical handoffs.
