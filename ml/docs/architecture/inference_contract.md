# Frozen primary classifier inference contract

The accepted N-BaIoT classifier is `xgb_frac1_seed42_lr01`. The [freeze manifest](../../artifacts/manifests/primary_model_freeze_20261105.json) records the model hash and the `primary_classifier_input_v1` contract.

| Field | Frozen behavior |
| --- | --- |
| Features | Exactly 115 numeric predictors in `input_contract.feature_order`. Pass the order alongside inputs to the portable handoff. The shared predictor takes rows in that order. |
| Input | A nonempty matrix of raw values cast to float32. The TRAIN scaler remains for lineage and LR. |
| Invalid input | Reject shape or order mismatch when the caller supplies names, text, booleans, NaN, infinity and float32 overflow. |
| Labels | `benign` = 0 and `malicious` = 1. Malicious is the positive class. |
| Decision | `malicious` when malicious probability is at least 0.5, otherwise `benign`. |
| Outputs | Aligned malicious probabilities, numeric predictions and labels. |
| Model SHA-256 | `cb090afa6ad4c3618e20d7c5d635e89aa2d122667ea00835a0acc2f75a4455e6` |

## Application and Raspberry Pi

The [shared predictor](../../../backend/app/predictor.py) loads the model after verifying its SHA-256 against the freeze manifest. Manual Analysis checks the supplied feature names before calling it and returns the [versioned response](../../../docs/analysis-response.md). The [upload guide](../../../docs/csv-upload-api-guide.md) documents HTTP errors. Both the shared predictor and portable handoff expect pre-extracted features.

## Portable A2 handoff

The [A2 handoff](../handoffs/A2_CLASSIFIER_EVALUATION.md) packages `iotguard.inference.primary_classifier`, the model and three VALIDATION examples covering both classes and a recorded false negative. Supply the published inference manifest SHA-256. The loader verifies the manifest and its payloads. The CLI exits with an error for invalid input or a failed integrity check.

Relocated verification used Python 3.11.15, NumPy 2.4.6, XGBoost 3.2.0 and SciPy 1.17.1. Training reported XGBoost 3.4.1. XGBoost 3.2.0 independently reproduced the full VALIDATION metrics and source-row errors before the freeze. Qualify runtime changes on VALIDATION. A different model requires a new freeze under the [final evaluation protocol](../protocols/primary_final_evaluation_v1.md).
