# Frozen primary classifier inference contract

The accepted N-BaIoT classifier is `xgb_frac1_seed42_lr01`. Its versioned
`primary_classifier_input_v1` contract and exact model travel together in the
[A2 technical inference handoff](../handoffs/A2_CLASSIFIER_EVALUATION.md).
This is a structured-feature inference contract; raw packet extraction, FastAPI,
React and Raspberry Pi execution are separate integration work.

| Field | Frozen behavior |
|---|---|
| Predictors | Exact 115 ordered names from the original G3B feature contract; no labels/device/source IDs in X |
| Input | Nonempty numeric matrix, n by 115; require the complete ordered name list |
| View | Original raw values; cast to float32 for the selected tree model |
| Scaling | Do not scale this model's inputs; package TRAIN scaler retained for lineage and LR only |
| Invalid input | Reject order/shape mismatch, text, booleans, NaN/infinity and float32 overflow |
| Labels | benign=0, malicious=1; malicious is the positive class |
| Decision | malicious when probability >= 0.5, otherwise benign |
| Outputs | Aligned malicious probabilities, numeric predictions and label strings |
| Integrity | Require externally published inference manifest SHA-256 and verify every payload |
| Model SHA-256 | cb090afa6ad4c3618e20d7c5d635e89aa2d122667ea00835a0acc2f75a4455e6 |
| Runtime verified | Python3.11.15, NumPy2.4.6, XGBoost3.2.0, SciPy1.17.1; no fitting |
| Errors | CLI exits nonzero with an explicit ValueError; HTTP error schema remains an application task |

`iotguard.inference.primary_classifier` is self-contained and copied by the
handoff builder; recipients do not need IoTGuard installed, raw datasets or a Git
checkout. Three executable VALIDATION examples include both classes and a real
false negative. Unit checks cover reordered, malformed, nonnumeric, nonfinite and
overflowing inputs, manifest substitution and payload tampering. The relocated
handoff passed inference and checksum verification in an isolated environment.

Historical training reported XGBoost3.4.1; 3.2.0 inference independently reproduced
the full VALIDATION metrics and original source-row errors before the freeze.
Do not silently substitute a different runtime or model. Changes require a new
compatibility receipt and must not use final TEST to make selection decisions.
