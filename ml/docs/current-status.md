# Current engineering status

| Area | Recorded state | Evidence |
| --- | --- | --- |
| Datasets | N-BaIoT is primary. Bot-IoT has separate supporting experiments. | [Dataset roles](decisions/ADR-001-dataset-role-selection.md), [Bot-IoT archive](handoffs/BOT_IOT_SECONDARY_RUN_ARCHIVE.md) |
| Primary data | The G3A split and G3B package were verified. The original package identities are retained. | [G3B handoff](handoffs/G3B_PRIMARY_DATA_HANDOFF.md), [build repair](handoffs/G3B_BUILD_IDENTITY_FIX.md) |
| Classifier | Fourteen received models passed VALIDATION replay. Nine Full candidates entered comparison. VALIDATION selected `xgb_frac1_seed42_lr01` before the final TEST run. | [A2 classifier evaluation](handoffs/A2_CLASSIFIER_EVALUATION.md), [final evaluation protocol](protocols/primary_final_evaluation_v1.md) |
| Inference handoff | The relocated A2 package passed verification. The A2 handoff records `PREPARED_FOR_REVIEW`. | [A2 classifier evaluation](handoffs/A2_CLASSIFIER_EVALUATION.md), [inference contract](architecture/inference_contract.md) |
| Manual Analysis | `POST /predict` classifies CSV/JSON with 115 ordered features through the shared predictor. | [PR #29](https://github.com/sonnnguyennn/cos30049hn-grp1_5/pull/29), [upload guide](../../docs/csv-upload-api-guide.md) |
| Raspberry Pi | The shared predictor passed standalone checks with three pre-extracted VALIDATION vectors. Live API integration is tracked separately. | [Pi receipt](https://github.com/sonnnguyennn/cos30049hn-grp1_5/blob/c03e7b733c4de63322709b3a8ffb5390cc067a5e/docs/a3-pi-predictor-result.json), [live API contract](../../docs/live-api-contract.md) |
| Clustering and analysis | Full TRAIN/VALIDATION clustering outputs and Duy's A2 figures are integrated. The analysis guide tracks recipient steps. | [Full clustering results](../notebooks/Clustering/Result/full/analysis.md), [Duy A2 analysis](../analysis/duy_a2/README.md) |

## Evaluation boundaries

Use TRAIN for fitting and VALIDATION for selection. The final TEST evaluation requires the frozen-model gate documented in the [final evaluation protocol](protocols/primary_final_evaluation_v1.md).

Historical [system context](architecture/system_context.md), [decisions](decisions/decision-log.md) and [protocols](protocols/README.md) describe their original checkpoints. See the [documentation index](README.md) for current guides and handoffs.
