# Current engineering status

Status as of 2026-11-05, based on the committed handoffs below. Automated technical
verification and human teammate acceptance are separate; this guide does not
grant approval or claim completion of other owners' deliverables.

| Area | Recorded state | Authoritative reference |
| --- | --- | --- |
| Dataset roles | N-BaIoT primary; Bot-IoT kept separate for supporting experiments. | [ADR-001](decisions/ADR-001-dataset-role-selection.md) |
| Primary data | Fixed G3A split and G3B preprocessing/package verified; original package identities retained. | [G3B handoff](handoffs/G3B_PRIMARY_DATA_HANDOFF.md), [build repair](handoffs/G3B_BUILD_IDENTITY_FIX.md) |
| Primary classifiers | Fourteen received models passed recorded VALIDATION replay; nine Full candidates entered comparison. | [A2 classifier evaluation](handoffs/A2_CLASSIFIER_EVALUATION.md) |
| Selection and final evaluation | XGBoost `xgb_frac1_seed42_lr01` frozen using VALIDATION before the recorded final TEST evaluation. | [A2 classifier evaluation](handoffs/A2_CLASSIFIER_EVALUATION.md), [final protocol](protocols/primary_final_evaluation_v1.md) |
| Technical inference handoff | Portable model and input contract prepared and independently verified; handoff status remains `PREPARED_FOR_REVIEW`. | [Inference contract](architecture/inference_contract.md), [A2 handoff](handoffs/A2_CLASSIFIER_EVALUATION.md) |
| Secondary experiments | Bot-IoT evidence archived separately; not pooled into primary selection. | [Bot-IoT archive](handoffs/BOT_IOT_SECONDARY_RUN_ARCHIVE.md) |
| Web application | Upload inspection and log viewing exist; connecting the accepted predictor remains application integration work. | [Backend](../../backend/README.md), [frontend](../../frontend/README.md) |
| Clustering, edge and final group deliverables | Separate owner work; the classifier handoff does not certify these as complete. | [Remaining responsibilities](handoffs/A2_CLASSIFIER_EVALUATION.md) |

The current core path is external structured features → verified preprocessing/data
package → accepted classifier → portable inference. FastAPI/React predictor integration
and Raspberry Pi compatibility/measurement are separate downstream activities.

TRAIN-only fitting and VALIDATION-only selection rules remain in effect. The original
G3A TEST seal prevents training and selection access; the later final evaluation uses
an explicit frozen-model gate. Do not infer that final TEST may be used for tuning or
rerun it just to refresh receipts after documentation changes.

The original [system context](architecture/system_context.md),
[decision log](decisions/decision-log.md), and [protocol index](protocols/README.md)
retain their foundation-checkpoint wording and import identities. Their statements
that G3B or classifier selection are pending are superseded for current navigation
by the committed records linked here. Earlier protocols and receipts remain evidence
of what was specified or executed at that time.
