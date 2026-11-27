# ML documentation

## Current guides

| Need | Guide |
| --- | --- |
| Setup and engineering status | [ML setup](../README.md), [current status](current-status.md) |
| Accepted classifier and portable handoff | [A2 evaluation](handoffs/A2_CLASSIFIER_EVALUATION.md), [inference contract](architecture/inference_contract.md) |
| Data contracts and parsers | [Human-readable contracts](contracts/), [machine-readable contracts](../artifacts/contracts/), [preprocessing](protocols/preprocessing_contract.md), [G2C reproducibility](protocols/reproducibility_validation.md) |
| Primary split and package | [G3A split](protocols/evaluation_split_protocol.md), [G3B handoff](handoffs/G3B_PRIMARY_DATA_HANDOFF.md), [build identity repair](handoffs/G3B_BUILD_IDENTITY_FIX.md) |
| Final TEST gate | [Final evaluation protocol](protocols/primary_final_evaluation_v1.md) |
| Secondary experiments | [Dataset role decision](decisions/ADR-001-dataset-role-selection.md), [Bot-IoT archive](handoffs/BOT_IOT_SECONDARY_RUN_ARCHIVE.md) |
| Artifact storage | [Git tracking policy](../../docs/git-tracking.md), [artifact restore](../../docs/experiment-artifacts.md) |

## Historical records and templates

- [System context](architecture/system_context.md), [decision log](decisions/decision-log.md) and [protocol index](protocols/README.md) record earlier checkpoints. For current milestones, see the status page.
- Handoffs keep their original dates, statuses, hashes and source revisions. G3A_IMPORT_VALIDATION.json records the original import.
- Use the [ADR template](decisions/ADR-000-template.md), [project templates](project-management/README.md), [edge benchmark template](protocols/edge_benchmark_protocol.md) and [reproducibility template](protocols/reproducibility_protocol.md) for new work.
- The [academic integrity guide](academic-integrity/README.md) documents the boundary between internal engineering work and assessment content.
