# Internal engineering documentation

This directory holds engineering support material, not ready-to-submit assessment
content. Results and claims require recorded evidence and team review. Start with
the current guides below; older checkpoint documents retain their original claims
and do not describe every later result.

## Current entry points

| Need | Guide |
| --- | --- |
| Current state and scope | [Current status](current-status.md) |
| Package setup and experiment workflow | [ML README](../README.md) |
| Accepted classifier, final results, model identity and handoff | [A2 classifier evaluation](handoffs/A2_CLASSIFIER_EVALUATION.md) |
| Predictor input/output and compatibility | [Inference contract](architecture/inference_contract.md) |
| Final evaluation gate and provenance rules | [Final evaluation protocol](protocols/primary_final_evaluation_v1.md) |
| Primary data package and portable build repair | [G3B handoff](handoffs/G3B_PRIMARY_DATA_HANDOFF.md), [build identity repair](handoffs/G3B_BUILD_IDENTITY_FIX.md) |
| Separate secondary experiment evidence | [Bot-IoT run archive](handoffs/BOT_IOT_SECONDARY_RUN_ARCHIVE.md) |
| Shared repository tracking rules | [Git tracking policy](../../docs/git-tracking.md) |

Current classifier acceptance, validation selection, committed freeze, final TEST and
portable inference are in [A2_CLASSIFIER_EVALUATION.md](handoffs/A2_CLASSIFIER_EVALUATION.md).
The additive [final evaluation protocol](protocols/primary_final_evaluation_v1.md)
preserves the original training/selection TEST seal and historical receipts.

Versioned human-readable data-contract explanations live under `contracts/`; their machine-readable
counterparts live under `artifacts/contracts/`.

The deterministic, non-learned G2B parsing rules and deferred learned-transform boundary are in
`protocols/preprocessing_contract.md`.

G2C stable row identity, canonical traversal, record-digest serialization, dry validation, and
closure semantics are specified in `protocols/reproducibility_validation.md`.

The fixed G3A numeric-equivalence grouping, deterministic primary split, acceptance gates,
membership digest, TEST seal, and train-only fit policy are specified in
`protocols/evaluation_split_protocol.md`.

## Historical checkpoints and templates

- [System context](architecture/system_context.md) and [decision log](decisions/decision-log.md)
  preserve the foundation checkpoint. Their pending G3B/model statements are historical;
  use [current status](current-status.md) and the current inference contract above.
- [Protocol index](protocols/README.md) describes the G2/G3A checkpoint. Its TEST seal
  applies to training/selection; the later final-only gate is documented separately.
- `handoffs/` records specific deliveries and checks. Dates, statuses, source revisions,
  and exact hashes belong to those deliveries; a later handoff does not rewrite them.
  `G3A_IMPORT_VALIDATION.json` inventories the original import rather than every future
  repository tree.
- [ADR template](decisions/ADR-000-template.md) supports new decisions;
  [ADR-001](decisions/ADR-001-dataset-role-selection.md) records the dataset roles.
- [Project-management templates](project-management/README.md), the
  [edge benchmark template](protocols/edge_benchmark_protocol.md), and the
  [reproducibility template](protocols/reproducibility_protocol.md) are optional blank
  scaffolds, not evidence of completed work. They remain available at their original
  paths, including entries referenced by the import inventory.
- [Academic integrity boundary](academic-integrity/README.md) records the project
  policy context and remains separate from submission content.

Keep historical evidence intact. Add new status/decision records and update this
index when work advances; do not edit frozen receipts to match current progress.
