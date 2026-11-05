# Internal engineering documentation

This directory holds architecture notes, decision records, protocols, and blank project-management templates. It is engineering support material, not ready-to-submit assessment content. Results and claims must be backed by recorded evidence and reviewed by the project team.

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
