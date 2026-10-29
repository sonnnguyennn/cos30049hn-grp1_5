# ADR-001: Dataset Role Selection for IoTGuard

- **ADR ID:** ADR-001
- **Date:** 2026-09-27
- **Status:** Accepted

## Context

IoTGuard requires one primary dataset for the core benign-versus-malicious pipeline and one secondary dataset for a meaningful additional ML experiment. A0-A6 established source provenance, structure, taxonomy, quality, duplicates, imbalance, leakage surfaces, split feasibility, and role-specific suitability without selecting roles.

## Decision drivers

The primary dataset must pass the non-numeric P1-P3 gate: core binary support, a leakage-controlled evaluation path, and meaningful evaluation resolution for both binary classes. P4-P8 must provide a defensible future path, while implementation choices remain deferred. Controllable limitations with verified mitigations are preferred over intrinsic source-distribution limits that prevent reliable primary evaluation.

## Decision

- **Primary = N-BaIoT**
- **Secondary = Bot-IoT**

This is a role-specific decision for IoTGuard, not a claim that N-BaIoT is universally better.

## Evidence used

The decision traces A0-A6 through `artifacts/audit/a7_decision_trace.csv`. Key source hashes are preserved in `artifacts/audit/a7_dataset_role_decision.json`.

- A6 summary SHA-256: `f83ce4bb2ca306673d5dae343ac7ded26a629eb6d6d5f7b8ee327cf617bdc740`
- A6 primary-requirement matrix SHA-256: `f3f1bb99ec8611596ecd4f8146efb4f886de868d0fcb76ea49b128790716f8a4`
- N-BaIoT leakage summary SHA-256: `7d9bc180da6e1378af98b32face3e32592911fcf426fdce777ddea2da4ab6d49`
- Bot-IoT split-feasibility SHA-256: `732afd638f6b29d2879f09d7f7d02de001f48efa02ec7f89bc74d028bc19d634`

## Why N-BaIoT is primary

N-BaIoT passes P1, P2, and P3. It contains 7,062,606 rows (555,932 benign and 6,506,674 malicious), 89 logical CSVs, one stable ordered 115-numeric-field schema, and 11 fine classes. A4 found no missing, NaN, infinity, numeric-parse, or read failures in those fields.

Its severe duplicate burden is material: 7,062,606 rows collapse to 2,482,676 exact vectors, naive row-random splitting leaves about 84.7% of test rows with an exact training vector, and device holdout alone does not remove that overlap. The limitation has a verified control path: N2 assigns exact-vector groups across boundaries, retaining 11/11 fine classes with zero exact-vector overlap, 5,650,017 train rows, 1,412,589 test rows, and minimum fine-class test support 51,596. N2 demonstrates feasibility; it is not adopted as the final split.

Blind global deduplication is not adopted because duplicate weighting materially changes class proportions. G2/G3 must explicitly prevent exact-vector boundary leakage or demonstrate an equivalent control.

## Why Bot-IoT is secondary

Bot-IoT contains 3,668,522 all-feature records but only 477 benign observations versus 3,668,045 malicious observations. Data exfiltration, keylogging, and theft have 6, 73, and 79 rows. Audited candidate tests contain 0-107 benign rows. The supplied split has near-total familiar-entity overlap; the chronological candidate loses benign coverage; entity grouping controls selected boundaries but cannot create independent benign or rare-class observations.

Bot-IoT remains useful because it provides a different flow/context schema, attack taxonomy, imbalance regime, representation structure, and entity/context leakage surface. It is authorized for a bounded future ML experiment rather than EDA-only use.

## Rejected alternative

Bot-IoT as primary and N-BaIoT as secondary was rejected for this project role. Bot-IoT only partially supports P1 and does not support P3 at the required level; resampling cannot improve independent evaluation resolution. This does not describe Bot-IoT as bad or unusable.

## Cross-dataset policy

Direct merging of the two feature matrices is outside the core pipeline. Exact named feature overlap is zero and the input definitions are not interchangeable. Direct cross-dataset model evaluation is **NOT_CURRENTLY_DEFENSIBLE** unless a future ADR justifies and verifies a common representation.

## Consequences

### Positive

- The core pipeline receives a dataset with supported binary evaluation resolution and a verified leakage-control path.
- Bot-IoT adds a meaningfully different secondary ML setting without constraining the deployment pipeline.
- G1 closes with explicit traceability and without selecting downstream implementation details.

### Negative

- N-BaIoT's duplicate burden requires split-boundary checks and an explicit weighting policy.
- The primary input contract is high-dimensional and depends on preserving 115-field order and provenance.
- Bot-IoT secondary claims remain bounded by benign and rare-label scarcity.

### Constraints

- The core supervised objective remains benign versus malicious.
- Family and fine labels remain preserved as metadata and analysis labels.
- Naive row-random evaluation is prohibited without duplicate-boundary control.
- Blind global deduplication is not adopted.
- Every future split must check exact-vector boundary leakage or prove an equivalent control.
- The 115-column order and feature-generation provenance must be versioned.
- N2 is a leading audited candidate and feasibility reference, not the final split.
- Device holdout remains a possible stress-test family, not automatically the main protocol.
- Bot-IoT: attack, category, and subcategory are target metadata and not ordinary predictors.
- Bot-IoT: pkSeqID and the unnamed physical index are lineage/identifier metadata and excluded from ordinary predictors unless a future ADR explicitly overturns this.
- Bot-IoT: Treatment of stime, ltime, seq, addresses, ports, and other context fields remains deferred.
- Bot-IoT: Hexadecimal ports require deterministic lexical-aware parsing if retained.
- Bot-IoT: The semantics of the -1 port token remain unresolved.
- Bot-IoT: A representation must be explicitly locked before any official experiment.
- Bot-IoT: The supplied split is not considered proven leakage-free.

## What this decision does not decide

A7 does not adopt a final split, predictor list, feature selection, scaler, duplicate-weighting policy, imbalance policy, clustering protocol, processed dataset, API payload, Raspberry Pi model, classifier, or final model. It performs no preprocessing, training, or clustering.

## G2/G3 follow-up

### Deferred to G2

- lock the primary 115-field representation, order, and provenance contract
- decide predictor eligibility and feature selection
- select scaling or normalization
- select duplicate weighting without blind global deduplication
- select imbalance and resampling policy
- lock the Bot-IoT representation and field treatment, including ports and unresolved sentinels
- materialize the reproducible processed Assignment-2 package and versioned feature contract

### Deferred to G3

- adopt the final train, validation, and test protocol; N2 is only the leading audited reference
- decide whether device holdout is used as a stress test
- select and evaluate classifiers and the final model
- select the clustering algorithm, sampling, and evaluation protocol
- select and execute at least one bounded Bot-IoT secondary ML experiment
- finalize the inference payload after the feature contract and defer Pi claims until benchmarking

## Jira handoff record

No external Jira mutation was performed.

| Task | Scope | G1 evidence outcome |
|---|---|---|
| IOTG-42 | Audit N-BaIoT | TECHNICALLY_COMPLETE: A1-A5 N-BaIoT compact artifacts |
| IOTG-43 | Audit Bot-IoT | TECHNICALLY_COMPLETE: A1-A5 Bot-IoT compact artifacts |
| IOTG-44 | Compare dataset schemas | TECHNICALLY_COMPLETE: n_baiot_schema.json; bot_iot_schema.json; a6_cross_dataset_compatibility.json |
| IOTG-45 | Inspect labels and attack classes | TECHNICALLY_COMPLETE: label_audit_summary.json; A3 verification |
| IOTG-46 | Inspect missing/invalid values | TECHNICALLY_COMPLETE: A4 quality artifacts and verification |
| IOTG-47 | Inspect duplicate records | TECHNICALLY_COMPLETE: A4 duplicate artifacts and verification |
| IOTG-48 | Assess class imbalance | TECHNICALLY_COMPLETE: A5 effective-imbalance artifacts |
| IOTG-49 | Assess leakage risks | TECHNICALLY_COMPLETE: A5 leakage and split-feasibility artifacts |
| IOTG-50 | Decide primary vs secondary dataset | TECHNICALLY_COMPLETE: ADR-001; a7_dataset_role_decision.json |

## Traceability

A0-A6 evidence paths, checkpoint commits, and SHA-256 values are recorded in `artifacts/audit/a7_decision_trace.csv`. The machine-readable decision and G1 checklist are independently checked by `scripts/verify_a7_evidence.py`.

## Revisit trigger

Revisit only if the audited source representation changes, new independent benign support becomes available, a verified common feature representation is created, or later G2/G3 evidence invalidates a mandatory gate.
