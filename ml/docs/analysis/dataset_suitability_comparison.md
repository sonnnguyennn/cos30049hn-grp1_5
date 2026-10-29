# A6 dataset suitability comparison

> Internal evidence synthesis only. A6 does not select primary/secondary roles, a final split, predictors, or a model.

## Scope and method

This comparison uses only compact, independently checked A0-A5 artifacts. No raw dataset was reread and no model, clustering job, processed split, or deployment benchmark was run. Statuses are categorical and there is no numeric score or winner.

## Suitability matrix

| Dimension | N-BaIoT | Bot-IoT |
|---|---|---|
| 1. Provenance and integrity | **FAVORABLE** — 27 raw files hashed; manifest and later source-metadata checks passed. Limitation: Sixteen attack archives required the documented extraction workspace. | **FAVORABLE** — 10 local files hashed; manifest and later source-metadata checks passed. Limitation: Evidence applies to the local 5% representations, not raw PCAP capture. |
| 2. Local structural completeness | **FAVORABLE** — 89 logical CSVs and 7,062,606 rows were parsed without structural failures. Limitation: Completeness is relative to the audited local source tree. | **FAVORABLE** — All-features and 10-best universes each contain 3,668,522 rows; split sums match. Limitation: The local corpus contains derived 5% representations rather than a capture pipeline. |
| 3. Schema consistency | **FAVORABLE** — One stable ordered 115-column numeric schema is observed across all 89 CSVs. Limitation: A downstream contract must preserve the exact order. | **MIXED** — Each representation is internally stable. Limitation: Three schemas, two delimiters, an unnamed index, case differences, and column-order differences exist. |
| 4. Label/taxonomy clarity | **FAVORABLE** — Audited mappings provide 2 binary, 3 family, and 11 fine classes. Limitation: Two devices lack observed Mirai coverage. | **MIXED** — Audited mappings provide 2 binary, 5 category, and 8 subcategory labels with no semantic conflict rows. Limitation: HTTP/TCP/UDP occur under multiple categories and rare classes have very small support. |
| 5. Core benign-vs-malicious suitability | **FAVORABLE** — Raw support is 555,932 benign and 6,506,674 malicious; unique-vector support remains 513,497 and 1,969,179. Limitation: The task remains imbalanced and duplicate weighting materially changes prevalence. | **ADVERSE** — Both labels exist, but only 477 of 3,668,522 rows are benign. Limitation: Audited test candidates contain only 0-107 benign rows, limiting benign-error resolution. |
| 6. Fine/multiclass support | **FAVORABLE** — N2 retains 11/11 fine classes; minimum test support is 51,596. Limitation: Device holdouts for Ennio and Samsung contain only 6/11 fine classes. | **ADVERSE** — Five categories and eight subcategories exist in the full corpus. Limitation: Data exfiltration has 6 rows, keylogging 73, theft 79; some candidate tests omit classes. |
| 7. Missing/invalid-data burden | **FAVORABLE** — A4 reports no empty/null/NaN/Inf/numeric-parse/read failures across the 115 numeric fields. Limitation: Scaling and distribution treatment remain future preprocessing decisions. | **MIXED** — A4 reports no empty/null/NaN/Inf/read failures. Limitation: Ports include 9,052 hexadecimal rows and 213 '-1' rows; the latter semantics remain unknown. |
| 8. Duplicate/effective-sample burden | **ADVERSE** — 7,062,606 rows collapse to 2,482,676 exact vectors; binary proportions shift from 7.8715% to 20.6832% benign. Limitation: Blind global deduplication would change the training distribution. | **FAVORABLE** — Identity-free all-feature views have zero exact duplicates; the narrow 10-best view without seq has 185 excess rows. Limitation: This does not remove entity/context or representation risks. |
| 9. Leakage-controlled split feasibility | **FAVORABLE** — N2 retains both binary labels and 11/11 fine classes with zero exact-vector boundary overlap. Limitation: N2 does not test unseen devices or contexts and is not adopted. | **MIXED** — B4 saddr grouping removes saddr overlap and retains both binary labels plus 8/8 subcategories. Limitation: Its test has 107 benign rows and only 5 data-exfiltration rows; no candidate is adopted. |
| 10. Generalization/stress-test feasibility | **MIXED** — N3 audits held-out-device identity; N4 additionally enforces exact-vector novelty. Limitation: N3 retains 83.85-97.35% exact-vector overlap; N4 excludes 36.36-54.78% of training rows. | **MIXED** — Entity-grouped candidates test selected unseen entity boundaries. Limitation: B3 loses benign coverage; B4 pair loses data exfiltration; context choices define the claim. |
| 11. Preprocessing complexity | **FAVORABLE** — All 115 inputs are finite numeric fields in one ordered schema. Limitation: Scaling, weighting, and duplicate handling are still unresolved. | **ADVERSE** — A deterministic pipeline is possible from audited representations. Limitation: Numeric, categorical, entity, lexical-port, ID, order, and representation choices must be separated and locked. |
| 12. Representation/provenance ambiguity | **FAVORABLE** — One observed feature representation and one stable schema are audited. Limitation: Feature-generation provenance is not a live-capture contract. | **ADVERSE** — Record-ID universe relationships across all-features, 10-best full, and supplied split are established. Limitation: Six numeric fields differ at serialization scale; the representation must be explicitly selected and documented. |
| 13. Classification readiness | **FAVORABLE** — Targets, stable numeric schema, meaningful support, and a zero-exact-overlap candidate are evidenced. Limitation: No final split, predictor set, balancing policy, or model is selected. | **MIXED** — Targets and multiple candidate protocols are evidenced. Limitation: Extreme benign scarcity, rare classes, context overlap, and representation locking constrain evaluation. |
| 14. Clustering readiness | **MIXED** — A deterministic all-numeric matrix can be formed directly. Limitation: Scale, duplicate weighting, sample strategy, and cluster-evaluation protocol are unresolved. | **MIXED** — Behavioral numeric fields can form a deterministic matrix after explicit processing. Limitation: Categorical encoding, lexical ports, ID/order/context exclusions, scaling, and representation must be fixed first. |
| 15. Structured inference-contract complexity | **MIXED** — The contract is a stable ordered vector of 115 finite numeric values. Limitation: The high-dimensional order and feature extraction assumptions must be versioned. | **ADVERSE** — Observed schemas and field roles provide a basis for a contract. Limitation: Heterogeneous types, port parsing, risky fields, and representation choice make the contract more conditional. |
| 16. Raspberry-Pi structural deployability | **MIXED** — Inference would consume an already-extracted fixed numeric vector. Limitation: No model-size, latency, memory, or feature-extraction benchmark exists. | **MIXED** — Inference can consume structured pre-extracted fields after a representation is locked. Limitation: Encoding and validation add complexity; no Pi benchmark exists. |
| 17. FastAPI/web input-contract practicality | **MIXED** — A versioned upload or pre-extracted-vector payload can preserve the 115-field order. Limitation: Manual entry of 115 fields would be impractical. | **MIXED** — A structured payload can represent the selected fields. Limitation: Lexical ports, categorical values, entity fields, and representation version require stricter validation. |
| 18. Assignment-2 packaging/reproducibility | **MIXED** — A0-A5 provide manifests, schema, labels, quality, duplicates, and deterministic split evidence. Limitation: The processed grader-facing package has not yet been materialized. | **MIXED** — A0-A5 provide the same audit chain and deterministic candidate definitions. Limitation: A representation, safe field contract, imbalance policy, and processed package remain unresolved. |
| 19. Value as a secondary/additional dataset | **FAVORABLE** — Supports bounded group-aware classification, clustering sensitivity, device stress tests, and leakage experiments. Limitation: A secondary use must still be an executed ML experiment, not EDA-only description. | **FAVORABLE** — Supports bounded entity-grouped classification, representation sensitivity, clustering, and imbalance studies. Limitation: Claims must be limited by benign and rare-class support. |
| 20. Cross-dataset compatibility | **ADVERSE** — The audited N-BaIoT and Bot-IoT schemas have zero exact named feature overlap. Limitation: Conceptually similar statistics have different scopes and definitions. | **ADVERSE** — The binary target concept overlaps, but the observed input schema does not. Limitation: Direct cross-dataset model evaluation lacks a verified common feature space. |

## Mandatory primary-capability evidence

These statuses evaluate present evidence only; they do not assign a role.

| Requirement | N-BaIoT | Bot-IoT |
|---|---|---|
| P1 — Core binary support | **SUPPORTED** — 555,932 benign and 6,506,674 malicious rows; unique-vector support is 513,497 and 1,969,179. | **PARTIALLY_SUPPORTED** — Both classes exist: 477 benign and 3,668,045 malicious. |
| P2 — Leakage-controlled evaluation candidate | **SUPPORTED** — N2 has zero exact-vector boundary overlap, both binary classes, and 11/11 fine classes. | **SUPPORTED** — B4 grouped by saddr has zero saddr overlap, both binary classes, 5/5 categories, and 8/8 subcategories. |
| P3 — Reasonable evaluation resolution | **SUPPORTED** — N2 test has 111,186 benign rows and 1,301,403 malicious rows; minimum fine support is 51,596. | **NOT_SUPPORTED** — Audited candidate tests contain 0-107 benign rows; one benign error changes the rate by about 0.93-1.79 percentage points when benign is present. |
| P4 — Deterministic inference contract | **SUPPORTED** — One ordered 115-field finite numeric schema can be versioned deterministically. | **PARTIALLY_SUPPORTED** — Audited schemas and field roles can define a deterministic contract. |
| P5 — Classification without direct target/record identifiers | **SUPPORTED** — The 115 feature columns are separate from labels and N2 operates on exact feature groups. | **PARTIALLY_SUPPORTED** — Identity-free exact views exist after excluding pkSeqID and the unnamed index. |
| P6 — Practical clustering path | **PARTIALLY_SUPPORTED** — A finite all-numeric matrix can be formed deterministically. | **PARTIALLY_SUPPORTED** — Behavioral numeric fields can form a matrix after deterministic encoding/exclusion. |
| P7 — Reproducible processed Assignment-2 package | **PARTIALLY_SUPPORTED** — A0-A5 provide source hashes, schema, labels, quality, and deterministic split evidence. | **PARTIALLY_SUPPORTED** — A0-A5 provide the same reproducibility chain for local representations. |
| P8 — Structural Pi/FastAPI plausibility | **PARTIALLY_SUPPORTED** — An already-extracted fixed 115-number vector is structurally serializable. | **PARTIALLY_SUPPORTED** — A locked subset of structured pre-extracted fields is serializable. |

## Evaluation-protocol claims

- N2 supports an unseen-exact-vector claim: 1,412,589 test rows, zero exact-vector overlap, 11/11 fine classes, minimum fine support 51,596. It does not test unseen devices or contexts.
- N3 supports a held-out-device-identity claim, but 83.85-97.35% of held-out rows still have an exact vector in training.
- N4 supports held-out-device plus exact-vector novelty, but excludes 36.36-54.78% of candidate training rows and two device tests contain only 6/11 fine classes.
- Bot B1 has all binary/category labels but misses data exfiltration in test and retains near-total entity overlap.
- Bot B2 has full audited label coverage but only one data-exfiltration test row and near-total entity overlap.
- Bot B3 has 1/2 binary, 2/5 category, and 4/8 subcategory classes in test; it cannot support complete-task evaluation.
- Bot B4-saddr has 2/2, 5/5, and 8/8 coverage with zero saddr overlap, but only 107 benign and 5 data-exfiltration rows in test. B4-pair misses data exfiltration.

## Effective samples and baseline-aware interpretation

N-BaIoT has 7,062,606 rows but 2,482,676 unique exact vectors. Benign prevalence changes from 7.8715% raw to 20.6832% by unique vector, so blind deduplication would alter the learning distribution; group-aware splitting can prevent boundary leakage without deleting observations.
Bot-IoT has 477 benign rows total. Audited candidate tests contain 107 (B1), 95 (B2), 0 (B3), 107 (B4-saddr), or 56 (B4-pair), so a single benign error changes a candidate error rate by roughly 0.93%, 1.05%, undefined, 0.93%, or 1.79%, respectively.
Bot binary majority baseline is 99.986997%; saddr+daddr binary purity is 100.000000% (only 0.013003 percentage points higher). Category majority baseline is 52.5177%; pair purity is 87.2950% (34.7773 points higher). Category concentration and entity overlap are therefore more informative than the near-baseline binary purity.

## Classification, clustering, and integration

N-BaIoT has stronger present evidence for stable numeric preprocessing, target support, and an exact-group-controlled evaluation candidate, while duplicate weighting and device claims remain material limitations. Bot-IoT has clear labels and candidate protocols, but extreme benign/rare-class scarcity, entity/context overlap, and representation choices constrain classification claims.

Both datasets can support a deterministic clustering matrix in principle. N-BaIoT still needs scaling, duplicate weighting, sampling, and cluster evaluation defined. Bot-IoT additionally needs categorical/port handling plus explicit exclusion or treatment of target, ID, order, and entity/context fields. No clustering algorithm is selected here.

For Pi/FastAPI/web integration, N-BaIoT is structurally a stable 115-number vector; an upload or pre-extracted-vector API is more practical than manual entry. Bot-IoT requires a locked representation and stricter heterogeneous-field validation. These are structural observations only; no Pi latency, memory, or throughput claim is made.

## Secondary-use value and cross-dataset limits

Each dataset has bounded ML uses if treated as secondary: N-BaIoT supports group-aware classification, device stress tests, and duplicate-weighting clustering sensitivity; Bot-IoT supports entity-grouped classification, representation sensitivity, behavioral clustering, and imbalance/context sensitivity. These must be executed ML experiments rather than EDA-only descriptions.

The schemas have zero exact named feature overlap. Similar statistical words do not establish compatible semantics because N-BaIoT fields are entity/window conditioned and Bot-IoT fields use different flow/context definitions. A shared binary label concept exists, but direct cross-dataset model evaluation is **NOT_CURRENTLY_DEFENSIBLE** without a separately verified common feature space.

## Assignment and project fit

A0-A6 provide traceable evidence for later construction of a processed Assignment-2 package, classification and clustering protocols, meaningful additional-dataset experiments, and reproducible evaluation. A7 must still decide roles and later phases must materialize the processed package. Deployment remains based on already-extracted structured features; raw PCAP/live capture is outside the core scope, and the web application must remain runnable without Raspberry Pi hardware.

## A7 unresolved decisions

- Assign primary and secondary dataset roles using the A6 matrices.
- Select and justify one final evaluation protocol without overstating its generalization claim.
- Lock the representation, predictor eligibility, preprocessing, imbalance treatment, and clustering protocol.
- Define the processed Assignment-2 package and versioned API/inference contract.
- Defer Pi performance claims until an actual benchmark exists.
