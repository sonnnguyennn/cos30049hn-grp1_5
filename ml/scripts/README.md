# Utility scripts

All scripts are non-destructive. `check_environment.py` reports local runtime details and `check_data_paths.py` checks configured roots without recursive scanning.

`dataset_inventory.py` implements A1. It recursively inventories both read-only roots, always streams SHA-256 for every regular file, inspects supported archive metadata without extraction, and writes two deterministic manifests plus a provenance summary under `artifacts/`. Configure roots with the environment variables documented in `.env.example`, explicit CLI arguments, or ignored `config/data_paths.local.yaml`. See `docs/protocols/dataset_audit_protocol.md` for the exact contract and rerun commands.

`n_baiot_archive_access.py` implements A2.0 with separate list/extract modes and a collision-safe external work hierarchy. `dataset_structure_audit.py` implements streamed full-file CSV validation, exact row accounting, ordered schema signatures, representation grouping, and documentation cross-checks. `verify_a2_evidence.py` independently reconciles source metadata and samples hashes, row counts, schema signatures, and artifact counts.

`dataset_label_audit.py` implements A3. It maps N-BaIoT labels from strict A2 provenance,
streams only the three Bot-IoT label columns, writes exact raw/canonical distributions, and
compares representations at aggregate label level. `verify_a3_evidence.py` independently
checks N-BaIoT mappings and uses pandas chunked aggregation for Bot-IoT. A3 does not prove
record identity or choose an ML representation.

`dataset_quality_audit.py` implements A4 with chunked lexical/numeric profiling, deterministic
64-bit duplicate-candidate hashes followed by exact source-value confirmation, and Bot-IoT
`pkSeqID` lineage maps stored outside the repository. `verify_a4_evidence.py` does not import
the primary implementation: it uses binary row counts, Python's CSV parser, direct original-row
comparisons, independent ID membership maps, Decimal-aware lineage samples, and exact sampled
row digests. A4 observes findings only; it does not clean, deduplicate, select predictors, adopt
the supplied split, or make leakage and dataset-role decisions.

`dataset_leakage_audit.py` implements the diagnostic A5 imbalance, duplicate-boundary,
identifier/entity/time-risk, port-encoding, numeric-lineage, and split-feasibility measurements.
It reuses the independently accepted A4 exact-group database, keeps new row-level state outside
Git, and writes only compact evidence. `verify_a5_evidence.py` is independent of the primary A5
module and reconciles whole-dataset N-BaIoT split diagnostics plus streamed Bot-IoT evidence and
direct source samples. A5 does not train, transform, remove, select, or adopt anything.

`dataset_suitability_audit.py` implements A6 as a lightweight synthesis of compact A0-A5
evidence. It writes categorical suitability, mandatory-capability, secondary-use, and
cross-dataset compatibility artifacts plus the internal analysis document. It does not reread raw
datasets or choose roles. `verify_a6_evidence.py` independently checks source/output hashes,
coverage-first split descriptions, baseline-adjusted Bot-IoT purity, schema overlap, allowed
statuses, and guards against scoring, ranking, or primary/secondary assignment.

`dataset_role_decision.py` implements A7 from compact A0-A6 evidence. It applies the P1-P3
requirements gate without numeric scoring, writes the machine-readable role decision, A0-A6
trace, G1 closure checklist, and ADR-001, and defers all G2/G3 implementation choices.
`verify_a7_evidence.py` does not import the primary A7 script: it independently recomputes the
role gate and key support facts, verifies hashes and traceability, cross-checks the ADR, and
rejects final split, predictor, preprocessing, clustering, or cross-dataset generalization claims.

`generate_g2a_contracts.py` creates versioned canonical contracts from compact A2-A7 evidence. It
reuses the exact A2 schema order and A4/A5 length-prefixed source-token equality semantics, defines
predictor/label/provenance boundaries and Bot-IoT lexical port behavior, and reads no dataset rows.
`verify_g2a_contracts.py` independently recomputes schema signatures, taxonomy, synthetic exact-
vector IDs, port examples, field-role boundaries, and contract/manifest hashes.

`run_g2b_smoke.py` performs a bounded read-only check of three rows from one benign, one Gafgyt,
one Mirai, and two canonical Bot-IoT sources. `verify_g2b_evidence.py` independently reconciles
G2A hashes and schemas, exact-vector encoding, provenance and port examples, smoke widths, source
manifest metadata, and the absence of fitted, split, resampled, or model artifacts.

`run_g2c_validation.py --mode bounded` deterministically generates the 89-source traversal and
bounded canonical evidence. `--mode full` additionally streams all 7,062,606 primary observations,
writes only reconciled counters, and creates the reproducibility manifest plus G2 checklist.
`verify_g2c_evidence.py` independently re-reads bounded coordinates and verifies G2 closure.

`run_g3a_primary_split.py` implements the fixed `primary_split_v1` numeric-group assignment. Its
default bounded mode samples every logical source without writing repository evidence; `--full`
streams all primary observations, retains group indexes outside Git, and writes only compact
counts, diagnostics, membership digest, and an ADOPTED contract when every predeclared gate
passes. `verify_g3a_evidence.py --full` independently rescans the entire corpus and reconciles
numeric/lexical boundaries, labels, counts, drift, golden examples, and membership.
