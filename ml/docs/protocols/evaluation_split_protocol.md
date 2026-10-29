# Primary evaluation split protocol (G3A)

Status: ADOPTED after full-corpus execution and independent verification.

## Scope and fixed rule

This protocol assigns all 7,062,606 canonical N-BaIoT observations to one final evaluation
boundary. It does not fit preprocessing, resample, train, cluster, inspect model performance, or
materialize train/validation/test rows. The fixed version is `primary_split_v1`; its namespace is
`iotguard-primary-split-v1`. The namespace is not varied in response to observed results.

For each record, parse the 115 finite values in feature-contract order. Canonicalize every value
equal to zero, including negative zero, to positive `+0.0`. Encode each value as IEEE-754
binary64, big-endian, concatenate the 115 encodings, and SHA-256 hash the 920 bytes. The split-only
identifier is `sha256:<64 lowercase hex>` and is named `evaluation_group_id_v1`. It is distinct
from the unchanged lexical `duplicate_group_id` and is never a predictor.

Hash the UTF-8 bytes of `iotguard-primary-split-v1`, one ASCII Unit Separator byte (`0x1f`), and
the ASCII text of the evaluation-group ID. Interpret the first eight SHA-256 bytes as an unsigned
big-endian integer `x`; conceptually `u = x / 2^64`:

- `u < 0.70`: TRAIN
- `0.70 <= u < 0.85`: VALIDATION
- `u >= 0.85`: TEST

The implementation compares integers against the exact ceilings of `0.70 * 2^64` and
`0.85 * 2^64`, avoiding floating-point boundary ambiguity. No label, device, file, source-row
identity, or provenance value enters the split hash.

## Predeclared gates

Adoption requires exact reconciliation to 89 logical sources and 7,062,606 rows; split fractions
within 69.5–70.5%, 14.5–15.5%, and 14.5–15.5%; complete 2/2 binary, 3/3 family, and 11/11 fine
coverage in every partition; at least 25,000 rows for every fine class in validation and test;
at least 50,000 benign rows in validation and test; and maximum fine-class prevalence drift of
0.25 percentage points. Numeric evaluation-group conflicts across any label level, evaluation-
group boundary overlap, or lexical duplicate-group boundary overlap must all be zero. A failed
gate stops adoption; it does not trigger a new salt or namespace.

## Compact evidence and reproducibility

The full driver keeps only counters, bounded examples, and an external SQLite group index under
`E:\Document\iotguard_dataset_work\g3a_split_v1`. It never writes observation-scale split files.
A streaming SHA-256 digest locks membership in canonical traversal order. Each membership record
encodes, in order: four-byte length plus UTF-8 source logical ID; unsigned eight-byte big-endian
1-based source row; four-byte length plus ASCII evaluation-group ID; and four-byte length plus
UTF-8 split name.

The independent verifier reimplements numeric serialization, split hashing, membership framing,
class reconciliation, and whole-corpus overlap checks without importing the G3A driver or split
module. Both external SQLite databases are retained until verification succeeds.

## Sealed test and fit policy

Only a passing full scan may create an `ADOPTED` contract. At adoption, TEST is `SEALED` and may
not influence feature selection, scaler fitting, resampling design, hyperparameters, model or
threshold selection. Future test access requires a frozen G3B candidate. Any learned or
data-dependent transform—including scaling, PCA, learned imputation, feature selection,
empirically derived class weights, or neighbor-based resampling—must fit on TRAIN only;
VALIDATION and TEST receive transform-only behavior. G3A performs none of these operations.

## Adopted result

The primary scan and independent whole-corpus rescan both reconciled 89 logical sources and
7,062,606 observations. TRAIN contains 4,944,968 rows (70.016195%); VALIDATION contains
1,056,372 rows (14.957255%); TEST contains 1,061,266 rows (15.026550%). All class and support
gates passed. Minimum fine-class support is 37,929 in VALIDATION and 38,501 in TEST; maximum
fine-class prevalence drift is 0.216460 percentage points.

The audit found 2,482,676 lexical duplicate groups and 2,482,676 numeric evaluation groups, with
no numeric-equivalence merges and no cross-label conflicts. Evaluation-group and lexical-group
cross-partition overlaps are both zero. All nine devices and all 89 logical sources have rows in
every partition; the absent Mirai sources for Ennio Doorbell and Samsung SNH 1011 N Webcam remain
expected source-design facts, not split failures.

The canonical membership SHA-256 is
`edfeb1d96cd2031e0b459fed16e59ef5b1203a56bd2af2306b15968331a0958c`. The adopted contract is
`artifacts/contracts/n_baiot_primary_split_contract_v1.json`; independent evidence is
`artifacts/audit/g3a_evidence_verification.json`. G3 remains in progress and G3B has not started.
