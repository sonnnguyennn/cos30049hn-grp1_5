# Deterministic preprocessing contract (G2B)

## Scope

G2B converts one valid source row into a canonical internal record using deterministic,
non-learned operations. The checked-in G2A JSON contracts remain the source of truth. G2B does
not choose or materialize evaluation partitions, fit transforms or selectors, resample or
deduplicate observations, assign training weights, train models, run clustering, or produce the
Assignment-2 dataset.

## N-BaIoT parsing flow

1. Resolve an exact logical source ID through the 89-entry A3 label mapping. Arbitrary substring
   inference is prohibited.
2. Require the CSV header to equal the 115 ordered names in
   `n_baiot_feature_contract_v1.json`. Reordered, missing, or additional columns fail.
3. Read each row with Python's streaming CSV reader. The full logical file is never loaded.
4. Preserve the 115 source lexemes and compute `duplicate_group_id` before numeric parsing.
5. Parse every token as a Python runtime `float` and require finiteness. Negative finite values
   are valid; no clipping, coercion, imputation, or scaling occurs.
6. Yield a canonical record containing the ordered feature tuple, three label levels, device and
   logical-file provenance, exact-vector group ID, and data-row index.

Python `float` is an implementation detail of row parsing, not the final training, storage, API,
or deployment dtype contract. `feature_array(record)` returns the same unscaled 115-value tuple
after explicit width and finiteness validation. Labels and provenance never enter that tuple.

## Exact-vector group identity

For every source lexeme in contract order, encode its exact text as UTF-8, prepend its unsigned
four-byte big-endian byte length, concatenate all 115 components, and hash the result with
SHA-256. The identifier is `sha256:<64 lowercase hex characters>`. There are no separators and
no whitespace, decimal, or exponent normalization. Consequently `1`, `1.0`, and `1e0` have equal
runtime numeric values but different v1 group IDs.

Every observation is preserved. `duplicate_group_id` is split-audit metadata only. G2B does not
collapse rows, select one row per group, apply inverse-frequency weights, or make a duplicate
weighting decision.

## Provenance and labels

Only exact logical IDs present in `artifacts/audit/n_baiot_label_mapping.csv` are accepted.
Verified benign sources map to `benign/benign/benign`; verified `gafgyt_attacks` and
`mirai_attacks` members map to their immutable binary, family, and fine labels. Unknown devices,
members, archive families, family/member combinations, and ambiguous strings raise errors; an
`UNKNOWN` label is never emitted.

## Bot-IoT secondary parsing

Only the four All-features 5% shards named by
`bot_iot_secondary_source_contract_v1.json` are canonical inputs. Each header must match all 46
columns in order. The 10-best full representation and its supplied training/testing files are
rejected as canonical sources and are not treated as an evaluation split.

Raw fields are preserved in groups defined by `bot_iot_field_role_contract_v1.json`:

- `attack`, `category`, and `subcategory` are target metadata;
- `pkSeqID` is identifier/lineage metadata;
- entity/context-sensitive, temporal/order-sensitive, and behavioral/statistical fields retain
  their role and raw value without a final predictor decision or categorical encoding.

`sport` and `dport` accept ASCII decimal integers, `0x`/`0X`-prefixed hexadecimal integers, or
the exact `-1` unresolved sentinel. Valid numeric ports must be in `0..65535`. The result preserves
the raw lexeme, parsing kind, and numeric value; the sentinel has kind `unresolved_sentinel` and
value `null`. It is never converted to zero, silently missing, imputed, or treated as an ordinary
port.

## Learned-transform boundary

`TrainFittedTransform` records the later architectural interface only:

- `fit(training_features)` may run on the training partition after G3 establishes evaluation
  boundaries;
- `transform(features)` may then apply the frozen fitted state to training, validation, or test;
- fitting on the full corpus or before the G3 split is prohibited.

G2B provides no scaler, imputer, PCA, selector, resampler, or concrete fitted transform.

## Error and evidence behavior

N-BaIoT failures identify the logical source, data-row index when available, and relevant field.
Wrong headers or widths, nonnumeric/non-finite values, invalid provenance, noncanonical Bot-IoT
representations, invalid ports, and wrong Bot-IoT headers fail immediately without recovery.

`run_g2b_smoke.py` reads three rows from one benign, one Gafgyt, one Mirai source and two canonical
Bot-IoT shards. Its compact JSON records only labels, widths, IDs, port categories, and metadata
safety—not raw feature rows. `verify_g2b_evidence.py` independently recomputes contract hashes,
schema signatures, length-prefixed SHA-256, port behavior, manifest metadata, smoke widths, and
absence of forbidden outputs.

## Deferred decisions

G2C/G3 or later work must decide the final split, predictor selection, learned preprocessing,
imbalance treatment, duplicate weighting, storage/deployment dtype, model, cross-dataset
experiment design, API payload, and Raspberry Pi benchmark. None is implied by these primitives.
