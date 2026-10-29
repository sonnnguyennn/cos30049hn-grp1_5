# Primary N-BaIoT data contract v1

> G2A specification only. No split, fitted transform, resampling, or model exists.

## Canonical representation

The primary universe contains 89 logical CSVs and uses 115 source fields in the exact A2 order. The schema signature is `sha256:84a9391e57a872b4b73f50e4b7f552cb208ab10e177e5bb93cb7062bebe25607`. Source feature names are not renamed or sorted.

Every record must contain exactly 115 finite numeric values. Negative values are allowed. Observed extrema are descriptive, not hard validation bounds, and deployment dtype remains deferred.

## Labels and predictor boundary

The core target is `binary` with values `benign` and `malicious`. Family and fine labels remain analysis metadata. Labels, device, logical source identity, filenames, and `duplicate_group_id` are not predictors. All 115 source fields are only the canonical candidate set; no learned feature selection has run.

## Exact-vector group metadata

`duplicate_group_id` is SHA-256 over the A4/A5 length-prefixed UTF-8 serialization of the exact 115 source lexemes in source order. Lossy float formatting is prohibited. The identifier is split/audit metadata and does not deduplicate the corpus.

## Downstream boundaries

- No blind global deduplication.
- No naive row-random evaluation without duplicate-boundary control.
- Data-dependent transforms fit on training data only after G3 locks the split.
- Resampling or class weighting, if later selected, operates on training data only.
- Validation and test retain their audited natural distribution and support counts.
- The logical record contract is internal and is not the final FastAPI payload.

## Logical record

The internal record contains `features`, `target_binary`, `label_family`, `label_fine`, `device`, `source_logical_id`, archive/source family, source/member filename, and `duplicate_group_id`. Only `features` is the candidate predictor container.

Record contract version: `1.0.0`.
