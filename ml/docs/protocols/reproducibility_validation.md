# G2 reproducibility validation protocol (G2C)

## Purpose and current state

G2C validates that the committed G2A contracts and G2B deterministic parsers form one
reproducible canonical data layer. The bounded checks, full 7,062,606-row primary streaming dry
validation, closure checklist, and independent verifier all pass. G2 is complete; G3 is next.

No G2C operation selects a split, fits a learned transform, selects predictors, resamples,
deduplicates, trains, clusters, or writes a row-scale processed dataset.

## Stable source-observation identity

One physical source observation is identified by the ordered pair:

`(source_logical_id, source_data_row_index)`

`source_data_row_index` is 1-based over data rows and excludes the header. The pair is stable for
an unchanged source file, is provenance metadata, and is never a predictor. It is distinct from
`duplicate_group_id`: source identity locates one physical row, while duplicate group identity
represents exact equality of the ordered 115 source lexemes.

G2B already carried both fields, so no immutable G2A v1 contract was silently changed.

## Canonical traversal

The primary traversal has two levels:

1. Sort the 89 A3-verified logical sources by exact `logical_id` in ascending Unicode/Python
   string order. Filesystem enumeration order is not consulted.
2. Within each logical CSV, consume physical data rows in source order with 1-based indexing.

`n_baiot_canonical_traversal_v1.csv` contains one row per logical source and records its stable
ordinal, source lineage, immutable labels, expected row count, content SHA-256, and parent archive
hash when applicable. It contains 89 unique logical sources whose expected rows sum to 7,062,606.
Two independent generations in one run must be byte-identical.

## Full primary dry validation

Full mode streams the actual G2B iterator over every traversal entry. Each record must pass exact
header order, 115-field width, exact-lexeme duplicate hashing, strict finite numeric parsing,
provenance mapping, feature-array validation, and stable row identity. Only counters are retained;
the canonical record is discarded immediately.

The deterministic result contains source/row totals, binary/family/fine counts, error counters,
and source-metadata safety. Execution timestamp and runtime are kept in a separate metadata
object and are excluded from the deterministic result hash.

The accepted full run completed all 89 logical sources and 7,062,606 rows in
2,027.423 seconds. Every schema, numeric-parse, nonfinite, provenance, width, identity, and
per-source row-count error counter was zero. Binary, family, and all 11 fine-label counts exactly
matched A3. The deterministic result SHA-256 is
`6822a1d4947944be86e05ed18c8097a98fbc59dcefc7b2c71b2e11327f580792`.

## Exact versus numeric equality

The v1 duplicate contract deliberately preserves exact lexical equality. `1`, `1.0`, and `1e0`
all parse to Python `1.0`, but their length-prefixed UTF-8 encodings and duplicate group IDs are
different. Bounded G2C evidence also rereads three cross-file duplicate pairs recorded by A4 and
requires exact 115-token tuple equality, equal G2B IDs, and equality with the A4 digest.

## Canonical record digest

`sha256:canonical-record-v1:<hex>` is a reproducibility digest, not a predictor and not a
duplicate-group identifier. Its SHA-256 input is:

1. domain bytes `IOTGUARD`, NUL, `CANONICAL_RECORD`, NUL, `V1`;
2. length-prefixed UTF-8 values for logical source ID, binary/family/fine labels, device,
   archive/source family, and member filename;
3. the 1-based source data-row index as unsigned 8-byte big-endian;
4. feature count as unsigned 4-byte big-endian, followed by each finite Python float encoded as
   IEEE-754 64-bit big-endian in contract order;
5. length-prefixed UTF-8 `duplicate_group_id`.

Changing physical source identity changes the record digest even when exact feature vectors are
duplicates. The bounded 17-record sample is generated twice and must reproduce identical record
digests and an identical aggregate JSON hash. Raw 115-value rows are not persisted.

## Secondary bounded validation

All four Bot-IoT All-features shard headers are checked without full scanning. Real parser paths
cover decimal ports, the `-1` unresolved sentinel, and the bounded hexadecimal coordinate at
All-features shard 1 data row 632,280 (`sport=0x0303`, `dport=0x5000`). The 10-best and supplied
train/test representations remain noncanonical references.

## Outputs and closure

The traversal CSV and bounded evidence are timestamp-free deterministic content. Full mode adds a
dry-run summary, reproducibility manifest, and closure checklist. The independent verifier
re-reads bounded source coordinates, independently encodes group and record digests, reconciles
all A3 counts, checks source-tree metadata against A5, and searches for prohibited downstream
artifacts.

G2 is marked complete because every mandatory checklist item and every independent verification
check is true. Completion means the canonical data layer is reproducible; final split, scaler,
selector, imbalance treatment,
predictor subset, classifier, clustering design, final Assignment-2 dataset, API payload, and Pi
benchmark remain G3-or-later work.
