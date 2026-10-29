# Generated artifacts

Future model, preprocessor, manifest, and evaluation outputs belong here with provenance, configuration, version, and hashes. Binary/generated outputs are ignored by default; only explicit lightweight metadata should be considered for tracking.

The lightweight A4 audit evidence under `audit/` includes per-file and per-column quality
summaries, compact exact-duplicate aggregates, bounded duplicate examples, Bot-IoT lineage
results, a hash-bearing A4 summary, and independent verification evidence. Large fingerprint
databases and lineage arrays are temporary external work products and are not repository
artifacts.

G2A contract specifications belong under `contracts/`. They are compact, versioned metadata and
must not contain processed full datasets, fitted preprocessors, split files, or model outputs.

G2B writes only compact smoke and independent-verification JSON under `audit/`. These artifacts
contain widths, labels, hashes, parser categories, and safety metadata—not source feature rows or
processed datasets.

G2C adds a one-row-per-logical-source traversal manifest and compact reproducibility evidence.
The full primary dry run retains counters only; it must never write observation-scale canonical
records or a processed feature matrix.

G3A adds only a compact adopted split contract, aggregate class/device/source diagnostics,
numeric-equivalence summary, bounded examples, a streaming membership digest, and independent evidence.
Observation-scale train/validation/test files and fitted model/preprocessor artifacts are
prohibited. Temporary whole-corpus group indexes remain outside Git.
