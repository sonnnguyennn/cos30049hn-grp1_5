# Evaluation protocol

> Experiment template. G3A has adopted primary_split_v1; TEST is SEALED. Model and learned preprocessing decisions remain pending. See evaluation_split_protocol.md.

## Experiment identity

- Experiment ID: TBD
- Dataset manifest/version: TBD
- Feature schema/version: TBD
- Code revision and environment: TBD
- Random seeds: TBD and recorded for every stochastic component

## Split strategy

- Selected primary strategy: deterministic numeric-equivalence-grouped primary_split_v1
- Unit of separation (row/device/session/time/scenario): TBD
- Train/validation/test proportions: fixed 70/15/15 hash boundaries; adopted counts are recorded in evaluation_split_protocol.md
- Justification and leakage controls: TBD
- Duplicate and group handling: TBD

## Classification reporting

- Precision, recall, and F1, with averaging method stated
- False-positive rate with the negative class defined
- Confusion matrix with label order
- Accuracy as supplementary only
- Class/support counts and threshold policy
- Per-class metrics where legitimate

## Clustering reporting

- Silhouette score, including distance and sampling details
- ARI/NMI only when ground-truth comparison is legitimate and clearly described
- Cluster sizes and stability across seeds

## Evidence retention

Preserve machine-readable predictions, labels, split indices or group assignments, metrics, confusion matrices, configuration, stdout/stderr, timing, environment details, and artifact hashes. Summaries must be traceable to raw outputs.
