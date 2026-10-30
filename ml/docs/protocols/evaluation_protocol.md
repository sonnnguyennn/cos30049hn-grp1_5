# Evaluation protocol

> G3A has adopted primary_split_v1; TEST is SEALED. G3B primary policy is locked in [primary_experiments_v1.md](primary_experiments_v1.md). This general template remains for experiment-specific details and later clustering decisions.

## Experiment identity

- Experiment ID: TBD
- Dataset manifest/version: TBD
- Feature schema/version: TBD
- Code revision and environment: TBD
- Random seeds: resolve Python/NumPy/scikit-learn defaults (42) from `config/seeds.yaml`; record the resolved values for every run

## Split strategy

- Selected primary strategy: deterministic numeric-equivalence-grouped primary_split_v1
- Primary unit of separation: numeric-equivalence group `evaluation_group_id_v1`
- Train/validation/test proportions: fixed 70/15/15 hash boundaries; adopted counts are recorded in evaluation_split_protocol.md
- Primary leakage control: deterministic group-disjoint G3A boundary; TEST stays sealed
- Primary duplicate policy: retain all observations and original row weighting; no resampling

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
