# Clustering experiment: measured validation analysis

Primary run: standard_k8_seed42. Protocol: unsupervised_v1_proposal.
All 115 ordered numeric predictors were used. Labels, source identity and device strings
were excluded from fitting. The complete TRAIN population (4,944,968 rows)
was processed for 2 epochs with batch size 4096.
Standardization reused the dataset's TRAIN-only scaler. TEST was not opened.

## Experiment design and selection
The pilot compared K=[2, 4, 8, 12] for both standardization and raw features, using the
same 100,000-row uniform TRAIN sample and seed(s) [42].
It shortlisted one K per scaling using internal VALIDATION silhouette only. Each finalist was then
trained on all TRAIN rows. Standardized geometry was the primary analysis by prior policy.
The selection was saved before any ground-truth validation labels were inspected.
This is a separate unsupervised protocol proposal, not a classifier macro-F1 result schema.

## Internal geometry
The primary model's silhouette mean was 0.432241, with sample standard
deviation 0.013217, over 3 fixed uniform
subsets of 1,500 validation observations.
DBI was 1.207384; CH was 1397.532001, on the same
10,000-row validation evaluation population used by every run.
Requested K=8; full VALIDATION represented
8 clusters.
The raw finalist used K=4 with silhouette 0.988735.
These geometries differ; this does not establish scale-free superiority of either scaling.
Use pilot/internal_comparison.csv and silhouette_by_k.png for measured K sensitivity.
Pilot and full scores have different fit populations and must not be presented as identical training.

## Post-selection relation to security labels
On all 1,056,372 VALIDATION records, ARI=0.007821
and NMI=0.091792. These compare cluster partitions with binary labels;
they are not classification accuracy and do not assign benign/malicious names to cluster IDs.
Overall malicious prevalence was 92.10%.
Among nonempty clusters, malicious fractions ranged from
0.00% to 98.80%.
There were 6 nonempty clusters with <1% of validation rows.
Inspect exact counts, enrichment, and centroid profiles before describing separation.

## Limits and interpretation still required
K-Means favors compact Euclidean groups, always assigns a cluster, and does not supply a calibrated
malicious probability. Scaling, outliers, related predictors and device/source effects can dominate.
The full stream used local buffer shuffling rather than a global permutation; order effects remain.
Two epochs are a budget, not evidence of full convergence. Default seed 42 provides no seed stability claim.
Uniform evaluation samples can miss rare groups; sample variation is not a confidence interval.
Binary-label agreement does not establish separation of attack types, unseen devices or future traffic.
The dataset preserves duplicates and original splits; this evaluation does not remove leakage/source risks.
The supplied handoff's verification does not by itself establish verification on this receiving machine.

Before submission, map the largest-spread centroid feature positions to canonical feature names,
describe the observed direction and support of at least two clusters, and state whether mixed
clusters suggest device/traffic structure rather than a useful benign/malicious partition.
Do not revise model selection after this post-selection inspection without a new protocol version.
