# Figure captions and commentary

## fig41a_binary_class_balance

**Caption.** Benign and malicious record counts in each full corpus: N-BaIoT, and the Bot-IoT 5% subset (all_features_5pct_shards). Audit counts on a log-scale axis; labels give the exact count and its share of that corpus.

**Commentary.** Both corpora are dominated by malicious traffic, but at very different levels: benign records are 7.87% of N-BaIoT and only 0.013% (477 records) of the Bot-IoT 5% subset. A classifier that labels everything malicious would therefore reach 92.13% and 99.987% accuracy respectively, so accuracy alone cannot show whether benign traffic is recognised. These are corpus totals from the audit; partition counts are in Table t41_class_counts_partitions.

*Dataset:* N-BaIoT; Bot-IoT. *Scope:* full corpus (historical audit), not a partition. *n:* N-BaIoT 7,062,606; Bot-IoT 3,668,522 (all_features_5pct_shards). *Weighting:* 1 per record. *Sampling/transform:* none; log-scale x axis. *Run ID:* N/A.

*Files:* analysis/duy_a2/outputs/figures/fig41a_binary_class_balance.png, analysis/duy_a2/outputs/figures/fig41a_binary_class_balance.pdf

## fig41b_attack_groups

**Caption.** Record counts by attack group: N-BaIoT fine classes (family / attack; family totals in Table t41_class_counts_corpus) and Bot-IoT category and subcategory (each panel is a single label level; levels are not added together).

**Commentary.** At family level N-BaIoT malicious traffic is Gafgyt (40.2%) and Mirai (51.9%), spread over 10 attack classes of 3.6% to 17.4% of the corpus each, with benign at 7.9%. Bot-IoT is concentrated in DDoS and DoS (97.5% of records), while Theft has only 79 records and Data_Exfiltration only 6. The binary task merges all attack groups, so these imbalances within the malicious class are not visible in binary metrics.

*Dataset:* N-BaIoT; Bot-IoT. *Scope:* full corpus (historical audit). *n:* N-BaIoT 7,062,606; Bot-IoT 3,668,522. *Weighting:* 1 per record. *Sampling/transform:* none; one label level per panel; log-scale x axis. *Run ID:* N/A.

*Files:* analysis/duy_a2/outputs/figures/fig41b_attack_groups.png, analysis/duy_a2/outputs/figures/fig41b_attack_groups.pdf

## fig41c_botiot_train_features

**Caption.** Bot-IoT TRAIN distributions by class of three of the 13 raw predictors, one per aspect of a flow: pkts (packet count), bytes (data volume) and dur (duration). Raw values from package.load("TRAIN") on a log1p scale, the same 40 bins for both classes, each curve sums to 1 within its class; benign n=286, malicious n=2,200,828 (all TRAIN records).

**Commentary.** Benign TRAIN records are mostly short flows (median 2 packets, 201 bytes, 0.17 s), while malicious records centre on 7 packets, 600 bytes and 15.4 s, so all three features shift between the classes. The ranges still overlap, and a small benign tail of very long flows (99th percentile about 53,090 packets) lies beyond the malicious maximum of 6,900. The benign curves rest on only 286 records and are coarse; these are 3 of the 13 predictors (10 numeric plus flgs/proto/state).

*Dataset:* Bot-IoT. *Scope:* TRAIN partition (package v2), raw numeric values via package.load('TRAIN'). *n:* all TRAIN records: benign 286, malicious 2,200,828. *Weighting:* 1 per record; each class normalised by its own size. *Sampling/transform:* no sampling; log1p transform; 40 shared bins per feature. *Run ID:* N/A.

*Files:* analysis/duy_a2/outputs/figures/fig41c_botiot_train_features.png, analysis/duy_a2/outputs/figures/fig41c_botiot_train_features.pdf

## fig41d_nbaiot_train_features

**Caption.** N-BaIoT TRAIN distributions by class of three of the 115 features, chosen as one each for volume, packet size and timing at the same decay window (L0.1); names and positions from the package's feature contract. Raw values on a log1p scale, the same 40 bins for both classes, each curve sums to 1 within its class; benign n=388,965, malicious n=4,556,003 (all TRAIN records).

**Commentary.** Medians (benign vs malicious): MI_dir_L0.1_weight 6.94 vs 4.01e+03; H_L0.1_mean 86.6 vs 74.1; HH_jit_L0.1_mean 14.1 vs 1.51e+09. The two class histograms overlap by 3%, 34%, 17% respectively (sum over the shared bins of the smaller class share; 100% = same shape), so MI_dir_L0.1_weight separates the classes most and H_L0.1_mean least. HH_jit_L0.1_mean exceeds 10^8 s (over 3 years) for 55.7% of malicious and 0.6% of benign records, and the median of those values is a Unix timestamp in 2017, so they are not real inter-packet gaps. All 4,944,968 TRAIN records are used (no sampling; benign 388,965), and the figure describes TRAIN only, not unseen devices.

*Dataset:* N-BaIoT. *Scope:* TRAIN partition (G3B package, raw float64 values). *n:* all TRAIN records: benign 388,965, malicious 4,556,003. *Weighting:* 1 per record; each class normalised by its own size. *Sampling/transform:* no sampling; log1p transform; 40 shared bins per feature. *Run ID:* N/A.

*Files:* analysis/duy_a2/outputs/figures/fig41d_nbaiot_train_features.png, analysis/duy_a2/outputs/figures/fig41d_nbaiot_train_features.pdf

## fig41e_duplicates_by_class

**Caption.** Rows versus distinct feature vectors per class (N-BaIoT: all 115 features; Bot-IoT: the 13 model predictors). Filled dot = all rows, open dot = distinct vectors; ×N = average rows per distinct vector. Bot-IoT has 1 vector that occurs with both labels (11 benign + 3,733 malicious rows); it is counted once in each class.

**Commentary.** Duplication is concentrated in the malicious class: N-BaIoT malicious rows repeat on average 3.30 times per distinct vector versus 1.08 for benign, so benign is 7.87% of rows but 20.68% of distinct vectors. On the 13 Bot-IoT predictors benign is 0.013% of rows and 0.060% of distinct vectors; on all 43 source fields Bot-IoT has no duplicates at all. Because identical vectors are kept inside one partition, repeated rows inflate support counts but cannot leak across TRAIN/VALIDATION/TEST.

*Dataset:* N-BaIoT; Bot-IoT. *Scope:* full corpora (historical audit / candidate scan). *n:* N-BaIoT 7,062,606 rows; Bot-IoT 3,668,522 rows. *Weighting:* 1 per record (rows) vs 1 per distinct vector. *Sampling/transform:* none; log-scale x axis. *Run ID:* N/A.

*Files:* analysis/duy_a2/outputs/figures/fig41e_duplicates_by_class.png, analysis/duy_a2/outputs/figures/fig41e_duplicates_by_class.pdf

## fig42a_validation_f1_recall

**Caption.** N-BaIoT VALIDATION (83,435 benign, 972,937 malicious records): macro-F1 and per-class recall of the nine Full runs, ranked by the selection rule; 0-1 scale, 1 per record, exact values labelled.

**Commentary.** On the full 0-1 scale every run except the Dummy is indistinguishable from 1 (even LR reaches macro-F1 0.9985). The Dummy classifier, which predicts malicious for every record, keeps malicious recall 1 but benign recall 0 (macro-F1 0.4794) despite 92.10% accuracy. The seven tree models differ by at most 0.00011 in macro-F1, so Figure fig42b compares their error counts instead.

*Dataset:* N-BaIoT. *Scope:* VALIDATION (1,056,372 records: 83,435 benign, 972,937 malicious). *n:* 9 Full runs; supports benign 83,435 / malicious 972,937. *Weighting:* 1 per record. *Sampling/transform:* none; 0-1 scale, no axis truncation. *Run ID:* xgb_frac1_seed42_lr01; xgb_frac1_seed42_d4; xgb_frac1_seed42; rf_frac1_seed42; xgb_frac1_seed42_d8; rf_frac1_seed42_leaf5; rf_frac1_seed42_mf03; lr_full_20261102T011513018213Z; dummy_full_20261102T011513018213Z.

*Files:* analysis/duy_a2/outputs/figures/fig42a_validation_f1_recall.png, analysis/duy_a2/outputs/figures/fig42a_validation_f1_recall.pdf

## fig42b_validation_errors_fpr

**Caption.** N-BaIoT VALIDATION false positives (benign flagged malicious) and false negatives (malicious missed) per Full run, and the false-positive rate FP/(FP+TN) over the 83,435 benign records (972,937 malicious); symmetric log axes, exact values labelled.

**Commentary.** The selected run xgb_frac1_seed42_lr01 makes 0 false positives and 18 false negatives, against 1 and 29 for the RF baseline and 246 and 220 for LR. The seven tree models make between 18 and 52 errors on 1,056,372 records, from a single seed, and the winner's 18 errors are only 2 distinct feature vectors repeated 9 times each (gafgyt tcp and gafgyt udp, per its error_analysis.json), so this ranking is not evidence of a stable advantage.

*Dataset:* N-BaIoT. *Scope:* VALIDATION (1,056,372 records: 83,435 benign, 972,937 malicious). *n:* 9 Full runs; FPR denominator 83,435 benign records. *Weighting:* 1 per record. *Sampling/transform:* none; symmetric log axes (linear below 1 record / 0.001%) so zero is shown. *Run ID:* xgb_frac1_seed42_lr01; xgb_frac1_seed42_d4; xgb_frac1_seed42; rf_frac1_seed42; xgb_frac1_seed42_d8; rf_frac1_seed42_leaf5; rf_frac1_seed42_mf03; lr_full_20261102T011513018213Z; dummy_full_20261102T011513018213Z.

*Files:* analysis/duy_a2/outputs/figures/fig42b_validation_errors_fpr.png, analysis/duy_a2/outputs/figures/fig42b_validation_errors_fpr.pdf

## fig42c_validation_confusion

**Caption.** N-BaIoT VALIDATION confusion matrices for LR (lr_full_20261102T011513018213Z), the RF baseline (rf_frac1_seed42) and the selected XGBoost (xgb_frac1_seed42_lr01): rows = true class (83,435 benign, 972,937 malicious), columns = prediction; counts with row percentages, colour = share of the row.

**Commentary.** Row normalisation keeps the 83,435 benign records visible next to 972,937 malicious ones: the benign-row error share is the FPR (0.295% for LR, 0.0012% for RF, 0% for the selected XGBoost). LR's errors are spread across both rows, whereas the tree models' few errors are almost all missed malicious records. Colour compares shares within a row only: the malicious row holds 11.7 times as many records as the benign row.

*Dataset:* N-BaIoT. *Scope:* VALIDATION (1,056,372 records: 83,435 benign, 972,937 malicious). *n:* 1,056,372 VALIDATION records per matrix. *Weighting:* 1 per record. *Sampling/transform:* none; colour and percentages are row-normalised (share of each true class). *Run ID:* lr_full_20261102T011513018213Z; rf_frac1_seed42; xgb_frac1_seed42_lr01.

*Files:* analysis/duy_a2/outputs/figures/fig42c_validation_confusion.png, analysis/duy_a2/outputs/figures/fig42c_validation_confusion.pdf

## fig42d_test_confusion_selected

**Caption.** N-BaIoT final TEST confusion matrix of the frozen XGBoost (xgb_frac1_seed42_lr01), read from the saved TEST receipt: rows = true class (83,532 benign, 977,734 malicious), columns = prediction, counts with row percentages; no other model was evaluated on TEST.

**Commentary.** On TEST the frozen model misclassifies 1 of 83,532 benign records (FPR 0.0012%) and 11 of 977,734 malicious records (macro-F1 0.99996), in line with its VALIDATION result. This is a single within-corpus run: all nine devices appear in every partition, so it does not show performance on unseen devices or future traffic. LR and RF have no TEST result in this evaluation.

*Dataset:* N-BaIoT. *Scope:* final TEST, single evaluation of the frozen model (1,061,266 records: 83,532 benign, 977,734 malicious). *n:* 1,061,266 TEST records. *Weighting:* 1 per record. *Sampling/transform:* none; row-normalised colour and percentages. *Run ID:* xgb_frac1_seed42_lr01.

*Files:* analysis/duy_a2/outputs/figures/fig42d_test_confusion_selected.png, analysis/duy_a2/outputs/figures/fig42d_test_confusion_selected.pdf

## fig42e_clustering_sizes_composition

**Caption.** N-BaIoT K-Means run g3b_standard_k8_seed42 (K=8, TRAIN-only standardisation): (a) cluster sizes on TRAIN (4,944,968 records) and VALIDATION (1,056,372); (b) true-label composition of each cluster on the entire VALIDATION partition (83,435 benign, 972,937 malicious), as shares of that cluster's records. Labels were used only after fitting and selection.

**Commentary.** Two clusters hold 98.6% of VALIDATION records, and 6 of the 8 clusters each hold under 1%. Clusters 4 and 5 contain no malicious VALIDATION records and cluster 7 is 98.89% benign, but the two large clusters are mixed and mostly malicious, so the partition aligns only weakly with the binary label (ARI 0.0078, NMI 0.0918 on all of VALIDATION). Silhouette 0.432 is a sample estimate (3 x 1,500 records) and K=8 used one seed, so no stability claim is made.

*Dataset:* N-BaIoT. *Scope:* TRAIN and VALIDATION assignments of the selected K-Means run (TEST not opened). *n:* TRAIN 4,944,968; VALIDATION 1,056,372 (every record assigned). *Weighting:* 1 per record. *Sampling/transform:* sizes and composition use full partitions; silhouette/DBI/CH in the metrics table use VALIDATION samples. *Run ID:* g3b_standard_k8_seed42.

*Files:* analysis/duy_a2/outputs/figures/fig42e_clustering_sizes_composition.png, analysis/duy_a2/outputs/figures/fig42e_clustering_sizes_composition.pdf

## fig43a_botiot_confusion_row

**Caption.** Bot-IoT VALIDATION confusion matrices for the Full Dummy and LR baselines (integer record counts, rows = true class, percentages of each true class).

**Commentary.** LR reaches 99.987% accuracy while flagging 89 of the 96 benign records as malicious (FPR 92.7%, benign recall 7.3%); the Dummy model scores 99.987% too by never predicting benign. Because 99.987% of VALIDATION records are malicious, accuracy is dominated by the malicious row and hides that benign traffic is almost never recognised. With only 96 benign VALIDATION records, each one moves benign recall by 1.04 percentage points.

*Dataset:* Bot-IoT. *Scope:* VALIDATION (733,704 records: 96 benign, 733,608 malicious). *n:* 733,704 per matrix. *Weighting:* 1 per record (row_primary). *Sampling/transform:* none; row-normalised colour and percentages. *Run ID:* bot_iot_secondary_full_20261102T062917639798Z.

*Files:* analysis/duy_a2/outputs/figures/fig43a_botiot_confusion_row.png, analysis/duy_a2/outputs/figures/fig43a_botiot_confusion_row.pdf

## fig43b_botiot_row_vs_group

**Caption.** Row-weighted versus group-weighted VALIDATION metrics for Dummy and LR. Group weighting gives every original exact-X group a total weight of 1; it is not label balancing.

**Commentary.** Down-weighting repeated rows raises LR macro-F1 from 0.5660 to 0.5803 and benign recall from 7.3% to 9.1%, but FPR stays above 90% either way, so the weak benign detection is not an artefact of duplicates. The 77 benign groups are not 77 guaranteed-independent observations (they can share capture context), and group weighting does not balance the two classes.

*Dataset:* Bot-IoT. *Scope:* VALIDATION. *n:* 733,704 records; 138,060 exact-X groups (77 benign). *Weighting:* row: 1 per record; group: 1/n_g per original exact-X group (13 raw predictors). *Sampling/transform:* none; 0-1 scale. *Run ID:* bot_iot_secondary_full_20261102T062917639798Z.

*Files:* analysis/duy_a2/outputs/figures/fig43b_botiot_row_vs_group.png, analysis/duy_a2/outputs/figures/fig43b_botiot_row_vs_group.pdf

## fig43c_botiot_benign_groups_lr

**Caption.** Sizes of the 77 benign exact-X groups in Bot-IoT VALIDATION and the LR prediction each group received (identical vectors always receive the same prediction). Groups are ranked by size; groups of equal size are listed TN first, then by group hash.

**Commentary.** The largest benign group alone holds 18 of the 96 benign records (18.8%) and LR predicts it malicious, which is why row-weighted and group-weighted benign recall differ. All 7 correctly recognised benign records are single-record groups. With only 77 groups, one group more or less changes benign recall by 1.3 percentage points.

*Dataset:* Bot-IoT. *Scope:* VALIDATION benign records only (96 records, 77 exact-X groups). *n:* 96 records / 77 groups. *Weighting:* sizes are record counts per group. *Sampling/transform:* none. *Run ID:* bot_iot_secondary_full_20261102T062917639798Z.

*Files:* analysis/duy_a2/outputs/figures/fig43c_botiot_benign_groups_lr.png, analysis/duy_a2/outputs/figures/fig43c_botiot_benign_groups_lr.pdf
