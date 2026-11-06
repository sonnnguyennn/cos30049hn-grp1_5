# Classifier tables (VALIDATION unless stated)

## Table A - Full runs, VALIDATION (n = 1,056,372; benign 83,435; malicious 972,937)

| Rank | Run ID | Algorithm | Accuracy | Macro-F1 | FPR | TN | FP | FN | TP |
|---:|---|---|---:|---:|---:|---:|---:|---:|---:|
| 1 | `xgb_frac1_seed42_lr01` (selected) | XGB | 0.999983 | 0.999941 | 0.0000000 | 83,435 | 0 | 18 | 972,919 |
| 2 | `xgb_frac1_seed42_d4` | XGB | 0.999981 | 0.999935 | 0.0000000 | 83,435 | 0 | 20 | 972,917 |
| 3 | `xgb_frac1_seed42` | XGB | 0.999973 | 0.999909 | 0.0000120 | 83,434 | 1 | 27 | 972,910 |
| 4 | `rf_frac1_seed42` | RF | 0.999972 | 0.999902 | 0.0000120 | 83,434 | 1 | 29 | 972,908 |
| 5 | `xgb_frac1_seed42_d8` | XGB | 0.999972 | 0.999902 | 0.0000120 | 83,434 | 1 | 29 | 972,908 |
| 6 | `rf_frac1_seed42_leaf5` | RF | 0.999963 | 0.999873 | 0.0000120 | 83,434 | 1 | 38 | 972,899 |
| 7 | `rf_frac1_seed42_mf03` | RF | 0.999951 | 0.999831 | 0.0000599 | 83,430 | 5 | 47 | 972,890 |
| 8 | `lr_full_20261102T011513018213Z` | LR | 0.999559 | 0.998484 | 0.0029484 | 83,189 | 246 | 220 | 972,717 |
| 9 | `dummy_full_20261102T011513018213Z` | Dummy | 0.921017 | 0.479443 | 1.0000000 | 0 | 83,435 | 0 | 972,937 |

## Table B - per-class results, VALIDATION

| Run ID | Class | Precision | Recall | F1 | Support |
|---|---|---:|---:|---:|---:|
| `xgb_frac1_seed42_lr01` | benign | 0.999784 | 1.000000 | 0.999892 | 83,435 |
| `xgb_frac1_seed42_lr01` | malicious | 1.000000 | 0.999981 | 0.999991 | 972,937 |
| `xgb_frac1_seed42_d4` | benign | 0.999760 | 1.000000 | 0.999880 | 83,435 |
| `xgb_frac1_seed42_d4` | malicious | 1.000000 | 0.999979 | 0.999990 | 972,937 |
| `xgb_frac1_seed42` | benign | 0.999676 | 0.999988 | 0.999832 | 83,435 |
| `xgb_frac1_seed42` | malicious | 0.999999 | 0.999972 | 0.999986 | 972,937 |
| `rf_frac1_seed42` | benign | 0.999653 | 0.999988 | 0.999820 | 83,435 |
| `rf_frac1_seed42` | malicious | 0.999999 | 0.999970 | 0.999985 | 972,937 |
| `xgb_frac1_seed42_d8` | benign | 0.999653 | 0.999988 | 0.999820 | 83,435 |
| `xgb_frac1_seed42_d8` | malicious | 0.999999 | 0.999970 | 0.999985 | 972,937 |
| `rf_frac1_seed42_leaf5` | benign | 0.999545 | 0.999988 | 0.999766 | 83,435 |
| `rf_frac1_seed42_leaf5` | malicious | 0.999999 | 0.999961 | 0.999980 | 972,937 |
| `rf_frac1_seed42_mf03` | benign | 0.999437 | 0.999940 | 0.999688 | 83,435 |
| `rf_frac1_seed42_mf03` | malicious | 0.999995 | 0.999952 | 0.999973 | 972,937 |
| `lr_full_20261102T011513018213Z` | benign | 0.997362 | 0.997052 | 0.997207 | 83,435 |
| `lr_full_20261102T011513018213Z` | malicious | 0.999747 | 0.999774 | 0.999761 | 972,937 |
| `dummy_full_20261102T011513018213Z` | benign | N/A | 0.000000 | 0.000000 | 83,435 |
| `dummy_full_20261102T011513018213Z` | malicious | 0.921017 | 1.000000 | 0.958885 | 972,937 |

N/A = undefined (no record predicted benign, so benign precision is 0/0).

## Table C - selected XGBoost, final TEST (single run, n = 1,061,266)

| Metric | Value |
|---|---:|
| TN | 83,531 |
| FP | 1 |
| FN | 11 |
| TP | 977,723 |
| accuracy | 0.999988693 |
| macro_f1 | 0.999961019 |
| fpr | 0.000011971 |
| benign_precision | 0.999868330 |
| benign_recall | 0.999988029 |
| benign_f1 | 0.999928176 |
| benign_support | 83,532 |
| malicious_precision | 0.999998977 |
| malicious_recall | 0.999988749 |
| malicious_f1 | 0.999993863 |
| malicious_support | 977,734 |
