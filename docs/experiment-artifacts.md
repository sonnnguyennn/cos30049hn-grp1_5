# Verify and restore experiment artifacts

The archive tool uses only the Python standard library. A custodian can provide
the ZIP and its corresponding release descriptor. The descriptor pins the ZIP
checksum and logical files. Validate the received copy before using it.

From the repository root, replace the placeholders and choose a new restore path
whose parent exists outside the checkout:

```powershell
python ml/scripts/experiment_payload_archive.py verify --archive <archive.zip> --release <release.json>
python ml/scripts/experiment_payload_archive.py restore --archive <archive.zip> --release <release.json> --output <new-external-directory>
```

A successful restore writes `restore_receipt.json` with status
`RESTORE_COMPLETE`. For the clustering report, point the analysis script at the
restored `full` results directory:

```powershell
python ml/analysis/duy_a2/scripts/t42_clustering_figures.py --results-dir <new-external-directory>/repository/ml/notebooks/Clustering/results/full
```

Add `--validation-labels` with the original G3B `VALIDATION_y.npy` to recompute
the label composition. To keep regenerated figures separate, set
`DUY_A2_OUTPUT_DIR` to an external directory before running.

Use the archive version that contains `g3b_standard_k8_seed42`, which the report script expects. The checked-in [clustering results](../ml/notebooks/Clustering/Result/full/analysis.md) use `standard_k8_seed42` and fail that identity check.

Cluster assignments and centres support figure generation. Prediction replay also
requires the saved estimators. Before migrating tracked payloads, agree on a retrieval
location and have a recipient verify the restore and report.
