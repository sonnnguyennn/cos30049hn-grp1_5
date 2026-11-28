# Manual Analysis response

`POST /predict` and the standalone analysis script return `traffic_analysis_v2`. See the [backend response schema](../backend/app/responses.py) and [frontend types](../frontend/src/app/ui/prediction/types.ts).

The top level includes the model ID, threshold, library versions, batch `summary`, one `results` entry per row and `feature_stats` for the 115 features.

## Batch summary

| Field | Meaning |
| --- | --- |
| `rows`, `features`, `benign`, `malicious` | Input dimensions and predicted class counts. |
| `file_name`, `input_format`, `file_size_bytes` | Filename, `csv` or `json`, and byte count. Unavailable file metadata is null. |
| `mode` | `manual_analysis`. |
| `started_at`, `completed_at` | UTC ISO 8601 processing timestamps. |
| `processing_ms` | Response preparation, validation, parsing for file uploads, and model loading if needed. Excludes network transfer and browser rendering. |
| `inference_ms` | Model matrix construction and prediction after loading the model. |
| `malicious_rate` | Fraction of rows predicted malicious. |
| `mean_score`, `mean_confidence` | Mean malicious probability and mean confidence in the predicted class. |
| `score_type`, `threshold` | `probability_malicious` and the decision threshold. Scores at or above 0.5 predict malicious. |
| `model` | Model `id`, `name`, `algorithm`, `objective` and `sha256`. |
| `preprocessor` | `name`, `feature_count`, `input_dtype`, `model_dtype`, `scaling_applied` and `steps`. The model receives raw values cast to float32. |
| `ground_truth` | `source`, `provided_rows`, `missing_rows`, `correct`, `incorrect` and `accuracy`. Accuracy covers labeled rows and is null if no labels are supplied. |

## Per-row results

| Field | Meaning |
| --- | --- |
| `row` | 1-based data row, excluding the CSV header. |
| `sample_name` | Supplied name or generated filename and row number. |
| `label` | Predicted `benign` or `malicious`. |
| `score`, `probability_malicious` | The same malicious probability, from 0 to 1. |
| `probability_benign` | `1 - score`. |
| `confidence` | Probability of the predicted class. |
| `ground_truth` | Supplied label or null. |
| `correct` | Whether the prediction matches the supplied label. Null for unlabeled rows. |

## Optional upload metadata

Keep metadata separate from the 115 model features.

- **CSV.** Append `sample_name`, `ground_truth` or both after the ordered feature columns. Labels accept `benign`, `malicious`, `0`, `1` or an empty cell. Case and surrounding whitespace are ignored.
- **JSON.** Add a `sample_metadata` array with one object per row. Each object may contain `sample_name` and `ground_truth`. Labels accept `"benign"`, `"malicious"`, numeric `0` or `1`, or `null`. Omitted fields are unknown.

Sample names, when provided, must be nonblank strings of at most 200 characters. See the [sample prediction guide](../ml/docs/experiments/sample_prediction.md) for VALIDATION inputs and the [TEST upload export guide](../ml/docs/experiments/test_upload_export.md) for labeled exports.

## View and export

Manual Analysis supports search by name or row number, prediction and match filters, sorting and pagination. The batch summary covers the entire upload. **Export** saves the full report as `<input-name>-analysis.json`, including rows outside the current table view.
