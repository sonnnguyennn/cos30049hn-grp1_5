# Detailed analysis response

`POST /predict` and `backend/app/analyze_csv.py` return `traffic_analysis_v2`.
Existing `model`, `threshold`, `runtime`, `summary.rows/features/benign/malicious`,
`results.row/label/probability_malicious` and `feature_stats` fields remain available.
The frontend's matching types are in `frontend/src/app/ui/prediction/types.ts`.

## Summary fields

| Field under `summary` | Meaning |
| --- | --- |
| `file_name`, `input_format`, `file_size_bytes` | Uploaded filename, `csv`/`json`, and byte count. Direct text-only Python calls leave unavailable file metadata null. |
| `mode` | `manual_analysis`, the current batch upload workflow. |
| `started_at`, `completed_at` | UTC ISO 8601 processing timestamps, not traffic capture times. |
| `processing_ms` | Parsing, validation, model loading if needed, inference and response preparation. Excludes network upload/download and browser rendering. |
| `inference_ms` | Model input matrix construction and prediction only; the model is already loaded. |
| `malicious_rate` | Fraction of rows predicted malicious, from 0 to 1. |
| `mean_score` | Mean malicious probability across all rows. |
| `mean_confidence` | Mean probability assigned to each row's predicted class. |
| `score_type` | `probability_malicious`. |
| `threshold` | Score at or above this value predicts malicious (currently 0.5). |
| `model` | `id`, readable `name`, `algorithm`, `objective` and frozen model `sha256`. |
| `preprocessor` | `name`, `feature_count`, `input_dtype`, `model_dtype`, `scaling_applied` and ordered `steps`. This model uses raw N-BaIoT values cast to float32, without scaling. |
| `ground_truth` | `source`, `provided_rows`, `missing_rows`, `correct`, `incorrect`, `accuracy`. Accuracy is null when no labels were supplied. It covers only labeled rows. |

The text-only functions `analyze_csv()` / `analyze_json()` time numeric validation,
inference and response preparation. Use `analyze_file()` (as the upload API does)
to include file parsing in the total processing time.

## Per-row results

| Field under each `results` entry | Meaning |
| --- | --- |
| `row` | 1-based data row, excluding the CSV header. |
| `sample_name` | Supplied sample name, or a generated filename and row number. |
| `label` | Predicted `benign` or `malicious`. |
| `score`, `probability_malicious` | Identical malicious probabilities, from 0 to 1. |
| `probability_benign` | `1 - score`. |
| `confidence` | `score` for a malicious prediction; `1 - score` for a benign prediction. |
| `ground_truth` | Supplied `benign`/`malicious` label, or null. Never inferred from the prediction or filename. |
| `correct` | Whether prediction matches supplied ground truth, or null when unknown. |

Model, preprocessor, mode and processing timestamps describe the whole batch and
are stored once in `summary`. There is no fabricated per-row latency or capture time.

## Optional upload metadata

Feature-only CSV/JSON inputs still work. Metadata is validated and kept separate
from the 115 columns passed to the model.

For **CSV**, append optional `sample_name` and/or `ground_truth` columns after all
115 ordered feature columns. Ground truth accepts `benign`, `malicious`, `0`, `1`,
or an empty cell. CSV labels ignore surrounding whitespace and case.

For **JSON**, add a `sample_metadata` array with exactly one object per feature
row. Each object may contain `sample_name` and `ground_truth`. Labels accept
`"benign"`, `"malicious"`, numeric `0`/`1`, or `null`. Omitted fields are unknown.
Names must be nonblank strings of at most 200 characters. Booleans and other
labels are rejected. For example, add this next to your existing `feature_order`
and two-row `rows` array:

```json
"sample_metadata": [
  {"sample_name": "Camera benign example", "ground_truth": "benign"},
  {"sample_name": "Camera attack example", "ground_truth": "malicious"}
]
```

To generate complete CSV and JSON files with real TEST names and labels:

```bash
ml/.venv/bin/python ml/scripts/export_test_upload.py --include-metadata --out ml/data/samples/test-detailed
```

Choose a new output directory for every export. Upload either generated
`test_input.csv` or `test_input.json`. The website shows names, scores, confidence,
ground truth and per-row matches, plus summary agreement on the supplied labels.
The predictions table browses the entire upload with 10, 25, 50 or 100 rows per page.
Search by sample name or row number, filter by prediction and ground-truth match,
or sort by sample name, malicious score and confidence. Summary statistics always
cover the entire upload, independently of the table's filters.

The Results panel's **Export** button downloads the complete JSON report as
`<input-name>-analysis.json`, including summary, model/preprocessor information,
all predictions, ground truth and feature statistics. Table filters and pagination
do not limit the exported report.
