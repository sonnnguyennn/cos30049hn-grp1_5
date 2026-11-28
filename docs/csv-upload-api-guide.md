# Try Manual Analysis

`POST /predict` accepts a UTF-8 CSV or JSON file in the multipart field `file`. Each row must contain 115 raw N-BaIoT features in the exact order in the [freeze manifest](../ml/artifacts/manifests/primary_model_freeze_20261105.json), under `input_contract.feature_order`. Extract the features before uploading. Use the raw values directly.

| Format | Required content |
| --- | --- |
| CSV | Header with the ordered feature names, followed by at least one numeric data row. |
| JSON | Object with `feature_order` and a nonempty `rows` array. Each row is an array of 115 JSON numbers. |

Both formats accept optional sample names and ground-truth labels. See the [response contract](analysis-response.md#optional-upload-metadata) for metadata rules. The [backend guide](../backend/README.md#endpoints) lists default size and row limits.

## Try the API

Start the [backend](../backend/README.md#run-locally), then run from the repository root:

```powershell
curl.exe -sS -F "file=@backend/examples/predict_input.csv" http://127.0.0.1:8000/predict
curl.exe -sS -F "file=@backend/examples/predict_input.json" http://127.0.0.1:8000/predict
```

In [Swagger](http://127.0.0.1:8000/docs), expand `POST /predict`, choose **Try it out**, select one of the example files and execute. To check the web interface, upload the same files in [Manual Analysis](http://localhost:3000/dashboard/prediction/manual-analysis).

The [CSV](../backend/examples/predict_input.csv) and [JSON](../backend/examples/predict_input.json) contain the same three synthetic rows and give the same labels and probabilities. For real VALIDATION inputs, follow the [sample prediction guide](../ml/docs/experiments/sample_prediction.md).

## Response and errors

HTTP 200 returns `traffic_analysis_v2` with the model hash, batch summary, per-row predictions and feature statistics. See the [response contract](analysis-response.md) for the fields.

| Status | Cause |
| --- | --- |
| 400 | Unsupported extension or encoding, invalid feature names or order, invalid values, wrong row length or too many rows. |
| 413 | Uploaded file exceeds the byte limit. |
| 422 | Missing or invalid multipart file field. |
| 503 | Frozen model or input contract is unavailable. |

FastAPI returns the error under `detail`. On 422, the field contains a validation list.
