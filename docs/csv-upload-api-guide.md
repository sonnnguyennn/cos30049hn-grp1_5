# Upload CSV or JSON and display model results

This guide connects `backend/app/analyze_csv.py` to your existing FastAPI backend
and Next.js website. The analyzer is implemented. The API and React code below
are examples for you to add; they are not installed in the application yet.

The flow is:

```text
Choose CSV or JSON in browser
  -> POST /predict (file upload)
  -> analyze_file(content, filename) in Python
  -> saved XGBoost model predicts each row
  -> API returns JSON
  -> React displays the counts and predictions
```

## 1. Understand the input files

To export real **TEST** rows as upload-ready CSV and JSON, run from the repository root:

```bash
ml/.venv/bin/python ml/scripts/export_test_upload.py
```

Upload `ml/data/samples/test-upload/test_input.csv` or `test_input.json`.
The separate `expected_labels.csv` lets you check the predictions. See the
[TEST export guide](../ml/docs/experiments/test_upload_export.md) for sample sizes,
full-split exports and source paths.

Each data row describes one traffic observation. The first line must contain the
exact 115 feature names, in the model's order. Every data cell must be a finite
number. Optional `sample_name` and `ground_truth` columns may follow the 115 features;
these are display/evaluation metadata and never enter the model. Other extra columns
are rejected. JSON may contain an optional row-aligned `sample_metadata` array.
See the [detailed response and metadata contract](analysis-response.md).
Use raw feature values; the script converts them to float32 without scaling.

The sample file generated earlier is ready to use:
`ml/data/samples/primary-prediction/sample_input.csv`.
To generate another example, run from the repository root:

```bash
ml/.venv/bin/python ml/scripts/sample_prediction.py --out ml/data/samples/upload-demo
```

Use a new output directory each time. Upload the generated `sample_input.csv`
or `sample_input.json`. Defaults are 100 MiB and 100,000 data rows. Empty cells, blank data rows, wrong
headers, NaN, infinity and values overflowing float32 are rejected.
Raw packet captures and Bot-IoT CSVs are not compatible with this N-BaIoT model.

JSON uses the same structure as the generated `sample_input.json`:

```json
{
  "feature_order": ["MI_dir_L5_weight", "MI_dir_L5_mean", "...remaining feature names..."],
  "rows": [[1.0, 2.0, 3.0]]
}
```

This is a shortened illustration: your real file needs all 115 names and 115
numbers in every row. JSON values must be numbers; strings, booleans and null
are rejected. Both formats return the same analysis structure. Arbitrary JSON
objects such as a previous prediction report are not model inputs.

### Change the size and row limits

Both the analyzer and the backend read these settings when the process starts:

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `IOTGUARD_MAX_UPLOAD_MB` | `100` | Maximum file size in MiB (1 MiB = 1,048,576 bytes). |
| `IOTGUARD_MAX_ANALYSIS_ROWS` | `100000` | Maximum number of observations in either format. |

For example, allow 250 MiB and 250,000 rows on Linux:

```bash
export IOTGUARD_MAX_UPLOAD_MB=250
export IOTGUARD_MAX_ANALYSIS_ROWS=250000
```

Or in Windows PowerShell:

```powershell
$env:IOTGUARD_MAX_UPLOAD_MB = "250"
$env:IOTGUARD_MAX_ANALYSIS_ROWS = "250000"
```

Then run the script or start/restart Uvicorn in that terminal. Set both variables
in your hosting service's environment for deployment. Your reverse proxy or
hosting platform may have its own request-size and timeout settings to raise too.
The old 10,000-row cap is now 100,000, so it will not block moderately larger files.

The current example reads the file and returns all predictions in memory. A
100 MiB file can consume substantially more RAM when parsed. For much larger
uploads or many simultaneous users, use a background analysis job, batch
processing and paginated results. The example UI below shows only the first
100 predictions while the counts cover every row.

## 2. Try the script without a website

Run these commands from the repository root. The existing `ml/.venv` already has
the inference dependencies installed in this workspace:

```bash
ml/.venv/bin/python backend/app/analyze_csv.py ml/data/samples/primary-prediction/sample_input.csv
```

The same script automatically detects JSON from the filename:

```bash
ml/.venv/bin/python backend/app/analyze_csv.py ml/data/samples/primary-prediction/sample_input.json
```

To save the JSON instead of printing it:

```bash
ml/.venv/bin/python backend/app/analyze_csv.py ml/data/samples/primary-prediction/sample_input.csv --output /tmp/csv-results.json
```

The output file must not exist yet. On Windows, replace
`ml/.venv/bin/python` with `ml\.venv\Scripts\python.exe`, and choose a suitable
local output path instead of `/tmp/csv-results.json`.

The main function you will reuse is:

```python
result = analyze_file(content, filename)
```

Here `content` is file bytes and `filename` ends in `.csv` or `.json`.
It reads and validates either format, loads the saved model, predicts labels, and
returns a Python dictionary. It also calculates each feature's minimum, maximum
and mean. It does not need the full validation dataset. Model and contract paths
are resolved relative to the repository, so keep `backend/` and `ml/` together.

The result has this structure (shortened for readability):

The response also includes sample names, scores, confidence, optional ground truth,
model/preprocessor details and processing timestamps. See the
[full field reference](analysis-response.md) for `traffic_analysis_v2`.

```json
{
  "model": "xgb_frac1_seed42_lr01",
  "threshold": 0.5,
  "runtime": {"numpy": "2.4.6", "xgboost": "3.2.0"},
  "summary": {"rows": 6, "features": 115, "benign": 3, "malicious": 3},
  "results": [
    {"row": 1, "label": "benign", "probability_malicious": 0.0008694713}
  ],
  "feature_stats": [
    {"feature": "MI_dir_L5_weight", "min": 1.0, "max": 3.0, "mean": 2.0}
  ]
}
```

The numbers in `feature_stats` above illustrate the format. Your actual values
come from the uploaded file. `row` starts at 1 for the first data row, excluding
the header. A malicious probability of at least 0.5 produces `malicious`.
Predictions alone cannot establish accuracy: an uploaded file has no known labels.

## 3. Install dependencies in the backend environment

The API needs the same inference dependencies as the script. From the repository
root on Linux:

```bash
backend/.venv/bin/python -m pip install numpy==2.4.6 scipy==1.17.1 xgboost-cpu==3.2.0
backend/.venv/bin/python -m pip install -e ./backend
```

For Windows use `backend\.venv\Scripts\python.exe` and `xgboost==3.2.0`
instead of `xgboost-cpu==3.2.0`. FastAPI's existing `standard` extra supplies
multipart upload support. Add the inference dependencies to
`backend/pyproject.toml` when making this a permanent backend feature.

The report records runtime versions. These pins use the verified model-inference
library versions; the original team acceptance environment used Python 3.11.15
on Windows. This local demo is not a replacement for that acceptance evidence.

## 4. Add an endpoint to FastAPI

Add this import to `backend/app/main.py`:

```python
from .analyze_csv import analyze_file
```

Then append this route. `UploadFile`, `HTTPException`, `MAX_UPLOAD_BYTES`,
`UPLOAD_LIMIT_MESSAGE`, `CHUNK_BYTES` and `run_in_threadpool` already exist
in that file. `MAX_UPLOAD_BYTES` now comes from the shared `upload_limits.py`:

```python
@app.post("/predict")
async def predict_file(file: UploadFile):
    # Read in chunks so an oversized upload is rejected early.
    content = bytearray()
    try:
        while chunk := await file.read(CHUNK_BYTES):
            content.extend(chunk)
            if len(content) > MAX_UPLOAD_BYTES:
                raise HTTPException(413, UPLOAD_LIMIT_MESSAGE)
    finally:
        await file.close()

    try:
        return await run_in_threadpool(analyze_file, content, file.filename or "")
    except ValueError as error:
        raise HTTPException(400, str(error))
```

FastAPI converts the returned dictionary into JSON. `run_in_threadpool` runs the
analysis outside the asynchronous request loop. The model is cached after its
first load; restart the backend after changing model files. The example processes
the upload in memory and does not save it to disk.

Start the backend from the repository root:

```bash
backend/.venv/bin/python -m uvicorn app.main:app --app-dir backend --reload --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/docs`, expand **POST /predict**, click **Try it out**,
select your CSV or JSON and click **Execute**. Get this working before adding the UI.
Alternatively, from the repository root:

```bash
curl -X POST http://127.0.0.1:8000/predict -F "file=@ml/data/samples/primary-prediction/sample_input.csv"
```

## 5. Connect a React upload form

The Manual Analysis page is
`frontend/src/app/dashboard/prediction/manual-analysis/page.tsx`.
For a minimal working form, replace that page's contents with:

```tsx
"use client";

import { useState, type SubmitEvent } from "react";

type Analysis = {
  summary: { rows: number; features: number; benign: number; malicious: number };
  results: { row: number; label: string; probability_malicious: number }[];
};

const API_URL = (
  process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000"
).replace(/\/$/, "");

export default function Page() {
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<Analysis | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function analyze(event: SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file || loading) return;
    setLoading(true);
    setResult(null);
    setError("");

    try {
      const body = new FormData();
      body.append("file", file);
      const response = await fetch(`${API_URL}/predict`, {
        method: "POST",
        body,
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(
          typeof data.detail === "string" ? data.detail : "Analysis failed"
        );
      }
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Cannot contact the API");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="space-y-4 p-6">
      <h1 className="text-2xl font-semibold">Analyze traffic file</h1>
      <form onSubmit={analyze} className="flex gap-4">
        <input
          type="file"
          accept=".csv,.json"
          aria-label="Traffic CSV or JSON"
          disabled={loading}
          onChange={(event) => {
            setFile(event.target.files?.[0] ?? null);
            setResult(null);
            setError("");
          }}
        />
        <button type="submit" disabled={!file || loading}>
          {loading ? "Analyzing..." : "Analyze"}
        </button>
      </form>
      {error && <p role="alert">{error}</p>}
      {result && (
        <section aria-live="polite">
          <p>
            {result.summary.rows} rows: {result.summary.benign} benign,
            {" "}{result.summary.malicious} malicious
          </p>
          {result.summary.rows > 100 && <p>Showing the first 100 predictions.</p>}
          <table>
            <thead>
              <tr><th>Row</th><th>Prediction</th><th>Malicious probability</th></tr>
            </thead>
            <tbody>
              {result.results.slice(0, 100).map((row) => (
                <tr key={row.row}>
                  <td>{row.row}</td>
                  <td>{row.label}</td>
                  <td>{(row.probability_malicious * 100).toFixed(4)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </main>
  );
}
```

Use `FormData`, not `JSON.stringify(file)`. Let the browser set the multipart
`Content-Type` header; setting it yourself omits the required boundary.
The API also returns `feature_stats` if you later want a feature summary table.

Run the frontend using its existing setup, then open
`http://localhost:3000/dashboard/prediction/manual-analysis` and upload the sample.
Both the frontend and backend must be running. For another backend address, set
`NEXT_PUBLIC_API_URL` in `frontend/.env.local` and restart the frontend. The
backend already permits local frontend origins on port 3000; update its CORS
origins if you host the website elsewhere.

## 6. Common errors

| Message or symptom | What to check |
| --- | --- |
| Header must contain exactly 115 model features | Use `sample_input.csv`; remove labels/metadata and preserve column order. |
| All values must be numeric | Remove text and fill missing values using your agreed preprocessing process. |
| CSV has no data rows / JSON rows is empty | Include at least one observation. |
| JSON feature_order mismatch | Use the full ordered list from `sample_input.json`. |
| Too many data rows | Raise `IOTGUARD_MAX_ANALYSIS_ROWS` and restart, or split the file. |
| HTTP 413 | Check `IOTGUARD_MAX_UPLOAD_MB` (default 100 MiB) and your proxy limit. |
| HTTP 422 | The multipart form field must be named `file`. |
| Failed to fetch | Confirm the backend URL, running server and allowed CORS origin. |
| ModuleNotFoundError | Install dependencies using the Python environment that runs Uvicorn. |
| Saved model does not match | Restore the accepted model; do not remove the checksum check. |
| HTTP 500 | Read the backend terminal for model/dependency errors. |

Keep the saved model in Python on the server. The browser sends feature data and
receives results; it does not need the model file.
