# IoTGuard: install, run and call the API

This guide covers installing and running the backend and frontend, and calling the
API with CSV/JSON uploads and live (Raspberry Pi) predictions. Every example below
uses files that ship in `backend/examples/`.

Commands assume Windows PowerShell and the repository root as the working folder
(the folder that contains `backend/`, `frontend/` and `ml/`). Replace `py -3.12` with
`python3.12` on Linux or macOS.

## 1. Install and run the backend

Requires Python 3.12 or later.

```powershell
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Leave this terminal open. When it prints "Application startup complete", open the
interactive API documentation at <http://127.0.0.1:8000/docs>.

Check that the model loaded:

```powershell
curl.exe http://127.0.0.1:8000/model/info
```

You should see `model_id` `xgb_frac1_seed42_lr01`, 115 features and the SHA-256
`cb090afa6ad4c3618e20d7c5d635e89aa2d122667ea00835a0acc2f75a4455e6`.

### Where the model files go

The backend loads two files and refuses to start predicting if they are missing or
do not match each other:

| File | Default location |
| --- | --- |
| Model | `ml/experiments/xgb_frac1_seed42_lr01/model.json` |
| Freeze manifest (feature order, threshold, expected SHA-256) | `ml/artifacts/manifests/primary_model_freeze_20261105.json` |

If you keep them elsewhere, set these variables before starting the server:

```powershell
$env:IOTGUARD_MODEL_PATH  = "C:\path\to\model.json"
$env:IOTGUARD_FREEZE_PATH = "C:\path\to\primary_model_freeze_20261105.json"
```

If the model file is missing, unreadable or its SHA-256 differs from the manifest,
`/predict` and the live endpoints answer **503** ("The prediction model is
unavailable; contact the operator").

### Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `IOTGUARD_MAX_UPLOAD_MB` | 100 | Largest accepted upload, in MiB |
| `IOTGUARD_MAX_ANALYSIS_ROWS` | 100000 | Most data rows per upload |

Set them before starting the server. CORS allows the frontend on
`http://localhost:3000` and `http://127.0.0.1:3000` only.

### Run the tests

Run from the repository root (the folder that contains `backend/`, `frontend/` and
`ml/`), and use `python -m pytest`, so that `backend` can be imported:

```powershell
.\backend\.venv\Scripts\python.exe -m pytest backend/tests -q
```

Expected result: `145 passed`.

## 2. Install and run the frontend

> Commands below come from `frontend/package.json`; confirm them with Duy.

```powershell
cd frontend
npm install
npm run dev
```

Open <http://localhost:3000/dashboard>. The frontend calls the backend at
`http://127.0.0.1:8000`. To use another address, set `NEXT_PUBLIC_API_URL` before
`npm run dev`.

## 3. Manual Analysis: upload a CSV or JSON file

`POST /predict` takes one file in a form field named `file`. The file must be `.csv`
or `.json`, UTF-8, at most 100 MiB and 100,000 rows.

**CSV.** The first line holds the 115 feature names in the model's order. Each
following line holds 115 numbers. Optional `sample_name` and `ground_truth` columns
may follow the features. They never enter the model.

**JSON.** An object with `feature_order` (the 115 names, in order), `rows` (arrays of
115 numbers) and an optional `sample_metadata` array with one object per row, using
only `sample_name` and `ground_truth` (`benign`, `malicious`, `0`, `1` or `null`).

Send the example files:

```powershell
curl.exe -F "file=@backend/examples/predict_input.csv"  http://127.0.0.1:8000/predict
curl.exe -F "file=@backend/examples/predict_input.json" http://127.0.0.1:8000/predict
```

Both files hold the same three synthetic rows, so CSV and JSON give the same labels
and probabilities.

**Success (200).** Abbreviated from `backend/examples/predict_success.json` (a real
response for `predict_input.csv`); `results` is cut to the third row.

```json
{
  "schema_version": "traffic_analysis_v2",
  "model": "xgb_frac1_seed42_lr01",
  "threshold": 0.5,
  "runtime": { "numpy": "2.5.4", "xgboost": "3.2.0" },
  "summary": {
    "rows": 3,
    "features": 115,
    "benign": 2,
    "malicious": 1,
    "file_name": "predict_input.csv",
    "input_format": "csv",
    "mode": "manual_analysis",
    "inference_ms": 0.867,
    "malicious_rate": 0.3333333333333333,
    "score_type": "probability_malicious",
    "model": { "id": "xgb_frac1_seed42_lr01", "algorithm": "XGBoost", "sha256": "cb090afa..." },
    "ground_truth": { "provided_rows": 0, "missing_rows": 3, "accuracy": null }
  },
  "results": [
    {
      "row": 3,
      "sample_name": "Synthetic attack-like row",
      "label": "malicious",
      "score": 0.996326744556427,
      "probability_malicious": 0.996326744556427,
      "probability_benign": 0.003673255443572998,
      "confidence": 0.996326744556427,
      "ground_truth": null,
      "correct": null
    }
  ],
  "feature_stats": [ { "feature": "MI_dir_L5_weight", "min": 0.0, "max": 1723.28, "mean": 914.29 } ]
}
```

`results` has one entry per row. A row is `malicious` when
`probability_malicious >= 0.5`. `feature_stats` has one entry per feature (115).
`summary` also holds the preprocessing steps, timings and the ground-truth accuracy,
which is `null` unless the file supplied `ground_truth`.

**Errors.** `/predict` returns FastAPI's standard `{"detail": "..."}` body.

| Status | When | Example `detail` |
| --- | --- | --- |
| 400 | Wrong extension, encoding, header or values | `Choose a .csv or .json file` |
| 400 | Wrong row length | `Data row 2: expected 115 values` |
| 413 | File larger than the limit | `Choose a file no larger than 100 MiB` |
| 422 | No `file` field in the request | (standard FastAPI list) |
| 503 | Model missing, tampered or unreadable | `The prediction model is unavailable; contact the operator` |

Example of a 400 (a README is not a CSV):

```powershell
curl.exe -i -F "file=@README.md" http://127.0.0.1:8000/predict
```

Saved copies: `backend/examples/predict_error_400.json` and
`backend/examples/predict_error_503.json`.

## 4. Live monitoring: predictions sent from the Raspberry Pi

In live mode the Pi predicts locally and sends the label and probability. The backend
stores them and does **not** predict again. Manual Analysis keeps working when the Pi
is offline.

| Step | Who | Call |
| --- | --- | --- |
| 1 | Frontend | `POST /live/sessions` with `{"source_name": "raspberry-pi-4"}`; returns `session_id` |
| 2 | Pi | `POST /live/sessions/{id}/events` with a batch of 1 to 100 events |
| 3 | Pi | `POST /live/sessions/{id}/heartbeat` when it has nothing to send |
| 4 | Frontend | `GET /live/sessions/{id}/events?after_seq=N` to fetch new events |
| 5 | Frontend | `GET /live/sessions/{id}/status` for connection state and counters |
| 6 | Frontend | `POST /live/sessions/{id}/stop` |

`GET /live/limits` returns the batch size (100), history size (1,000 events per
session) and connection thresholds (stale after 15 s, offline after 45 s).

Try the whole flow. Replace `ses_xxxxxxxx` with the `session_id` from step 1.

```powershell
curl.exe -X POST -H "Content-Type: application/json" -d "@backend/examples/live_session_create.json" http://127.0.0.1:8000/live/sessions
curl.exe -X POST -H "Content-Type: application/json" -d "@backend/examples/live_event_batch.json" http://127.0.0.1:8000/live/sessions/ses_xxxxxxxx/events
curl.exe "http://127.0.0.1:8000/live/sessions/ses_xxxxxxxx/events?after_seq=0"
curl.exe http://127.0.0.1:8000/live/sessions/ses_xxxxxxxx/status
```

An event sent by the Pi looks like this (a batch also carries the model hash):

```json
{
  "model_sha256": "cb090afa6ad4c3618e20d7c5d635e89aa2d122667ea00835a0acc2f75a4455e6",
  "events": [
    {
      "event_id": "pi4-0000",
      "pi_seq": 0,
      "sample_name": "Synthetic all-zero row",
      "source_row": 0,
      "label": "benign",
      "probability_malicious": 3.159569814670249e-06,
      "ground_truth": null,
      "predicted_at": "2026-11-21T09:00:01Z",
      "inference_ms": 1.8
    }
  ]
}
```

Rules the Pi must follow:

- `event_id` is unique per record and `pi_seq` increases by 1. After a network failure
  the Pi may resend the whole batch. Stored events are reported as `duplicates` and
  not counted twice.
- A jump in `pi_seq` sets `gap_detected`, so lost events are visible.
- `label` must agree with `probability_malicious` at the 0.5 threshold.
- `ground_truth` is `null` unless the labelled replay file supplied it. Accuracy is
  calculated only from events that carry ground truth.
- Sessions are kept in memory. If the server restarts, a 404 on a session means the
  frontend must start a new one.

**Live errors** use `{"code": "...", "message": "...", "detail": [...]}`:

| Status | `code` | When |
| --- | --- | --- |
| 404 | `session_not_found` | Unknown session id |
| 409 | `model_mismatch` | The Pi's model hash differs from the backend's; nothing is stored |
| 409 | `session_stopped` | Events or a heartbeat sent to a stopped session |
| 413 | `payload_too_large` | More than 100 events in one batch |
| 422 | `validation_error` | Invalid body, for example a probability outside 0 to 1 |

Live endpoints also return a plain 503 `{"detail": "..."}` if the model cannot be
loaded.

Setting up and running the Pi side is described in the Raspberry Pi guide:
**TODO: add link to Minh Sơn's Pi guide.**

## 5. All endpoints

| Method and path | Purpose |
| --- | --- |
| `POST /predict` | Classify an uploaded CSV or JSON file |
| `GET /model/info` | Model name, SHA-256, threshold and the 115 feature names |
| `GET /live/limits` | Live limits and thresholds |
| `POST /live/sessions` | Start a live session |
| `POST /live/sessions/{id}/stop` | Stop a session |
| `POST /live/sessions/{id}/events` | Pi sends a batch of predictions |
| `POST /live/sessions/{id}/heartbeat` | Pi keep-alive |
| `GET /live/sessions/{id}/events` | Poll new events with `after_seq` |
| `GET /live/sessions/{id}/status` | Connection state and counters |
| `POST /files/inspect` | Check an upload and log it; does not classify |
| `GET /logs` | Recent activity (`limit` 1 to 200) |

The full request and response schemas are in the interactive documentation at
<http://127.0.0.1:8000/docs>. Design details for the live API are in
`docs/live-api-contract.md`.

## 6. Troubleshooting

| Symptom | Fix |
| --- | --- |
| `503 ... model is unavailable` | Check the two model paths above and that the model file is the one with the SHA-256 shown in `/model/info`. |
| `ModuleNotFoundError: No module named 'backend'` when running tests | Run pytest from the repository root, not from `backend/`. |
| Browser shows a CORS error | Open the site at `localhost:3000` or `127.0.0.1:3000`; other origins are not allowed. |
| Port 8000 already in use | Stop the other server, or start uvicorn with another `--port` and set `NEXT_PUBLIC_API_URL` to match. |