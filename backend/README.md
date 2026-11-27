# IoTGuard backend

The FastAPI service validates manual-analysis uploads, runs the frozen N-BaIoT model and stores activity logs in SQLite.

## Run locally

Use Python 3.12 or later. From `backend/` in PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open [Swagger](http://127.0.0.1:8000/docs). The [frontend](../frontend/README.md) connects to this address by default. CORS allows `localhost:3000` and `127.0.0.1:3000`.

## Endpoints

| Endpoint | Purpose |
| --- | --- |
| `POST /predict` | Return N-BaIoT predictions and a `traffic_analysis_v2` report for a CSV or JSON upload. |
| `POST /files/inspect` | Check that an upload is nonempty and within the size limit, then log the inspection. |
| `GET /logs` | Return recent activity. The `limit` query parameter accepts 1–200 and defaults to 50. |
| `POST /goon` | Serve the existing dashboard demo. |

The upload size limit defaults to 100 MiB (`IOTGUARD_MAX_UPLOAD_MB`). Prediction also limits each file to 100,000 data rows by default (`IOTGUARD_MAX_ANALYSIS_ROWS`). Set overrides before starting the service. The [upload guide](../docs/csv-upload-api-guide.md) shows example requests and HTTP errors.

The [shared loader](app/predictor.py) reads the model and freeze manifest from the repository by default. For alternate locations, set `IOTGUARD_MODEL_PATH` and `IOTGUARD_FREEZE_PATH` before startup. On first model load, the loader checks its SHA-256 against the manifest.

Startup creates `app/db/traffic.db` if needed. SQLite data and journal files are ignored by Git. Back up the database to keep local activity history.

## Run tests

From the repository root, using the environment above:

```powershell
.\backend\.venv\Scripts\python.exe -m pytest backend/tests -q
```
