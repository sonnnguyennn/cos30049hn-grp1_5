# IoTGuard backend

FastAPI service that serves the frozen XGBoost classifier for CSV/JSON uploads
(`POST /predict`), stores live predictions sent by the Raspberry Pi, and keeps
SQLite-backed activity logs. Full install steps, model file locations and API
examples are in the [install and API guide](../docs/api-and-install-guide.md).

Requires Python 3.12 or later, as declared in `pyproject.toml`. From `backend/`
on Windows:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Use a separately installed supported Python version if `py -3.12` is unavailable.
The virtual environment and package build metadata are ignored by Git.

Open [interactive API docs](http://127.0.0.1:8000/docs) for the request/response
schemas. The [frontend](../frontend/README.md) connects to this address by default.
CORS permits the frontend on `localhost:3000` and `127.0.0.1:3000`.

For a standalone CSV/JSON analysis script and steps to connect it to an upload API and
React page, see the [CSV/JSON upload API guide](../docs/csv-upload-api-guide.md).

| Endpoint | Purpose |
| --- | --- |
| `POST /predict` | Classify an uploaded CSV/JSON file (115 features per row) |
| `GET /model/info` | Model id, SHA-256, threshold, feature names |
| `GET /live/limits` | Live batch/history limits and connection thresholds |
| `POST /live/sessions` | Start a live session |
| `POST /live/sessions/{id}/stop` | Stop a session |
| `POST /live/sessions/{id}/events` | Pi sends a batch of predictions |
| `POST /live/sessions/{id}/heartbeat` | Pi keep-alive |
| `GET /live/sessions/{id}/events?after_seq=N` | Frontend polls new events |
| `GET /live/sessions/{id}/status` | Connection state and counters |
| `POST /files/inspect` | Check and log an upload; does not classify |
| `GET /logs` | Recent activity (`limit` 1 to 200) |
| `POST /goon` | Existing demonstration request/response flow used by the dashboard demo route. |

Startup creates `app/db/traffic.db` if needed. This database contains local activity;
it and SQLite journal/WAL files stay outside source control. Keep your own backup
if the local log history matters. Do not delete the database as part of routine Git
cleanup.
