# IoTGuard backend

FastAPI service for upload inspection and SQLite-backed activity logs. Accepted
classifier inference is a separate integration task; its input contract is in the
[ML inference guide](../ml/docs/architecture/inference_contract.md).

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

| Endpoint | Current behavior |
| --- | --- |
| `POST /files/inspect` | Inspect a nonempty upload of at most 10 MiB and log the event; does not classify traffic. |
| `GET /logs` | Return recent activity, with a `limit` between 1 and 200. |
| `POST /goon` | Existing demonstration request/response flow used by the dashboard demo route. |

Startup creates `app/db/traffic.db` if needed. This database contains local activity;
it and SQLite journal/WAL files stay outside source control. Keep your own backup
if the local log history matters. Do not delete the database as part of routine Git
cleanup.
