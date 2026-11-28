# IoTGuard frontend

The Next.js dashboard uses the [FastAPI backend](../backend/README.md) for Manual Analysis.

## Run locally

Start the backend, then run these commands from `frontend/` with Node.js 20.9 or later and a compatible pnpm version:

```powershell
pnpm install --frozen-lockfile
pnpm dev
```

Open the [dashboard](http://localhost:3000/dashboard). Manual Analysis is at [`/dashboard/prediction/manual-analysis`](http://localhost:3000/dashboard/prediction/manual-analysis). Follow the [upload guide](../docs/csv-upload-api-guide.md) to try a sample CSV or JSON file.

The backend URL defaults to `http://127.0.0.1:8000`. To override it, set `NEXT_PUBLIC_API_URL` in `frontend/.env.local` and restart the dev server. The local backend allows frontend origins on port 3000 at `localhost` and `127.0.0.1`.

## Checks

From `frontend/`, run `pnpm lint` or `pnpm build`.
