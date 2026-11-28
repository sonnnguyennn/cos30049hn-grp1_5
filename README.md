# IoTGuard

IoTGuard classifies IoT traffic from structured features. N-BaIoT is the primary dataset. Bot-IoT supports separate experiments.

| Area | Start here |
| --- | --- |
| FastAPI service | [Backend setup](backend/README.md) |
| Next.js dashboard | [Frontend setup](frontend/README.md) |
| Model, datasets and experiments | [ML setup](ml/README.md) and [current status](ml/docs/current-status.md) |
| Cross-component changes | [Repository layout](docs/repository-layout.md) and [Git tracking policy](docs/git-tracking.md) |

## Run the application

Start the backend and frontend in separate terminals, then open the [dashboard](http://localhost:3000/dashboard). The frontend calls the backend at `http://127.0.0.1:8000` by default.

Manual Analysis uploads a CSV or JSON file to `POST /predict`. It requires 115 pre-extracted features in the frozen order. Use the [upload guide](docs/csv-upload-api-guide.md) for a quick check and the [response contract](docs/analysis-response.md) for report fields.

The backend also provides live sessions for predictions made on the Pi. Follow the [API and installation guide](docs/api-and-install-guide.md) to create a session, send example events and poll the results. The [live monitoring contract](docs/live-api-contract.md) defines the data and retry rules. The Pi client and Replay UI still need an end-to-end integration check.

The [A2 classifier handoff](ml/docs/handoffs/A2_CLASSIFIER_EVALUATION.md) records the accepted model and evaluation.
