# IoTGuard

IoTGuard is a group project for classifying structured IoT network traffic. N-BaIoT is the primary dataset; Bot-IoT is used for separate supporting experiments. The application combines a machine-learning pipeline, a FastAPI backend, and a React frontend.

## Repository layout

| Path | Purpose |
| --- | --- |
| `ml/` | Dataset audit, data contracts, preprocessing, experiments, evaluation, and the versioned inference package. |
| `backend/` | FastAPI service and application integration. |
| `frontend/` | React/Next.js user interface. |
| `docs/` | Shared repository and integration decisions. Component-specific documentation stays with its component. |

See [repository layout](docs/repository-layout.md) for boundaries and the process for bringing reviewed work into this repository.

## Run the application

Start the [FastAPI backend](backend/README.md) and [Next.js frontend](frontend/README.md)
in separate terminals. The frontend uses npm and its committed `package-lock.json`.
It connects to `http://127.0.0.1:8000` by default; see the frontend guide for local
configuration. The dashboard is at `http://localhost:3000/dashboard`.

The application currently supports upload inspection and log viewing. Connecting the
accepted classifier to the web application remains separate integration work.

## ML and contribution guides

- [ML setup and workflow](ml/README.md)
- [Current ML status and historical documentation](ml/docs/README.md)
- [Accepted classifier and portable inference handoff](ml/docs/handoffs/A2_CLASSIFIER_EVALUATION.md)
- [Git tracking policy](docs/git-tracking.md)
- [Optional Git contribution reports](docs/gitinspector.md)

Raw datasets, data packages, environments, and new large experiment payloads belong
outside Git. Existing tracked experiment arrays remain in place until an independently
verified artifact migration is complete. Compact contracts, manifests, and evidence
remain versioned; see the tracking policy before adding or removing generated files.
