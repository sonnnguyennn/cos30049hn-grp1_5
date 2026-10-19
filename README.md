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

Raw datasets, extracted working data, local environments, and generated large artifacts stay outside Git. The existing backend and frontend are early scaffolds; their interfaces and deployment instructions will be documented as they mature.
