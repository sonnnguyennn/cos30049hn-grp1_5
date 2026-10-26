# Repository layout and contribution boundaries

The top level has four areas: `ml/`, `backend/`, `frontend/`, and `docs/`. Each component keeps its own dependencies, tests, and detailed documentation. `docs/` holds decisions that affect more than one component, especially the inference request/response contract and integration instructions.

The dataset-audit and ML work is developed and checked in a separate local checkout. Reviewed files enter this repository under `ml/`; its existing relative `artifacts/`, `config/`, `data/`, `docs/`, `scripts/`, `src/`, and `tests/` paths stay together. This avoids conflicts with `backend/` and `frontend/` and lets the ML package keep a separate `pyproject.toml`.

Before merging a contribution, compare it with current `origin/main`, review the exact file list and diff, and run checks relevant to the changed component. Bring across only source, documentation, configuration examples, and compact evidence needed for reproducibility. Do not copy a checkout's `.git` directory, virtual environment, raw datasets, extracted data, temporary indexes, secrets, or observation-scale outputs.

The ML package will provide a versioned predictor and feature contract to the FastAPI backend. The backend owns HTTP validation and responses; the frontend calls that API. A change to the shared contract needs coordinated review across the affected components.
