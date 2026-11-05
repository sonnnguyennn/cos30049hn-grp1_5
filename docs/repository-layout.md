# Repository layout and contribution boundaries

The top level has four areas: `ml/`, `backend/`, `frontend/`, and `docs/`. Each component keeps its own dependencies, tests, and detailed documentation. `docs/` holds decisions that affect more than one component, especially the inference request/response contract and integration instructions.

Reviewed dataset-audit and ML work lives under `ml/`; its relative `artifacts/`,
`config/`, `data/`, `docs/`, `scripts/`, `src/`, and `tests/` paths stay together.
The original foundation import is recorded in the ML historical handoffs. New work
can use a topic branch or isolated worktree based on current `origin/main`; a separate
source checkout is not required. Each Python component keeps its own `pyproject.toml`.

Before merging a contribution, compare it with current `origin/main`, review the exact file list and diff, and run checks relevant to the changed component. Bring across only source, documentation, configuration examples, and compact evidence needed for reproducibility. Do not copy a checkout's `.git` directory, virtual environment, raw datasets, extracted data, temporary indexes, secrets, or observation-scale outputs.

The ML package provides an accepted classifier, a versioned input contract, and a
portable technical inference handoff. See the [inference contract](../ml/docs/architecture/inference_contract.md).
Connecting that predictor to FastAPI is separate application work. The backend owns
HTTP validation and responses; the frontend calls that API. A change to the shared
contract needs coordinated review across the affected components.

Use the [Git tracking policy](git-tracking.md) for payload, lockfile, notebook, and
historical evidence rules. Use the [ML documentation index](../ml/docs/README.md) to
distinguish current instructions from records of earlier checkpoints.
