# Repository layout and contribution boundaries

| Path | Responsibility |
| --- | --- |
| [`ml/`](../ml/README.md) | Dataset contracts, preprocessing, evaluation, frozen model and portable inference. Keep its relative artifact, configuration and source paths together. |
| [`backend/`](../backend/README.md) | HTTP validation, shared predictor and API responses. |
| [`frontend/`](../frontend/README.md) | Dashboard and API client. |
| [`docs/`](.) | Cross-component contracts and integration guides. |

Each component maintains its own dependencies, tests and setup guide. Changes to the [frozen model contract](../ml/docs/architecture/inference_contract.md) or [Manual Analysis response](analysis-response.md) need review from the affected components.

Base new work on current `origin/main`. Review the exact diff and run the checks for the components you changed. Use the [Git tracking policy](git-tracking.md) for datasets, generated payloads, local environments and evidence. The [ML documentation index](../ml/docs/README.md) links to earlier handoffs and current instructions.

For optional contribution reports, see the [Gitinspector guide](gitinspector.md).
