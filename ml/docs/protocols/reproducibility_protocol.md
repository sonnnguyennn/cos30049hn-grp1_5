# Reproducibility protocol

> Internal template; complete per experiment or release.

## Environment capture

- OS, architecture, Python, package manager, and dependency versions
- Hardware relevant to timing or numerical behavior
- Code revision and clean/dirty workspace state

## Determinism

- Record Python, NumPy, scikit-learn, and algorithm-specific seeds
- Record deterministic/non-deterministic settings and known limitations
- Preserve the exact resolved configuration

## Data and artifacts

- Reference immutable dataset manifests and provenance
- Hash preprocessors, models, feature schemas, and packaged bundles with SHA-256
- Retain raw evaluation outputs; never retain only rounded summary metrics
- Version preprocessing and model artifacts together and validate compatibility

## Inference parity

- Maintain test vectors for valid, boundary, missing, and invalid inputs
- Run the same vectors through offline, CLI, API, and edge paths
- Record expected outputs, tolerances, runtime versions, and failure behavior
