# IoTGuard

> **Internal engineering documentation â€” not assessment submission content.**

**Topic:** Network Traffic Classification for Anomaly Detection

## Engineering objective

Build a reproducible network-traffic machine-learning pipeline, evaluate supervised and unsupervised approaches, package a final inference pipeline, evaluate edge feasibility on Raspberry Pi 4, and integrate the final Assignment 2 model with a React/FastAPI application.

## Delivery paths

Core path:

`dataset â†’ preprocessing â†’ ML evaluation â†’ packaged inference â†’ FastAPI â†’ React`

Parallel edge path:

`candidate/final models â†’ Raspberry Pi compatibility â†’ latency/resource benchmark`

Raspberry Pi evaluation is important, but it must not block the core Assignment 2 â†’ Assignment 3 path. Raw datasets remain outside this Git repository. ADR-001 assigns N-BaIoT as the primary dataset and Bot-IoT as the secondary dataset for this project-specific workflow.

## Current status

- **G1 complete, independently verified, accepted, and committed:** A0 source/protocol freeze
  through A7 dataset-role decision; N-BaIoT is primary and Bot-IoT is secondary
- **G2 complete, independently verified, and committed:** G2A/G2B implement contracts and
  parsers; G2C reconciles the complete primary corpus and closes the canonical data layer
- **G3 in progress:** G3A's fixed primary split is ADOPTED and independently verified across all
  7,062,606 rows; TEST is SEALED. G3B primary preprocessing and independent data handoff are now verified

The read-only A1-A4 evidence is stored under `artifacts/manifests/` and `artifacts/audit/`;
extracted N-BaIoT working files remain outside the repository. A4 measures lexical and
numeric quality, exact duplicate groups, and record lineage without cleaning data or choosing
predictors, a split, or dataset roles. Its `PASS` status means the audit completed and
reconciled; it does not mean the datasets contain no quality or duplicate findings. A5 remains
diagnostic: it may simulate candidates but cannot adopt a split or predictor set.
A6 compares both datasets against the fixed project requirements without a numeric score, winner,
role assignment, final split, or final predictor decision.
A7 applies a requirements gate without numeric scoring. N-BaIoT passes the P1-P3 primary gates;
Bot-IoT remains required for at least one bounded secondary ML experiment. ADR-001 does not adopt
a final split, predictor set, preprocessing policy, clustering algorithm, or model.
G2A locks version `1.0.0` source, feature-order, label, record, field-role, exact-vector grouping,
and lexical port contracts. It does not materialize processed data or fit any transform.
G2B implements strict streaming parsers and bounded smoke verification without splitting,
deduplicating, fitting, resampling, encoding a final matrix, or training.
G2C validates all 89 primary logical sources and 7,062,606 observations without materializing a
processed dataset. Stable row identity, deterministic traversal, record digests, secondary header
and port behavior, and source immutability are independently verified.

## Quick start

Run these commands from the team repository's `ml/` directory (`Set-Location ml`). Use Python 3.11 or newer. Copy `config/data_paths.example.yaml` to the ignored `config/data_paths.local.yaml` only when machine-local paths differ.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python scripts/check_environment.py
python scripts/check_data_paths.py
pytest
```

Do not place raw datasets, generated model files, secrets, or assessment prose in this repository.

Historical audit evidence is preserved byte-for-byte from the source checkout. Some historical records include absolute Windows paths; use CLI arguments, documented environment variables, or ignored local YAML for current paths. The bounded G2/G3 tools also recover historical roots from evidence by default; override their documented root arguments or G3A `--n-baiot-raw-root`, `--n-baiot-extracted-root`, and `--bot-iot-root` arguments when relocating datasets. See `docs/handoffs/G3A_IMPORT_HANDOFF.md` for migration validation and limitations.

## G3B primary data package

The full primary package is READY_FOR_TEAM after independent relocated loading; TEAM_VERIFIED awaits a recipient run. See [G3B handoff](docs/handoffs/G3B_PRIMARY_DATA_HANDOFF.md) for exact package paths, checksums, commands and raw/scaled loading. The package is stored outside Git. Classification, clustering and final inference packaging remain pending.
