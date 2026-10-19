# Machine learning and dataset audit

This directory is reserved for the reviewed IoTGuard dataset-audit and ML work from the separate local experimentation checkout. No source code or evidence has been transferred into this directory yet.

The intended internal layout preserves the existing local project's relative paths:

```text
ml/
  artifacts/       compact, reviewable audit evidence and versioned contracts
  config/          reproducible configuration examples
  data/            documentation and lightweight manifests only
  docs/            audit, preprocessing, and evaluation protocols
  scripts/         audit and verification entry points
  src/iotguard/    installable Python package
  tests/           focused checks for the ML package
  pyproject.toml   ML package dependencies and test configuration
```

Raw N-BaIoT and Bot-IoT sources and extracted or observation-scale working files remain outside the repository. Keep the adopted G3A TEST partition sealed when continuing model work: fit data-dependent transformations on TRAIN only, use VALIDATION for selection, and access TEST only after the candidate is frozen.

Transfer reviewed files by path into `ml/`, then update any machine-specific paths and verify the package from this location before committing. The FastAPI and frontend code remain in their own directories; integration should use an explicit, versioned inference contract.
