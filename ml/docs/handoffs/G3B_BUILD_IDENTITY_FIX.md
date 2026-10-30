# G3B reproducible build and experiment identity repair

Base: clean `main` at `3ff90d3be1a1c0eb380fb3e4d6c50ac0d3f89bf8` in `E:\Document\iotguard-cos30049hn-grp1-5`. Repair branch: `fix/g3b-build-and-experiment-identity`. The local checkpoint containing this document records the final commit (`git log -1 --format=%H -- ml/docs/handoffs/G3B_BUILD_IDENTITY_FIX.md`). No push or merge is included.

## Build repair

`materialize_primary.py` now produces the portable loader, README, standalone verifier, scaler state, canonical contracts and arrays in one invocation. `files` records size and SHA-256 for every payload. `implementation_sha256` covers the builder, verifier, loader, canonical parsing/split/contract code, seeds, source label mapping and README template. These files must exist at preflight and their hashes must still match at completion; otherwise the build remains incomplete. Python/NumPy/scikit-learn versions are recorded. No manual post-build copy or manifest rewrite is needed.

VERIFIED with a bounded real-data integration test: one builder subprocess reads ten rows from each of 89 real primary sources (890 observations) and writes a new temporary SMOKE package. The test checks generated payload and implementation hashes, moves the output to a new directory (old location no longer exists), then loads TRAIN/VALIDATION raw and scaled views in an isolated Python subprocess. `-I -S -B` excludes cwd, PYTHONPATH, user-site and editable-install hooks; the subprocess makes NumPy available directly without loading .pth files. IoTGuard is not importable from the checkout, scikit-learn is not imported, and the only data files consumed are in the moved package. The copied verifier's command interface also executes there. Default TEST loading remains denied.

The smoke package remains SMOKE and is not a training population. The standalone verifier continues to require FULL data. No full materialisation or fresh full-membership rescan was performed for this repair, as requested.

## Experiment identity repair

The API and JSON schema now require:

- `package_version`: nonempty string from the loaded package.
- `package_manifest_sha256`: SHA-256 of the exact received `manifest.json`.
- `dirty_worktree`: explicit boolean for the training checkout, separate from the package's historical build-time Git status.

The selector validates these fields and refuses different package versions, manifest checksums, protocol revisions or TRAIN/VALIDATION population fingerprints. Resolved configuration must agree with the result's protocol revision. Missing identity is rejected even for one candidate. Dirty state may differ between runs but is always recorded. Macro-F1 tolerance 1e-6, then lower FPR, then higher malicious recall, and stable exact ties are unchanged.

Regression tests exercise different package/manifest/protocol/populations, missing identity, invalid hashes/types, required API keywords, schema validation, and existing selection ties. `jsonschema` was added to development dependencies only; the lockfile was updated without upgrading existing core dependencies. Recipient loading still needs only NumPy.

## Validation and commands actually executed

Run from the repository root:

```powershell
uv lock --project ml
uv pip install --python ml/.venv/Scripts/python.exe "jsonschema>=4,<5"
```

Run from `ml/`:

```powershell
.venv/Scripts/python.exe -m pytest -q tests/unit/test_primary_package.py tests/unit/test_experiment_identity.py tests/integration/test_primary_builder_portability.py
.venv/Scripts/ruff.exe check . --output-format concise
.venv/Scripts/python.exe -m pytest -q -ra
```

Results: targeted tests **36 passed**; final full suite **235 passed in 10.82s, 0 failed, 0 skipped, 0 blocked**. Ruff and Git whitespace checks passed. The real-source integration test passed without mocking raw data or removing assertions. If real sources are unavailable on another machine, that integration test explicitly skips with `BLOCKED_BY_EXTERNAL_DATA` and identifies the missing inputs; this is distinct from a unit-test failure and must not be reported as a data-integration PASS.

## Receiving a package

The accepted `E:\Document\iotguard_primary_packages\g3b_primary_v1` package was not modified or rebuilt. Its manifest SHA-256 remains `6ab99e86397242e219bfa1f8490d8e03b169ec87a092af80cb3e7aef1e61147b`; all 80 historical audit artifact hashes remain unchanged. It can still be used as the existing accepted data package. TEAM_VERIFIED still requires a real recipient run.

For a future new full package, the single build command in `primary_experiments_v1.md` writes a complete directory to a new external path. Copy that entire output directory, follow its generated README, install NumPy and run the included verifier. This command is documented for future use and was not run in this repair:

```powershell
# From the copied FULL package directory, using its recipient environment:
.venv/Scripts/python.exe -I -B verify_primary_package.py . --output recipient_verification.json
```

Load TRAIN/VALIDATION via the portable loader as before. Extract the new result identity directly from the manifest/version and actual manifest file checksum; population fingerprints are `TRAIN_metadata.npy` / `VALIDATION_metadata.npy` hashes. Use the complete example in `docs/protocols/primary_experiments_v1.md` for result creation. No manual changes to the accepted package or its manifest are needed to use the stricter experiment API.

No classifier/clustering model was trained. No TEST model evaluation, backend/frontend changes or external project-record updates were performed.
