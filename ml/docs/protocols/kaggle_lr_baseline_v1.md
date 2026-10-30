# Kaggle LR + Dummy baseline extension v1

Status: IMPLEMENTED, NOT_RUN on Kaggle. This extension uses the primary_experiments_v1 metrics, data identity and validation rules without changing the adopted G3A split, 115 features, observation weighting, TRAIN-only scaler, or TEST seal.

Two execution modes use the same original FULL primary package, pinned to manifest SHA-256 `6ab99e86397242e219bfa1f8490d8e03b169ec87a092af80cb3e7aef1e61147b`:

- Smoke: deterministic stratified subsets of 50,000 existing TRAIN rows (seed 42) and 10,000 existing VALIDATION rows (seed 43). These are diagnostics, not an adopted evaluation population. Save indices and derived population fingerprints; never mix them into official full-population comparisons.
- Full: all 4,944,968 TRAIN and 1,056,372 VALIDATION rows, unchanged. Requires a successful smoke receipt with matching data manifest, exact exported code-bundle hash, and run configuration (iteration budget, thread limit, chunk size and diagnostic sizes).

DummyClassifier uses most_frequent and random_state=42; its predictions ignore features. LogisticRegression uses lbfgs, C=1.0, class_weight=None, tol=1e-4, max_iter=1000, random_state=42. lbfgs with finite C supplies the L2 baseline in supported sklearn versions. The runner exports the actual estimator parameters and runtime versions, rather than assuming a dependency's defaults are stable. The iteration and diagnostic population settings are locked; changing them requires a reviewed protocol/bundle revision and a matching new smoke. Resource options default to four threads and 8,192-row chunks and are recorded explicitly. Canonical seed config must still be 42 for Python/NumPy/scikit-learn.

All fitting runs on Kaggle through the guarded runner. Local work is syntax, provenance, packaging, diagnostic-index tests and review only; no local estimator fitting is needed to validate integration. This workflow does not upload or publish anything automatically.

LR consumes a disk-backed C-ordered float64 scaled TRAIN cache using the already fitted package scaler. Full preflight budgets at least two scaled-matrix sizes plus 1 GiB available RAM, and cache size plus 1 GiB free disk. A budget failure is BLOCKED_RESOURCE, with no automatic fallback to a subset, float32, alternate solver or SGD. Normal completion/failure cleans only the per-run cache under /kaggle/working. A hard interruption may leave an incomplete cache; never treat it as successful or reuse it manually.

Predict VALIDATION in chunks, but calculate metrics globally from all validation probabilities. Threshold stays 0.5. Serialize and reload each model and compare prediction probabilities. TEST is never loaded for model fitting/evaluation; checksum reads of its payload are mechanical integrity checks only.

Nonconverged LR results are diagnostic_only=true and eligible_for_official_comparison=false, written separately from official result files. A full run is BASELINES_COMPLETE only if both baselines complete with accepted convergence. SMOKE_PASS is never eligible for official comparison. No tuning or retry-policy change may be justified after looking at scores without a protocol revision.

Source identity comes from the bundle exporter: actual Git revision, actual dirty-worktree boolean and exact source hashes. Results bind the original data manifest, package version, primary protocol revision, population fingerprints and exported bundle manifest checksum. A source edit invalidates the release identity and requires rebuilding the external ZIP; never rewrite historical experiment receipts. READY_TO_RUN code is not evidence of a successful Kaggle run or of model quality.
