# IoTGuard primary package v1

Copy the entire directory produced by the builder. It includes this README, portable loader, standalone verifier, scaler state, contracts, manifest, and partition arrays. No post-build file copying or manifest editing is required. Use Python 3.11+ and NumPy; loading does not require the original raw datasets, local configuration, IoTGuard installation, or scikit-learn.

From the copied package directory:

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install "numpy>=1.26,<3"
.venv/Scripts/python.exe -I -B verify_primary_package.py . --output recipient_verification.json
```

The standalone verifier checks a FULL package: payload checksums, counts, TRAIN-only scaler moments, and full deterministic membership. It does not evaluate a model. Smoke builds are explicitly marked SMOKE, are not official training populations, and are rejected by the default loader and full verifier. For development smoke-loading only, use `PrimaryPackage('.', verify=True, allow_smoke=True)`.

```python
from primary_package import PrimaryPackage, sha256_file

p = PrimaryPackage('.', verify=True)
X_train, y_train, metadata = p.load('TRAIN')
X_validation, y_validation, _ = p.load('VALIDATION')
assert X_train.shape == (4944968, 115)
assert X_validation.shape == (1056372, 115)
for X_chunk, y_chunk in p.chunks('TRAIN', scaled=True, chunk_size=4096):
    pass  # Consume with the future training routine; do not concatenate by default.
# Optional streaming readable export (can be large):
# p.export_csv('VALIDATION', 'validation.csv')

package_version = p.manifest['package_version']
package_manifest_sha256 = sha256_file(p.root / 'manifest.json')
train_population_sha256 = p.manifest['files']['TRAIN_metadata.npy']['sha256']
validation_population_sha256 = p.manifest['files']['VALIDATION_metadata.npy']['sha256']
```

X contains exactly the 115 ordered float64 predictors, benign=0 and malicious=1. Metadata contains source-table index and 1-based source row; original taxonomy and device labels remain in the manifest source table and contracts. Preserve observations and row weighting. Scaled views use saved TRAIN-only statistics. TEST is SEALED and denied by default; explicit mechanical preparation does not authorize model selection on TEST.

Future experiment results must record package version, exact manifest SHA-256, training code revision, boolean dirty-worktree status, protocol revision, resolved configuration/seeds, and both population fingerprints. Use the team repository's shared experiment API/schema. Successful isolated loading establishes READY_FOR_TEAM; TEAM_VERIFIED requires Hiếu or Minh Sơn to run verification on their machine.
