# 4.4.1-4.4.3 clean-environment check on Windows - PASS

Run with `scripts/t44_handoff_check.ps1` on Windows 11 Pro 10.0.22631, PowerShell 5.1,
Miniconda (conda 26.9.4) at `D:\miniconda3`. The bundle was extracted into a new folder and a
NEW Conda environment `duy-iotguard-check-06` was created from the bundle's `environment.yml`.

| Run | Result | Cause |
|---|---|---|
| 01 | FAIL before the check | wrong `-HandoffZip` path (ZIP not found) |
| 02 | FAIL before the check | `conda.exe` not found in that PowerShell |
| 03 | FAIL at env create | Miniconda's default Anaconda channels required Terms of Service acceptance |
| 04 | FAIL before the check | `conda.exe` not found (VS Code terminal) |
| 05 | FAIL at env create | same Terms of Service block as run 03 |
| **06** | **PASS** | after removing `defaults` from `D:\miniconda3\.condarc`, so only conda-forge is used, as the bundle's `environment.yml` specifies |

None of runs 01-05 reached a bundle check that failed; all were local setup problems.
Nothing in the bundle, manifest, model or example files was edited.

Run 06 evidence (`evidence_06/`):

* ZIP SHA-256 `6ff11f67d25c75822b51936cfa22a7746b6a28ed7f2cc4de7b39cfee89ed6d77` (published value)
* manifest.json SHA-256 `9fac1acde3f696bb765937c997977b3d7b1e1c2fa6cd60626e910037ea1fe132` (published value)
* environment: channel conda-forge only; Python 3.11.18, numpy 2.4.6, xgboost 3.2.0, scipy 1.17.1
  (`conda_env_create.stdout.txt`, `conda_list.stdout.txt`, `pip_freeze.stdout.txt`)
* `predict_primary.py --verify`: status PASS, model SHA-256
  `cb090afa6ad4c3618e20d7c5d635e89aa2d122667ea00835a0acc2f75a4455e6`, no raw dataset or git checkout
  required, no classifier fitted (`duy_verification_06.json`)
* `predict_primary.py --input example_input.json`: labels `[benign, malicious, benign]`,
  predictions `[0, 1, 0]`, probabilities equal to `example_expected.json` within 1e-12; the third
  example is the documented false negative (`duy_predictions_06.json`, `comparison_06.json`,
  15/15 checks in `compare.stdout.txt`)

Remaining errors: none.

`failed_runs/` keeps the checklists and transcripts of runs 01-05. The final group package check
(4.4.4) is separate and still waits for the group package.
