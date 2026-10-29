# G1-G3A foundation import handoff

Date: 2026-10-29. Outcome: PASS for migration and focused verification.

## Source and checkpoint

- Source: `E:\Document\iotguard`, local `master`, HEAD `df57739ebb5573655ba6fb371770c1192087b304`, no remote. Imported the working tree, including uncommitted G3A files, rather than HEAD alone. Source files and Git status were preserved.
- Destination: `E:\Document\iotguard-cos30049hn-grp1-5\ml`, branch `chore/import-g3a-ml-foundation`, based on `origin/main` commit `745039322c24683782486b3418f2294eb340f7c1` (0 ahead / 0 behind at preflight).
- The migration checkpoint is the commit containing this handoff. Obtain its exact hash with `git log -1 --format=%H -- ml/docs/handoffs/G3A_IMPORT_HANDOFF.md`; an external commit receipt is also saved beside the backup. This avoids embedding a commit's own hash in its contents.
- External recovery snapshot: `E:\Document\iotguard_import_backups\20261029_151059\source_snapshot.zip`. The same directory contains the original Git status, binary diff, source HEAD, import hash manifest, and fresh bounded-check outputs.
- Imported 194 source files: artifacts, config, managed data documentation/placeholders, protocols, scripts, package, tests, packaging metadata, dependency lock, and environment examples. Excluded assessment PDF/proposal HTML, source Git internals, environments, caches, raw data, and working databases. Backend and frontend have no changes.

## Accepted state

G1/A0-A7 and G2A/G2B/G2C retain their historical verified completion state. G3A remains ADOPTED and independently verified historically; G3B has not started. All 80 imported artifact files retain their source bytes. Historical verification timestamps, absolute source paths, and hashes were preserved; no full-corpus results were regenerated.

N-BaIoT is primary: 7,062,606 records, 115 ordered numeric fields. Bot-IoT is secondary, using four All-features 5% shards under the G2A source contract. The datasets remain separate.

The adopted `primary_split_v1` uses numeric-equivalence groups and unchanged binary64/SHA-256 membership rules. TRAIN has 4,944,968 rows, VALIDATION 1,056,372, TEST 1,061,266. TEST remains SEALED; learned transformations fit on TRAIN only. Final predictors, preprocessing, models, and thresholds remain pending.

## Fresh validation

- Clean Python 3.11.15 environment created from `ml/pyproject.toml` with development dependencies, without copying the source environment. The editable import resolves to `ml/src/iotguard`; no backend/frontend execution is needed.
- `python -m pytest -q`: **199 passed, 0 failed, 0 skipped, 0 blocked**. Imported baseline also passed 199 tests. Configuration tests now assert the accepted dataset roles and binary target instead of obsolete undecided defaults.
- `ruff check . --output-format concise`: PASS before and after migration repairs; no pre-existing lint findings or new findings.
- G2A independent contract checks: PASS. Its write function was redirected to an external fresh report; input contract paths and verification logic were unchanged.
- G2B real-source parser smoke: PASS, three rows from each of three primary and two secondary sources. Output saved externally.
- G2C bounded validation: PASS, using original bounded traversal checks with output writes redirected externally. Full primary dry validation was not requested.
- G3A driver and independent verifier: both passed in bounded mode, ten records from each of 89 sources (890 records). Both produced membership digest `ffa77fe572465f5772524e229b7800db95ab1f61caf1fb0c598481205a3767b3`, with 613 TRAIN, 112 VALIDATION, 165 TEST; zero group overlap or label conflicts in this sample. Source metadata matched the baseline. These are reproducibility checks, not model evaluation or a fresh full-corpus proof.
- Original datasets and extracted primary files were available. No required focused check was blocked by external data. Full 7,062,606-row rescans were deliberately not run; historical whole-corpus evidence remains authoritative for those historical runs.
- File completeness, source immutability, artifact hashes, and staged-file safety were checked. Git attributes disable text normalization for artifacts so their bytes survive future checkouts.

See `G3A_IMPORT_VALIDATION.json` for the source hash manifest, intentional changes, and bounded results. Fresh logs and JSON outputs are retained with the external recovery snapshot.

## Migration repairs and operation

Commands run from `ml/`. Updated stale config/documentation to reflect ADR-001 and the adopted split, fixed one command's old checkout output path, and added explicit source-root CLI arguments to both G3A scripts. The split implementation, membership hashing, labels, feature order, and accepted contract were unchanged. Historical default paths are retained for compatibility; other machines should supply the three root arguments shown below. Matching the original file metadata is still required by locked provenance checks; changing a path does not waive that gate.

```powershell
Set-Location ml
uv venv --python 3.11 .venv
uv pip install --python .venv/Scripts/python.exe -e ".[dev]"
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/ruff.exe check .
.venv/Scripts/python.exe scripts/run_g3a_primary_split.py --max-rows-per-source 10 --n-baiot-raw-root E:/Document/N_BaIoT_Dataset --n-baiot-extracted-root E:/Document/iotguard_dataset_work/n_baiot_extracted --bot-iot-root E:/Document/Bot_IoT_Dataset
```

The independent bounded verifier accepts the same root arguments plus `--work-dir` pointing to a new external directory. Its default work directory may contain accepted existing SQLite state, so explicitly choose a fresh directory. Several historical verification scripts write evidence by default; redirect fresh output externally as done during this import instead of overwriting accepted reports.

## Readiness, remaining work, and Jira handoff

The imported foundation is ready for the team to begin G3B planning and controlled ML experimentation. Before fitting, freeze the candidate feature/preprocessing policy, validation-based selection procedure, and experiment configuration. Preserve the TEST seal. No classifier, clustering model, or final inference package exists yet.

No migration blocker remains on this machine. Portability limits: datasets are external, metadata checks are tied to the accepted sources, and contract loading currently assumes a source/editable installation with repository artifacts. A standalone wheel/inference distribution requires later packaging work.

Jira coordination below uses logical gate names only; no Jira issues were queried or modified and no issue keys or statuses are asserted:

- Candidates for Done after evidence review: G1/A0-A7, G2A/G2B/G2C, and G3A implementation/verification.
- In Progress: the overall G3 evaluation/model-work gate; G3A is complete but subsequent work remains.
- Not started: G3B learned preprocessing and experiment design, classification baselines/tuning, clustering, bounded secondary-dataset ML experiments, final evaluation/model selection, and versioned final inference packaging. Application integration and Pi benchmarking remain later work.

The migration is committed locally on the dedicated branch. Remote push and merge are separate actions requiring user authorization for this checkpoint.
