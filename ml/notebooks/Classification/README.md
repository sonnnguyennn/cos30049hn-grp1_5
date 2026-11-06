# RF and XGBoost on Kaggle

These notebooks use the repository training scripts. Both use the approved G3B
manifest SHA-256
`6ab99e86397242e219bfa1f8490d8e03b169ec87a092af80cb3e7aef1e61147b`.
The scripts import the loader from the reviewed source checkout and verify the
package before fitting. They fit on TRAIN and evaluate on VALIDATION.

1. Import the notebook into a private Kaggle notebook and attach the existing
   G3B dataset. Set `PACKAGE_DIRECTORY` to the folder containing `manifest.json`.
2. With Internet enabled, prepare the reviewed source checkout in a notebook
   setup cell. Replace the placeholder with the reviewed PR or merge commit.

   ```bash
   git clone --filter=blob:none --sparse https://github.com/sonnnguyennn/cos30049hn-grp1_5.git /kaggle/working/iotguard
   cd /kaggle/working/iotguard
   git sparse-checkout set ml/config ml/scripts ml/src ml/notebooks/Classification
   git checkout --detach <reviewed-commit>
   python -m pip install -r ml/notebooks/Classification/requirements.txt
   ```

   In a Python notebook, use a separate `%%bash` cell for these commands.
   Restart the kernel if Kaggle prompts for it after installing dependencies.
3. Run the configuration and preflight cells and confirm the printed source
   revision and manifest. For a quick smoke, set `FRACTION = 0.0001` and
   `RUN_TRAINING = True`. Keep the default two CPU threads. Execute each notebook
   from its first cell. The fraction changes the TRAIN subset only.
4. Retain `result.json`, `package_verification.json` and `run_notes.json` from
   the fresh output directory printed by each notebook. The result should have
   schema `primary_result_v1`, `diagnostic_only: true`, the reviewed source
   revision and the actual subset fingerprint. Check the verification receipt
   lists TRAIN and VALIDATION and records `TEST_opened: false`.

The [A2 evaluation handoff](../../docs/handoffs/A2_CLASSIFIER_EVALUATION.md)
remains the reference for the accepted Full comparison and frozen final TEST.
