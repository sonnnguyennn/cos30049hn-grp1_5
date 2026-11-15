# Export TEST data for web uploads

From the repository root:

```bash
ml/.venv/bin/python ml/scripts/export_test_upload.py
```

This exports 1,000 real rows sampled without replacement from the N-BaIoT **TEST**
partition, using seed 42. The default source is `../g3b_primary_v1` beside the
repository. It verifies the published package identity and TEST checksums, preserves
the 115 raw feature columns in the classifier's order, and performs no inference
or training. Only NumPy is required beyond the Python standard library.

Files are saved in `ml/data/samples/test-upload/`:

| File | Purpose |
| --- | --- |
| `test_input.csv` | Upload this to the website. Features only, with a header. |
| `test_input.json` | Alternative upload containing the identical rows as `feature_order` and `rows`. |
| `expected_labels.csv` | Actual benign/malicious labels and source coordinates for checking results. Do not upload this as feature data. |
| `export_manifest.json` | Source verification, selection settings, class counts and output filenames. |

Choose either the CSV or JSON; uploading both repeats the same observations.
Match each returned prediction's 1-based `row` to `expected_labels.csv`. For multiple
upload pairs, also match `upload_stem` to the input filename without its extension.
The `test_index` field is the original 0-based TEST array index.

To show names and ground truth directly in the website, include upload metadata:

```bash
ml/.venv/bin/python ml/scripts/export_test_upload.py --include-metadata --out ml/data/samples/test-detailed
```

This appends `sample_name` and `ground_truth` CSV columns and adds the same values
in a JSON `sample_metadata` array. The backend keeps metadata separate from model
features and reports per-row matches plus accuracy over the supplied labels.
See the [analysis response contract](../../../docs/analysis-response.md).

Change the sample size, seed or source location:

```bash
ml/.venv/bin/python ml/scripts/export_test_upload.py --rows 5000 --seed 7 --out ml/data/samples/test-5000
ml/.venv/bin/python ml/scripts/export_test_upload.py --package /path/to/g3b_primary_v1 --out ml/data/samples/test-other
```

The output directory must be new; previous exports are preserved. The default
sample follows the TEST class distribution approximately; it is not deliberately
balanced. The manifest reports the actual class counts.

To export **only benign traffic**, filtered by the original dataset labels:

```bash
ml/.venv/bin/python ml/scripts/export_test_upload.py --traffic-class benign --include-metadata --out ml/data/samples/test-benign
```

This creates 1,000 benign TEST examples in matching CSV and JSON files, with sample
names and ground truth for the website. Use `--traffic-class malicious` for attack-only
examples, or combine the filter with `--all` to export all TEST rows of that class.
Rows are selected by dataset labels, independently of the model's predictions.

To export the entire TEST split:

```bash
ml/.venv/bin/python ml/scripts/export_test_upload.py --all --out ml/data/samples/test-full
```

Large exports are split into `test_input_001.csv`, `test_input_001.json`, etc., with
at most 10,000 rows per pair. Change this with `--chunk-size 2000` (range 1–10,000).
The full split has over a million rows, so exporting both formats takes more time
and disk space. Each pair can be uploaded separately under the backend's default
100 MiB / 100,000-row limits; check any smaller hosting or custom limits.

On Windows, replace `ml/.venv/bin/python` with `ml\.venv\Scripts\python.exe`.
