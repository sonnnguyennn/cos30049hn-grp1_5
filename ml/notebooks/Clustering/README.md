# Run training, evaluation, and replay

Install Python 3.11 or 3.12 and keep at least **15 GiB of free disk space**.
Open a terminal in this project folder, where `requirements.txt` is located.

## 1. Create and activate a virtual environment

Run the commands for your operating system.

**Windows — Command Prompt**

```bat
py -m venv .venv
.venv\Scripts\activate.bat
```

**Windows — PowerShell**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use Command Prompt and its commands above.

**macOS — Terminal**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Linux — Terminal**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Ubuntu, Debian, or Linux Mint, if `venv` is missing, run
`sudo apt install python3-venv`, then try again.

## 2. Install dependencies

With the virtual environment active, run these commands on any OS:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m ipykernel install --sys-prefix --name iot-clustering --display-name "IoT clustering (.venv)"
```

## 3. Run the notebooks

Leave `experiment_config.json` as supplied. Training downloads the dataset from the
configured Drive link if the local copy is missing. If your dataset is elsewhere,
set `package_dir` to the folder containing `primary_package.py`.

Start JupyterLab from this project folder:

```bash
python -m jupyterlab
```

1. Open `01_Training.ipynb` and select **IoT clustering (.venv)** as the kernel.
2. Choose **Run → Run All Cells** and wait for training to finish.
3. Open `02_Evaluation.ipynb`, select the same kernel, and run all cells.

Keep the same configuration for both notebooks. Models and results are saved in
`outputs/<experiment_id>/`, using `experiment_id` from the configuration file.
For a fresh training run or to recover from interrupted training, choose a new
`experiment_id` before running both notebooks again.

Next time, activate `.venv` with the command for your OS, then run
`python -m jupyterlab`. You do not need to repeat installation.

## 4. Replay saved predictions

Finish `01_Training.ipynb` first. Keep the complete `full/` output folder and the
original dataset package. Replay uses the saved models to regenerate every TRAIN
and VALIDATION cluster assignment, then checks for an exact match with the originals.

Open a terminal in this project folder and activate `.venv` using step 1.
Run this command on Windows, macOS, or Linux:

```bash
python replay_predictions.py --run-dir outputs/clustering_001/full --output-dir replay_check_002
```

- Replace `clustering_001` with the experiment folder you want to check.
- `--run-dir` must point to its `full` folder, containing `configuration.json`,
  `package_identity.json`, `run_index.json`, and the model folders.
- Each model folder must include `model.joblib`, `TRAIN_clusters.npy`, and
  `VALIDATION_clusters.npy`.
- `--output-dir` must be a **new folder**. Choose a different name for each replay.

If the dataset has moved, add `--package-dir` with the folder containing
`primary_package.py`. It must be a copy of the same dataset used for training:

```bash
python replay_predictions.py --run-dir outputs/clustering_001/full --output-dir replay_check_003 --package-dir "../primary_package"
```

Replay reads the saved `full/configuration.json`, so changing the top-level
`experiment_config.json` does not change its settings.

When every prediction matches, the terminal prints:

```text
Replay passed: all saved cluster assignments match exactly.
```

The new output folder contains:

- `<run_id>_TRAIN_clusters.npy` and `<run_id>_VALIDATION_clusters.npy` for each model.
- `replay_receipt.json`, with `exact_prediction_match: true` for every model and split.

Open the receipt or print it in the terminal:

```bash
python -m json.tool replay_check_002/replay_receipt.json
```

If replay fails, fix the reported problem and rerun with a new output folder.
