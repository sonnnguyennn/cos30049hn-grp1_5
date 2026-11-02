"""Export only code/notebooks for Bot-IoT secondary Kaggle runs; never fit models."""

import argparse
import ast
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

from iotguard.experiments.kaggle_secondary_v2 import BUNDLE_ID, PACKAGE_SHA, configuration

ML = Path(__file__).resolve().parents[1]
SOURCES = {
    "kaggle_secondary_runner.py": "src/iotguard/experiments/kaggle_secondary_v2.py",
    "vendor/bot_iot_package_v2.py": "src/iotguard/data/bot_iot_package_v2.py",
    "protocols/bot_iot_secondary_kaggle_baseline_v1.md": ("docs/protocols/"
        "bot_iot_secondary_kaggle_baseline_v1.md"),
    "protocols/bot_iot_secondary_experiment_v2.md": ("docs/protocols/"
        "bot_iot_secondary_experiment_v2.md"),
    "contracts/bot_iot_secondary_ml_v2.json": "artifacts/contracts/bot_iot_secondary_ml_v2.json",
    "README.md": "docs/experiments/kaggle_bot_iot_secondary_v2.md",
    "requirements.txt": "notebooks/kaggle/bot_iot_secondary_v2/requirements.txt",
    "01_Bot_IoT_Secondary_Smoke.ipynb": ("notebooks/kaggle/bot_iot_secondary_v2/"
        "01_Bot_IoT_Secondary_Smoke.ipynb"),
    "02_Bot_IoT_Secondary_Full.ipynb": ("notebooks/kaggle/bot_iot_secondary_v2/"
        "02_Bot_IoT_Secondary_Full.ipynb"),
}


def build(output):
    output = Path(output).resolve()
    if output.is_relative_to(ML.parent) or output.exists():
        raise ValueError("Use a fresh external ZIP path")
    files = {name: (ML / source).read_bytes() for name, source in SOURCES.items()}
    for name, content in files.items():
        if name.endswith(".py"):
            ast.parse(content, filename=name)
        if name.endswith(".ipynb"):
            notebook = json.loads(content)
            if notebook["nbformat"] != 4:
                raise ValueError("Notebook format must be4")
            for index, cell in enumerate(notebook["cells"]):
                if cell["cell_type"] == "code":
                    if cell["execution_count"] is not None or cell["outputs"]:
                        raise ValueError("Export only unexecuted notebooks")
                    ast.parse("".join(cell["source"]), filename=f"{name}:cell{index}")
    files["LOCAL_QA.json"] = (
        json.dumps(
            {
                "syntax_and_notebook_structure": "PASS",
                "model_fits_executed_locally": 0,
                "Kaggle_execution": "NOT_RUN",
                "Hiếu_review_and_execution": "PENDING",
                "package_status_not_modified": "PREPARED_PENDING_REVIEW",
            },
            indent=2,
        )
        + "\n"
    ).encode()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ML.parent).decode().strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=ML.parent).decode()
    manifest = {
        "bundle_id": BUNDLE_ID,
        "source_git_revision": revision,
        "source_dirty_worktree": bool(dirty),
        "source_dirty_status": dirty,
        "expected_package_manifest": PACKAGE_SHA,
        "configuration": configuration(),
        "files": {name: hashlib.sha256(content).hexdigest() for name, content in files.items()},
        "source_sha256": {
            "ml/" + source: hashlib.sha256(files[name]).hexdigest()
            for name, source in SOURCES.items()
        },
        "Kaggle_execution": "NOT_RUN",
    }
    files["bundle_manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as handle, zipfile.ZipFile(handle, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in sorted(files.items()):
            item = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            item.compress_type = zipfile.ZIP_DEFLATED
            item.external_attr = 0o100644 << 16
            archive.writestr(item, content)
    return {
        "zip": str(output),
        "bytes": output.stat().st_size,
        "zip_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "bundle_manifest_sha256": hashlib.sha256(files["bundle_manifest.json"]).hexdigest(),
        "source_git_revision": revision,
        "source_dirty_worktree": bool(dirty),
        "package_manifest_sha256": PACKAGE_SHA,
        "files": len(files),
        "model_fits_executed_locally": 0,
        "Kaggle_execution": "NOT_RUN",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.receipt.exists():
        raise FileExistsError(args.receipt)
    result = build(args.output)
    with args.receipt.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    print(json.dumps(result))
