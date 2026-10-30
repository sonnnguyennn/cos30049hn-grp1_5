"""Export a standalone Kaggle code ZIP from canonical repository sources; never train."""

import argparse
import ast
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path

ML_ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = {
    "kaggle_lr_runner.py": "src/iotguard/experiments/kaggle_lr.py",
    "vendor/iotguard/data/primary_package.py": "src/iotguard/data/primary_package.py",
    "vendor/iotguard/evaluation/primary.py": "src/iotguard/evaluation/primary.py",
    "config/seeds.yaml": "config/seeds.yaml",
    "protocols/primary_experiments_v1.md": "docs/protocols/primary_experiments_v1.md",
    "protocols/primary_result_v1.schema.json": "docs/protocols/primary_result_v1.schema.json",
    "protocols/kaggle_lr_baseline_v1.md": "docs/protocols/kaggle_lr_baseline_v1.md",
    "README.md": "docs/experiments/kaggle_lr.md",
    "requirements.txt": "notebooks/kaggle/requirements.txt",
    "01_IoTGuard_LR_Smoke.ipynb": "notebooks/kaggle/01_IoTGuard_LR_Smoke.ipynb",
    "02_IoTGuard_LR_Full.ipynb": "notebooks/kaggle/02_IoTGuard_LR_Full.ipynb",
}
EXPECTED_DATA_MANIFEST = "6ab99e86397242e219bfa1f8490d8e03b169ec87a092af80cb3e7aef1e61147b"


def encoded_json(value):
    return (json.dumps(value, indent=2, allow_nan=False) + "\n").encode()


def build_bundle(output):
    output = Path(output).resolve()
    if output.is_relative_to(ML_ROOT.parent):
        raise ValueError(
            "Export bundles outside the repository; do not duplicate vendored sources in Git"
        )
    if output.exists():
        raise FileExistsError(output)
    files = {
        destination: (ML_ROOT / source).read_bytes() for destination, source in SOURCE_FILES.items()
    }
    for name, content in files.items():
        if name.endswith(".py"):
            ast.parse(content, filename=name)
        if name.endswith(".ipynb"):
            notebook = json.loads(content)
            if notebook["nbformat"] != 4:
                raise ValueError("Only nbformat 4 notebooks supported")
            for index, cell in enumerate(notebook["cells"]):
                if cell["cell_type"] == "code":
                    if cell.get("outputs") or cell.get("execution_count") is not None:
                        raise ValueError("Export only unexecuted notebooks")
                    ast.parse("".join(cell["source"]), filename=f"{name}:cell{index}")
    for package in ("iotguard", "iotguard/data", "iotguard/evaluation"):
        files[f"vendor/{package}/__init__.py"] = b""
    files["LOCAL_QA.json"] = encoded_json(
        {
            "python_syntax": "PASS",
            "notebook_json_and_cell_syntax": "PASS",
            "shared_sources": "copied directly from canonical repository files",
            "model_fits_executed": 0,
            "kaggle_execution": "NOT_RUN",
            "scope": "export checks only; runtime/tests are recorded in repository handoff",
        }
    )
    revision = (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ML_ROOT.parent).decode().strip()
    )
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=ML_ROOT.parent).decode()
    manifest = {
        "bundle_id": "iotguard_primary_lr_kaggle_v2",
        "foundation_commit": "e478e8e7ff0d374d9fd6f53e411bd4f414ce1c14",
        "source_git_revision": revision,
        "source_dirty_worktree": bool(dirty),
        "source_dirty_status": dirty,
        "execution_status": "NOT_RUN",
        "expected_data_manifest_sha256": EXPECTED_DATA_MANIFEST,
        "files": {name: hashlib.sha256(content).hexdigest() for name, content in files.items()},
        "source_sha256": {
            "ml/" + source: hashlib.sha256(files[name]).hexdigest()
            for name, source in SOURCE_FILES.items()
        },
    }
    files["bundle_manifest.json"] = encoded_json(manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    with (
        output.open("xb") as handle,
        zipfile.ZipFile(handle, "w", compression=zipfile.ZIP_DEFLATED) as archive,
    ):
        for name, content in sorted(files.items()):
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, content)
    return {
        "output": str(output),
        "bytes": output.stat().st_size,
        "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "manifest_sha256": hashlib.sha256(files["bundle_manifest.json"]).hexdigest(),
        "source_git_revision": revision,
        "source_dirty_worktree": bool(dirty),
        "files": len(files),
        "training_execution": "NOT_RUN",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build_bundle(args.output), indent=2))
