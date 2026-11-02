from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import nbformat


def test_secondary_export_snapshot_notebooks_and_standalone_guard(tmp_path):
    script = Path(__file__).resolve().parents[2] / "scripts/build_kaggle_secondary_bundle.py"
    spec = importlib.util.spec_from_file_location("secondary_export", script)
    exporter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exporter)
    output = tmp_path / "secondary.zip"
    receipt = exporter.build(output)
    assert receipt["model_fits_executed_locally"] == 0
    assert receipt["Kaggle_execution"] == "NOT_RUN"
    with zipfile.ZipFile(output) as archive:
        manifest = json.loads(archive.read("bundle_manifest.json"))
        assert set(archive.namelist()) == set(manifest["files"]) | {"bundle_manifest.json"}
        for name, expected in manifest["files"].items():
            content = archive.read(name)
            assert hashlib.sha256(content).hexdigest() == expected
            if name.endswith(".ipynb"):
                notebook = nbformat.reads(content.decode(), as_version=4)
                nbformat.validate(notebook)
                for cell in notebook.cells:
                    if cell.cell_type == "code":
                        assert not cell.outputs and cell.execution_count is None
                        ast.parse(cell.source)
        root = tmp_path / "relocated"
        archive.extractall(root)
    code = """import importlib.util,sys
from pathlib import Path
root=Path(sys.argv[1])
spec=importlib.util.spec_from_file_location('runner',root/'kaggle_secondary_runner.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
module.check_bundle()
try: module.run('smoke')
except RuntimeError as error:
 assert 'Kaggle' in str(error)
else: raise AssertionError('Local training guard failed')
print('PASS standalone bundle integrity and local guard; zero classifier fits')
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", code, str(root)],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=True,
    )
    assert "zero classifier fits" in result.stdout
