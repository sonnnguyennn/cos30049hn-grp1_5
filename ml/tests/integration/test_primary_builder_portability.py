"""Bounded real-data integration; external-data absence is an explicit skip/block."""

import csv
import json
import shutil
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

from iotguard.data.primary_package import sha256_file

ROOT = Path(__file__).resolve().parents[2]


def test_real_builder_output_relocates_and_loads_without_project(tmp_path):
    safety = json.loads((ROOT / "artifacts/audit/a4_evidence_verification.json").read_text())[
        "source_safety"]
    roots = {name: Path(info["root"]) for name, info in safety.items()}
    with (ROOT / "artifacts/manifests/n_baiot_canonical_traversal_v1.csv").open(
            encoding="utf-8", newline="") as f:
        sources = list(csv.DictReader(f))
    missing = [str(roots[row["source_root_kind"]] / row["source_relative_path"])
               for row in sources
               if not (roots[row["source_root_kind"]] / row["source_relative_path"]).is_file()]
    if missing:
        pytest.skip(f"BLOCKED_BY_EXTERNAL_DATA: {len(missing)} sources absent; {missing[0]}")
    produced = tmp_path / "produced"
    subprocess.run([
        sys.executable, str(ROOT / "scripts/materialize_primary.py"),
        "--output", str(produced), "--rows-per-source", "10", "--chunk-size", "64",
        "--n-baiot-raw-root", str(roots["n_baiot_raw"]),
        "--n-baiot-extracted-root", str(roots["n_baiot_extracted"]),
    ], cwd=ROOT, check=True, capture_output=True, text=True)
    m = json.loads((produced / "manifest.json").read_text())
    assert m["status"] == "SMOKE" and sum(m["counts"].values()) == 890
    for name in ("primary_package.py", "README.md", "verify_primary_package.py"):
        assert sha256_file(produced / name) == m["files"][name]["sha256"]
    assert not (produced / "INCOMPLETE.json").exists()
    for name, expected in m["implementation_sha256"].items():
        assert sha256_file(ROOT.parent / name) == expected
    recipient = tmp_path / "recipient"
    assert produced.resolve().is_relative_to(tmp_path.resolve())
    assert recipient.resolve().is_relative_to(tmp_path.resolve())
    shutil.move(str(produced), str(recipient))
    assert not produced.exists()
    # -I -S removes cwd, PYTHONPATH, user-site and editable-install .pth hooks.
    # Add the numerical library's site directory directly, without executing .pth files.
    site = str(Path(np.__file__).resolve().parents[1])
    script = r'''
import sys, importlib.util, pathlib, json, runpy
sys.path.append(sys.argv[1])
assert importlib.util.find_spec('iotguard') is None
root = pathlib.Path.cwd()
spec = importlib.util.spec_from_file_location('portable', root / 'primary_package.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
p = module.PrimaryPackage(root, verify=True, allow_smoke=True)
for partition in ('TRAIN', 'VALIDATION'):
    x, y, meta = p.load(partition)
    assert x.shape == (p.manifest['counts'][partition], 115)
    assert len(meta) == len(y)
    scaled, labels = next(p.chunks(partition, scaled=True, chunk_size=16))
    assert scaled.shape[1] == 115 and len(labels) == len(scaled)
try:
    p.load('TEST')
except PermissionError:
    pass
else:
    raise AssertionError('TEST must remain sealed')
assert 'iotguard' not in sys.modules and 'sklearn' not in sys.modules
print('INDEPENDENT_LOAD_PASS')
sys.argv = ['verify_primary_package.py', '--help']
runpy.run_path(str(root / 'verify_primary_package.py'), run_name='__main__')
'''
    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", script, site],
                            cwd=recipient, check=True, capture_output=True, text=True)
    assert "INDEPENDENT_LOAD_PASS" in result.stdout
    assert "--output" in result.stdout
