import hashlib
import importlib.util
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import nbformat
import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def exported(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "build_kaggle_lr_bundle", ROOT / "scripts/build_kaggle_lr_bundle.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = tmp_path / "IoTGuard_Kaggle_LR_Bundle.zip"
    receipt = module.build_bundle(output)
    recipient = tmp_path / "standalone"
    with zipfile.ZipFile(output) as archive:
        manifest = json.loads(archive.read("bundle_manifest.json"))
        assert set(archive.namelist()) == set(manifest["files"]) | {"bundle_manifest.json"}
        for name, expected in manifest["files"].items():
            assert hashlib.sha256(archive.read(name)).hexdigest() == expected
            assert name != "primary_package.py"  # No second loader implementation in the bundle.
        for destination, source in module.SOURCE_FILES.items():
            assert archive.read(destination) == (ROOT / source).read_bytes()
            if destination.endswith(".ipynb"):
                nbformat.validate(
                    nbformat.reads(archive.read(destination).decode("utf-8"), as_version=4)
                )
        archive.extractall(recipient)
    assert (
        manifest["source_git_revision"]
        == subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip()
    )
    assert type(manifest["source_dirty_worktree"]) is bool
    assert receipt["training_execution"] == "NOT_RUN"
    return module, output, recipient, manifest


def test_exported_bundle_is_standalone_and_binds_actual_source(exported):
    _, _, recipient, manifest = exported
    script = r"""
import pathlib,sys,json,types
root=pathlib.Path.cwd()
sys.path[:0]=[str(root/'vendor'),str(root)]
import kaggle_lr_runner as runner
identity, bundle_hash=runner.check_bundle()
import iotguard.evaluation.primary as metrics
import iotguard.data.primary_package as loader
assert pathlib.Path(metrics.__file__).resolve()==root/'vendor/iotguard/evaluation/primary.py'
assert pathlib.Path(loader.__file__).resolve()==root/'vendor/iotguard/data/primary_package.py'
assert identity['bundle_id']=='iotguard_primary_lr_kaggle_v2'
import numpy as np
# Synthetic formatting only: no package data, estimator creation, fitting or model evaluation run.
package=types.SimpleNamespace(manifest={'package_version':'primary_package_v1','files':{
    'TRAIN_metadata.npy':{'sha256':'a'*64},'VALIDATION_metadata.npy':{'sha256':'b'*64}}})
settings={'input_view':'raw','parameters':{}}
indices={'TRAIN':np.array([0,3]),'VALIDATION':np.array([1,2])}
official=runner.make_result('synthetic-format',np.array([0.1,0.9]),np.array([0,1]),
                           package,settings,bundle_hash,indices,'full')
diagnostic=runner.make_result('synthetic-format',np.array([0.1,0.9]),np.array([0,1]),
                             package,settings,bundle_hash,indices,'smoke')
assert official['code_revision']==identity['source_git_revision']
assert official['dirty_worktree']==identity['source_dirty_worktree']
assert official['package_manifest_sha256']==runner.EXPECTED_MANIFEST
assert diagnostic['diagnostic_only'] and not official['diagnostic_only']
assert official['train_population_sha256']!=diagnostic['train_population_sha256']
try:
    metrics.select_validation([official,diagnostic])
except ValueError:
    pass
else:
    raise AssertionError('Cannot mix diagnostic and official populations')
runtime=runner.environment()
print(json.dumps({'source_git_revision':official['code_revision'],
                  'source_dirty_worktree':official['dirty_worktree'],
                  'bundle_hash':bundle_hash,'model_fits':0,'standalone':'PASS'}))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script],
        cwd=recipient,
        check=True,
        capture_output=True,
        text=True,
    )
    qa = json.loads(result.stdout)
    assert qa["source_git_revision"] == manifest["source_git_revision"]
    assert qa["source_dirty_worktree"] == manifest["source_dirty_worktree"]
    assert qa["model_fits"] == 0 and qa["standalone"] == "PASS"


def test_exported_bundle_detects_tampering(exported):
    _, _, recipient, _ = exported
    with (recipient / "requirements.txt").open("ab") as handle:
        handle.write(b"\n# tamper\n")
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import sys;sys.path.insert(0,'.');import kaggle_lr_runner as r;r.check_bundle()",
        ],
        cwd=recipient,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Bundle integrity mismatch: requirements.txt" in result.stderr


def test_export_does_not_overwrite_or_put_vendor_copies_in_repo(exported):
    module, output, _, _ = exported
    with pytest.raises(FileExistsError):
        module.build_bundle(output)
    with pytest.raises(ValueError, match="outside the repository"):
        module.build_bundle(ROOT / "duplicate_vendor.zip")


def test_bundle_cannot_omit_checksums_for_runtime_code(exported):
    _, _, recipient, _ = exported
    path = recipient / "bundle_manifest.json"
    manifest = json.loads(path.read_bytes())
    del manifest["files"]["vendor/iotguard/evaluation/primary.py"]
    path.write_text(json.dumps(manifest), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import sys;sys.path.insert(0,'.');import kaggle_lr_runner as r;r.check_bundle()",
        ],
        cwd=recipient,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "missing checksummed runtime payloads" in result.stderr
