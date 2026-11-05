"""Lossless custody, tampering and extraction boundaries; no model execution."""

import hashlib
import importlib.util
import io
import json
import subprocess
import zipfile
from copy import deepcopy
from pathlib import Path

import numpy as np
import pytest

SPEC = importlib.util.spec_from_file_location(
    "experiment_payload_archive", Path(__file__).resolve().parents[2]
    / "scripts" / "experiment_payload_archive.py",
)
archive = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(archive)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fixture_zip(tmp_path, *, extra=False, duplicate=False, bad_blob=False):
    data = b"not an executable model\x00immutable payload"
    files = {p: {"sha256": sha(data), "bytes": len(data), "source": {"kind": "fixture"}}
             for p in ["repository/ml/experiments/a/train_sample_indices.npy",
                       "repository/ml/experiments/b/train_sample_indices.npy",
                       "received/a/model.joblib"]}
    manifest = {"schema_version": "experiment_payload_archive_v1",
                "source_git_revision": "a" * 40, "files": files}
    raw = archive.json_bytes(manifest)
    path = tmp_path / "payloads.zip"
    with zipfile.ZipFile(path, "x") as z:
        z.writestr("manifest.json", raw)
        z.writestr("blobs/" + sha(data), b"bad" if bad_blob else data)
        if extra:
            z.writestr("unlisted.txt", b"unexpected")
        if duplicate:
            with pytest.warns(UserWarning, match="Duplicate"):
                z.writestr("manifest.json", raw)
    release = {"schema_version": "experiment_payload_release_v1",
               "source_git_revision": "a" * 40, "manifest_sha256": sha(raw),
               "archive": {"bytes": path.stat().st_size, "sha256": archive.digest_file(path)},
               "logical_files": 3, "unique_blobs": 1,
               "payloads": {p.removeprefix("repository/"): e for p, e in files.items()
                            if p.startswith("repository/")}}
    return path, release, data


def test_deduplicated_restore_keeps_exact_bytes_and_never_executes_models(tmp_path):
    path, release, data = fixture_zip(tmp_path)
    manifest = archive.verify_archive(path, release)
    target = tmp_path / "restored"
    receipt = archive.restore_archive(path, release, target)
    assert receipt["files_verified"] == 3
    assert receipt["models_loaded"] is receipt["classifiers_fitted"] is False
    for name in manifest["files"]:
        assert (target / name).read_bytes() == data
    with pytest.raises(ValueError, match="must not exist"):
        archive.restore_archive(path, release, target)
    assert (target / "received/a/model.joblib").read_bytes() == data


@pytest.mark.parametrize("case", ["outer_hash", "inner_blob", "extra_entry", "duplicate_entry"])
def test_tampering_fails_before_creating_destination(tmp_path, case):
    path, release, _ = fixture_zip(
        tmp_path, extra=case == "extra_entry", duplicate=case == "duplicate_entry",
        bad_blob=case == "inner_blob",
    )
    if case == "outer_hash":
        release["archive"]["sha256"] = "0" * 64
    target = tmp_path / "restore-must-not-appear"
    with pytest.raises(ValueError):
        archive.restore_archive(path, release, target)
    assert not target.exists()


@pytest.mark.parametrize("paths", [
    ["received/../escape"], ["/received/absolute"], ["received/C:/absolute"],
    ["received\\escape"], ["received/CON.json"], ["received/name."],
    ["received/name "], ["received//file"], ["received/./file"],
    ["received/ok\x00bad"], ["received/File", "received/file"],
    ["received/file", "received/file/child"], ["other/file"],
])
def test_windows_traversal_alias_and_collision_paths_rejected(paths):
    with pytest.raises(ValueError):
        archive.safe_paths(paths)


def test_release_mapping_cannot_omit_a_payload(tmp_path):
    path, release, _ = fixture_zip(tmp_path)
    release["payloads"].pop(next(iter(release["payloads"])))
    with pytest.raises(ValueError, match="mapping"):
        archive.verify_archive(path, release)


def test_duplicate_json_keys_rejected():
    with pytest.raises(ValueError, match="Duplicate JSON key"):
        archive.read_json('{"files":{},"files":{}}')


def test_sampling_file_and_array_contents_are_distinct_identities():
    indices = np.arange(7, dtype="<i8")
    stream = io.BytesIO()
    np.save(stream, indices)
    sampling = {"rows": len(indices), "indices_sha256": sha(indices.tobytes())}
    data = stream.getvalue()
    assert archive.sampling_identity(data, sampling) == sha(indices.tobytes()) != sha(data)
    with pytest.raises(ValueError, match="contents hash"):
        archive.sampling_identity(data, {**sampling, "indices_sha256": "0" * 64})
    with pytest.raises(ValueError, match="representation/count"):
        archive.sampling_identity(data, {**sampling, "rows": 8})


@pytest.fixture
def source_repo(tmp_path):
    repo, received = tmp_path / "repo", tmp_path / "received"
    repo.mkdir()

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=repo, stderr=subprocess.DEVNULL)

    git("init")
    git("config", "user.name", "Archive test")
    git("config", "user.email", "archive-test@example.invalid")
    git("config", "core.autocrlf", "false")
    git("commit", "--allow-empty", "-m", "source fixture")
    source = git("rev-parse", "HEAD").decode().strip()
    run = repo / "ml/experiments/a"
    run.mkdir(parents=True)
    indices = np.arange(5, dtype="<i8")
    np.save(run / "train_sample_indices.npy", indices)
    (run / "model.json").write_bytes(b'{"fixture":"never loaded"}')
    result = {"run_id": "a", "code_revision": source, "package_manifest_sha256": "b" * 64,
              "resolved_configuration": {"parameters": {"train_sampling": {
                  "rows": len(indices), "indices_sha256": sha(indices.tobytes()),
              }}}}
    (run / "result.json").write_bytes(archive.json_bytes(result))
    git("add", ".")
    git("commit", "-m", "saved evidence")
    for file in run.iterdir():
        dest = received / "a" / file.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(file.read_bytes())
    (received / "a/model.joblib").write_bytes(b"original RF bytes; not deserialized")
    inventory = {"status": "PASS", "files": {
        p.relative_to(received).as_posix(): {"bytes": p.stat().st_size,
                                            "sha256": archive.digest_file(p)}
        for p in received.rglob("*") if p.is_file()
    }}
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_bytes(archive.json_bytes(inventory))
    return repo, received, inventory_path, git


def test_build_uses_git_snapshot_and_verified_received_inventory(tmp_path, source_repo):
    repo, received, inventory, git = source_repo
    expected = git("show", "HEAD:ml/experiments/a/model.json")
    (repo / "ml/experiments/a/model.json").write_bytes(b"uncommitted unrelated edit")
    output, descriptor = tmp_path / "archive.zip", tmp_path / "release.json"
    release = archive.build_archive(repo, "HEAD", received, inventory, output, descriptor)
    assert len(release["payloads"]) == 2
    assert release["logical_files"] == 7
    assert release["unique_blobs"] == 4
    assert json.loads(descriptor.read_bytes()) == release
    target = tmp_path / "recipient"
    archive.restore_archive(output, release, target)
    assert (target / "repository/ml/experiments/a/model.json").read_bytes() == expected
    assert (target / "received/a/model.joblib").read_bytes().startswith(b"original RF")
    assert (repo / "ml/experiments/a/model.json").read_bytes() == b"uncommitted unrelated edit"


@pytest.mark.parametrize("change", ["changed", "extra", "missing"])
def test_build_refuses_received_inventory_drift(tmp_path, source_repo, change):
    repo, received, inventory, _ = source_repo
    path = received / "a/model.joblib"
    if change == "changed":
        path.write_bytes(b"changed")
    elif change == "missing":
        path.unlink()
    else:
        (received / "extra.txt").write_text("unaccounted")
    output, descriptor = tmp_path / "archive.zip", tmp_path / "release.json"
    with pytest.raises(ValueError, match="inventory"):
        archive.build_archive(repo, "HEAD", received, inventory, output, descriptor)
    assert not output.exists()
    assert not descriptor.exists()


def test_missing_clustering_models_are_disclosed_not_invented(tmp_path, source_repo):
    repo, received, inventory, git = source_repo
    path = repo / "ml/notebooks/Clustering/results/full/run_index.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(archive.json_bytes([{"run_id": "k8", "model_sha256": "a" * 64}]))
    git("add", ".")
    git("commit", "-m", "clustering record without estimator")
    release = archive.build_archive(repo, "HEAD", received, inventory,
                                    tmp_path / "archive.zip", tmp_path / "release.json")
    missing = release["missing_clustering_estimators"]
    assert missing["ml/notebooks/Clustering/results/full/k8/model.joblib"][
        "reported_sha256"
    ] == "a" * 64
    manifest = archive.verify_archive(tmp_path / "archive.zip", release)
    assert not any(p.endswith("k8/model.joblib") for p in manifest["files"])


def test_build_and_restore_never_overwrite_existing_files(tmp_path, source_repo):
    repo, received, inventory, _ = source_repo
    output, descriptor = tmp_path / "existing.zip", tmp_path / "release.json"
    output.write_bytes(b"keep original")
    with pytest.raises(ValueError, match="new paths"):
        archive.build_archive(repo, "HEAD", received, inventory, output, descriptor)
    assert output.read_bytes() == b"keep original"
    path, release, _ = fixture_zip(tmp_path)
    with pytest.raises(ValueError, match="must not exist"):
        archive.restore_archive(path, release, output)
    assert output.read_bytes() == b"keep original"


def test_bad_descriptor_does_not_mutate_original_release(tmp_path):
    path, release, _ = fixture_zip(tmp_path)
    original = deepcopy(release)
    release["manifest_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="manifest checksum"):
        archive.verify_archive(path, release)
    assert original["manifest_sha256"] != release["manifest_sha256"]
