"""Archive/verify/restore experiment evidence without loading models or datasets.

Python standard library only. Git snapshots and received inventory bytes are
preserved; equal payloads share one checksummed blob in the ZIP.
"""

import argparse
import ast
import hashlib
import json
import re
import stat
import subprocess
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT_ROOTS = ("ml/experiments", "ml/notebooks/Clustering/results")
HEX = re.compile(r"[0-9a-f]{64}\Z")
RESERVED = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{i}" for prefix in ("COM", "LPT") for i in range(1, 10)
}


def digest_file(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def read_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(data, object_pairs_hook=unique)


def safe_paths(paths):
    """Reject traversal, Windows aliases and file/directory collisions."""
    seen = set()
    for name in paths:
        path = PurePosixPath(name)
        if (
            not name
            or path.is_absolute()
            or path.as_posix() != name
            or "\\" in name
            or ":" in name
            or any(ord(c) < 32 for c in name)
            or path.parts[0] not in {"repository", "received"}
            or any(
                p in {".", ".."} or p.endswith((".", " "))
                or p.split(".", 1)[0].upper() in RESERVED for p in path.parts
            )
            or name.casefold() in seen
        ):
            raise ValueError(f"Unsafe or colliding archive path: {name}")
        seen.add(name.casefold())
    for name in seen:
        if any(str(p) in seen for p in PurePosixPath(name).parents):
            raise ValueError(f"File/directory collision: {name}")


def sampling_identity(data, sampling):
    """Hash int64 array contents separately from the serialized .npy file."""
    if data[:6] != b"\x93NUMPY" or data[6:8] not in {b"\x01\x00", b"\x02\x00"}:
        raise ValueError("Unsupported sampling array format")
    width = 2 if data[6] == 1 else 4
    start = 8 + width
    length = int.from_bytes(data[8:start], "little")
    if length > 65536 or start + length > len(data):
        raise ValueError("Invalid sampling array header length")
    header = ast.literal_eval(data[start:start + length].decode("latin1").strip())
    if (
        header.get("descr") != "<i8" or header.get("fortran_order") is not False
        or header.get("shape") != (sampling["rows"],)
        or len(data) - start - length != sampling["rows"] * 8
    ):
        raise ValueError("Sampling array representation/count mismatch")
    value = hashlib.sha256(memoryview(data)[start + length:]).hexdigest()
    if value != sampling["indices_sha256"]:
        raise ValueError("Sampling contents hash differs from original result")
    return value


def is_payload(path):
    return path.endswith(".npy") or (
        path.startswith("ml/experiments/") and path.endswith("/model.json")
    )


def build_archive(repo, revision, received, inventory_path, output, release_path):
    repo, received = Path(repo).resolve(), Path(received).resolve()
    output, release_path = Path(output).resolve(), Path(release_path).resolve()
    for path in (output, release_path):
        if path == repo or repo in path.parents or path.exists() or path.is_symlink():
            raise ValueError("Build outputs must be new paths outside the checkout")
        if not path.parent.is_dir():
            raise ValueError("Build output parent must already exist")
    if output == release_path:
        raise ValueError("Archive and release descriptor paths must differ")

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=repo)

    revision = git("rev-parse", "--verify", revision + "^{commit}").decode().strip()
    inventory_raw = Path(inventory_path).read_bytes()
    inventory = json.loads(inventory_raw)
    if inventory.get("status") != "PASS":
        raise ValueError("Received inventory is not a PASS record")
    actual = {p.relative_to(received).as_posix() for p in received.rglob("*") if p.is_file()}
    if actual != set(inventory["files"]):
        raise ValueError("Received inventory coverage differs")
    files, blobs, removed = {}, {}, {}

    def add(name, data, source, metadata=None):
        sha = hashlib.sha256(data).hexdigest()
        blobs.setdefault(sha, data)
        files[name] = {"sha256": sha, "bytes": len(data), "source": source, **(metadata or {})}

    tree = git("ls-tree", "-r", "-z", revision, "--", *SNAPSHOT_ROOTS)
    for record in tree.rstrip(b"\0").split(b"\0"):
        if not record:
            continue
        meta, raw_name = record.split(b"\t", 1)
        mode, kind, oid = meta.decode().split()
        name = raw_name.decode("utf-8")
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise ValueError(f"Unsupported snapshot entry: {name}")
        data = git("cat-file", "blob", oid)
        metadata = {}
        if name.startswith("ml/experiments/") and name.count("/") == 3:
            result_path = str(PurePosixPath(name).parent / "result.json")
            result = json.loads(git("show", revision + ":" + result_path))
            metadata = {
                "run_id": result["run_id"],
                "training_source_revision": result["code_revision"],
                "package_manifest_sha256": result["package_manifest_sha256"],
            }
            if name.endswith("/train_sample_indices.npy"):
                sampling = result["resolved_configuration"]["parameters"]["train_sampling"]
                metadata["array_contents_sha256"] = sampling_identity(data, sampling)
        add("repository/" + name, data, {"kind": "git_blob", "revision": revision,
                                       "path": name, "oid": oid}, metadata)
        if is_payload(name):
            removed[name] = files["repository/" + name]

    for name, expected in sorted(inventory["files"].items()):
        path = received / name
        if path.is_symlink() or not path.resolve().is_relative_to(received):
            raise ValueError(f"Unsafe received source: {name}")
        data = path.read_bytes()
        if len(data) != expected["bytes"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
            raise ValueError(f"Received inventory checksum mismatch: {name}")
        peer = files.get("repository/ml/experiments/" + name)
        if peer and peer["sha256"] != expected["sha256"]:
            raise ValueError(f"Received evidence differs from Git snapshot: {name}")
        add("received/" + name, data, {"kind": "received_inventory", "path": name,
                                    "inventory_sha256": hashlib.sha256(inventory_raw).hexdigest()})
    safe_paths(files)
    if not removed:
        raise ValueError("Snapshot contains no payloads to migrate")
    missing_models = {}
    for name, entry in files.items():
        if name.startswith("repository/ml/notebooks/Clustering/results/") and name.endswith(
            "/run_index.json"
        ):
            for run in read_json(blobs[entry["sha256"]]):
                model = str(PurePosixPath(name).parent / run["run_id"] / "model.joblib")
                if model not in files:
                    missing_models[model.removeprefix("repository/")] = {
                        "reported_sha256": run.get("model_sha256"),
                        "reason": "Estimator absent from source Git snapshot; not archived",
                    }
    manifest = {"schema_version": "experiment_payload_archive_v1",
                "source_git_revision": revision, "files": files}
    manifest_raw = json_bytes(manifest)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        z.writestr("manifest.json", manifest_raw)
        for sha, data in sorted(blobs.items()):
            z.writestr("blobs/" + sha, data)
    release = {
        "schema_version": "experiment_payload_release_v1", "custody": "LOCAL_ONLY_NOT_PUBLISHED",
        "source_git_revision": revision,
        "archive": {"filename": output.name, "bytes": output.stat().st_size,
                    "sha256": digest_file(output)},
        "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "logical_files": len(files), "unique_blobs": len(blobs), "payloads": removed,
        "received_inventory_sha256": hashlib.sha256(inventory_raw).hexdigest(),
        "missing_clustering_estimators": missing_models,
    }
    with release_path.open("xb") as stream:
        stream.write(json_bytes(release))
    return release


def verify_archive(archive, release):
    identity = release["archive"]
    if release.get("schema_version") != "experiment_payload_release_v1":
        raise ValueError("Unsupported release descriptor")
    if (Path(archive).stat().st_size != identity["bytes"]
            or digest_file(archive) != identity["sha256"]):
        raise ValueError("Archive checksum/size mismatch")
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Duplicate ZIP entries")
        if z.getinfo("manifest.json").file_size > 16 * 1024 * 1024:
            raise ValueError("Archive manifest too large")
        raw = z.read("manifest.json")
        if hashlib.sha256(raw).hexdigest() != release["manifest_sha256"]:
            raise ValueError("Archive manifest checksum mismatch")
        manifest = read_json(raw)
        if (manifest.get("schema_version") != "experiment_payload_archive_v1"
                or manifest["source_git_revision"] != release["source_git_revision"]):
            raise ValueError("Archive provenance mismatch")
        files = manifest["files"]
        safe_paths(files)
        expected = {}
        for entry in files.values():
            sha, size = entry["sha256"], entry["bytes"]
            if not HEX.fullmatch(sha) or type(size) is not int or size < 0:
                raise ValueError("Invalid blob identity")
            if sha in expected and expected[sha] != size:
                raise ValueError("Inconsistent duplicate blob size")
            expected[sha] = size
        if set(names) != {"manifest.json"} | {"blobs/" + sha for sha in expected}:
            raise ValueError("ZIP payload coverage mismatch")
        if len(files) != release["logical_files"] or len(expected) != release["unique_blobs"]:
            raise ValueError("Release file/blob counts differ")
        payloads = {p.removeprefix("repository/"): e for p, e in files.items()
                    if p.startswith("repository/") and is_payload(p.removeprefix("repository/"))}
        if release["payloads"] != payloads:
            raise ValueError("Release payload mapping mismatch")
        for name in names:
            info = z.getinfo(name)
            if info.is_dir() or stat.S_ISLNK(info.external_attr >> 16):
                raise ValueError("ZIP directories/symlinks are not supported")
        for sha, size in expected.items():
            if z.getinfo("blobs/" + sha).file_size != size:
                raise ValueError("Blob size mismatch")
            h = hashlib.sha256()
            with z.open("blobs/" + sha) as stream:
                for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
                    h.update(block)
            if h.hexdigest() != sha:
                raise ValueError("Blob checksum mismatch")
    return manifest


def restore_archive(archive, release, output):
    # A restore has its own new directory; never overlay a checkout or received evidence.
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("Restore destination must not exist")
    for parent in output.parents:
        if parent.is_symlink() or (parent.exists() and getattr(
                parent.lstat(), "st_file_attributes", 0) & 0x400):
            raise ValueError("Restore parent must not be a symlink/junction")
    if not output.parent.is_dir() or output.resolve().is_relative_to(ROOT):
        raise ValueError("Restore into an existing parent outside the checkout")
    manifest = verify_archive(archive, release)
    output.mkdir(exist_ok=False)
    with zipfile.ZipFile(archive) as z:
        for name, entry in manifest["files"].items():
            target = output.joinpath(*PurePosixPath(name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            h, size = hashlib.sha256(), 0
            with z.open("blobs/" + entry["sha256"]) as source, target.open("xb") as dest:
                for block in iter(lambda: source.read(4 * 1024 * 1024), b""):
                    h.update(block)
                    size += len(block)
                    dest.write(block)
            if size != entry["bytes"] or h.hexdigest() != entry["sha256"]:
                raise ValueError(f"Restored payload checksum mismatch: {name}")
    receipt = {"status": "RESTORE_COMPLETE", "archive_sha256": release["archive"]["sha256"],
               "source_git_revision": manifest["source_git_revision"],
               "files_verified": len(manifest["files"]), "models_loaded": False,
               "classifiers_fitted": False, "TEST_opened": False}
    with (output / "restore_receipt.json").open("xb") as stream:
        stream.write(json_bytes(receipt))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    build.add_argument("--repo", type=Path, default=ROOT)
    build.add_argument("--revision", default="HEAD")
    build.add_argument("--received", type=Path, required=True)
    build.add_argument("--inventory", type=Path, required=True)
    build.add_argument("--archive", type=Path, required=True)
    build.add_argument("--release", type=Path, required=True)
    for command in ("verify", "restore"):
        p = sub.add_parser(command)
        p.add_argument("--archive", type=Path, required=True)
        p.add_argument("--release", type=Path, required=True)
        if command == "restore":
            p.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "build":
        result = build_archive(args.repo, args.revision, args.received, args.inventory,
                               args.archive, args.release)
        result = {k: result[k] for k in ("archive", "logical_files", "unique_blobs")}
    else:
        release = read_json(args.release.read_bytes())
        if args.command == "restore":
            result = restore_archive(args.archive, release, args.output)
        else:
            manifest = verify_archive(args.archive, release)
            result = {"status": "PASS", "files_verified": len(manifest["files"])}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
