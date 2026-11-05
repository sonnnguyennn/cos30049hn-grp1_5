"""Read-only inventory of received RF/XGB evidence and the original LR archive."""

import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def inventory(received, lr_archive, output):
    repo = Path(__file__).resolve().parents[2]
    files, runs = {}, []
    for path in sorted(received.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(received).as_posix()
        entry = {"bytes": path.stat().st_size, "sha256": digest(path)}
        git_path = f"ml/experiments/{relative}"
        blob = subprocess.run(["git", "show", f"HEAD:{git_path}"], cwd=repo, capture_output=True)
        if blob.returncode == 0:
            entry["git_blob_sha256"] = hashlib.sha256(blob.stdout).hexdigest()
            entry["matches_git"] = entry["sha256"] == entry["git_blob_sha256"]
            if not entry["matches_git"]:
                raise ValueError(f"Received evidence conflicts with Git: {relative}")
        files[relative] = entry
    for path in sorted(received.glob("*/result.json")):
        result = json.loads(path.read_text())
        revision = result["code_revision"]
        subprocess.run(
            ["git", "cat-file", "-e", f"{revision}^{{commit}}"],
            cwd=repo,
            check=True,
            capture_output=True,
        )
        family = (
            "train_rf_baseline.py"
            if path.parent.name.startswith("rf_")
            else ("train_xgb_baseline.py")
        )
        historical = subprocess.check_output(
            ["git", "ls-tree", "-r", "--name-only", revision], cwd=repo, text=True
        ).splitlines()
        if f"ml/scripts/{family}" not in historical:
            if family == "train_rf_baseline.py" and "ml/scripts/rf_first_run.py" in historical:
                family = "rf_first_run.py"
            else:
                raise ValueError(f"Training implementation missing at {revision}")
        blob = subprocess.check_output(["git", "show", f"{revision}:ml/scripts/{family}"], cwd=repo)
        runs.append(
            {
                "run_id": result["run_id"],
                "training_source_revision": revision,
                "training_source_path": f"ml/scripts/{family}",
                "training_source_git_blob_sha256": hashlib.sha256(blob).hexdigest(),
                "training_dirty_worktree": result["dirty_worktree"],
                "files": sorted(p.name for p in path.parent.iterdir() if p.is_file()),
            }
        )
    if len({r["run_id"] for r in runs}) != len(runs):
        raise ValueError("Duplicate run IDs in received evidence")
    with zipfile.ZipFile(lr_archive) as archive:
        names = [n for n in archive.namelist() if not n.endswith("/")]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate ZIP entries")
        checksums = json.loads(archive.read("output_checksums.json"))
        if set(checksums) != set(names) - {"output_checksums.json"}:
            raise ValueError("LR checksum coverage mismatch")
        for name in names:
            p = Path(name)
            if p.is_absolute() or ".." in p.parts or ":" in name or "\\" in name:
                raise ValueError("Unsafe ZIP entry")
            if (
                name in checksums
                and hashlib.sha256(archive.read(name)).hexdigest() != (checksums[name])
            ):
                raise ValueError(f"LR checksum mismatch: {name}")
        lr_info = {
            "path": str(lr_archive.resolve()),
            "sha256": digest(lr_archive),
            "bytes": lr_archive.stat().st_size,
            "files": len(names),
            "payload_checksums": checksums,
        }
    result = {
        "schema_version": "primary_evidence_inventory_v1",
        "status": "PASS",
        "received_root": str(received.resolve()),
        "files": files,
        "runs": runs,
        "lr_archive": lr_info,
        "evaluation_source_revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True
        ).strip(),
        "TEST_opened": False,
        "models_loaded": False,
        "classifiers_fitted": False,
    }
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(f"PASS: {len(runs)} runs, {len(files)} received files, {len(names)} LR files")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--received", required=True, type=Path)
    parser.add_argument("--lr-archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    inventory(args.received, args.lr_archive, args.output)
