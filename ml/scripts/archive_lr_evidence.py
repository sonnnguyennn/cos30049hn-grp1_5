"""Read-only archive/source verification; write a new small summary, never old receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import zipfile
from pathlib import Path, PurePosixPath


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read_zip(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "Duplicate ZIP members")
        require(sum(i.file_size for i in archive.infolist()) < 200 * 1024**2,
                "Archive exceeds bounded evidence size")
        for name in names:
            require(not PurePosixPath(name).is_absolute() and ".." not in name.split("/")
                    and "\\" not in name and ":" not in name, "Unsafe ZIP path")
        return {n: archive.read(n) for n in names if not n.endswith("/")}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-dir", type=Path, required=True)
    parser.add_argument("--release-zip", type=Path, required=True)
    parser.add_argument("--package-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    old = json.loads((args.review_dir / "verification.json").read_bytes())
    release = read_zip(args.release_zip)
    manifest = json.loads(release["bundle_manifest.json"])
    revision = manifest["source_git_revision"]
    package_bytes = args.package_manifest.read_bytes()
    require(sha(package_bytes) == manifest["expected_data_manifest_sha256"],
            "Original package manifest differs from released package identity")
    actual = subprocess.check_output(["git", "rev-parse", f"{revision}^{{commit}}"], cwd=repo)
    require(actual.decode().strip() == revision, "Source revision is not an actual Git commit")
    source_git_blobs = {}
    for path, expected in manifest["source_sha256"].items():
        committed = subprocess.check_output(["git", "show", f"{revision}:{path}"], cwd=repo)
        working = (repo / path).read_bytes()
        require(sha(working) == expected, f"Current source mismatch: {path}")
        recipe = "identity"
        if sha(committed) != expected:
            require(sha(committed.replace(b"\n", b"\r\n")) == expected,
                    f"Committed source differs beyond LF-to-CRLF checkout: {path}")
            recipe = "replace LF bytes with CRLF bytes in Git blob"
        source_git_blobs[path] = {"git_blob_sha256": sha(committed),
                                  "exact_snapshot_recipe": recipe}
    for name, expected in manifest["files"].items():
        require(sha(release[name]) == expected, f"Bundle payload mismatch: {name}")
    summary = {
        "status": "VERIFIED_ARCHIVE_AND_SOURCE_LINEAGE",
        "original_review": str(args.review_dir / "REVIEW.md"),
        "original_verification": str(args.review_dir / "verification.json"),
        "original_review_sha256": sha((args.review_dir / "REVIEW.md").read_bytes()),
        "original_verification_sha256": sha((args.review_dir / "verification.json").read_bytes()),
        "release_zip": str(args.release_zip),
        "release_zip_sha256": sha(args.release_zip.read_bytes()),
        "original_package_manifest": str(args.package_manifest),
        "original_package_manifest_sha256": sha(package_bytes),
        "source_revision_kind": "Git commit; ea57689 is its abbreviated object ID",
        "actual_source_revision": revision,
        "source_dirty_worktree": manifest["source_dirty_worktree"],
        "bundle_id": manifest["bundle_id"],
        "bundle_manifest_sha256": sha(release["bundle_manifest.json"]),
        "exact_source_sha256": manifest["source_sha256"],
        "source_git_blob_lineage": source_git_blobs,
        "exact_snapshot_sha256": {n: sha(b) for n, b in sorted(release.items())},
        "runs": {},
        "metrics_evidence_status": "REPORTED_BY_ORIGINAL_INDEPENDENT_AUDIT; "
                                   "result JSON equality rechecked, metrics not recomputed here",
        "model_reload_parity": "REPORTED_BY_RUNNER; models not deserialized",
        "TEST": "SEALED; no TEST evaluation artifacts",
    }
    statuses = {}
    for mode, previous in old["runs"].items():
        path = Path(previous["archive"])
        archive_hash = sha(path.read_bytes())
        require(archive_hash == previous["archive_sha256"], f"Archive hash mismatch: {mode}")
        files = read_zip(path)
        checksums = json.loads(files["output_checksums.json"])
        require(set(checksums) == set(files) - {"output_checksums.json"}, "Checksum coverage")
        for name, expected in checksums.items():
            require(sha(files[name]) == expected, f"Output checksum mismatch: {name}")
        snapshot = {n[7:]: b for n, b in files.items() if n.startswith("source/")}
        require(snapshot == release, "Run source differs from exact release snapshot")
        status = json.loads(files["run_status.json"])
        require(status == previous["status"], "Status differs from original audit")
        require(status["package_manifest_sha256"] == sha(files["data_manifest.json"]),
                "Data manifest identity mismatch")
        require(files["data_manifest.json"] == package_bytes, "Original package manifest mismatch")
        require(status["bundle_manifest_sha256"] == summary["bundle_manifest_sha256"],
                "Bundle identity mismatch")
        require(not status["TEST_evaluated"] and not any("TEST" in n for n in files),
                "Unexpected TEST evaluation evidence")
        statuses[mode] = files["run_status.json"]
        results = {model: json.loads(files[f"{model}_result.json"])
                   for model in ("dummy", "lr")}
        for model, result in results.items():
            require(result["metrics"] == previous["metrics"][model], "Metrics JSON mismatch")
            require(result["code_revision"] == revision, "Result code revision mismatch")
            require(result["package_manifest_sha256"] == sha(package_bytes),
                    "Result package identity mismatch")
        summary["runs"][mode] = {
            "archive": str(path), "archive_sha256": archive_hash,
            "run_id": Path(status["output_directory"]).name,
            "verified_output_files": len(checksums), "status": status,
            "metrics": previous["metrics"],
            "result_identities": {m: {k: r[k] for k in (
                "run_id", "protocol_revision", "code_revision", "package_version",
                "package_manifest_sha256", "dirty_worktree", "train_population_sha256",
                "validation_population_sha256", "run_mode", "diagnostic_only",
                "eligible_for_official_comparison")} for m, r in results.items()},
        }
    full = json.loads(statuses["full"])
    require(full["smoke_receipt"]["receipt_sha256"] == sha(statuses["smoke"]),
            "Smoke linkage mismatch")
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
        handle.write("\n")
    print(f"PASS: archive/source lineage -> {args.output}")


if __name__ == "__main__":
    main()
