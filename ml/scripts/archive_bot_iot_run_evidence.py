"""Archive reviewed Bot-IoT evidence; no model loading, fitting or TEST payload access."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import shutil
import subprocess
import zipfile
from pathlib import Path, PurePosixPath

import numpy as np

SOURCE = "84f3068386f1c11a5691d5383b2c4a46c8591b21"
PACKAGE = "dd4fdc2551df68f294968f38ca3ecced0c27ac8bc2d1e1ae22239b7d676bae7c"
EXPECTED_ZIPS = {
    "smoke": "043a12b177791d624e34c44c4b1c7a0c6c69d80bd853dbc0380f6251ae69a2d7",
    "full": "dc7ca7e5cf3ce91367673622c0591ea318cabba8b0fad4d2b9d0dcea3c20f377",
}


def sha_file(path):
    with Path(path).open("rb") as handle:
        return sha_stream(handle)


def sha_stream(handle):
    digest = hashlib.sha256()
    for block in iter(lambda: handle.read(4 * 1024**2), b""):
        digest.update(block)
    return digest.hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def metrics(y, probabilities, sizes, weighted):
    """Independent vector-based confusion accumulation, never call runner/model code."""
    predicted = probabilities >= 0.5
    weights = 1 / sizes if weighted else np.ones(len(y), dtype=np.float64)
    tn, fp, fn, tp = (
        float(weights[mask].sum())
        for mask in (
            (y == 0) & ~predicted,
            (y == 0) & predicted,
            (y == 1) & ~predicted,
            (y == 1) & predicted,
        )
    )

    def ratio(a, b):
        return a / b if b else None

    f0, f1 = ratio(2 * tn, 2 * tn + fp + fn), ratio(2 * tp, 2 * tp + fp + fn)
    return {
        "confusion": dict(zip(("TN", "FP", "FN", "TP"), (tn, fp, fn, tp))),
        "class_supports": {"benign": tn + fp, "malicious": fn + tp},
        "benign_recall": ratio(tn, tn + fp),
        "malicious_recall": ratio(tp, tp + fn),
        "malicious_precision": ratio(tp, tp + fp),
        "FPR": ratio(fp, fp + tn),
        "macro_f1": (f0 + f1) / 2 if f0 is not None and f1 is not None else None,
        "accuracy_supplementary": ratio(tn + tp, tn + fp + fn + tp),
    }


def compare(actual, expected):
    if isinstance(actual, dict):
        for key, value in actual.items():
            compare(value, expected[key])
    elif actual is None:
        require(expected is None, "Undefined metric mismatch")
    else:
        require(bool(np.isclose(actual, expected, rtol=1e-12, atol=1e-10)), "Metric mismatch")


def notebook_evidence(path, mode, status, zip_sha, template):
    data = json.loads(path.read_bytes())
    code = [c for c in data["cells"] if c["cell_type"] == "code"]
    require(
        len(code) == 3 and all(c.get("execution_count") is not None for c in code),
        "Notebook execution evidence missing",
    )
    import ast

    def normalized(cell):
        tree = ast.parse("".join(cell["source"]))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "SMOKE_RECEIPT_PATH" for t in node.targets
            ):
                node.value = ast.Constant(value="ALLOWED_INPUT_PATH")
        return ast.dump(tree, include_attributes=False)

    original = [c for c in json.loads(template)["cells"] if c["cell_type"] == "code"]
    require(
        [normalized(c) for c in code] == [normalized(c) for c in original],
        "Executed notebook changed algorithm beyond allowed input path",
    )
    output = "".join("".join(o.get("text", [])) for c in code for o in c.get("outputs", []))
    require(
        status["run_id"] in output and zip_sha in output and status["status"] in output,
        "Notebook output does not reference archived run",
    )
    return {
        "original": str(path),
        "sha256": sha_file(path),
        "bytes": path.stat().st_size,
        "execution_counts": [c["execution_count"] for c in code],
        "mode": mode,
        "template_algorithm_match": True,
        "note": "Execution transcript; not reexecuted. Only Full receipt input path differs.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "smoke-zip",
        "full-zip",
        "smoke-notebook",
        "full-notebook",
        "release-zip",
        "package",
        "archive-dir",
        "receipt",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    require(not args.archive_dir.resolve().is_relative_to(repo), "Keep bulk outside Git")
    require(
        not args.archive_dir.exists() and not args.receipt.exists(), "Use fresh archive/receipt"
    )
    args.archive_dir.mkdir(parents=True)
    package_bytes = (args.package / "manifest.json").read_bytes()
    require(hashlib.sha256(package_bytes).hexdigest() == PACKAGE, "Package identity mismatch")
    package = json.loads(package_bytes)
    # Only VALIDATION payloads are opened. Standalone verifier is not rerun.
    for suffix in ("y", "metadata"):
        name = f"VALIDATION_{suffix}.npy"
        require(
            sha_file(args.package / name) == package["files"][name]["sha256"],
            "Original VALIDATION payload mismatch",
        )
    original_y = np.load(args.package / "VALIDATION_y.npy", mmap_mode="r", allow_pickle=False)
    original_meta = np.load(
        args.package / "VALIDATION_metadata.npy", mmap_mode="r", allow_pickle=False
    )
    summary = {
        "status": "VERIFIED_ARCHIVE_VALIDATION_EVIDENCE",
        "historical_run_source_revision": SOURCE,
        "integration_checkout_revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo
        )
        .decode()
        .strip(),
        "archive_verifier_sha256": sha_file(Path(__file__)),
        "package_manifest_sha256": PACKAGE,
        "release_zip_sha256": sha_file(args.release_zip),
        "review_reference": "https://github.com/sonnnguyennn/cos30049hn-grp1_5/pull/1",
        "archive_directory": str(args.archive_dir),
        "runs": {},
        "current_TEST_payloads_opened": False,
        "model_deserialization_or_fit": False,
        "reload_parity_evidence": "REPORTED_BY_ARCHIVED_RUNNER; model files hash-checked only",
        "package_standalone_evidence": "REPORTED_KAGGLE_PASS; receipt hash verified, not rerun",
    }
    with zipfile.ZipFile(args.release_zip) as release:
        released = {name: release.read(name) for name in release.namelist()}
    saved_statuses = {}
    for mode in ("smoke", "full"):
        archive_path = getattr(args, mode + "_zip")
        zip_hash = sha_file(archive_path)
        require(zip_hash == EXPECTED_ZIPS[mode], "ZIP differs from PM-reviewed archive")
        with zipfile.ZipFile(archive_path) as archive:
            names = archive.namelist()
            require(len(names) == len(set(names)), "Duplicate ZIP members")
            for name in names:
                require(
                    not PurePosixPath(name).is_absolute()
                    and ".." not in name.split("/")
                    and "\\" not in name
                    and ":" not in name,
                    "Unsafe ZIP path",
                )
                require(
                    not name.startswith("TEST_") and "_TEST_" not in name,
                    "Unexpected TEST evaluation artifact",
                )
            checksums = json.loads(archive.read("output_checksums.json"))
            require(set(checksums) == set(names) - {"output_checksums.json"}, "Checksum coverage")
            for name, expected in checksums.items():
                with archive.open(name) as handle:
                    require(sha_stream(handle) == expected, f"Output checksum mismatch:{name}")
            source = {n[7:]: archive.read(n) for n in names if n.startswith("source/")}
            require(source == released, "Run snapshot differs from exact released source")
            manifest = json.loads(source["bundle_manifest.json"])
            require(manifest["source_git_revision"] == SOURCE, "Historical source revision changed")
            for name, expected in manifest["source_sha256"].items():
                blob = subprocess.check_output(["git", "show", SOURCE + ":" + name], cwd=repo)
                require(
                    hashlib.sha256(blob).hexdigest() == expected, "Historical Git source mismatch"
                )
            status_bytes = archive.read("run_status.json")
            saved_statuses[mode] = status_bytes
            status = json.loads(status_bytes)
            identity = status["identity"]
            require(
                identity["source_git_revision"] == SOURCE
                and identity["package_manifest_sha256"] == PACKAGE,
                "Run identity mismatch",
            )
            require(
                not status["training_runner_TEST_opened"]
                and not status["TEST_performance_evaluated"],
                "Unexpected TEST evaluation",
            )
            require(status["validation_rows"] == 733704, "VALIDATION count changed")
            require(
                status["status"] == ("SMOKE_PASS" if mode == "smoke" else "BASELINES_COMPLETE"),
                "Run did not complete",
            )
            for partition in ("TRAIN", "VALIDATION"):
                with archive.open(f"{partition}_membership.jsonl") as handle:
                    require(
                        sha_stream(handle) == status[partition.lower() + "_population_sha256"],
                        "Actual population fingerprint mismatch",
                    )
            for name, suffix in (
                ("VALIDATION_y.npy", original_y),
                ("VALIDATION_metadata.npy", original_meta),
            ):
                data = np.load(io.BytesIO(archive.read(name)), allow_pickle=False)
                require(
                    np.array_equal(data, suffix) and data.dtype == suffix.dtype,
                    "Saved VALIDATION identity/labels differ from original package",
                )
            for model in ("dummy", "lr"):
                result = json.loads(archive.read(f"{model}_result.json"))
                require(result["identity"] == identity, "Model source identity mismatch")
                require(
                    result["train_population_sha256"] == status["train_population_sha256"]
                    and result["validation_population_sha256"]
                    == status["validation_population_sha256"],
                    "Model population mismatch",
                )
                require(
                    result["metrics"] == status["models"][model]["metrics"], "Report disagreement"
                )
                probabilities = np.load(
                    io.BytesIO(archive.read(f"{model}_VALIDATION_probabilities.npy")),
                    allow_pickle=False,
                )
                predictions = np.load(
                    io.BytesIO(archive.read(f"{model}_VALIDATION_predictions.npy")),
                    allow_pickle=False,
                )
                require(
                    probabilities.shape == original_y.shape
                    and np.isfinite(probabilities).all()
                    and ((probabilities >= 0) & (probabilities <= 1)).all(),
                    "Invalid probability",
                )
                require(np.array_equal(predictions, probabilities >= 0.5), "Threshold mismatch")
                for weighted, key in ((False, "row_primary"), (True, "group_sensitivity")):
                    compare(
                        metrics(original_y, probabilities, original_meta["group_size"], weighted),
                        result["metrics"][key],
                    )
            preflight = archive.read("package_verification.json")
            require(
                hashlib.sha256(preflight).hexdigest() == status["package_verification"]["sha256"],
                "Historical standalone receipt hash mismatch",
            )
            if mode == "full":
                require(
                    archive.read("accepted_smoke_receipt.json") == saved_statuses["smoke"],
                    "Full did not accept exact archived Smoke status",
                )
            notebook = getattr(args, mode + "_notebook")
            template = source[
                "01_Bot_IoT_Secondary_Smoke.ipynb"
                if mode == "smoke"
                else "02_Bot_IoT_Secondary_Full.ipynb"
            ]
            notebook_info = notebook_evidence(notebook, mode, status, zip_hash, template)
            for path in (archive_path, notebook):
                shutil.copyfile(path, args.archive_dir / path.name)
                require(
                    sha_file(path) == sha_file(args.archive_dir / path.name),
                    "Archive copy mismatch",
                )
            summary["runs"][mode] = {
                "original_zip": str(archive_path),
                "archived_zip": str(args.archive_dir / archive_path.name),
                "zip_sha256": zip_hash,
                "zip_bytes": archive_path.stat().st_size,
                "output_checksums_verified": len(checksums),
                "run_status_sha256": hashlib.sha256(status_bytes).hexdigest(),
                "run_id": status["run_id"],
                "identity": identity,
                "status": status["status"],
                "training_rows": status["training_rows"],
                "validation_rows": status["validation_rows"],
                "train_population_sha256": status["train_population_sha256"],
                "validation_population_sha256": status["validation_population_sha256"],
                "smoke_plan": status["smoke_plan"],
                "models": status["models"],
                "eligible_for_full_population_comparison": status[
                    "eligible_for_full_population_comparison"
                ],
                "elapsed_seconds": status["elapsed_seconds_including_package_verification"],
                "peak_runner_rss_bytes": status["peak_runner_rss_bytes_after_package_verification"],
                "executed_notebook": {
                    **notebook_info,
                    "archived": str(args.archive_dir / notebook.name),
                },
                "independent_saved_VALIDATION_metrics_recomputation": "PASS",
            }
    for output in (args.archive_dir / "archive_receipt.json", args.receipt):
        with output.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(summary, handle, indent=2, allow_nan=False)
            handle.write("\n")
    print(
        "PASS: archives/notebooks/source/populations/saved VALIDATION metrics; zero models loaded"
    )


if __name__ == "__main__":
    main()
