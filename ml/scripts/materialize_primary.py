"""G3B primary materialisation, bounded memory and immutable G3A membership."""

import argparse
import csv
import hashlib
import json
import shutil
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from importlib.metadata import version
from itertools import islice
from pathlib import Path

import numpy as np
import psutil
import yaml
from sklearn.preprocessing import StandardScaler

from iotguard.data.contracts import PROJECT_ROOT, n_baiot_feature_names
from iotguard.data.n_baiot import iter_n_baiot_records
from iotguard.data.primary_package import sha256_file
from iotguard.data.split import (
    assign_evaluation_group,
    evaluation_group_id,
    update_membership_digest,
)

PARTITIONS = ("TRAIN", "VALIDATION", "TEST")
META = np.dtype([("source", "<u2"), ("row", "<u8")])
IMPLEMENTATION_PATHS = (
    "scripts/materialize_primary.py", "scripts/verify_primary_package.py",
    "src/iotguard/data/primary_package.py", "src/iotguard/data/n_baiot.py",
    "src/iotguard/data/split.py", "src/iotguard/data/contracts.py",
    "config/seeds.yaml", "docs/package/PRIMARY_PACKAGE_README.md",
    "artifacts/audit/n_baiot_label_mapping.csv",
)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--rows-per-source", type=int, default=10)
    parser.add_argument("--chunk-size", type=int, default=4096)
    parser.add_argument("--n-baiot-raw-root", type=Path)
    parser.add_argument("--n-baiot-extracted-root", type=Path)
    args = parser.parse_args()
    if args.chunk_size < 1 or args.rows_per_source < 1:
        parser.error("Positive chunk and smoke sizes required")
    implementation_hashes = {"ml/" + name: sha256_file(PROJECT_ROOT / name)
                             for name in IMPLEMENTATION_PATHS}
    safety = json.loads((PROJECT_ROOT / "artifacts/audit/a4_evidence_verification.json")
                        .read_text())["source_safety"]
    roots = {k: Path(v["root"]) for k, v in safety.items()}
    if args.n_baiot_raw_root:
        roots["n_baiot_raw"] = args.n_baiot_raw_root.resolve()
    if args.n_baiot_extracted_root:
        roots["n_baiot_extracted"] = args.n_baiot_extracted_root.resolve()
    contract_path = PROJECT_ROOT / "artifacts/contracts/n_baiot_primary_split_contract_v1.json"
    contract = json.loads(contract_path.read_text())
    if (contract["status"] != "ADOPTED" or contract["test_set_status"] != "SEALED"
            or contract["split_version"] != "primary_split_v1"):
        raise ValueError("Accepted split contract required")
    traversal_path = PROJECT_ROOT / "artifacts/manifests/n_baiot_canonical_traversal_v1.csv"
    if sha256_file(traversal_path) != contract["canonical_traversal_sha256"]:
        raise ValueError("Traversal contract hash mismatch")
    traversal = list(csv.DictReader(traversal_path.open(encoding="utf-8", newline="")))
    for row in traversal:
        path = roots[row["source_root_kind"]] / row["source_relative_path"]
        if not path.is_file():
            raise FileNotFoundError(path)
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError("Use a new output directory; existing packages are never overwritten")
    if output.is_relative_to(PROJECT_ROOT.parent):
        raise ValueError("Bulk package must be outside the team repository")
    if any(output.is_relative_to(root.resolve()) for root in roots.values()):
        raise ValueError("Output inside raw source prohibited")
    output.parent.mkdir(parents=True, exist_ok=True)

    def records(row):
        stream = iter_n_baiot_records(
            roots[row["source_root_kind"]] / row["source_relative_path"], row["logical_id"])
        return stream if args.full else islice(stream, args.rows_per_source)

    counts = {p: contract["observed_counts"][p]["row_count"] for p in PARTITIONS}
    if not args.full:
        counts = dict.fromkeys(PARTITIONS, 0)
        for row in traversal:
            for record in records(row):
                counts[assign_evaluation_group(evaluation_group_id(record.features))] += 1
    estimated = sum(counts.values()) * (115 * 8 + 1 + META.itemsize)
    resources = {"available_ram_bytes": psutil.virtual_memory().available,
                 "disk_free_bytes": shutil.disk_usage(output.parent).free,
                 "estimated_array_bytes": estimated}
    if resources["disk_free_bytes"] < estimated + 1024**3:
        raise OSError("Insufficient disk: require arrays plus 1 GiB reserve")
    if resources["available_ram_bytes"] < args.chunk_size * 115 * 8 * 12:
        raise MemoryError("Insufficient RAM for bounded buffers")
    output.mkdir()
    write_json(output / "INCOMPLETE.json", {"status": "BUILDING", "resources": resources})
    arrays = {}
    buffers = {}
    for p in PARTITIONS:
        arrays[p] = [np.lib.format.open_memmap(output / f"{p}_{name}.npy", mode="w+",
                                              dtype=dtype, shape=shape)
                     for name, dtype, shape in (("X", np.float64, (counts[p], 115)),
                                                ("y", np.uint8, (counts[p],)),
                                                ("metadata", META, (counts[p],)))]
        buffers[p] = [np.empty((args.chunk_size, 115), dtype=np.float64),
                      np.empty(args.chunk_size, dtype=np.uint8),
                      np.empty(args.chunk_size, dtype=META)]
    used = Counter()
    written = Counter()
    classes = {p: Counter() for p in PARTITIONS}
    fine = {p: Counter() for p in PARTITIONS}
    scaler = StandardScaler()

    def flush(p):
        n = used[p]
        if not n:
            return
        start = written[p]
        if start + n > counts[p]:
            raise ValueError("Split count exceeds contract")
        for destination, buffer in zip(arrays[p], buffers[p], strict=True):
            destination[start:start + n] = buffer[:n]
        if p == "TRAIN":
            scaler.partial_fit(buffers[p][0][:n])
        written[p] += n
        used[p] = 0

    membership = hashlib.sha256()
    source_results = []
    for source_index, row in enumerate(traversal):
        path = roots[row["source_root_kind"]] / row["source_relative_path"]
        before = path.stat()
        if args.full and sha256_file(path) != row["source_content_sha256"]:
            raise ValueError(f"Source hash mismatch: {path}")
        n = 0
        for record in records(row):
            group = evaluation_group_id(record.features)
            p = assign_evaluation_group(group)
            update_membership_digest(membership, record.source_logical_id,
                                     record.data_row_index, group, p)
            target = {"benign": 0, "malicious": 1}[record.target_binary]
            if (record.target_binary != row["canonical_binary"]
                    or record.label_fine != row["canonical_fine_class"]):
                raise ValueError("Source label contract mismatch")
            pos = used[p]
            buffers[p][0][pos] = record.features
            buffers[p][1][pos] = target
            buffers[p][2][pos] = (source_index, record.data_row_index)
            used[p] += 1
            classes[p][record.target_binary] += 1
            fine[p][record.label_fine] += 1
            n += 1
            if used[p] == args.chunk_size:
                flush(p)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("Source mutated during build")
        if args.full and n != int(row["expected_row_count"]):
            raise ValueError("Source row count mismatch")
        source_results.append({**row, "rows_materialized": n,
                               "source_sha256_verified": args.full})
        print(f"[{source_index + 1}/89] {row['logical_id']}: {n}", flush=True)
    for p in PARTITIONS:
        flush(p)
        for array in arrays[p]:
            array.flush()
    if dict(written) != counts:
        raise ValueError("Final partition counts mismatch")
    if args.full:
        if membership.hexdigest() != contract["membership_digest"]["sha256"]:
            raise ValueError("Canonical membership digest mismatch")
        for p in PARTITIONS:
            if dict(classes[p]) != contract["observed_class_counts"][p]["binary"]:
                raise ValueError("Binary class counts mismatch")
            if dict(fine[p]) != contract["observed_class_counts"][p]["fine"]:
                raise ValueError("Fine class counts mismatch")
    write_json(output / "scaler.json", {"type": "StandardScaler", "fit_partition": "TRAIN",
               "n_samples_seen": int(scaler.n_samples_seen_), "mean": scaler.mean_.tolist(),
               "var": scaler.var_.tolist(), "scale": scaler.scale_.tolist(),
               "with_mean": True, "with_std": True})
    if implementation_hashes != {"ml/" + name: sha256_file(PROJECT_ROOT / name)
                                  for name in IMPLEMENTATION_PATHS}:
        raise ValueError("Implementation/configuration changed during build")
    shutil.copyfile(PROJECT_ROOT / "src/iotguard/data/primary_package.py",
                    output / "primary_package.py")
    shutil.copyfile(PROJECT_ROOT / "scripts/verify_primary_package.py",
                    output / "verify_primary_package.py")
    shutil.copyfile(PROJECT_ROOT / "docs/package/PRIMARY_PACKAGE_README.md",
                    output / "README.md")
    hashes = {}
    for path in (PROJECT_ROOT / "artifacts/contracts").glob("n_baiot_*v1.json"):
        shutil.copyfile(path, output / path.name)
        hashes[path.name] = sha256_file(path)
    seeds = yaml.safe_load((PROJECT_ROOT / "config/seeds.yaml").read_text())
    repo = PROJECT_ROOT.parent
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo).decode().strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=repo).decode()
    files = {p.name: {"bytes": p.stat().st_size, "sha256": sha256_file(p)}
             for p in output.iterdir() if p.name != "INCOMPLETE.json"}
    manifest = {"package_version": "primary_package_v1", "status": "FULL" if args.full else "SMOKE",
                "created_at_utc": datetime.now(UTC).isoformat(), "dataset": "N-BaIoT",
                "dtype": "float64", "feature_order": list(n_baiot_feature_names()),
                "label_mapping": {"benign": 0, "malicious": 1}, "fit_partition": "TRAIN",
                "split_version": "primary_split_v1", "test_status": "SEALED",
                "counts": counts, "class_counts": classes, "fine_class_counts": fine,
                "membership_sha256": membership.hexdigest(), "files": files,
                "implementation_sha256": implementation_hashes,
                "environment": {"python": sys.version, "numpy": version("numpy"),
                                "scikit-learn": version("scikit-learn")},
                "sources": source_results, "contract_sha256": hashes,
                "traversal_sha256": sha256_file(traversal_path), "code_revision": revision,
                "dirty_worktree": dirty, "command": [sys.executable, *sys.argv],
                "resolved_configuration": {"seeds": seeds, "chunk_size": args.chunk_size,
                    "source_roots": {k: str(v) for k, v in roots.items()},
                    "duplicate_policy": "retain all observations and original row weighting",
                    "resampling": "none", "threshold": 0.5, "protocol": "primary_experiments_v1"},
                "resources_preflight": resources, "location_at_creation": str(output),
                "roundtrip_tolerance": {"raw_float64": 0, "scaled_atol": 1e-12,
                                        "scaled_rtol": 1e-12}}
    write_json(output / "manifest.json", manifest)
    (output / "INCOMPLETE.json").unlink()
    print(f"COMPLETE {output}; membership={membership.hexdigest()}", flush=True)


if __name__ == "__main__":
    main()
