"""Build a new external PREPARED_PENDING_REVIEW package from verified exact groups."""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import subprocess
import sys
import time
from importlib.metadata import version
from pathlib import Path

import numpy as np
import psutil

from iotguard.data.bot_iot_package_v2 import (
    META,
    PARTITIONS,
    PortablePreprocessor,
    sha_file,
)
from iotguard.data.bot_iot_secondary_v2 import V2Preprocessor

ML = Path(__file__).resolve().parents[1]
REPO = ML.parent
IMPLEMENTATION = (
    "scripts/build_bot_iot_secondary_v2.py", "scripts/verify_bot_iot_package_v2.py",
    "src/iotguard/data/bot_iot_package_v2.py", "src/iotguard/data/bot_iot_secondary_v2.py",
    "src/iotguard/data/bot_iot_secondary.py", "src/iotguard/data/bot_iot.py",
)


def write_json(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, allow_nan=False)
        handle.write("\n")


def batches(db, partition):
    cursor = db.execute("""SELECT o.source,o.rownum,o.pk,o.y,g.sha,g.payload,g.n0+g.n1
      FROM observations o JOIN groups g ON g.gid=o.gid WHERE g.partition=?
      ORDER BY o.source,o.rownum""", (partition,))
    while rows := cursor.fetchmany(8192):
        values = [json.loads(row[5]) for row in rows]
        yield (rows, np.asarray([v[:10] for v in values], dtype=np.float64),
               np.asarray([v[10:] for v in values], dtype=object))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.is_relative_to(REPO.resolve()) or output.exists() or args.receipt.exists():
        parser.error("Use fresh external output and receipt paths")
    started = time.perf_counter()
    contract_path = ML/"artifacts/contracts/bot_iot_secondary_ml_v2.json"
    contract = json.loads(contract_path.read_bytes())
    if contract["contract_version"] != "2.0.0" or contract["status"] != "PREPARED_PENDING_REVIEW":
        raise ValueError("v2 preparation policy required")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO).decode().strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=REPO).decode()
    policy_commit = subprocess.check_output([
        "git", "log", "--format=%H", "--diff-filter=A", "--",
        "ml/artifacts/contracts/bot_iot_secondary_ml_v2.json"], cwd=REPO).decode().strip()
    if not policy_commit:
        raise ValueError("Commit v2 policy before fitting/materialising")
    for name, expected in contract["inherited_evidence"].items():
        if sha_file(ML/"artifacts/manifests"/name) != expected:
            raise ValueError(f"Historical evidence changed: {name}")
    evidence = args.evidence_dir.resolve()
    scan = json.loads((evidence/"verification.json").read_bytes())
    if sha_file(evidence/"verification.json") != contract["inherited_evidence"][
            "bot_iot_candidate_full_verification.json"]:
        raise ValueError("External scan report identity mismatch")
    evidence_db_sha = scan["external_files"]["candidate.sqlite"]["sha256"]
    if sha_file(evidence/"candidate.sqlite") != evidence_db_sha:
        raise ValueError("External exact-group database changed")
    if scan["invalid_rows"] or scan["sha256_collision_buckets"]:
        raise ValueError("Cannot reuse invalid/colliding scan")
    for source in scan["sources"]:
        if sha_file(Path(source["path"])) != source["manifest_sha256"]:
            raise ValueError("Raw source content changed; targeted evidence not reusable")
    for name in PARTITIONS:
        if sha_file(evidence/f"{name}_membership.jsonl") != contract["expected_partitions"][name][
                "membership_sha256"]:
            raise ValueError("Frozen membership changed")
    implementation = {"ml/"+p: sha_file(ML/p) for p in IMPLEMENTATION}
    db = sqlite3.connect((evidence/"candidate.sqlite").as_uri()+"?mode=ro", uri=True)
    db.execute("PRAGMA cache_size=-65536")
    db.execute("PRAGMA temp_store=FILE")
    output.mkdir(parents=True, exist_ok=False)
    write_json(output/"INCOMPLETE.json", {"status": "BUILDING", "source_revision": revision})
    reference = V2Preprocessor()
    for _, numeric, categorical in batches(db, 0):
        reference.fit_chunk(numeric, categorical, partition="TRAIN")
    state = reference.finalize()
    if (state["n_samples_seen"] != 2201114 or len(state["encoded_features"]) != 36
            or {f: len(v) for f, v in state["vocabulary"].items()}
            != contract["preprocessing"]["observed_train_vocabulary_sizes"]):
        raise ValueError("Unexpected TRAIN state/encoded dimension")
    state["fit_membership_sha256"] = contract["expected_partitions"]["TRAIN"]["membership_sha256"]
    state["contract_sha256"] = sha_file(contract_path)
    write_json(output/"preprocessing.json", state)
    portable = PortablePreprocessor(json.loads((output/"preprocessing.json").read_bytes()))
    print("TRAIN-only preprocessing fitted and serialized:36 features", flush=True)
    target = sqlite3.connect(output/"groups.sqlite")
    target.executescript("""CREATE TABLE groups(sha TEXT PRIMARY KEY,payload BLOB UNIQUE,
      n0 INTEGER NOT NULL,n1 INTEGER NOT NULL,partition INTEGER NOT NULL);""")
    cursor = db.execute("SELECT sha,payload,n0,n1,partition FROM groups ORDER BY sha")
    while rows := cursor.fetchmany(8192):
        target.executemany("INSERT INTO groups VALUES(?,?,?,?,?)", rows)
    target.commit()
    if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise ValueError("Group dictionary integrity failed")
    target.close()
    unknowns = {}
    parity_rows = 0
    for p, name in enumerate(PARTITIONS):
        n = contract["expected_partitions"][name]["rows"]
        arrays = [np.lib.format.open_memmap(output/f"{name}_{suffix}.npy", mode="w+",
                                           dtype=dtype, shape=shape)
                  for suffix, dtype, shape in (("numeric", "<f8", (n, 10)),
                                               ("categorical", "<u2", (n, 3)),
                                               ("y", "u1", (n,)), ("metadata", META, (n,)))]
        offset = 0
        unknown = np.zeros(3, dtype=np.int64)
        unknown_rows = 0
        binary = np.zeros(2, dtype=np.int64)
        for rows, numeric, cats in batches(db, p):
            codes = portable.category_codes(cats)
            expected_encoded = reference.transform(numeric, cats)
            actual_encoded = portable.transform(numeric, cats)
            if not np.array_equal(expected_encoded, actual_encoded):
                raise ValueError("Reference/serialized portable preprocessing parity failed")
            stop = offset+len(rows)
            if stop > n:
                raise ValueError("Population grew")
            arrays[0][offset:stop] = numeric
            arrays[1][offset:stop] = codes
            arrays[2][offset:stop] = [r[3] for r in rows]
            if any(str(int(r[2])) != r[2] for r in rows):
                raise ValueError("Identifier lexical form needs lossless schema revision")
            arrays[3][offset:stop] = [(r[0], r[1], int(r[2]), r[4].encode(), r[6]) for r in rows]
            flags = np.column_stack([codes[:, j] == len(state["vocabulary"][f])
                                     for j, f in enumerate(state["vocabulary"])])
            unknown += flags.sum(axis=0)
            unknown_rows += int(flags.any(axis=1).sum())
            binary += np.bincount([r[3] for r in rows], minlength=2)
            offset = stop
            parity_rows += len(rows)
        if offset != n or binary.tolist() != [contract["expected_partitions"][name][
                "binary_rows"][f] for f in ("benign", "malicious")]:
            raise ValueError("Population count changed")
        for array in arrays:
            array.flush()
            array._mmap.close()
        shutil.copyfile(evidence/f"{name}_membership.jsonl", output/f"{name}_membership.jsonl")
        unknowns[name] = {"per_field": unknown.tolist(), "observations": unknown_rows}
        print(f"Materialised {name}:{n:,}, full preprocessing parity PASS", flush=True)
    db.close()
    copies = {
        "contract_v2.json": contract_path,
        "protocol_v2.md": ML/"docs/protocols/bot_iot_secondary_experiment_v2.md",
        "decision.md": ML/"docs/decisions/BOT_IOT_V2_PREPARATION.md",
        "bot_iot_package_v2.py": ML/"src/iotguard/data/bot_iot_package_v2.py",
        "verify_package.py": ML/"scripts/verify_bot_iot_package_v2.py",
        "README.md": ML/"docs/package/BOT_IOT_SECONDARY_V2_README.md",
    }
    for name in contract["inherited_evidence"]:
        copies[name] = ML/"artifacts/manifests"/name
    for name, source in copies.items():
        shutil.copyfile(source, output/name)
    # Verify reused evidence and source contents remained immutable throughout build.
    if sha_file(evidence/"candidate.sqlite") != evidence_db_sha:
        raise ValueError("Evidence database changed during build")
    for source in scan["sources"]:
        if sha_file(Path(source["path"])) != source["manifest_sha256"]:
            raise ValueError("Source changed during build")
    for path, expected in implementation.items():
        if sha_file(REPO/path) != expected:
            raise ValueError("Implementation changed during build")
    files = {p.name: {"bytes": p.stat().st_size, "sha256": sha_file(p)}
             for p in sorted(output.iterdir()) if p.name != "INCOMPLETE.json"}
    manifest = {
        "package_version": "bot_iot_secondary_v2", "status": "PREPARED_PENDING_REVIEW",
        "test_status": "SEALED_DEFAULT", "dtype": "float64", "fit_partition": "TRAIN",
        "label_mapping": {"benign": 0, "malicious": 1}, "source_git_revision": revision,
        "source_dirty_worktree": bool(dirty), "source_dirty_status": dirty,
        "policy_git_revision": policy_commit, "implementation_sha256": implementation,
        "contract_sha256": files["contract_v2.json"]["sha256"],
        "protocol_sha256": files["protocol_v2.md"]["sha256"],
        "decision_sha256": files["decision.md"]["sha256"],
        "preprocessor_sha256": files["preprocessing.json"]["sha256"],
        "expected_partitions": contract["expected_partitions"],
        "sources": contract["canonical_sources"], "source_content_identities": scan["sources"],
        "inherited_evidence": contract["inherited_evidence"],
        "encoded_features": state["encoded_features"], "unknowns": unknowns,
        "preprocessing_parity": {"all_observations": parity_rows,
                                "reference_vs_portable_after_serialization": "PASS"},
        "runtime": {"numpy": np.__version__, "python": sys.version,
                    "scikit-learn": version("scikit-learn")}, "files": files,
    }
    write_json(output/"manifest.json", manifest)
    (output/"INCOMPLETE.json").unlink()
    receipt = {
        "status": "PREPARED_PENDING_REVIEW", "package": str(output),
        "manifest_sha256": sha_file(output/"manifest.json"),
        "bytes": sum(p.stat().st_size for p in output.iterdir()),
        "files": len(files)+1, "source_git_revision": revision,
        "source_dirty_worktree": bool(dirty), "policy_git_revision": policy_commit,
        "preprocessor_sha256": files["preprocessing.json"]["sha256"],
        "preprocessing_parity_rows": parity_rows, "unknowns": unknowns,
        "elapsed_seconds": time.perf_counter()-started,
        "peak_rss_bytes": getattr(psutil.Process().memory_info(), "peak_wset",
                                  psutil.Process().memory_info().rss),
        "standalone_verification": "NOT_YET_RUN; separate immutable receipt required",
        "classifier_clustering_fitted": False, "TEST_performance_evaluated": False,
    }
    write_json(args.receipt, receipt)
    print(json.dumps(receipt), flush=True)


if __name__ == "__main__":
    main()
