"""Standalone NumPy-only full integrity, lineage and preprocessing verification."""

import argparse
import hashlib
import importlib.util
import json
import shutil
import sqlite3
import sys
import tempfile
import time
from functools import lru_cache
from itertools import islice
from pathlib import Path

import numpy as np

sys.dont_write_bytecode = True


def verify(root, expected_manifest=None):
    started = time.perf_counter()
    root = Path(root).resolve()
    manifest_sha = hashlib.sha256((root/"manifest.json").read_bytes()).hexdigest()
    if expected_manifest and manifest_sha != expected_manifest:
        raise ValueError("Expected manifest SHA256 differs")
    spec = importlib.util.spec_from_file_location("portable_bot_iot", root/"bot_iot_package_v2.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    package = module.SecondaryPackage(root, verify=True)
    manifest = package.manifest
    state = package.preprocessor.state
    if state["fit_membership_sha256"] != manifest["expected_partitions"]["TRAIN"][
            "membership_sha256"] or state["contract_sha256"] != manifest["contract_sha256"]:
        raise ValueError("Preprocessor fit identity mismatch")
    try:
        package.load("TEST")
    except PermissionError:
        pass
    else:
        raise ValueError("Default TEST seal failed")
    original_db_sha = module.sha_file(root/"groups.sqlite")
    seen = [np.zeros(s["rows"], dtype=bool) for s in manifest["source_content_identities"]]
    counts = {}
    unknowns = {}
    vocab = {f: set() for f in module.CATEGORICAL}
    n, mean, moment = 0, np.zeros(10), np.zeros(10)
    with tempfile.TemporaryDirectory(prefix="iotguard-v2-verify-") as temporary:
        database = Path(temporary)/"verification.sqlite"
        shutil.copyfile(root/"groups.sqlite", database)
        db = sqlite3.connect(database)
        db.execute("PRAGMA cache_size=-65536")
        db.execute("PRAGMA temp_store=FILE")
        db.executescript("""ALTER TABLE groups ADD observed0 INTEGER DEFAULT 0;
          ALTER TABLE groups ADD observed1 INTEGER DEFAULT 0;
          ALTER TABLE groups ADD observed_mask INTEGER DEFAULT 0;""")
        group_counts = [[0, 0], [0, 0], [0, 0]]
        mixed = []
        group_totals = [0, 0, 0]
        for sha, payload, n0, n1, p in db.execute(
                "SELECT sha,payload,n0,n1,partition FROM groups"):
            values = json.loads(payload)
            canonical = json.dumps(values, ensure_ascii=True, allow_nan=False,
                                   separators=(",", ":")).encode("ascii")
            if payload != canonical or hashlib.sha256(payload).hexdigest() != sha:
                raise ValueError("Exact group tuple identity mismatch")
            if p not in (0, 1, 2) or min(n0, n1) < 0 or n0+n1 < 1:
                raise ValueError("Invalid group counts/partition")
            module.validate_inputs(np.array([values[:10]]), [values[10:]])
            group_counts[p][0] += n0
            group_counts[p][1] += n1
            group_totals[p] += 1
            if p == 0:
                for j, f in enumerate(module.CATEGORICAL, 10):
                    vocab[f].add(values[j])
            if n0 and n1:
                mixed.append([sha, n0, n1, p])
        if {f: sorted(v) for f, v in vocab.items()} != state["vocabulary"]:
            raise ValueError("Vocabulary not exactly TRAIN-only")
        if mixed != [["413952c7fb9dc5b9ed4e85b5bd90fcf56ad147a666dacec19fd8ada49a90b844",
                      11, 3733, 0]]:
            raise ValueError("Mixed-label group changed")

        @lru_cache(maxsize=32768)
        def group(sha):
            result = db.execute("SELECT payload,n0,n1,partition FROM groups WHERE sha=?",
                                (sha,)).fetchone()
            if result is None:
                raise ValueError("Unknown exact-X group")
            payload, n0, n1, partition = result
            values = json.loads(payload)
            codes = [state["vocabulary"][f].index(v) if v in state["vocabulary"][f]
                     else len(state["vocabulary"][f])
                     for f, v in zip(module.CATEGORICAL, values[10:], strict=True)]
            return values[:10], codes, n0+n1, partition

        for p, name in enumerate(module.PARTITIONS):
            numeric, categorical, labels, metadata = package.load(name, allow_test=True)
            expected = manifest["expected_partitions"][name]
            if module.sha_file(root/f"{name}_membership.jsonl") != expected["membership_sha256"]:
                raise ValueError("Frozen membership digest changed")
            binary = np.zeros(2, dtype=np.int64)
            unknown = np.zeros(3, dtype=np.int64)
            unknown_rows = 0
            checked = 0
            with (root/f"{name}_membership.jsonl").open("rb") as membership:
                for start in range(0, len(labels), 8192):
                    nums, cats, y, meta = (a[start:start+8192] for a in
                                           (numeric, categorical, labels, metadata))
                    if not np.isin(y, [0, 1]).all():
                        raise ValueError("Invalid binary label")
                    keys, inverse = np.unique(meta["group"], return_inverse=True)
                    details = [group(key.decode("ascii")) for key in keys]
                    if any(d[3] != p for d in details):
                        raise ValueError("Exact group crossed partitions")
                    expected_numeric = np.array([d[0] for d in details])[inverse]
                    expected_codes = np.array([d[1] for d in details], dtype=np.uint16)[inverse]
                    sizes = np.array([d[2] for d in details])[inverse]
                    if (not np.array_equal(nums, expected_numeric)
                            or not np.array_equal(cats, expected_codes)
                            or not np.array_equal(meta["group_size"], sizes)):
                        raise ValueError("Arrays do not represent original exact-X groups")
                    zeros = np.bincount(inverse[y == 0], minlength=len(keys))
                    ones = np.bincount(inverse[y == 1], minlength=len(keys))
                    db.executemany("""UPDATE groups SET observed0=observed0+?,
                      observed1=observed1+?,observed_mask=observed_mask|? WHERE sha=?""",
                                   [(int(a), int(b), 1 << p, key.decode("ascii"))
                                    for key, a, b in zip(keys, zeros, ones, strict=True)])
                    binary += np.bincount(y, minlength=2)
                    flags = np.column_stack([cats[:, j] == len(state["vocabulary"][f])
                                             for j, f in enumerate(module.CATEGORICAL)])
                    unknown += flags.sum(axis=0)
                    unknown_rows += int(flags.any(axis=1).sum())
                    encoded = package.preprocessor.transform_codes(nums, cats)
                    if (not np.isfinite(encoded).all()
                            or not (encoded[:, 10:].sum(axis=1) == 3).all()):
                        raise ValueError("Invalid encoded values/one-hot slots")
                    if name == "TRAIN":
                        bn = len(nums)
                        bm = nums.mean(axis=0)
                        delta = bm-mean
                        moment += ((nums-bm)**2).sum(axis=0)+delta**2*n*bn/(n+bn)
                        mean += delta*bn/(n+bn)
                        n += bn
                    for s in np.unique(meta["source"]):
                        if s >= len(seen):
                            raise ValueError("Invalid lineage source")
                        rows = meta["row"][meta["source"] == s].astype(np.int64)-1
                        if (rows < 0).any() or (rows >= len(seen[s])).any() or len(
                                np.unique(rows)) != len(rows) or seen[s][rows].any():
                            raise ValueError("Duplicate/out-of-range source lineage")
                        seen[s][rows] = True
                    lines = list(islice(membership, len(y)))
                    if len(lines) != len(y):
                        raise ValueError("Membership truncated")
                    for raw, m, target in zip(lines, meta, y, strict=True):
                        value = json.loads(raw)
                        if value != [manifest["sources"][int(m["source"])], int(m["row"]),
                                     str(m["pk"]), str(target), m["group"].decode("ascii")]:
                            raise ValueError("Lineage/label membership mismatch")
                    checked += len(y)
                if membership.read(1):
                    raise ValueError("Unexpected membership rows")
            db.commit()
            if binary.tolist() != [expected["binary_rows"][f] for f in ("benign", "malicious")]:
                raise ValueError("Binary support changed")
            if (binary.tolist() != group_counts[p]
                    or group_totals[p] != expected["distinct_X_groups"]):
                raise ValueError("Group counts changed")
            for y, label in enumerate(("benign", "malicious")):
                support = db.execute(f"SELECT COUNT(*) FROM groups WHERE partition=? AND n{y}>0",
                                     (p,)).fetchone()[0]
                if support != expected["distinct_groups_per_class"][label]:
                    raise ValueError("Distinct class-group support changed")
            counts[name] = {"rows": checked, "binary": binary.tolist(), "groups": group_totals[p]}
            unknowns[name] = {"per_field": unknown.tolist(), "observations": unknown_rows}
            print(f"Verified {name}: {checked:,} rows", flush=True)
        mismatches = db.execute("""SELECT COUNT(*) FROM groups WHERE observed0!=n0
          OR observed1!=n1 OR observed_mask!=(1 << partition)""").fetchone()[0]
        if mismatches or not all(s.all() for s in seen):
            raise ValueError("Original group/label/membership reconciliation failed")
        db.close()
    np.testing.assert_allclose(mean, state["mean"], rtol=1e-10, atol=1e-10)
    np.testing.assert_allclose(moment/n, state["var"], rtol=1e-10, atol=1e-10)
    variance = np.asarray(state["var"])
    epsilon = np.finfo(np.float64).eps
    constant = variance <= n*epsilon*variance+(n*np.asarray(state["mean"])*epsilon)**2
    scale = np.sqrt(variance)
    scale[constant] = 1.0
    np.testing.assert_allclose(scale, state["scale"], rtol=1e-14, atol=1e-14)
    if unknowns != {"TRAIN": {"per_field": [0, 0, 0], "observations": 0},
                   "VALIDATION": {"per_field": [0, 0, 0], "observations": 0},
                   "TEST": {"per_field": [0, 8, 8], "observations": 8}}:
        raise ValueError("Unknown handling count differs from frozen diagnostics")
    fake = [["arbitrary_valid_novel_"+f for f in module.CATEGORICAL]]
    codes = package.preprocessor.category_codes(fake)
    if codes.tolist() != [[len(state["vocabulary"][f]) for f in module.CATEGORICAL]]:
        raise ValueError("Generic UNKNOWN mapping failed")
    if module.sha_file(root/"groups.sqlite") != original_db_sha:
        raise ValueError("Verification modified package")
    return {"status": "PASS_STANDALONE_FULL_VERIFICATION",
            "package_status": manifest["status"], "manifest_sha256": manifest_sha,
            "counts": counts, "unknowns": unknowns, "encoded_features": 36,
            "original_exact_X_overlap": 0, "group_label_mismatches": mismatches,
            "TRAIN_only_vocabulary_and_scaler": True, "TEST_default_seal": True,
            "raw_dataset_or_checkout_required": False, "performance_metrics_computed": False,
            "elapsed_seconds": time.perf_counter()-started}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--expected-manifest")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.directory, args.expected_manifest)
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    print(json.dumps(result))
