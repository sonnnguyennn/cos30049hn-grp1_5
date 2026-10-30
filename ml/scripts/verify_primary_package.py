"""Standalone NumPy-only independent package verification, with no raw-data access."""

import argparse
import hashlib
import heapq
import importlib.util
import json
from pathlib import Path

import numpy as np


def verify(root, *, full_membership=True):
    spec = importlib.util.spec_from_file_location("portable_loader", root / "primary_package.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    package = module.PrimaryPackage(root, verify=True)
    m = package.manifest
    expected = {"TRAIN": 4944968, "VALIDATION": 1056372, "TEST": 1061266}
    assert m["counts"] == expected
    assert package.scaler["n_samples_seen"] == expected["TRAIN"]
    assert m["test_status"] == "SEALED"
    try:
        package.load("TEST")
    except PermissionError:
        pass
    else:
        raise AssertionError("Default TEST access must fail")
    arrays = {p: package.load(p, allow_test=True) for p in expected}
    for p, (x, y, meta) in arrays.items():
        classes = np.zeros(2, dtype=np.int64)
        for start in range(0, len(y), 4096):
            block = x[start:start + 4096]
            assert np.isfinite(block).all()
            labels = y[start:start + 4096]
            assert np.isin(labels, [0, 1]).all()
            classes += np.bincount(labels, minlength=2)
            assert (meta[start:start + 4096]["source"] < len(m["sources"])).all()
        assert classes.tolist() == [m["class_counts"][p][s] for s in ("benign", "malicious")]
    # Independent chunk-merged population moments; no scikit-learn dependency.
    n, mean, moment = 0, np.zeros(115), np.zeros(115)
    train = arrays["TRAIN"][0]
    for start in range(0, len(train), 4096):
        block = train[start:start + 4096]
        bn = len(block)
        bm = block.mean(axis=0)
        delta = bm - mean
        moment += ((block - bm)**2).sum(axis=0) + delta**2 * n * bn / (n + bn)
        mean += delta * bn / (n + bn)
        n += bn
    np.testing.assert_allclose(mean, package.mean, rtol=1e-10, atol=1e-10)
    np.testing.assert_allclose(moment / n, package.scaler["var"], rtol=1e-10, atol=1e-10)
    raw = arrays["VALIDATION"][0][:16]
    expected_scaled = (raw - package.mean) / package.scale
    actual = next(package.chunks("VALIDATION", scaled=True, chunk_size=16))[0]
    np.testing.assert_allclose(actual, expected_scaled, rtol=1e-12, atol=1e-12)
    digest = hashlib.sha256()
    checked = 0
    if full_membership:
        heap = []
        for p, (_, _, meta) in arrays.items():
            heapq.heappush(heap, (int(meta[0]["source"]), int(meta[0]["row"]), p, 0))
        previous_source, previous_row = 0, 0
        while heap:
            source, row, p, i = heapq.heappop(heap)
            if source != previous_source:
                assert previous_row == int(m["sources"][previous_source]["expected_row_count"])
                assert source == previous_source + 1
                previous_source, previous_row = source, 0
            assert row == previous_row + 1
            previous_row = row
            x, y, meta = arrays[p]
            vector = np.array(x[i], dtype=np.float64)
            vector[vector == 0] = 0.0
            group = "sha256:" + hashlib.sha256(vector.astype(">f8").tobytes()).hexdigest()
            value = int.from_bytes(hashlib.sha256(
                b"iotguard-primary-split-v1\x1f" + group.encode()).digest()[:8], "big")
            actual_split = ("TRAIN" if value < (70 * 2**64 + 99) // 100 else
                            "VALIDATION" if value < (85 * 2**64 + 99) // 100 else "TEST")
            assert p == actual_split
            s = m["sources"][source]
            assert int(y[i]) == {"benign": 0, "malicious": 1}[s["canonical_binary"]]
            encoded = s["logical_id"].encode()
            digest.update(len(encoded).to_bytes(4, "big") + encoded + row.to_bytes(8, "big"))
            for text in (group, p):
                encoded = text.encode()
                digest.update(len(encoded).to_bytes(4, "big") + encoded)
            checked += 1
            if checked % 500000 == 0:
                print(f"Independent membership: {checked}/7062606", flush=True)
            if i + 1 < len(y):
                heapq.heappush(heap, (int(meta[i + 1]["source"]),
                                      int(meta[i + 1]["row"]), p, i + 1))
        assert previous_source == 88
        assert previous_row == int(m["sources"][-1]["expected_row_count"])
        assert checked == 7062606
        assert digest.hexdigest() == m["membership_sha256"] == (
            "edfeb1d96cd2031e0b459fed16e59ef5b1203a56bd2af2306b15968331a0958c")
    return {"status": "VERIFIED", "counts": expected, "checked_membership_rows": checked,
            "membership_sha256": digest.hexdigest() if full_membership else None,
            "payload_checksums": "PASS", "train_only_scaler_moments": "PASS",
            "test_default_denied": True, "loader_requires_raw_sources": False,
            "manifest_sha256": module.sha256_file(root / "manifest.json")}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.package.resolve())
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
