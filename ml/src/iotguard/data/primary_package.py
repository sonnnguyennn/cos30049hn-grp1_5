"""Portable NumPy-only reader. This file can travel with the processed package."""

import csv
import hashlib
import json
from pathlib import Path

import numpy as np


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


class PrimaryPackage:
    """Read-only memmaps; scaled view is returned only in bounded chunks."""

    def __init__(self, directory, *, verify=False, allow_smoke=False):
        self.root = Path(directory).resolve()
        if (self.root / "INCOMPLETE.json").exists():
            raise ValueError("Package build is incomplete")
        self.manifest = json.loads((self.root / "manifest.json").read_text())
        m = self.manifest
        required = {"package_version", "dtype", "feature_order", "split_version",
                    "label_mapping", "fit_partition", "status", "files", "counts"}
        if not required.issubset(m):
            raise ValueError("Incomplete package manifest schema")
        if (m["package_version"] != "primary_package_v1" or m["dtype"] != "float64"
                or len(m["feature_order"]) != 115 or len(set(m["feature_order"])) != 115
                or m["split_version"] != "primary_split_v1"
                or m["label_mapping"] != {"benign": 0, "malicious": 1}
                or m["fit_partition"] != "TRAIN"
                or m["status"] not in ({"FULL", "SMOKE"} if allow_smoke else {"FULL"})):
            raise ValueError("Incompatible package schema/version")
        feature_contract = json.loads(
            (self.root / "n_baiot_feature_contract_v1.json").read_text())
        if (feature_contract["contract_version"] != "1.0.0"
                or m["feature_order"] != feature_contract["ordered_feature_names"]):
            raise ValueError("Feature order does not match canonical contract")
        required_files = {"scaler.json", "n_baiot_feature_contract_v1.json"} | {
            f"{p}_{name}.npy" for p in ("TRAIN", "VALIDATION", "TEST")
            for name in ("X", "y", "metadata")}
        if not required_files.issubset(m["files"]):
            raise ValueError("Missing checksummed payload entries")
        for name, info in m["files"].items():
            path = (self.root / name).resolve()
            if path.parent != self.root or path.stat().st_size != info["bytes"]:
                raise ValueError("Invalid package file/size")
            if verify and sha256_file(path) != info["sha256"]:
                raise ValueError(f"Checksum mismatch: {name}")
        self.scaler = json.loads((self.root / "scaler.json").read_text())
        if (self.scaler["fit_partition"] != "TRAIN"
                or self.scaler["n_samples_seen"] != m["counts"]["TRAIN"]):
            raise ValueError("Scaler must fit TRAIN")
        self.mean = np.asarray(self.scaler["mean"], dtype=np.float64)
        self.scale = np.asarray(self.scaler["scale"], dtype=np.float64)
        if (self.mean.shape != (115,) or self.scale.shape != (115,)
                or not np.isfinite(self.mean).all() or not np.isfinite(self.scale).all()
                or (self.scale <= 0).any()):
            raise ValueError("Invalid scaler state")

    def load(self, partition, *, allow_test=False):
        if partition not in {"TRAIN", "VALIDATION", "TEST"}:
            raise ValueError("Choose TRAIN or VALIDATION explicitly")
        if partition == "TEST" and not allow_test:
            raise PermissionError("TEST is sealed; explicit mechanical access required")
        n = self.manifest["counts"][partition]
        arrays = tuple(np.load(self.root / f"{partition}_{name}.npy", mmap_mode="r",
                               allow_pickle=False) for name in ("X", "y", "metadata"))
        x, y, meta = arrays
        if (x.dtype != np.float64 or x.shape != (n, 115) or y.dtype != np.uint8
                or y.shape != (n,) or meta.shape != (n,)
                or meta.dtype != np.dtype([("source", "<u2"), ("row", "<u8")])):
            raise ValueError("Array schema/count mismatch")
        return arrays

    def chunks(self, partition, *, scaled=False, chunk_size=4096, allow_test=False):
        if chunk_size < 1:
            raise ValueError("chunk_size must be positive")
        x, y, _ = self.load(partition, allow_test=allow_test)
        for start in range(0, len(y), chunk_size):
            block = x[start:start + chunk_size]
            if scaled:
                block = (block - self.mean) / self.scale
            yield block, y[start:start + chunk_size]

    def export_csv(self, partition, output, *, allow_test=False):
        """Streaming submission-readable CSV; 17 significant digits round-trip float64."""
        with open(output, "x", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(self.manifest["feature_order"] + ["target_binary_numeric"])
            for x, y in self.chunks(partition, allow_test=allow_test):
                for row, target in zip(x, y, strict=True):
                    writer.writerow([format(v, ".17g") for v in row] + [int(target)])
