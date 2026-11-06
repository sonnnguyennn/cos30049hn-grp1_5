"""CODE 4.1.2 (N-BaIoT, local step) - run on the machine that holds the G3B primary package.

Reads the package straight from g3b_primary_v1.zip (no 6 GB extraction needed) or from an
already-extracted package folder, and writes a small extract for the EDA plots:

  * 3 chosen TRAIN feature columns + TRAIN labels (all 4,944,968 rows, no sampling);
  * a copy of VALIDATION_y.npy (labels only, for the clustering composition cross-check);
  * nbaiot_local_receipt.json (hashes, counts, versions, timing, command).

Integrity: manifest.json must have the published SHA-256; every member that is read is
hashed while streaming and must match the manifest. TEST members are never opened.
Needs only Python 3.9+ and NumPy (for example the EDA environment from requirements-eda.txt).

PowerShell example:
  python -I t41_nbaiot_extract_local.py `
      --package "C:\\...\\Primary Data (N-BaIoT)\\g3b_primary_v1.zip" `
      --out "C:\\...\\Primary Data (N-BaIoT)\\nbaiot_extract_01"
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import numpy as np

PUBLISHED_MANIFEST_SHA256 = "6ab99e86397242e219bfa1f8490d8e03b169ec87a092af80cb3e7aef1e61147b"
# One feature per behavioural aspect, all at the same decay window (lambda = 0.1), chosen by
# meaning before looking at any distribution:
FEATURES = {
    "MI_dir_L0.1_weight": "volume: decayed packet count from the source MAC-IP",
    "H_L0.1_mean": "size: mean packet size sent from the source IP",
    "HH_jit_L0.1_mean": "timing: mean inter-packet interval on the source-destination channel",
}
CHUNK_ROWS = 32768
NEEDED = (
    "manifest.json",
    "n_baiot_feature_contract_v1.json",
    "TRAIN_y.npy",
    "VALIDATION_y.npy",
    "TRAIN_X.npy",
)


class HashingReader:
    """File-like wrapper that hashes every byte read and counts them."""

    def __init__(self, handle):
        self.handle = handle
        self.sha = hashlib.sha256()
        self.bytes = 0

    def read(self, size=-1):
        data = self.handle.read(size)
        self.sha.update(data)
        self.bytes += len(data)
        return data

    def read_exact(self, size):
        parts, remaining = [], size
        while remaining:
            data = self.read(min(remaining, 64 * 1024 * 1024))
            if not data:
                raise EOFError("member ended early")
            parts.append(data)
            remaining -= len(data)
        return b"".join(parts)

    def finish(self):
        while self.read(16 * 1024 * 1024):
            pass
        return self.sha.hexdigest(), self.bytes


class PackageSource:
    def __init__(self, path: Path):
        self.path = path
        self.opened = []
        if path.is_dir():
            self.zip = None
            self.members = {p.name: p for p in path.iterdir() if p.is_file()}
        else:
            self.zip = zipfile.ZipFile(path)
            found = {}
            for info in self.zip.infolist():
                name = PurePosixPath(info.filename).name
                if info.is_dir() or not name:
                    continue
                if name in found:
                    raise ValueError(f"ZIP holds more than one {name}; pass the extracted folder")
                found[name] = info
            parents = {str(PurePosixPath(found[n].filename).parent) for n in NEEDED if n in found}
            if len(parents) > 1:
                raise ValueError(f"package members are in different folders: {sorted(parents)}")
            self.members = found
        missing = [n for n in NEEDED if n not in self.members]
        if missing:
            raise FileNotFoundError(f"package is missing {missing}")

    def open(self, name):
        if name.upper().startswith("TEST"):
            raise PermissionError("TEST members are never opened by this script")
        self.opened.append(name)
        member = self.members[name]
        handle = self.zip.open(member) if self.zip else open(member, "rb")
        return HashingReader(handle)


def verified_bytes(source, name, manifest):
    reader = source.open(name)
    data = reader.read()
    digest, size = reader.finish()
    expect = manifest["files"][name]
    if digest != expect["sha256"] or size != expect["bytes"]:
        raise ValueError(f"{name}: checksum/size mismatch with manifest")
    return data


def read_header(reader):
    version = np.lib.format.read_magic(reader)
    if version == (1, 0):
        shape, fortran, dtype = np.lib.format.read_array_header_1_0(reader)
    elif version == (2, 0):
        shape, fortran, dtype = np.lib.format.read_array_header_2_0(reader)
    else:
        raise ValueError(f"unsupported .npy version {version}")
    if fortran:
        raise ValueError("Fortran-ordered arrays are not expected in the package")
    return shape, np.dtype(dtype)


def load_small_npy(source, name, manifest):
    import io

    data = verified_bytes(source, name, manifest)
    return np.load(io.BytesIO(data), allow_pickle=False), data


def stream_columns(source, manifest, columns, expected_rows):
    reader = source.open("TRAIN_X.npy")
    shape, dtype = read_header(reader)
    if shape != (expected_rows, 115) or dtype != np.dtype("<f8"):
        raise ValueError(
            f"TRAIN_X.npy has shape {shape} dtype {dtype}; expected ({expected_rows}, 115) <f8"
        )
    out = np.empty((expected_rows, len(columns)), dtype=np.float64)
    row_bytes = 115 * 8
    started, done, next_report = time.time(), 0, 0.1
    while done < expected_rows:
        rows = min(CHUNK_ROWS, expected_rows - done)
        block = np.frombuffer(reader.read_exact(rows * row_bytes), dtype="<f8").reshape(rows, 115)
        out[done : done + rows] = block[:, columns]
        done += rows
        if done / expected_rows >= next_report:
            print(
                f"  TRAIN_X.npy {100 * done / expected_rows:5.1f}%  {time.time() - started:6.1f}s",
                flush=True,
            )
            next_report += 0.1
    digest, size = reader.finish()
    expect = manifest["files"]["TRAIN_X.npy"]
    if digest != expect["sha256"] or size != expect["bytes"]:
        raise ValueError("TRAIN_X.npy: checksum/size mismatch with manifest")
    return out, {"sha256": digest, "bytes": size, "seconds": round(time.time() - started, 1)}


def main():
    parser = argparse.ArgumentParser(description="Extract 3 TRAIN features from the G3B package")
    parser.add_argument(
        "--package",
        required=True,
        type=Path,
        help="g3b_primary_v1.zip or the extracted package folder",
    )
    parser.add_argument(
        "--out", required=True, type=Path, help="NEW output folder (must not exist)"
    )
    parser.add_argument("--expected-manifest-sha256", default=PUBLISHED_MANIFEST_SHA256)
    parser.add_argument(
        "--hash-zip", action="store_true", help="also record the SHA-256 of the whole ZIP (slower)"
    )
    args = parser.parse_args()
    started = time.time()
    if args.out.exists():
        raise SystemExit(f"{args.out} already exists; choose a new folder (e.g. ..._02)")
    source = PackageSource(args.package.resolve())

    manifest_reader = source.open("manifest.json")
    manifest_bytes = manifest_reader.read()
    manifest_sha, _ = manifest_reader.finish()
    if manifest_sha != args.expected_manifest_sha256:
        raise SystemExit(
            f"manifest.json SHA-256 {manifest_sha} != expected "
            f"{args.expected_manifest_sha256}; wrong or modified package"
        )
    manifest = json.loads(manifest_bytes)
    print(f"manifest.json OK ({manifest_sha})")

    contract = json.loads(verified_bytes(source, "n_baiot_feature_contract_v1.json", manifest))
    names = contract["ordered_feature_names"]
    if len(names) != 115:
        raise ValueError("feature contract must list 115 ordered names")
    columns = [names.index(f) for f in FEATURES]
    print("features:", dict(zip(FEATURES, columns)))

    y_train, _ = load_small_npy(source, "TRAIN_y.npy", manifest)
    y_val, y_val_bytes = load_small_npy(source, "VALIDATION_y.npy", manifest)
    counts = {
        p: {"benign": int((a == 0).sum()), "malicious": int((a == 1).sum()), "rows": int(len(a))}
        for p, a in (("TRAIN", y_train), ("VALIDATION", y_val))
    }
    for p, c in counts.items():
        if c["benign"] + c["malicious"] != c["rows"]:
            raise ValueError(f"{p} labels contain values other than 0/1")
    print("label counts:", counts)

    X, train_x_identity = stream_columns(source, manifest, columns, len(y_train))
    if not np.isfinite(X).all():
        raise ValueError("non-finite values in the selected columns")

    args.out.mkdir(parents=True)
    npz_path = args.out / "nbaiot_train_selected_features.npz"
    np.savez_compressed(
        npz_path,
        X=X,
        y=y_train.astype(np.uint8),
        feature_names=np.array(list(FEATURES)),
        feature_indices=np.array(columns),
    )
    (args.out / "VALIDATION_y.npy").write_bytes(y_val_bytes)

    def sha(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(4 * 1024 * 1024), b""):
                h.update(block)
        return h.hexdigest()

    receipt = {
        "schema": "duy_nbaiot_local_extract_v1",
        "status": "PASS",
        "created_utc": datetime.now(timezone.utc).isoformat(),  # noqa: UP017 (Python 3.9+)
        "command": [Path(sys.executable).name, *sys.argv],
        "package_source": {
            "path_name": args.package.name,
            "kind": "zip" if source.zip else "folder",
            "bytes": args.package.stat().st_size if source.zip else None,
            "sha256": sha(args.package) if (args.hash_zip and source.zip) else None,
        },
        "manifest_sha256": manifest_sha,
        "package_version": manifest.get("package_version"),
        "members_read_and_verified": {
            "manifest.json": manifest_sha,
            "n_baiot_feature_contract_v1.json": manifest["files"][
                "n_baiot_feature_contract_v1.json"
            ]["sha256"],
            "TRAIN_y.npy": manifest["files"]["TRAIN_y.npy"]["sha256"],
            "VALIDATION_y.npy": manifest["files"]["VALIDATION_y.npy"]["sha256"],
            "TRAIN_X.npy": train_x_identity["sha256"],
        },
        "members_opened": source.opened,
        "test_members_opened": [m for m in source.opened if m.upper().startswith("TEST")],
        "label_counts": counts,
        "features": [
            {"name": f, "index": c, "reason": FEATURES[f]} for f, c in zip(FEATURES, columns)
        ],
        "sampling": "none: every TRAIN row",
        "outputs": {
            "nbaiot_train_selected_features.npz": {
                "sha256": sha(npz_path),
                "bytes": npz_path.stat().st_size,
            },
            "VALIDATION_y.npy": {
                "sha256": sha(args.out / "VALIDATION_y.npy"),
                "bytes": (args.out / "VALIDATION_y.npy").stat().st_size,
            },
        },
        "timing_seconds": {
            "TRAIN_X_stream": train_x_identity["seconds"],
            "total": round(time.time() - started, 1),
        },
        "environment": {
            "python": sys.version.split()[0],
            "numpy": np.__version__,
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
    }
    (args.out / "nbaiot_local_receipt.json").write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
    )
    print(f"PASS - wrote {args.out} in {receipt['timing_seconds']['total']} s")


if __name__ == "__main__":
    main()
