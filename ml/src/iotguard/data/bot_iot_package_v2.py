"""Portable NumPy-only Bot-IoT v2 loader and typed UNKNOWN preprocessing."""

import hashlib
import json
from pathlib import Path

import numpy as np

NUMERIC = ("pkts", "bytes", "dur", "spkts", "dpkts", "sbytes", "dbytes",
           "rate", "srate", "drate")
CATEGORICAL = ("flgs", "proto", "state")
PREDICTORS = NUMERIC + CATEGORICAL
PARTITIONS = ("TRAIN", "VALIDATION", "TEST")
META = np.dtype([("source", "<u2"), ("row", "<u8"), ("pk", "<u8"),
                 ("group", "S64"), ("group_size", "<u8")])


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(4*1024*1024), b""):
            digest.update(block)
    return digest.hexdigest()


def valid_category(value):
    return (isinstance(value, str) and bool(value) and value == value.strip()
            and value.lower() not in {"nan", "null", "none"})


def validate_inputs(numeric, categorical):
    raw = np.asarray(numeric)
    cats = np.asarray(categorical, dtype=object)
    if (raw.ndim != 2 or raw.shape[1] != 10 or raw.dtype.kind not in "fiu"
            or cats.shape != (len(raw), 3)):
        raise ValueError("Expected numeric(n,10) and categorical(n,3)")
    counts = raw[:, [0, 1, 3, 4, 5, 6]]
    if (counts > 2**53).any() or (counts != np.floor(counts)).any():
        raise ValueError("Invalid exact count")
    nums = raw.astype(np.float64, copy=False)
    if not np.isfinite(nums).all() or (nums < 0).any():
        raise ValueError("Invalid finite nonnegative numeric values")
    if not all(valid_category(v) for v in cats.flat):
        raise ValueError("Invalid category syntax; UNKNOWN is only for valid novel strings")
    return nums, cats


def feature_names(vocabulary):
    names = ["numeric:" + n for n in NUMERIC]
    for field in CATEGORICAL:
        names.extend("source:" + field + ":" + json.dumps(v, ensure_ascii=True)
                     for v in vocabulary[field])
        names.append("reserved_unknown:" + field)
    return names


class PortablePreprocessor:
    def __init__(self, state):
        self.state = state
        if (state["schema"] != "bot_iot_preprocessor_v2" or state["fit_partition"] != "TRAIN"
                or state["predictors"] != list(PREDICTORS) or state["drop"] is not None
                or state["n_samples_seen"] < 1):
            raise ValueError("Invalid preprocessing schema")
        self.vocabulary = state["vocabulary"]
        if set(self.vocabulary) != set(CATEGORICAL):
            raise ValueError("Categorical field mismatch")
        for field in CATEGORICAL:
            values = self.vocabulary[field]
            if values != sorted(set(values)) or not all(valid_category(v) for v in values):
                raise ValueError("Invalid learned vocabulary")
            if state["unknown"][field] != {
                    "kind": "reserved_unknown", "field": field, "index": len(values)}:
                raise ValueError("Invalid typed UNKNOWN slot")
        if state["encoded_features"] != feature_names(self.vocabulary):
            raise ValueError("Encoded order mismatch")
        self.mean = np.asarray(state["mean"], dtype=np.float64)
        self.var = np.asarray(state["var"], dtype=np.float64)
        self.scale = np.asarray(state["scale"], dtype=np.float64)
        if any(a.shape != (10,) or not np.isfinite(a).all()
               for a in (self.mean, self.var, self.scale)):
            raise ValueError("Invalid numeric state")
        if (self.var < 0).any() or (self.scale <= 0).any():
            raise ValueError("Invalid variance/scale")
        self.maps = {f: {v: i for i, v in enumerate(self.vocabulary[f])} for f in CATEGORICAL}

    def category_codes(self, categorical):
        cats = np.asarray(categorical, dtype=object)
        if cats.ndim != 2 or cats.shape[1] != 3 or not all(
                valid_category(v) for v in cats.flat):
            raise ValueError("Invalid category syntax")
        result = np.empty(cats.shape, dtype=np.uint16)
        for j, field in enumerate(CATEGORICAL):
            result[:, j] = [self.maps[field].get(v, len(self.maps[field])) for v in cats[:, j]]
        return result

    def transform_codes(self, numeric, codes):
        raw = np.asarray(numeric)
        codes = np.asarray(codes)
        # Codes are package schema values, not source categories.
        if (raw.ndim != 2 or raw.shape[1] != 10 or raw.dtype != np.float64
                or not np.isfinite(raw).all() or (raw < 0).any()
                or codes.shape != (len(raw), 3) or codes.dtype.kind not in "iu"):
            raise ValueError("Invalid numeric/code arrays")
        counts = raw[:, [0, 1, 3, 4, 5, 6]]
        if (counts > 2**53).any() or (counts != np.floor(counts)).any():
            raise ValueError("Invalid numeric counts")
        result = np.zeros((len(raw), len(self.state["encoded_features"])), dtype=np.float64)
        result[:, :10] = (raw-self.mean)/self.scale
        offset = 10
        for j, field in enumerate(CATEGORICAL):
            width = len(self.vocabulary[field])+1
            if (codes[:, j] < 0).any() or (codes[:, j] >= width).any():
                raise ValueError("Invalid categorical code")
            result[np.arange(len(raw)), offset+codes[:, j].astype(np.int64)] = 1.0
            offset += width
        return result

    def transform(self, numeric, categorical):
        nums, cats = validate_inputs(numeric, categorical)
        return self.transform_codes(nums, self.category_codes(cats))


class SecondaryPackage:
    def __init__(self, directory, *, verify=True):
        self.root = Path(directory).resolve()
        if (self.root / "INCOMPLETE.json").exists():
            raise ValueError("Incomplete package")
        self.manifest = json.loads((self.root / "manifest.json").read_bytes())
        m = self.manifest
        if (m["package_version"] != "bot_iot_secondary_v2"
                or m["status"] != "PREPARED_PENDING_REVIEW" or m["test_status"] != "SEALED_DEFAULT"
                or m["dtype"] != "float64" or m["fit_partition"] != "TRAIN"
                or m["label_mapping"] != {"benign": 0, "malicious": 1}):
            raise ValueError("Incompatible package identity/schema")
        required = {"preprocessing.json", "contract_v2.json", "protocol_v2.md", "decision.md",
                    "groups.sqlite", "bot_iot_package_v2.py", "verify_package.py", "README.md"}
        suffixes = ("numeric.npy", "categorical.npy", "y.npy", "metadata.npy", "membership.jsonl")
        required |= {f"{p}_{s}" for p in PARTITIONS for s in suffixes}
        if not required.issubset(m["files"]):
            raise ValueError("Missing required payload identity")
        actual_files = {p.name for p in self.root.iterdir() if p.is_file()}
        if actual_files != set(m["files"]) | {"manifest.json"}:
            raise ValueError("Checksum coverage differs from package files")
        for name, info in m["files"].items():
            path = (self.root / name).resolve()
            if path.parent != self.root or path.stat().st_size != info["bytes"]:
                raise ValueError("Invalid payload path/size")
            if verify and sha_file(path) != info["sha256"]:
                raise ValueError(f"Payload hash mismatch: {name}")
        for name, key in (("contract_v2.json", "contract_sha256"),
                          ("protocol_v2.md", "protocol_sha256"),
                          ("decision.md", "decision_sha256"),
                          ("preprocessing.json", "preprocessor_sha256")):
            if m["files"][name]["sha256"] != m[key]:
                raise ValueError("Identity binding mismatch")
        contract = json.loads((self.root / "contract_v2.json").read_bytes())
        if (contract["contract_version"] != "2.0.0"
                or m["expected_partitions"] != contract["expected_partitions"]
                or m["sources"] != contract["canonical_sources"]):
            raise ValueError("Contract identity/count mismatch")
        for name, expected in contract["inherited_evidence"].items():
            if m["files"][name]["sha256"] != expected:
                raise ValueError("Inherited evidence identity mismatch")
        code_payloads = {"bot_iot_package_v2.py": "src/iotguard/data/bot_iot_package_v2.py",
                         "verify_package.py": "scripts/verify_bot_iot_package_v2.py"}
        for payload, source in code_payloads.items():
            if m["files"][payload]["sha256"] != m["implementation_sha256"]["ml/"+source]:
                raise ValueError("Portable implementation identity mismatch")
        if (len(m["source_git_revision"]) != 40 or len(m["policy_git_revision"]) != 40
                or not isinstance(m["source_dirty_worktree"], bool)):
            raise ValueError("Invalid source Git identity")
        self.preprocessor = PortablePreprocessor(json.loads(
            (self.root / "preprocessing.json").read_bytes()))
        if (self.preprocessor.state["n_samples_seen"] != m["expected_partitions"]["TRAIN"]["rows"]
                or self.preprocessor.state["encoded_features"] != m["encoded_features"]
                or len(m["encoded_features"]) != 36):
            raise ValueError("TRAIN preprocessing identity mismatch")

    def load(self, partition, *, allow_test=False):
        if partition not in PARTITIONS:
            raise ValueError("Invalid partition")
        if partition == "TEST" and not allow_test:
            raise PermissionError("TEST sealed; explicit mechanical access required")
        arrays = tuple(np.load(self.root/f"{partition}_{s}.npy", mmap_mode="r", allow_pickle=False)
                       for s in ("numeric", "categorical", "y", "metadata"))
        n = self.manifest["expected_partitions"][partition]["rows"]
        for array, shape, dtype in zip(arrays, ((n, 10), (n, 3), (n,), (n,)),
                                       (np.dtype("<f8"), np.dtype("<u2"), np.dtype("u1"), META),
                                       strict=True):
            if array.shape != shape or array.dtype != dtype:
                raise ValueError("Array schema/count mismatch")
        return arrays

    def chunks(self, partition, *, chunk_size=8192, allow_test=False):
        if chunk_size < 1:
            raise ValueError("chunk_size must be positive")
        nums, cats, labels, metadata = self.load(partition, allow_test=allow_test)
        for start in range(0, len(labels), chunk_size):
            stop = start+chunk_size
            yield (self.preprocessor.transform_codes(nums[start:stop], cats[start:stop]),
                   labels[start:stop], metadata[start:stop])
