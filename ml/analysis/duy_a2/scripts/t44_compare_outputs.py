"""CODE 4.4.2 - compare the two handoff outputs with the published expectations.

Runs INSIDE the freshly created environment (standard library + the env's own packages), so
it also records the Python/NumPy/XGBoost/SciPy versions that the check really used.
It never edits the bundle, the manifest or example_expected.json.

  python -I t44_compare_outputs.py --bundle . --verification <verify.json> \
         --predictions <predictions.json> --output <comparison.json>
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as md
import json
import math
import platform
import sys
from pathlib import Path

EXPECTED_MANIFEST = "9fac1acde3f696bb765937c997977b3d7b1e1c2fa6cd60626e910037ea1fe132"
EXPECTED_MODEL = "cb090afa6ad4c3618e20d7c5d635e89aa2d122667ea00835a0acc2f75a4455e6"
EXPECTED_LABELS = ["benign", "malicious", "benign"]
PINNED = {"numpy": "2.4.6", "xgboost": "3.2.0", "scipy": "1.17.1"}
TOL = 1e-12  # same tolerance as predict_primary.py --verify


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--verification", required=True, type=Path)
    parser.add_argument("--predictions", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    checks = []

    def check(name, ok, detail):
        checks.append({"check": name, "status": "PASS" if ok else "FAIL", "detail": detail})

    expected = json.loads((args.bundle / "example_expected.json").read_text(encoding="utf-8"))
    lineage = json.loads((args.bundle / "example_lineage.json").read_text(encoding="utf-8"))
    verification = json.loads(args.verification.read_text(encoding="utf-8"))
    predictions = json.loads(args.predictions.read_text(encoding="utf-8"))

    check(
        "bundle manifest.json SHA-256",
        sha256(args.bundle / "manifest.json") == EXPECTED_MANIFEST,
        sha256(args.bundle / "manifest.json"),
    )
    check("verification status", verification.get("status") == "PASS", verification.get("status"))
    check(
        "verification manifest SHA-256",
        verification.get("manifest_sha256") == EXPECTED_MANIFEST,
        verification.get("manifest_sha256"),
    )
    check(
        "verification model SHA-256",
        verification.get("model_sha256") == EXPECTED_MODEL,
        verification.get("model_sha256"),
    )
    check(
        "example_expected.json labels unchanged",
        expected["labels"] == EXPECTED_LABELS,
        expected["labels"],
    )
    for source, payload in (
        ("verification actual_output", verification.get("actual_output", {})),
        ("prediction output", predictions),
    ):
        check(
            f"{source}: labels == expected",
            payload.get("labels") == expected["labels"],
            payload.get("labels"),
        )
        check(
            f"{source}: predictions == expected",
            payload.get("predictions") == expected["predictions"],
            payload.get("predictions"),
        )
        probs = payload.get("probabilities", [])
        close = len(probs) == len(expected["probabilities"]) and all(
            math.isclose(a, b, rel_tol=TOL, abs_tol=TOL)
            for a, b in zip(probs, expected["probabilities"])
        )
        check(f"{source}: probabilities within 1e-12 of expected", close, probs)
    third_actual = lineage["actual_labels"][2]
    check(
        "third example is the documented false negative (true malicious, predicted benign)",
        third_actual == 1 and predictions.get("labels", [None] * 3)[2] == "benign",
        {"true_label": third_actual, "predicted": predictions.get("labels", [None] * 3)[2]},
    )
    versions = {}
    for package in PINNED:
        try:
            versions[package] = md.version(package)
        except md.PackageNotFoundError:
            versions[package] = None
    for package, pin in PINNED.items():
        check(f"{package} version == pinned {pin}", versions[package] == pin, versions[package])
    result = {
        "overall": "PASS" if all(c["status"] == "PASS" for c in checks) else "FAIL",
        "checks": checks,
        "environment": {
            "python": sys.version,
            "executable_name": Path(sys.executable).name,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "packages": versions,
        },
    }
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    for c in checks:
        print(f"[{c['status']}] {c['check']}: {c['detail']}")
    print("OVERALL", result["overall"])
    sys.exit(0 if result["overall"] == "PASS" else 1)


if __name__ == "__main__":
    main()
