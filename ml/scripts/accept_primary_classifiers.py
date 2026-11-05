"""Independently replay received classifiers on VALIDATION; no fitting or TEST."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from iotguard.data.primary_package import PrimaryPackage, sha256_file
from iotguard.evaluation.primary_acceptance import accept_run
from iotguard.evaluation.primary_runtime import (
    EXPECTED_MANIFEST,
    check_file,
    file_identity,
    read_json,
    verified_package,
    write_json,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--package-receipt", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument(
        "--lr", action="store_true", help="Use the extracted checksummed LR archive"
    )
    parser.add_argument("--run", action="append", help="Limit received RF/XGB run folder names")
    args = parser.parse_args()
    inventory = read_json(args.inventory)
    if inventory["status"] != "PASS":
        raise ValueError("Inventory must pass")
    inventory["inventory_identity"] = file_identity(args.inventory)
    if not args.package_receipt.exists():
        package, receipt = verified_package(args.package)
        write_json(args.package_receipt, receipt)
    else:
        receipt = read_json(args.package_receipt)
        check_file(receipt["manifest"])
        if (
            receipt["status"] != "PASS"
            or receipt["manifest"]["sha256"] != EXPECTED_MANIFEST
            or receipt["TEST_opened"]
            or receipt["partitions"] != ["TRAIN", "VALIDATION"]
            or sha256_file(args.package / "manifest.json") != EXPECTED_MANIFEST
        ):
            raise ValueError("Invalid earlier package verification")
        package = PrimaryPackage(args.package)
    if args.lr:
        for name in ("lr_result.json", "dummy_result.json"):
            result = read_json(args.source / name)
            accept_run(package, args.source, name, inventory, args.out / result["run_id"])
    else:
        runs = sorted(args.source.glob("*/result.json"))
        if args.run:
            runs = [p for p in runs if p.parent.name in args.run]
            if len(runs) != len(set(args.run)):
                raise ValueError("Some requested run folders were not found")
        for path in runs:
            accept_run(package, path.parent, path.name, inventory, args.out / path.parent.name)


if __name__ == "__main__":
    main()
