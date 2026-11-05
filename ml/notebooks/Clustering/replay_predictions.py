"""Regenerate a full run's predictions from saved configuration and model files."""
import argparse
import json
from pathlib import Path

import joblib
import numpy as np
from threadpoolctl import threadpool_limits

from clustering_utils import open_package, read_config, save_predictions, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--package-dir", type=Path, help="Optional relocated copy of the SAME package")
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    cfg = read_config(run_dir / "configuration.json")
    if cfg["stage"] != "full":
        raise ValueError("Replay expects a full run, not a sampled pilot")
    if args.package_dir:
        cfg["package_dir"] = str(args.package_dir.resolve())
    package, identity = open_package(cfg)
    saved_identity = json.loads((run_dir / "package_identity.json").read_text())
    if identity != saved_identity:
        raise ValueError("Package / population fingerprints differ")
    # New destination preserves the original experiment evidence.
    args.output_dir.mkdir(parents=True, exist_ok=False)
    index = json.loads((run_dir / "run_index.json").read_text())
    receipt = []
    with threadpool_limits(limits=cfg["threads"]):
        for item in index:
            bundle = joblib.load(run_dir / item["run_id"] / "model.joblib")
            if bundle["identity"] != identity or bundle["scaling"] != item["scaling"]:
                raise ValueError("Model bundle mismatch")
            for split in ("TRAIN", "VALIDATION"):
                target = args.output_dir / f'{item["run_id"]}_{split}_clusters.npy'
                stats = save_predictions(package, bundle["estimator"], item["scaling"], split,
                                         identity["partitions"][split]["shape"][0],
                                         target, cfg["batch_size"])
                original = np.load(run_dir / item["run_id"] / f"{split}_clusters.npy", mmap_mode="r")
                replayed = np.load(target, mmap_mode="r")
                # Integer cluster IDs must reproduce exactly from this saved estimator.
                equal = all(np.array_equal(original[start:start + cfg["batch_size"]],
                                           replayed[start:start + cfg["batch_size"]])
                            for start in range(0, len(original), cfg["batch_size"]))
                if not equal:
                    raise AssertionError(f"Replay mismatch: {item['run_id']} {split}")
                receipt.append({"run_id": item["run_id"], "split": split,
                                "exact_prediction_match": equal, **stats})
    write_json(args.output_dir / "replay_receipt.json", receipt)
    print("Replay passed: all saved cluster assignments match exactly.")


if __name__ == "__main__":
    main()
