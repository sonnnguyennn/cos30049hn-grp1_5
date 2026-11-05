"""Build an external technical inference handoff from the frozen accepted model."""

import argparse
import importlib.util
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from iotguard.data.primary_package import PrimaryPackage
from iotguard.evaluation.primary_runtime import (
    check_file,
    file_identity,
    read_json,
    write_json,
)


def build(freeze_path, final_receipt_path, package_root, output):
    freeze, final_receipt = read_json(freeze_path), read_json(final_receipt_path)
    if (
        freeze["status"] != "FROZEN_VALIDATION_ONLY"
        or freeze["input_contract"]["family"] != "XGB"
        or final_receipt["status"] != "FINAL_TEST_COMPLETE"
        or final_receipt["freeze"]["sha256"] != file_identity(freeze_path)["sha256"]
        or final_receipt["model"] != freeze["model"]
    ):
        raise ValueError("Require consistent frozen XGBoost and completed final evaluation")
    model = check_file(freeze["model"])
    package = PrimaryPackage(package_root)
    if (
        file_identity(package.root / "manifest.json")["sha256"]
        != freeze["package"]["manifest"]["sha256"]
    ):
        raise ValueError("Package differs from freeze")
    for identity in (
        freeze["input_contract"]["feature_contract"],
        freeze["input_contract"]["scaler"],
    ):
        check_file(identity)
    output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(model, output / "model.json")
    shutil.copyfile(freeze_path, output / "freeze.json")
    shutil.copyfile(final_receipt_path, output / "final_evaluation_receipt.json")
    for name in ("scaler.json", "n_baiot_feature_contract_v1.json"):
        shutil.copyfile(package.root / name, output / name)
    portable = Path(__file__).resolve().parents[1] / "src/iotguard/inference/primary_classifier.py"
    shutil.copyfile(portable, output / "predict_primary.py")
    contract = {
        "schema_version": "primary_classifier_input_v1",
        "dataset": "N-BaIoT",
        "selected_run_id": freeze["selected_run_id"],
        "model_sha256": freeze["model"]["sha256"],
        "package_manifest_sha256": freeze["package"]["manifest"]["sha256"],
        "feature_order": freeze["input_contract"]["feature_order"],
        "input_view": "raw",
        "source_dtype": "float64",
        "model_dtype": "float32",
        "apply_scaler": False,
        "scaler_retention_reason": "Lineage only; selected tree model is raw",
        "label_mapping": {"benign": 0, "malicious": 1},
        "threshold": 0.5,
        "invalid_input_policy": "Reject wrong order/shape, text, nonfinite or float32 overflow",
        "raw_packet_input_supported": False,
    }
    write_json(output / "input_contract.json", contract)
    x, y, metadata = package.load("VALIDATION")
    original_p = np.load(freeze["validation_payloads"]["probabilities.npy"]["path"], mmap_mode="r")
    # A fixed documentation rule, not a new model/threshold selection step.
    chosen = [int(np.flatnonzero(y == label)[0]) for label in (0, 1)]
    errors = np.flatnonzero((original_p >= 0.5) != y)
    if len(errors):
        chosen.append(int(errors[0]))
    write_json(
        output / "example_input.json",
        {"feature_order": contract["feature_order"], "rows": x[chosen].tolist()},
    )
    decisions = (original_p[chosen] >= 0.5).astype("uint8")
    write_json(
        output / "example_expected.json",
        {
            "probabilities": np.asarray(original_p[chosen], dtype=float).tolist(),
            "predictions": decisions.tolist(),
            "labels": ["malicious" if value else "benign" for value in decisions],
        },
    )
    write_json(
        output / "example_lineage.json",
        {
            "partition": "VALIDATION",
            "selection_rule": "first benign, first malicious, first error",
            "partition_indices": chosen,
            "source_row": [
                {"source": int(metadata[i]["source"]), "row": int(metadata[i]["row"])}
                for i in chosen
            ],
            "population_sha256": freeze["selected_result"]["validation_population_sha256"],
            "actual_labels": y[chosen].tolist(),
            "used_for_selection": False,
        },
    )
    (output / "requirements.txt").write_text(
        "numpy==2.4.6\nxgboost==3.2.0\nscipy==1.17.1\n", encoding="utf-8"
    )
    (output / "environment.yml").write_text(
        "name: iotguard-primary-inference\nchannels: [conda-forge]\ndependencies:\n"
        "  - python=3.11\n  - pip\n  - pip:\n"
        "      - numpy==2.4.6\n      - xgboost==3.2.0\n      - scipy==1.17.1\n",
        encoding="utf-8",
    )
    (output / "README.md").write_text(
        "# Frozen primary classifier technical handoff\n\n"
        "This handoff contains the accepted XGBoost model, contract and executable examples. "
        "It supports Minh Son's final packaging and Duy's independent verification. "
        "It does not claim teammate approval, raw packet extraction or operational readiness.\n\n"
        "Create the documented Conda environment with `conda env create -f environment.yml`, "
        "then `conda activate iotguard-primary-inference`. Alternatively create a Python 3.11 "
        "venv and run `python -m pip install -r requirements.txt`.\n\n"
        "The separately published release receipt provides the exact manifest SHA-256. "
        "Replace `<MANIFEST_SHA256>` below with that value; no raw dataset or Git checkout "
        "is needed. Run outputs must use new external paths.\n\n"
        "```text\npython -I predict_primary.py --bundle . --expected-manifest <MANIFEST_SHA256> "
        "--verify --output <fresh-verification.json>\n"
        "python -I predict_primary.py --bundle . --expected-manifest <MANIFEST_SHA256> "
        "--input example_input.json --output <fresh-prediction.json>\n```\n\n"
        "Inputs are numeric feature rows in the exact 115-feature order in input_contract.json. "
        "Use the existing G3B NumPy-only package loader to obtain compatible raw values. "
        "Do not apply scaler.json to this selected tree model; that state is retained for lineage. "
        "The model converts raw values to float32, predicts malicious probabilities and uses "
        "p >= 0.5. Invalid inputs are rejected.\n\n"
        "Historical training reported XGBoost 3.4.1; acceptance/final inference used 3.2.0 "
        "on Windows. All validation confusion counts and original error row identities replayed "
        "exactly. The full accepted replay is the probability reference for these examples. "
        "Do not claim bitwise parity with unavailable historical XGBoost probabilities.\n\n"
        "For primary package verification, obtain the original complete G3B directory from "
        "the custodian, verify manifest SHA256 "
        "6ab99e86397242e219bfa1f8490d8e03b169ec87a092af80cb3e7aef1e61147b, "
        "then run its `python -I -B verify_primary_package.py . --output <new-receipt.json>`. "
        "Its verifier may mechanically check TEST; it does not authorize tuning.\n\n"
        "Training reproduction requires the original source revision/configuration in freeze.json, "
        "the unchanged package and Kaggle. No fitting is implemented in this inference handoff. "
        "Do not refit, retune or select again from final TEST results. "
        "Source ZIP/report/clustering and human review remain with their designated owners.\n",
        encoding="utf-8",
    )
    files = {
        p.name: {k: v for k, v in file_identity(p).items() if k != "path"}
        for p in output.iterdir()
        if p.is_file()
    }
    write_json(
        output / "manifest.json",
        {
            "schema_version": "primary_inference_handoff_v1",
            "status": "PREPARED_FOR_REVIEW",
            "selected_run_id": freeze["selected_run_id"],
            "freeze_sha256": file_identity(freeze_path)["sha256"],
            "final_receipt_sha256": file_identity(final_receipt_path)["sha256"],
            "builder": file_identity(Path(__file__)),
            "builder_source_revision": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[2], text=True
            ).strip(),
            "builder_dirty_worktree": bool(
                subprocess.check_output(
                    ["git", "status", "--porcelain"], cwd=Path(__file__).resolve().parents[2]
                )
            ),
            "files": files,
        },
    )
    # Invoke the copied implementation, without loading or fitting any training code.
    spec = importlib.util.spec_from_file_location(
        "handoff_predictor", output / "predict_primary.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    manifest = file_identity(output / "manifest.json")
    verification = module.verify(output, manifest["sha256"])
    return {
        "status": "PREPARED_FOR_REVIEW",
        "directory": str(output.resolve()),
        "bytes": sum(p.stat().st_size for p in output.iterdir() if p.is_file()),
        "manifest": manifest,
        "model": file_identity(output / "model.json"),
        "builder_verification": verification,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", required=True, type=Path)
    parser.add_argument("--final-receipt", required=True, type=Path)
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--release-receipt", required=True, type=Path)
    parser.add_argument("--zip", required=True, type=Path)
    args = parser.parse_args()
    if args.zip.exists() or args.release_receipt.exists():
        parser.error("ZIP and release receipt must use fresh paths")
    result = build(args.freeze, args.final_receipt, args.package, args.out)
    with zipfile.ZipFile(args.zip, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(args.out.iterdir()):
            if path.is_file():
                archive.write(path, path.name)
    result["zip"] = file_identity(args.zip)
    write_json(args.release_receipt, result)
    print(result)
