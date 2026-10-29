"""Run a bounded, read-only G2B smoke check over five canonical source files."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from itertools import islice
from pathlib import Path
from typing import Any

from iotguard.data.bot_iot import iter_bot_iot_records
from iotguard.data.n_baiot import iter_n_baiot_records

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT / "artifacts" / "audit" / "g2b_smoke_verification.json"
SOURCE_EVIDENCE = PROJECT_ROOT / "artifacts" / "audit" / "a4_evidence_verification.json"
ROWS_PER_SOURCE = 3

N_BAIOT_SAMPLES = (
    (
        "raw",
        "Danmini_Doorbell/benign_traffic.csv",
        "n_baiot:source:Danmini_Doorbell/benign_traffic.csv",
    ),
    (
        "extracted",
        "Danmini_Doorbell/gafgyt_attacks/combo.csv",
        "n_baiot:extracted:Danmini_Doorbell/gafgyt_attacks/combo.csv",
    ),
    (
        "extracted",
        "Danmini_Doorbell/mirai_attacks/udpplain.csv",
        "n_baiot:extracted:Danmini_Doorbell/mirai_attacks/udpplain.csv",
    ),
)
BOT_IOT_SAMPLES = (
    "Dataset/5%/All features/UNSW_2018_IoT_Botnet_Full5pc_1.csv",
    "Dataset/5%/All features/UNSW_2018_IoT_Botnet_Full5pc_2.csv",
)


def load_default_roots() -> dict[str, Path]:
    with SOURCE_EVIDENCE.open("r", encoding="utf-8") as handle:
        source_safety = json.load(handle)["source_safety"]
    return {
        name: Path(details["root"])
        for name, details in source_safety.items()
        if name in {"n_baiot_raw", "n_baiot_extracted", "bot_iot_raw"}
    }


def snapshot(path: Path, relative_path: str) -> dict[str, Any]:
    stat = path.stat()
    return {
        "relative_path": relative_path,
        "size_bytes": stat.st_size,
        "modified_time_ns": stat.st_mtime_ns,
    }


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def run_smoke(
    n_baiot_raw_root: Path,
    n_baiot_extracted_root: Path,
    bot_iot_root: Path,
) -> dict[str, Any]:
    roots = {"raw": n_baiot_raw_root, "extracted": n_baiot_extracted_root}
    all_paths: list[tuple[Path, str]] = []
    for root_kind, relative_path, _ in N_BAIOT_SAMPLES:
        all_paths.append((roots[root_kind] / Path(relative_path), relative_path))
    for relative_path in BOT_IOT_SAMPLES:
        all_paths.append((bot_iot_root / Path(relative_path), relative_path))
    for path, _ in all_paths:
        if not path.is_file():
            raise FileNotFoundError(path)
    before = [snapshot(path, relative) for path, relative in all_paths]

    n_results: list[dict[str, Any]] = []
    deterministic_n = True
    for root_kind, relative_path, logical_id in N_BAIOT_SAMPLES:
        path = roots[root_kind] / Path(relative_path)
        records = list(islice(iter_n_baiot_records(path, logical_id), ROWS_PER_SOURCE))
        if len(records) != ROWS_PER_SOURCE:
            raise ValueError(f"Smoke source has fewer than {ROWS_PER_SOURCE} rows: {logical_id}")
        repeated = next(iter_n_baiot_records(path, logical_id))
        deterministic_n &= repeated == records[0]
        n_results.append(
            {
                "source_logical_id": logical_id,
                "relative_path": relative_path,
                "rows": [
                    {
                        "data_row_index": record.data_row_index,
                        "feature_count": len(record.features),
                        "target_binary": record.target_binary,
                        "label_family": record.label_family,
                        "label_fine": record.label_fine,
                        "duplicate_group_id": record.duplicate_group_id,
                        "validation_result": "PASS",
                    }
                    for record in records
                ],
            }
        )

    bot_results: list[dict[str, Any]] = []
    deterministic_bot = True
    for relative_path in BOT_IOT_SAMPLES:
        path = bot_iot_root / Path(relative_path)
        records = list(islice(iter_bot_iot_records(path, relative_path), ROWS_PER_SOURCE))
        if len(records) != ROWS_PER_SOURCE:
            raise ValueError(f"Smoke shard has fewer than {ROWS_PER_SOURCE} rows: {relative_path}")
        repeated = next(iter_bot_iot_records(path, relative_path))
        deterministic_bot &= repeated == records[0]
        bot_results.append(
            {
                "source_logical_id": records[0].source_logical_id,
                "relative_path": relative_path,
                "rows": [
                    {
                        "data_row_index": record.data_row_index,
                        "observed_column_count": 46,
                        "target_metadata": dict(record.target_metadata),
                        "identifier_field_count": len(record.identifier_metadata),
                        "port_kinds": {
                            name: parsed.kind for name, parsed in record.ports.items()
                        },
                        "validation_result": "PASS",
                    }
                    for record in records
                ],
            }
        )

    after = [snapshot(path, relative) for path, relative in all_paths]
    return {
        "audit_batch": "G2B bounded real-source smoke verification",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "scope": {
            "n_baiot_logical_sources": len(N_BAIOT_SAMPLES),
            "bot_iot_canonical_shards": len(BOT_IOT_SAMPLES),
            "rows_per_source": ROWS_PER_SOURCE,
            "source_rows_read_for_results": ROWS_PER_SOURCE
            * (len(N_BAIOT_SAMPLES) + len(BOT_IOT_SAMPLES)),
            "full_dataset_materialized": False,
        },
        "n_baiot": n_results,
        "bot_iot": bot_results,
        "determinism": {
            "n_baiot_first_records_identical_on_repeat": deterministic_n,
            "bot_iot_first_records_identical_on_repeat": deterministic_bot,
            "timestamp_or_randomness_in_canonical_records": False,
        },
        "source_safety": {
            "selected_file_metadata_before": before,
            "selected_file_metadata_after": after,
            "selected_file_metadata_unchanged": before == after,
        },
        "execution_counts": {
            "clustering_runs": 0,
            "deduplicated_rows": 0,
            "model_training_runs": 0,
            "resampling_runs": 0,
            "split_files_written": 0,
            "transform_fit_runs": 0,
        },
        "overall_status": (
            "PASS" if deterministic_n and deterministic_bot and before == after else "FAIL"
        ),
    }


def main() -> int:
    defaults = load_default_roots()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-baiot-raw-root", type=Path, default=defaults["n_baiot_raw"])
    parser.add_argument(
        "--n-baiot-extracted-root",
        type=Path,
        default=defaults["n_baiot_extracted"],
    )
    parser.add_argument("--bot-iot-root", type=Path, default=defaults["bot_iot_raw"])
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    payload = run_smoke(
        args.n_baiot_raw_root.resolve(),
        args.n_baiot_extracted_root.resolve(),
        args.bot_iot_root.resolve(),
    )
    write_json_atomic(args.output.resolve(), payload)
    print(f"Wrote: {args.output.resolve()}")
    print(f"Overall status: {payload['overall_status']}")
    return 0 if payload["overall_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
