"""Bounded assembly/preprocessing smoke; never train a classifier or create a package."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, deque
from importlib.metadata import version
from pathlib import Path

import numpy as np

from iotguard.data.bot_iot import parse_bot_iot_record
from iotguard.data.bot_iot_secondary import (
    PREDICTORS,
    SecondaryPreprocessor,
    assemble_secondary,
    feature_frame,
)
from iotguard.data.contracts import bot_iot_source_columns, load_contract


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prefix-rows", type=int, default=2048)
    args = parser.parse_args()
    if not 1 <= args.prefix_rows <= 4096:
        parser.error("prefix-rows must be 1..4096")
    selected = {}
    scanned = {}
    columns = bot_iot_source_columns()
    ai, si, di = (columns.index(n) for n in ("attack", "sport", "dport"))
    sources = load_contract("bot_iot_secondary_source_contract_v1.json")["canonical_source_files"]
    for shard_no, source in enumerate(sources):
        tail = deque(maxlen=2048)
        quotas = Counter()
        count = 0
        with (args.root / source).open(encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            if tuple(next(reader)) != columns:
                raise ValueError(f"Noncanonical header: {source}")
            for index, raw in enumerate(reader, 1):
                count = index
                if len(raw) != len(columns):
                    raise ValueError(f"Wrong width: {source}:{index}")
                if index <= args.prefix_rows:
                    selected[source, index] = raw
                # Only shard 4 gets a targeted lexical scan: benign and unusual ports
                # concentrate there. Do not repeat all G1/G2 audits.
                if shard_no == 3:
                    tail.append((index, raw))
                    kinds = []
                    if raw[ai] == "0":
                        kinds.append("benign")
                    for port in (raw[si], raw[di]):
                        if port == "-1":
                            kinds.append("sentinel")
                        elif port.lower().startswith("0x"):
                            kinds.append("hex")
                    for kind in set(kinds):
                        if quotas[kind] < 32:
                            selected[source, index] = raw
                            quotas[kind] += 1
                elif index >= args.prefix_rows:
                    break
        for index, raw in tail:
            selected[source, index] = raw
        scanned[source] = count
    rows = [assemble_secondary(parse_bot_iot_record(raw, source, data_row_index=index))
            for (source, index), raw in sorted(selected.items())]
    again = [assemble_secondary(parse_bot_iot_record(raw, source, data_row_index=index))
             for (source, index), raw in sorted(selected.items())]
    if rows != again:
        raise ValueError("Nondeterministic assembly")
    frame = feature_frame(rows)
    # Diagnostic preprocessing partitions only; not the proposed official split.
    train_indices = {i for i in range(len(rows)) if i % 5 != 0}
    # Ensure diagnostic TRAIN contains each sampled category. This is a coverage
    # fixture, not an official split or a claim about unseen categories.
    for name in ("flgs", "proto", "state"):
        for value in frame[name].unique():
            train_indices.add(int(frame.index[frame[name] == value][0]))
    validation_indices = sorted(set(range(len(rows))) - train_indices)
    preprocessing = SecondaryPreprocessor().fit(
        frame.iloc[sorted(train_indices)], partition="TRAIN")
    transformed = preprocessing.transform(frame.iloc[validation_indices])
    data = transformed.data if hasattr(transformed, "tocsr") else transformed
    if not np.isfinite(data).all():
        raise ValueError("Nonfinite transformed values")
    groups = Counter(r.equivalence_sha256 for r in rows)
    labels_by_group = {}
    for row in rows:
        labels_by_group.setdefault(row.equivalence_sha256, set()).add(row.target)
    report = {
        "status": "VERIFIED_BOUNDED_PREPROCESSING_ONLY",
        "candidate_status": "PROPOSED_FOR_REVIEW",
        "ready_for_training": False,
        "scan_reason": "New transaction-only feature equivalence and real benign/hex/sentinel "
                       "assembly coverage; reuse prior full audits, scan only shard4 plus prefixes",
        "root": str(args.root), "scanned_data_rows": scanned,
        "runtime": {name: version(name) for name in ("numpy", "pandas", "scikit-learn")},
        "implementation_sha256": {
            str(path.relative_to(Path(__file__).resolve().parents[1])):
            hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (Path(__file__).resolve(),
                         Path(__file__).resolve().parents[1]
                         / "src/iotguard/data/bot_iot_secondary.py")},
        "candidate_contract_sha256": hashlib.sha256(
            (Path(__file__).resolve().parents[1]
             / "artifacts/contracts/bot_iot_secondary_ml_candidate_v1.json").read_bytes()
        ).hexdigest(),
        "assembled_rows": len(rows), "prefix_rows_per_shard": args.prefix_rows,
        "sampling": "Each shard prefix; shard4 tail2048 and first32 per benign/hex/sentinel",
        "predictor_order": PREDICTORS,
        "label_counts": dict(Counter(str(r.target) for r in rows)),
        "distinct_effective_groups_per_class_in_sample": {
            str(label): len({r.equivalence_sha256 for r in rows if r.target == label})
            for label in (0, 1)},
        "categorical_values": {n: sorted(frame[n].unique().tolist())
                               for n in ("flgs", "proto", "state")},
        "port_kinds": dict(Counter(p["kind"] for r in rows
                                   for p in r.metadata["ports"].values())),
        "deterministic_reassembly": True,
        "assembled_X_sha256": hashlib.sha256(
            "\n".join(r.equivalence_sha256 for r in rows).encode()).hexdigest(),
        "sample_membership_sha256": hashlib.sha256(json.dumps(
            sorted(selected), separators=(",", ":")).encode()).hexdigest(),
        "duplicate_groups_in_sample": sum(v > 1 for v in groups.values()),
        "duplicate_excess_in_sample": sum(v - 1 for v in groups.values()),
        "conflicting_binary_groups_in_sample": sum(len(v) > 1 for v in labels_by_group.values()),
        "preprocessing_diagnostic_train_rows": len(train_indices),
        "preprocessing_diagnostic_assignment": "every fifth row held out; first representative "
                                               "of each sampled category forced into TRAIN",
        "preprocessing_diagnostic_transform_shape": list(transformed.shape),
        "encoded_feature_order": preprocessing.transformer.get_feature_names_out().tolist(),
        "limitations": ["Nonrandom diagnostic sample; no performance estimate",
                        "No full candidate-equivalence scan or official membership",
                        "No adopted split, official package, classifier or clustering fit",
                        "Sample category coverage is not full-domain validation",
                        "Raw shard hashes inherited from audit; not recomputed by this smoke"],
    }
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps({k: report[k] for k in ("status", "assembled_rows", "label_counts",
                                           "port_kinds", "duplicate_groups_in_sample")}))


if __name__ == "__main__":
    main()
