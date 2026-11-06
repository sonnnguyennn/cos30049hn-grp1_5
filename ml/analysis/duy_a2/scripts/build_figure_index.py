"""Merge the per-figure records into outputs/figure_index.csv and outputs/captions.md.

Each plotting script writes one JSON record per figure (inputs with SHA-256, dataset, run ID,
scope, sample size, weighting, sampling/transform, caption, 2-4 sentence commentary).
Fields that do not apply are written as N/A. Run this last.

Usage (from ml/):  python analysis/duy_a2/scripts/build_figure_index.py
"""

from __future__ import annotations

import json

import _common as C

EXPECTED = [  # report order; figures not produced yet are listed as PENDING
    "fig41a_binary_class_balance",
    "fig41b_attack_groups",
    "fig41c_botiot_train_features",
    "fig41d_nbaiot_train_features",
    "fig41e_duplicates_by_class",
    "fig42a_validation_f1_recall",
    "fig42b_validation_errors_fpr",
    "fig42c_validation_confusion",
    "fig42d_test_confusion_selected",
    "fig42e_clustering_sizes_composition",
    "fig43a_botiot_confusion_row",
    "fig43b_botiot_row_vs_group",
    "fig43c_botiot_benign_groups_lr",
]
PENDING_REASON = {
    "fig41d_nbaiot_train_features": "needs t41_nbaiot_extract_local.py run on the machine that "
    "holds g3b_primary_v1.zip, then t41_nbaiot_train_features.py",
}


def main():
    C.ensure_dirs()
    records = {}
    for path in sorted(C.INDEX_FRAGMENT_DIR.glob("*.json")):
        record = C.read_json(path)
        records[record["figure_id"]] = record
    rows, md = [], ["# Figure captions and commentary", ""]
    for number, figure_id in enumerate(EXPECTED, start=1):
        r = records.get(figure_id)
        if r is None:
            rows.append(
                {
                    "figure_id": figure_id,
                    "status": "PENDING",
                    "files": "N/A",
                    "input_files_sha256": "N/A",
                    "dataset": "N/A",
                    "run_id": "N/A",
                    "scope": "N/A",
                    "n": "N/A",
                    "weighting": "N/A",
                    "sampling_transform": "N/A",
                    "caption": PENDING_REASON.get(figure_id, "not produced"),
                }
            )
            md += [f"## {figure_id} - PENDING", "", PENDING_REASON.get(figure_id, ""), ""]
            continue
        inputs = "; ".join(f"{i['path']} (sha256 {i['sha256']})" for i in r["inputs"])
        rows.append(
            {
                "figure_id": figure_id,
                "status": "DONE",
                "files": "; ".join(r["files"]),
                "input_files_sha256": inputs,
                "dataset": r["dataset"],
                "run_id": r.get("run_id") or "N/A",
                "scope": r["scope"],
                "n": r["n"],
                "weighting": r["weighting"],
                "sampling_transform": r["sampling_transform"],
                "caption": r["caption"],
            }
        )
        md += [
            f"## {figure_id}",
            "",
            f"**Caption.** {r['caption']}",
            "",
            f"**Commentary.** {r['commentary']}",
            "",
            f"*Dataset:* {r['dataset']}. *Scope:* {r['scope']}. *n:* {r['n']}. "
            f"*Weighting:* {r['weighting']}. "
            f"*Sampling/transform:* {r['sampling_transform']}. "
            f"*Run ID:* {r.get('run_id') or 'N/A'}.",
            "",
            f"*Files:* {', '.join(r['files'])}",
            "",
        ]
    unknown = sorted(set(records) - set(EXPECTED))
    if unknown:
        raise SystemExit(f"figure records not in EXPECTED order list: {unknown}")
    index = C.write_csv(C.OUTPUT_DIR / "figure_index.csv", rows)
    (C.OUTPUT_DIR / "captions.md").write_text("\n".join(md), encoding="utf-8")
    done = sum(1 for r in rows if r["status"] == "DONE")
    print(f"{done} figures indexed, {len(rows) - done} pending -> {C.rel(index)}")
    print(json.dumps([r["figure_id"] for r in rows if r["status"] != "DONE"]))


if __name__ == "__main__":
    main()
