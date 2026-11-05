import argparse
import csv
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

THRESHOLD = 0.5


def load_model(run_dir):
    joblib_path, json_path = run_dir / "model.joblib", run_dir / "model.json"

    if joblib_path.exists():
        import joblib

        model = joblib.load(joblib_path)

        def predict_rf(X):
            return model.predict_proba(X.astype(np.float32))[:, 1]

        return "RandomForest", predict_rf
    if json_path.exists():
        import xgboost as xgb

        model = xgb.Booster()
        model.load_model(str(json_path))

        def predict_xgb(X):
            return model.predict(xgb.DMatrix(X.astype(np.float32)))

        return "XGBoost", predict_xgb

    sys.exit(f"No model.joblib or model.json found in {run_dir}")


def vector_id(row):
    v = np.array(row, dtype=np.float64)
    v[v == 0] = 0.0
    return hashlib.sha256(v.astype(">f8").tobytes()).hexdigest()[:16]


def type_counts():
    return {"rows": 0, "errors": 0}


def device_counts():
    return {"rows": 0, "FP": 0, "FN": 0}


def near(rows):
    return sum(abs(r["p_malicious"] - THRESHOLD) <= 0.1 for r in rows)


def med(rows):
    return float(np.median([r["p_malicious"] for r in rows])) if rows else None


def type_errors_desc(kv):
    return -kv[1]["errors"]


def device_errors_desc(kv):
    return -(kv[1]["FP"] + kv[1]["FN"])


def source_errors_desc(r):
    return -r["errors"]


def main():
    # ----- 1. Read arguments -----
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--package", required=True, type=Path, help="folder containing manifest.json")
    ap.add_argument(
        "--run-dir",
        required=True,
        type=Path,
        help="a finished run folder (has model.joblib or model.json)",
    )
    ap.add_argument(
        "--out", type=Path, default=None, help="where to write results (default: the run folder)"
    )
    ap.add_argument(
        "--chunk-size", type=int, default=50000, help="validation rows scored at a time"
    )
    ap.add_argument(
        "--max-rows",
        type=int,
        default=5000,
        help="keep at most this many wrong rows in detail (all are still COUNTED)",
    )
    args = ap.parse_args()
    out = args.out or args.run_dir
    out.mkdir(parents=True, exist_ok=True)

    # ----- 2. Open package and model -----
    sys.path.insert(0, str(args.package.resolve()))
    from primary_package import PrimaryPackage

    package = PrimaryPackage(args.package, verify=False)
    sources = package.manifest["sources"]
    n_src = len(sources)
    model_name, predict = load_model(args.run_dir)
    x, y, meta = package.load("VALIDATION")
    print(f"model: {model_name}   validation rows: {len(y):,}   sources: {n_src}")

    # ----- 3. Score VALIDATION -----
    support = np.zeros(n_src, dtype=np.int64)
    errors = np.zeros(n_src, dtype=np.int64)
    wrong_rows = []
    n_wrong_total = 0
    for start in range(0, len(y), args.chunk_size):
        block = np.asarray(x[start : start + args.chunk_size])
        labels = np.asarray(y[start : start + args.chunk_size])
        m = meta[start : start + args.chunk_size]
        src = m["source"].astype(np.int64)
        proba = predict(block)
        pred = (proba >= THRESHOLD).astype(np.uint8)
        wrong = pred != labels
        support += np.bincount(src, minlength=n_src)
        errors += np.bincount(src[wrong], minlength=n_src)
        n_wrong_total += int(wrong.sum())
        for i in np.flatnonzero(wrong):
            if len(wrong_rows) < args.max_rows:
                s = sources[int(src[i])]
                wrong_rows.append(
                    {
                        "type": "FP (false alarm)" if labels[i] == 0 else "FN (missed attack)",
                        "device": s["device"],
                        "traffic_type": s["canonical_fine_class"],
                        "source_file": s["logical_id"].split(":", 2)[-1],
                        "source_row": int(m["row"][i]),
                        "p_malicious": round(float(proba[i]), 4),
                        "vector_id": vector_id(block[i]),
                    }
                )
    print(f"scored; wrong rows: {n_wrong_total:,}")

    # ----- 4. Aggregate per source, attack type, device -----
    per_source = []
    by_type = defaultdict(type_counts)
    by_device = defaultdict(device_counts)
    for k, s in enumerate(sources):
        n, e = int(support[k]), int(errors[k])
        kind = "FP" if s["canonical_binary"] == "benign" else "FN"
        per_source.append(
            {
                "device": s["device"],
                "traffic_type": s["canonical_fine_class"],
                "rows": n,
                "errors": e,
                "error_rate": (e / n if n else None),
                "error_kind": kind,
            }
        )
        by_type[s["canonical_fine_class"]]["rows"] += n
        by_type[s["canonical_fine_class"]]["errors"] += e
        by_device[s["device"]]["rows"] += n
        by_device[s["device"]][kind] += e
    fp = sum(d["FP"] for d in by_device.values())
    fn = sum(d["FN"] for d in by_device.values())

    # ----- 5. Detect identical rows -----
    id_counts = Counter(r["vector_id"] for r in wrong_rows)

    # ----- 6. How confident were the wrong predictions? -----
    fn_rows = [r for r in wrong_rows if r["type"].startswith("FN")]
    fp_rows = [r for r in wrong_rows if r["type"].startswith("FP")]
    summary = {
        "model": model_name,
        "run_dir": str(args.run_dir),
        "validation_rows": int(len(y)),
        "wrong_rows": n_wrong_total,
        "false_positives": fp,
        "false_negatives": fn,
        "detail_truncated": n_wrong_total > len(wrong_rows),
        "distinct_wrong_vectors": len(id_counts),
        "most_repeated_wrong_vector_counts": [c for _, c in id_counts.most_common(5)],
        "false_negatives_within_0.1_of_threshold": near(fn_rows),
        "false_positives_within_0.1_of_threshold": near(fp_rows),
        "median_p_malicious_of_false_negatives": med(fn_rows),
        "median_p_malicious_of_false_positives": med(fp_rows),
        "by_traffic_type": {
            k: {**v, "error_rate": v["errors"] / v["rows"] if v["rows"] else None}
            for k, v in by_type.items()
        },
        "by_device": dict(by_device),
    }
    (out / "error_analysis.json").write_text(json.dumps(summary, indent=2))
    with open(out / "errors_by_source.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(per_source[0].keys()))
        w.writeheader()
        w.writerows(per_source)
    with open(out / "misclassified_rows.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(wrong_rows[0].keys()) if wrong_rows else ["none"])
        w.writeheader()
        w.writerows(wrong_rows)

    # ----- 7. Print tables -----
    print(
        f"\nOVERALL  wrong rows {n_wrong_total}  =  {fp} false alarms (FP) + "
        f"{fn} missed attacks (FN)"
        f"   of {len(y):,} rows"
    )
    print(
        f"         {len(id_counts)} distinct feature vectors among "
        f"the {len(wrong_rows)} wrong rows examined"
        f" (most repeated: {summary['most_repeated_wrong_vector_counts']})"
    )
    print(
        f"         confidence: {near(fn_rows)}/{len(fn_rows)} FN and "
        f"{near(fp_rows)}/{len(fp_rows)} FP are within 0.1 of the 0.5 threshold"
    )
    if summary["detail_truncated"]:
        print(
            f"         NOTE: the two lines above cover only the first {len(wrong_rows)} wrong rows "
            f"(raise --max-rows to see all {n_wrong_total}); "
            "all counts and tables below are complete"
        )
    print("\nBY TRAFFIC TYPE (sorted by mistakes)")
    for k, v in sorted(by_type.items(), key=type_errors_desc):
        print(
            f"  {k:16s} rows {v['rows']:>9,}   wrong {v['errors']:>4}   "
            f"rate {v['errors'] / max(v['rows'], 1):.6f}"
        )
    print("\nBY DEVICE (sorted by mistakes)")
    for k, v in sorted(by_device.items(), key=device_errors_desc):
        print(f"  {k:42s} rows {v['rows']:>9,}   FP {v['FP']:>3}   FN {v['FN']:>3}")
    print("\nTOP SOURCES (device x traffic type)")
    for r in sorted(per_source, key=source_errors_desc)[:10]:
        if r["errors"]:
            print(
                f"  {r['device']:42s} {r['traffic_type']:16s} wrong {r['errors']:>3} "
                f"of {r['rows']:>8,}  ({r['error_kind']})"
            )
    print(f"\nFiles written to {out}")


if __name__ == "__main__":
    main()
