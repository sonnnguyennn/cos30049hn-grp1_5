import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from src.iotguard.evaluation.primary import select_validation

# Settings shown in the table, per algorithm: (short name, key in "parameters", default).
# A run that lacks a key (older scripts) used the default, so it counts as "not changed".
SETTINGS = {
    "RF": [("trees", "n_estimators", 100), ("depth", "max_depth", None), ("leaf", "min_samples_leaf", 1),
           ("maxfeat", "max_features", "sqrt")],
    "XGB": [("rounds", "num_boost_round", 100), ("depth", "max_depth", 6), ("lr", "learning_rate", 0.3),
            ("mcw", "min_child_weight", 1.0), ("subsample", "subsample", 1.0),
            ("colsample", "colsample_bytree", 1.0), ("lambda", "reg_lambda", 1.0), ("bins", "max_bin", 256)]
}

# Fields that must be identical for runs to be comparable
IDENTITY = {"package_version", "package_manifest_sha256", "protocol_revision",
            "train_population_sha256", "validation_population_sha256"}

def macro_f1(tn, fp, fn, tp):
    def f1(a, b, c):
        return 2 * a / (2 * a + b + c) if 2 * a + b + c else None
    benign, malicious = f1(tn, fn, fp), f1(tp, fp, fn)
    return None if benign is None or malicious is None else (benign + malicious) / 2

def load_runs(runs_dir):
    runs, skipped = [], []
    for path in sorted(runs_dir.glob("*/result.json")):
        try:
            result = json.loads(path.read_text())
        except (OSError, ValueError) as err:
            skipped.append((str(path), f"cannot read: {err}")); continue
        if result.get("schema_version") != "primary_result_v1":
            skipped.append((str(path), "not a primary_result_v1 file")); continue
        notes_path = path.with_name("run_notes.json")
        try:
            notes = json.loads(notes_path.read_text()) if notes_path.exists() else {}
        except (OSError, ValueError):
            notes = {}
        runs.append({"result": result, "notes": notes, "folder": path.parent.name})
    return runs, skipped

def describe(run):
    r, notes = run["result"], run["notes"]
    p = r["resolved_configuration"]["parameters"]
    m, s = r["metrics"], p["train_sampling"]
    res = notes.get("resources", {})
    mem = res.get("peak_memory")
    mem = mem if isinstance(mem, dict) else {"peak_private_mb": res.get("peak_memory_mb")}  # one number in older notes
    family = "RF" if "RandomForest" in p["algorithm"] else "XGB" if "XGBoost" in p["algorithm"] else "other"
    changed = [f"{short}={p.get(key, default)}" for short, key, default in SETTINGS.get(family, [])
               if p.get(key, default) != default]
    parts = ("load_sample_seconds", "choose_rows_seconds", "build_matrix_seconds", "fit_seconds")
    return {
        "run_id": r["run_id"], "algorithm": family,
        "train_fraction": s["fraction"], "train_rows": s["rows"],
        "settings": " ".join(changed) or "baseline",
        "TN": m["TN"], "FP": m["FP"], "FN": m["FN"], "TP": m["TP"], "wrong_rows": m["FP"] + m["FN"],
        "macro_f1": m["macro_f1"], "fpr": m["fpr"], "malicious_recall": m["per_class"]["malicious"]["recall"],
        "train_seconds": round(sum(res.get(k) or 0 for k in parts), 1) if res else None,
        "peak_private_mb": mem.get("peak_private_mb"), "peak_working_set_mb": mem.get("peak_working_set_mb"),
        "model_size_mb": res.get("model_size_mb"),
        "dirty_worktree": r["dirty_worktree"], "code_revision": r["code_revision"][:10]
    }

def choose_pool(runs, target_fraction):
    excluded, candidates = [], []
    for run in runs:
        r = run["result"]; m = r["metrics"]; s = r["resolved_configuration"]["parameters"]["train_sampling"]
        per_class = m["per_class"]["malicious"]["recall"]
        if m["partition"] != "VALIDATION":
            excluded.append((run, f"scored on {m['partition']}, not VALIDATION"))
        elif None in (m["macro_f1"], m["fpr"], per_class):
            excluded.append((run, "has an undefined rate, so it cannot be selected"))
        elif s["fraction"] != target_fraction:
            excluded.append((run, f"trained on {s['fraction']:g} of TRAIN; the pool is {target_fraction:g}"))
        elif target_fraction == 1 and s["rows"] != s["rows_in_train"]:
            excluded.append((run, "claims the whole TRAIN but the row count differs"))
        else:
            candidates.append(run)
    
    groups = defaultdict(list)
    for run in candidates:
        s = run["result"]["resolved_configuration"]["parameters"]["train_sampling"]
        groups[(s["rows"], s["indices_sha256"])].append(run)
    if not groups:
        return [], excluded
    pool = max(groups.values(), key=len)
    for group in groups.values():
        if group is not pool:
            excluded += [(run, "trained on different rows than the rest of the pool") for run in group]
    return pool, excluded

def identity_problems(pool):
    problems = []
    for key in IDENTITY:
        who = defaultdict(list)
        for run in pool:
            who[run["result"][key]].append(run["result"]["run_id"])
        if len(who) > 1:
            problems.append((key, dict(who)))
    return problems

def rank_pool(pool):
    remaining = sorted(pool, key=lambda run: run["result"]["run_id"])
    ranking = []
    while remaining:
        best = select_validation([run["result"] for run in remaining])
        winner = next(run for run in remaining if run["result"] is best)
        ranking.append(winner)
        remaining = [run for run in remaining if run is not winner]
    return ranking

def main():
    # ----- 1. Read arguments -----
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs-dir", required=True, type=Path,
                    help="folder that holds the run folders")
    ap.add_argument("--fraction", type=float, default=1.0,
                    help="training-data size to compare: 1 = whole TRAIN (default), 0.1 = the 10%% runs")
    ap.add_argument("--out", type=Path, default=None,
                    help="where to write comparison.csv and selection.json (default: the runs folder)")
    args = ap.parse_args()
    if not args.run_dir.is_dir():
        sys.exit(f"{args.runs_dir} is not a folder")
    out = args.out or args.runs_dir
    out.mkdir(parents=True, exist_ok=True)

    # ----- 2. Read runs -----
    runs, skipped = load_runs(args.runs_dir)
    for path, why in skipped:
        print(f"skipped {path}: {why}")
    if not runs:
        sys.exit(f"No usable result.json files found under {args.runs_dir}")
    folders_of = defaultdict(list)
    for run in runs:
        folders_of[run["result"]["run_id"]].append(run["folder"])
    duplicates = {run_id: folders for run_id, folders in folders_of.items() if len(folders) > 1}
    if duplicates:
        for run_id, folders in duplicates.items():
            print(f"duplicate run_id {run_id!r} in folders: {', '.join(folders)}")
        sys.exit("Each run must appear once: remove or move the duplicate folders (the run_id inside result.json is what counts).")
    rows = {run["result"]["run_id"]: describe(run) for run in runs}
    print(f"Read {len(runs)} runs from {args.runs_dir}")

    # ----- 3. Pick pool, check identity, and rank -----
    pool, excluded = choose_pool(runs, args.fraction)
    if not pool:
        have = sorted({row["train_fraction"] for row in rows.values()})
        sys.exit(f"No runs were trained on fraction {args.fraction:g}. Fractions in this folder: {have}")
    problems = identity_problems(pool)
    if problems:
        print("\nThese runs cannot be compared: they differ in the fields the protocol requires to match.")
        for key, who in problems:
            print(f"  {key}:")
            for value, run_ids in who.items():
                print(f"     {str(value)[:14]:14} <- {', '.join(sorted(run_ids))}")
        sys.exit("Move runs made against another package, or another protocol revision, into a separate folder.")
    ranking = rank_pool(pool)
    winner = ranking[0]["result"]
    wm = winner["metrics"]

    # ----- 4. How far ahead the winner is -----
    base = macro_f1(wm["TN"], wm["FP"], wm["FN"], wm["TP"])
    one_row = (macro_f1(wm["TN"], wm["FP"], wm["FN"] - 1, wm["TP"] + 1) - base) if wm["FN"] else \
              (macro_f1(wm["TN"] + 1, wm["FP"] - 1, wm["FN"], wm["TP"]) - base) if wm["FP"] else None
    runner = ranking[1]["result"]["metrics"] if len(ranking) > 1 else None
    gap = (wm["macro_f1"] - runner["macro_f1"]) if runner else None
    gap_rows = (gap / one_row) if (gap is not None and one_row) else None
    # Exact ties: same macro-F1 (within 1e-6), same FPR, same recall as the winner.
    ties = [run["result"]["run_id"] for run in ranking[1:]
            if abs(run["result"]["metrics"]["macro_f1"] - wm["macro_f1"]) <= 1e-6
            and run["result"]["metrics"]["fpr"] == wm["fpr"]
            and run["result"]["metrics"]["per_class"]["malicious"]["recall"] == wm["per_class"]["malicious"]["recall"]]

    # ----- 5. Write files -----
    rank_of = {run["result"]["run_id"]: i + 1 for i, run in enumerate(ranking)}
    reason_of = {run["result"]["run_id"]: why for run, why in excluded}
    fields = ["rank", "run_id", "algorithm", "settings", "train_fraction", "train_rows", "TN", "FP", "FN", "TP",
              "wrong_rows", "macro_f1", "fpr", "malicious_recall", "train_seconds", "peak_private_mb",
              "peak_working_set_mb", "model_size_mb", "dirty_worktree", "code_revision", "not_in_pool_because"]
    with open(out / "comparison.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for run_id, row in sorted(rows.items(), key=lambda kv: (rank_of.get(kv[0], 10**6), kv[0])):
            w.writerow({**row, "rank": rank_of.get(run_id, ""), "not_in_pool_because": reason_of.get(run_id, "")})
    selection = {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rule": "highest VALIDATION macro-F1; within 1e-6 lower FPR, then higher malicious recall (primary.select_validation)",
        "pool": f"runs trained on fraction {args.fraction:g} with identical training rows",
        "winner": winner["run_id"],
        "winner_lead_over_runner_up": {"macro_f1": gap, "about_wrong_rows": gap_rows},
        "exact_ties_with_winner": ties,
        "ranking": [{"rank": i + 1, "run_id": run["result"]["run_id"], "macro_f1": run["result"]["metrics"]["macro_f1"],
                     "wrong_rows": rows[run["result"]["run_id"]]["wrong_rows"]} for i, run in enumerate(ranking)],
        "not_in_pool": {run["result"]["run_id"]: why for run, why in excluded},
        "skipped_files": dict(skipped),
        "test_partition_used": False,
    }
    (out / "selection.json").write_text(json.dumps(selection, indent=2))

    # ----- 6. Print table -----
    n_rows = pool[0]["result"]["resolved_configuration"]["parameters"]["train_sampling"]["rows"]
    size = "the whole TRAIN" if args.fraction == 1 else f"{args.fraction:g} of TRAIN"
    print(f"\nPOOL: {len(pool)} runs trained on the same {n_rows:,} rows ({size}), "
          "ranked with the official select_validation rule")
    print(f"{'#':>2}  {'run_id':32} {'wrong':>5} {'FP':>3} {'FN':>4}  {'macro-F1':>10}  {'FPR':>9}  {'recall':>9}  {'min':>6}  {'priv MB':>8}  settings")
    for i, run in enumerate(ranking, 1):
        d = rows[run["result"]["run_id"]]
        minutes = f"{d['train_seconds'] / 60:.1f}" if d["train_seconds"] is not None else "-"
        mem = f"{d['peak_private_mb']:.0f}" if d["peak_private_mb"] is not None else "-"
        flag = "  [dirty]" if d["dirty_worktree"] else ""
        print(f"{i:>2}{'*' if i == 1 else ' '} {d['run_id']:32} {d['wrong_rows']:>5} {d['FP']:>3} {d['FN']:>4}  "
              f"{d['macro_f1']:>10.7f}  {d['fpr']:>9.2e}  {d['malicious_recall']:>9.7f}  {minutes:>6}  {mem:>8}  {d['settings']}{flag}")
    print(f"\nWINNER (official rule): {winner['run_id']}")
    if gap is not None:
        about = f", about {gap_rows:.1f} wrong rows" if gap_rows is not None else ""
        print(f"  lead over runner-up: macro-F1 +{gap:.2e}{about}")
        if gap_rows is not None and gap_rows < 10:
            print("  Each run used one seed and seed-to-seed variation was not measured, so a lead of only a few rows may not repeat.")
    if ties:
        print(f"  EXACT TIE with: {', '.join(ties)}")
        print("  Same counts, so the official rule cannot separate them; the winner above is only first by name.")
        print("  Choose between them on other grounds (training time, memory, model size) and say so in the report.")
    if any(rows[r['result']['run_id']]['dirty_worktree'] for r in pool):
        print("  [dirty] = run from a checkout with uncommitted changes; allowed, but rerun the winner clean before reporting.")
    if excluded:
        print("\nNOT IN THE POOL (listed in comparison.csv too):")
        for run, why in sorted(excluded, key=lambda x: x[0]["result"]["run_id"]):
            print(f"  {run['result']['run_id']:32} {why}")
    print(f"\nWrote {out / 'comparison.csv'} and {out / 'selection.json'}")
    print("Selection used VALIDATION only; TEST stays sealed.")

if __name__ == "__main__":
    main()
