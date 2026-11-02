"""Independent read-only replay of external exact groups and diagnostic membership."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import time
from fractions import Fraction
from pathlib import Path


def digest_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024*1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check(work: Path) -> dict:
    started = time.perf_counter()
    verification = json.loads((work / "verification.json").read_bytes())
    db = sqlite3.connect((work / "candidate.sqlite").resolve().as_uri() + "?mode=ro", uri=True)
    db.execute("PRAGMA cache_size=-65536")
    db.execute("PRAGMA temp_store=FILE")
    names = ("TRAIN", "VALIDATION", "TEST")
    weights = (Fraction(3, 5), Fraction(1, 5), Fraction(1, 5))
    totals = db.execute("SELECT SUM(n0),SUM(n1) FROM groups").fetchone()
    assigned = [[0, 0], [0, 0], [0, 0]]
    digest = hashlib.sha256()
    mismatches = 0
    groups = 0
    for payload, sha, sortkey, n0, n1, actual in db.execute("""
      SELECT payload,sha,sortkey,n0,n1,partition FROM groups
      ORDER BY CASE WHEN n0>0 AND n1>0 THEN 0 WHEN n0>0 THEN 1 ELSE 2 END,
      sortkey COLLATE BINARY,sha COLLATE BINARY,payload"""):
        groups += 1
        values = json.loads(payload)
        canonical = json.dumps(values, ensure_ascii=True, allow_nan=False,
                               separators=(",", ":")).encode("ascii")
        if canonical != payload or hashlib.sha256(payload).hexdigest() != sha:
            raise ValueError("Exact tuple serialization/digest mismatch")
        if hashlib.sha256(("1729:" + sha).encode()).hexdigest() != sortkey:
            raise ValueError("Ordering key mismatch")
        labels = [y for y, n in enumerate((n0, n1)) if n]
        scores = [sum(weights[p]*totals[y]-assigned[p][y] for y in labels) for p in range(3)]
        proposed = scores.index(max(scores))
        mismatches += proposed != actual
        assigned[proposed][0] += n0
        assigned[proposed][1] += n1
        digest.update(json.dumps([sha, payload.decode("ascii"), names[proposed]],
                                 ensure_ascii=True, separators=(",", ":")).encode()+b"\n")
    if mismatches or digest.hexdigest() != verification["split"][
            "ordered_group_assignment_sha256"]:
        raise ValueError("Independent rational allocation replay mismatch")
    disagreement = db.execute("""SELECT COUNT(*) FROM groups g JOIN
      (SELECT gid,SUM(y=0) n0,SUM(y=1) n1 FROM observations GROUP BY gid) o
      ON o.gid=g.gid WHERE o.n0!=g.n0 OR o.n1!=g.n1""").fetchone()[0]
    if disagreement:
        raise ValueError("Observation labels disagree with group counts")
    membership = {name: hashlib.sha256() for name in names}
    row_counts = [0, 0, 0]
    source_paths = verification["sources"]
    # Relative canonical paths recorded in the frozen candidate, not inferred from cwd.
    contract_path = work / "frozen_candidate_contract.json"
    if not contract_path.exists():
        contract_path = (Path(__file__).resolve().parents[1]
                         / "artifacts/contracts/bot_iot_secondary_ml_candidate_v1.json")
    if digest_file(contract_path) != verification["contract_sha256"]:
        raise ValueError("Expected exact frozen candidate contract bytes")
    contract = json.loads(contract_path.read_bytes())
    for source, index, pk, y, sha, p in db.execute("""SELECT o.source,o.rownum,o.pk,o.y,g.sha,
      g.partition FROM observations o JOIN groups g ON o.gid=g.gid
      ORDER BY o.source,o.rownum"""):
        value = [contract["canonical_sources"][source], index, pk, str(y), sha]
        membership[names[p]].update(json.dumps(value, ensure_ascii=True,
                                             separators=(",", ":")).encode("ascii")+b"\n")
        row_counts[p] += 1
    for p, name in enumerate(names):
        expected = verification["split"]["partitions"][name]["membership_sha256"]
        if membership[name].hexdigest() != expected or digest_file(
                work / f"{name}_membership.jsonl") != expected:
            raise ValueError("Independent membership digest mismatch")
        if row_counts[p] != sum(assigned[p]):
            raise ValueError("Membership row count mismatch")
    for source in source_paths:
        if digest_file(Path(source["path"])) != source["manifest_sha256"]:
            raise ValueError("Source changed since full scan")
    foreign = db.execute("""SELECT COUNT(*) FROM observations o LEFT JOIN groups g
      ON g.gid=o.gid WHERE g.gid IS NULL""").fetchone()[0]
    largest_by_class = {}
    for p, name in enumerate(names):
        largest_by_class[name] = {}
        for y, label in enumerate(("benign", "malicious")):
            sha, n0, n1 = db.execute(f"""SELECT sha,n0,n1 FROM groups WHERE partition=?
              AND n{y}>0 ORDER BY n{y} DESC,sha,payload LIMIT 1""", (p,)).fetchone()
            count = (n0, n1)[y]
            largest_by_class[name][label] = {
                "sha256": sha, "class_rows": count, "total_group_rows": n0+n1,
                "fraction_of_partition_class": count/assigned[p][y],
                "fraction_of_full_class": count/totals[y]}
    db.close()
    if foreign:
        raise ValueError("Observation has no exact group")
    return {"status": "PASS_INDEPENDENT_READ_ONLY_REPLAY", "groups_checked": groups,
            "observations_checked": sum(row_counts), "partition_rows": row_counts,
            "group_label_count_disagreements": disagreement,
            "rational_allocation_mismatches": mismatches,
            "ordered_group_assignment_sha256": digest.hexdigest(),
            "membership_sha256": {n: d.hexdigest() for n, d in membership.items()},
            "source_content_hashes_rechecked": True,
            "largest_groups_by_class": largest_by_class,
            "verification_sha256": digest_file(work / "verification.json"),
            "implementation_sha256": digest_file(Path(__file__)),
            "elapsed_seconds": time.perf_counter()-started}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = check(args.work_dir)
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    print(json.dumps(result))
