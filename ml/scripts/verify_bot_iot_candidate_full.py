"""Targeted full candidate scan; external SQLite/memberships, no training/package."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import sqlite3
import subprocess
import time
from collections import Counter, deque
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

import psutil

from iotguard.data.bot_iot import BotIoTParseError, parse_bot_iot_record
from iotguard.data.bot_iot_candidate_scan import (
    PARTITIONS,
    allocate,
    duplicate_statistics,
    make_database,
    tuple_bytes,
)
from iotguard.data.bot_iot_secondary import CATEGORICAL, assemble_secondary
from iotguard.data.contracts import bot_iot_source_columns

ML = Path(__file__).resolve().parents[1]
REPO = ML.parent


def sha_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


def flush(db, batch):
    grouped = {}
    for record, assembled, payload in batch:
        counts = grouped.setdefault(payload, [0, 0])
        counts[assembled.target] += 1
    ids = {}
    for payload, (n0, n1) in grouped.items():
        sha = hashlib.sha256(payload).hexdigest()
        sortkey = hashlib.sha256(("1729:" + sha).encode("ascii")).hexdigest()
        gid = db.execute("""INSERT INTO groups(payload,sha,sortkey,n0,n1) VALUES(?,?,?,?,?)
          ON CONFLICT(payload) DO UPDATE SET n0=n0+excluded.n0,n1=n1+excluded.n1
          RETURNING gid""", (payload, sha, sortkey, n0, n1)).fetchone()[0]
        ids[payload] = gid
    db.executemany("INSERT INTO observations VALUES(?,?,?,?,?,?,?)", [
        (record[0], record[1], assembled.metadata["pkSeqID"], assembled.target,
         ids[payload], assembled.metadata["category"], assembled.metadata["subcategory"])
        for record, assembled, payload in batch])
    db.commit()
    batch.clear()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    work = args.work_dir.resolve()
    if work.is_relative_to(REPO.resolve()):
        parser.error("Bulk working directory must be outside repository")
    work.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter()
    process = psutil.Process()
    peak = process.memory_info().rss
    contract_path = ML / "artifacts/contracts/bot_iot_secondary_ml_candidate_v1.json"
    contract = json.loads(contract_path.read_bytes())
    if contract["scan_policy"]["algorithm_id"] != "bot_iot_candidate_group_split_v1":
        raise ValueError("Scan policy not frozen")
    sources = contract["canonical_sources"]
    manifest = {r["relative_path"]: r for r in csv.DictReader(
        (ML / "artifacts/manifests/bot_iot_raw_manifest.csv").open(encoding="utf-8"))}
    report = {
        "status": "SCANNING", "candidate_status": "PROPOSED_FOR_REVIEW",
        "ready_for_training": False, "utc_started": datetime.now(UTC).isoformat(),
        "source_revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO).decode().strip(),
        "git_status_at_start": subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=REPO).decode(),
        "contract_sha256": sha_file(contract_path),
        "protocol_sha256": sha_file(ML / "docs/protocols/bot_iot_secondary_experiment_v1.md"),
        "implementation_sha256": {str(p.relative_to(ML)).replace("\\", "/"): sha_file(p)
                                  for p in (Path(__file__),
                                            ML / "src/iotguard/data/bot_iot_candidate_scan.py",
                                            ML / "src/iotguard/data/bot_iot_secondary.py",
                                            ML / "src/iotguard/data/bot_iot.py")},
        "runtime": {"python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                    **{n: version(n) for n in ("numpy", "pandas", "scikit-learn", "psutil")}},
        "sources": [], "invalid_rows": 0, "blockers": [],
    }
    db = sqlite3.connect(work / "candidate.sqlite")
    make_database(db)
    columns = bot_iot_source_columns()
    positions = {n: columns.index(n) for n in columns}
    sample_keys = set()
    expected_rows = (1000000, 1000000, 1000000, 668522)
    batch = []
    with (work / "invalid_rows.jsonl").open("x", encoding="utf-8") as errors:
        for source_no, source in enumerate(sources):
            path = args.root / source
            before = path.stat()
            pre_hash = sha_file(path)
            expected = manifest[source]
            if pre_hash != expected["sha256"] or before.st_size != int(expected["size_bytes"]):
                raise ValueError(f"Source identity mismatch before scan: {source}")
            scan_hash = hashlib.sha256()
            tail = deque(maxlen=2048)
            quotas = Counter()
            count = 0
            with path.open("rb") as handle:
                def lines():
                    for line in handle:
                        scan_hash.update(line)
                        yield line.decode("utf-8")
                reader = csv.reader(lines())
                if tuple(next(reader)) != columns:
                    raise ValueError(f"Wrong ordered header: {source}")
                for index, raw in enumerate(reader, 1):
                    count = index
                    if index <= 2048:
                        sample_keys.add((source_no, index))
                    if source_no == 3 and len(raw) == len(columns):
                        tail.append((source_no, index))
                        kinds = {"benign"} if raw[positions["attack"]] == "0" else set()
                        for port in (raw[positions["sport"]], raw[positions["dport"]]):
                            if port == "-1":
                                kinds.add("sentinel")
                            elif port.lower().startswith("0x"):
                                kinds.add("hex")
                        for kind in kinds:
                            if quotas[kind] < 32:
                                sample_keys.add((source_no, index))
                                quotas[kind] += 1
                    try:
                        row = assemble_secondary(parse_bot_iot_record(
                            raw, source, data_row_index=index))
                    except (BotIoTParseError, KeyError) as error:
                        report["invalid_rows"] += 1
                        errors.write(json.dumps([source, index, str(error)]) + "\n")
                        continue
                    payload = tuple_bytes(row.values)
                    if hashlib.sha256(payload).hexdigest() != row.equivalence_sha256:
                        raise ValueError("Assembler/scan equivalence serialization mismatch")
                    batch.append(((source_no, index), row, payload))
                    if len(batch) >= 8192:
                        flush(db, batch)
                        peak = max(peak, process.memory_info().rss)
                    if index % 100000 == 0:
                        print(f"shard{source_no+1}: {index:,} rows", flush=True)
            if batch:
                flush(db, batch)
            sample_keys.update(tail)
            post_hash = sha_file(path)
            after = path.stat()
            immutable = (pre_hash == scan_hash.hexdigest() == post_hash
                         and (before.st_size, before.st_mtime_ns)
                         == (after.st_size, after.st_mtime_ns))
            report["sources"].append({"path": str(path), "rows": count,
                                      "expected_rows": expected_rows[source_no],
                                      "bytes": before.st_size,
                                      "mtime_ns_before": before.st_mtime_ns,
                                      "mtime_ns_after": after.st_mtime_ns,
                                      "manifest_sha256": expected["sha256"],
                                      "pre_sha256": pre_hash,
                                      "streamed_sha256": scan_hash.hexdigest(),
                                      "post_sha256": post_hash, "immutable": immutable})
            if not immutable or count != expected_rows[source_no]:
                report["blockers"].append(f"Source immutability/row reconciliation: {source}")
    report["full_statistics"] = duplicate_statistics(
        r[0] for r in db.execute("SELECT n0+n1 FROM groups"))
    report["class_counts"] = {str(y): {"rows": db.execute(
        f"SELECT SUM(n{y}) FROM groups").fetchone()[0], "groups": db.execute(
            f"SELECT COUNT(*) FROM groups WHERE n{y}>0").fetchone()[0]} for y in (0, 1)}
    report["row_reconciliation"] = {
        "source_observations": sum(s["rows"] for s in report["sources"]),
        "valid_observations": db.execute("SELECT COUNT(*) FROM observations").fetchone()[0],
        "invalid_observations": report["invalid_rows"],
        "group_observations": report["full_statistics"]["total_observations"]}
    report["sha256_collision_buckets"] = db.execute(
        "SELECT COUNT(*) FROM (SELECT sha FROM groups GROUP BY sha HAVING COUNT(*)>1)"
    ).fetchone()[0]
    report["equality_authority"] = "Exact canonical tuple BLOB UNIQUE; SHA256 not equality key"
    conflicts = {"groups": 0, "rows": 0, "benign_rows": 0, "malicious_rows": 0,
                 "minority_label_rows": 0, "examples": []}
    with (work / "conflicting_groups.jsonl").open("x", encoding="utf-8") as out:
        for sha, payload, n0, n1 in db.execute(
                "SELECT sha,payload,n0,n1 FROM groups WHERE n0>0 AND n1>0 ORDER BY sha,payload"):
            item = {"sha256": sha, "tuple": json.loads(payload), "benign": n0, "malicious": n1}
            out.write(json.dumps(item) + "\n")
            conflicts["groups"] += 1
            conflicts["rows"] += n0 + n1
            conflicts["benign_rows"] += n0
            conflicts["malicious_rows"] += n1
            conflicts["minority_label_rows"] += min(n0, n1)
            if len(conflicts["examples"]) < 10:
                conflicts["examples"].append(item)
    report["binary_label_conflicts"] = conflicts
    if conflicts["groups"]:
        report["blockers"].append("Cross-label exact-X conflicts; diagnostic membership only")
    if report["invalid_rows"]:
        report["blockers"].append("Invalid observations; no full-corpus membership constructed")
    sample_groups = Counter()
    sample_hash = hashlib.sha256()
    for sample_index, (source_no, index) in enumerate(sorted(sample_keys)):
        result = db.execute("""SELECT g.payload,g.sha FROM observations o JOIN groups g
          ON o.gid=g.gid WHERE o.source=? AND o.rownum=?""", (source_no, index)).fetchone()
        if result is None:
            raise ValueError("Historical smoke selection includes invalid/unavailable row")
        sample_groups[result[0]] += 1
        sample_hash.update((b"\n" if sample_index else b"") + result[1].encode())
    old_smoke_path = ML / "artifacts/manifests/bot_iot_secondary_smoke.json"
    old = json.loads(old_smoke_path.read_bytes())
    keys_for_hash = [(sources[s], i) for s, i in sorted(sample_keys)]
    sample_membership = hashlib.sha256(json.dumps(
        keys_for_hash, separators=(",", ":")).encode()).hexdigest()
    report["smoke_addendum"] = {
        "historical_evidence_sha256": sha_file(old_smoke_path),
        **duplicate_statistics(sample_groups.values()),
        "assembled_X_sha256": sample_hash.hexdigest(),
        "sample_membership_sha256": sample_membership,
        "historical_hashes_match": (sample_hash.hexdigest() == old["assembled_X_sha256"]
                                    and sample_membership == old["sample_membership_sha256"]),
        "terminology": "1365 = repeated groups, not all unique groups or duplicated rows"}
    if not report["smoke_addendum"]["historical_hashes_match"]:
        report["blockers"].append("Historical smoke reconciliation mismatch")
    if not report["invalid_rows"]:
        split = allocate(db, persist=True)
        replay = allocate(db, persist=False)
        if split != replay:
            raise ValueError("Deterministic allocation replay mismatch")
        report["split"] = summarize_split(db, sources, work, contract, split)
        report["blockers"].extend(report["split"]["blockers"])
    report["group_size_histogram"] = dict(db.execute(
        "SELECT n0+n1,COUNT(*) FROM groups GROUP BY n0+n1 ORDER BY n0+n1"))
    # Compact histogram in Git; full histogram retained externally.
    write_json(work / "group_size_histogram.json", report.pop("group_size_histogram"))
    report["database_integrity"] = db.execute("PRAGMA integrity_check").fetchone()[0]
    db.close()
    for source in report["sources"]:
        path = Path(source["path"])
        source["final_sha256"] = sha_file(path)
        source["immutable_through_allocation"] = (
            source["final_sha256"] == source["pre_sha256"]
            and path.stat().st_mtime_ns == source["mtime_ns_before"])
        if not source["immutable_through_allocation"]:
            report["blockers"].append(f"Source changed during allocation: {path}")
    report["external_files"] = {p.name: {"bytes": p.stat().st_size, "sha256": sha_file(p)}
                                for p in sorted(work.iterdir()) if p.is_file()}
    report["resources"] = {"elapsed_seconds": time.perf_counter()-started,
                           "cpu_seconds": sum(process.cpu_times()[:2]),
                           "peak_rss_bytes": max(peak, process.memory_info().rss,
                                                 process.memory_info().peak_wset
                                                 if hasattr(process.memory_info(), "peak_wset")
                                                 else 0),
                           "sqlite_cache_limit_bytes": 64 * 1024**2, "batch_rows": 8192}
    report["external_work_dir"] = str(work)
    report["status"] = "VERIFIED_SCAN_SPLIT_BLOCKED" if report["blockers"] else "VERIFIED_SCAN"
    write_json(work / "verification.json", report)
    print(json.dumps({"status": report["status"], "statistics": report["full_statistics"],
                      "blockers": report["blockers"], "resources": report["resources"]}),
          flush=True)


def summarize_split(db, sources, work, contract, allocation):
    summary = {**allocation, "deterministic_replay_match": True,
               "partitions": {}, "blockers": [], "exact_group_overlap": 0}
    for p, name in enumerate(PARTITIONS):
        counts = allocation["rows_by_class"][p]
        groups = allocation["groups_by_class"][p]
        largest = db.execute("""SELECT sha,n0,n1 FROM groups WHERE partition=?
                              ORDER BY n0+n1 DESC,sha,payload LIMIT 1""", (p,)).fetchone()
        categories = {}
        for field_index, field in enumerate(CATEGORICAL, 10):
            values = Counter()
            for payload, n0, n1 in db.execute(
                    "SELECT payload,n0,n1 FROM groups WHERE partition=?", (p,)):
                values[json.loads(payload)[field_index]] += n0+n1
            categories[field] = dict(sorted(values.items()))
        digest = hashlib.sha256()
        rows = 0
        with (work / f"{name}_membership.jsonl").open("xb") as out:
            for source_no, index, pk, y, sha in db.execute("""
              SELECT o.source,o.rownum,o.pk,o.y,g.sha
              FROM observations o JOIN groups g ON o.gid=g.gid WHERE g.partition=?
              ORDER BY o.source,o.rownum""", (p,)):
                data = tuple_bytes([sources[source_no], index, pk, str(y), sha]) + b"\n"
                out.write(data)
                digest.update(data)
                rows += 1
        group_count = db.execute(
            "SELECT COUNT(*) FROM groups WHERE partition=?", (p,)).fetchone()[0]
        item = {"rows": rows, "binary_rows": dict(zip(("benign", "malicious"), counts)),
                "distinct_X_groups": group_count,
                "distinct_groups_per_class": dict(zip(("benign", "malicious"), groups)),
                "membership_sha256": digest.hexdigest(), "categorical_coverage": categories,
                "largest_group": {"sha256": largest[0], "benign": largest[1],
                                  "malicious": largest[2], "rows": sum(largest[1:]),
                                  "fraction_of_partition": sum(largest[1:])/rows},
                "label_metadata_support": {field: dict(db.execute(f"""SELECT o.{field},COUNT(*)
                  FROM observations o JOIN groups g ON o.gid=g.gid WHERE g.partition=?
                  GROUP BY o.{field} ORDER BY o.{field}""", (p,)))
                                           for field in ("category", "subcategory")}}
        item["support_gates"] = {
            label: {"rows_pass": counts[y] >= contract["split_proposal"][
                "minimum_rows_per_class"][name], "groups_pass": groups[y] >= contract[
                    "split_proposal"]["minimum_distinct_groups_per_class"][name]}
            for y, label in enumerate(("benign", "malicious"))}
        if any(not all(g.values()) for g in item["support_gates"].values()):
            summary["blockers"].append(f"Support gate failed: {name}")
        summary["partitions"][name] = item
    train = summary["partitions"]["TRAIN"]["categorical_coverage"]
    for name in ("VALIDATION", "TEST"):
        item = summary["partitions"][name]
        item["valid_but_unseen_categories"] = {
            f: {v: n for v, n in item["categorical_coverage"][f].items() if v not in train[f]}
            for f in CATEGORICAL}
        if any(item["valid_but_unseen_categories"].values()):
            summary["blockers"].append(f"Valid-but-unseen categories: {name}; no vocab expansion")
    # Each exact tuple has one groups row and one scalar partition; check all observations map.
    unassigned = db.execute("""SELECT COUNT(*) FROM observations o LEFT JOIN groups g
      ON o.gid=g.gid WHERE g.partition IS NULL""").fetchone()[0]
    summary["unassigned_observations"] = unassigned
    if unassigned or sum(i["rows"] for i in summary["partitions"].values()) != sum(
            sum(c) for c in allocation["rows_by_class"]):
        raise ValueError("Membership reconciliation failed")
    return summary


if __name__ == "__main__":
    main()
